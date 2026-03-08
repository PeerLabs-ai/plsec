"""Tests for plsec.engine.orchestrator -- scan lifecycle coordinator.

Covers the Orchestrator.scan() method, _detect_environment(), the
build_orchestrator() factory, and the full pipeline: environment
detection -> layer walk -> correlation -> policy -> verdict.

Contract: The orchestrator is the single entry point for running a
scan. It coordinates engines, correlation, policy, and verdict
strategy without knowing about specific engines.
"""

from unittest.mock import patch

from plsec.engine.base import (
    Engine,
    ScanResult,
)
from plsec.engine.correlation import CorrelationEngine, CorrelationRule
from plsec.engine.orchestrator import (
    KNOWN_TOOLS,
    Orchestrator,
    build_orchestrator,
)
from plsec.engine.policy import Policy, Suppression
from plsec.engine.registry import EngineRegistry
from plsec.engine.types import (
    AvailabilityResult,
    EngineStatus,
    EnvironmentInfo,
    Finding,
    FindingCategory,
    Layer,
    Preset,
    ScanContext,
    Severity,
)
from plsec.engine.verdict import (
    AuditVerdictStrategy,
    VerdictStatus,
)

# -----------------------------------------------------------------------
# Test engine stubs
# -----------------------------------------------------------------------


class StubEngine(Engine):
    """A configurable stub engine for orchestrator tests."""

    def __init__(
        self,
        engine_id: str = "stub",
        layer: Layer = Layer.STATIC,
        presets: frozenset[Preset] | None = None,
        available: bool = True,
        findings: list[Finding] | None = None,
    ):
        self._engine_id = engine_id
        self._layer = layer
        self._presets = presets or frozenset(Preset)
        self._available = available
        self._findings = findings or []

    @property
    def engine_id(self) -> str:
        return self._engine_id

    @property
    def layer(self) -> Layer:
        return self._layer

    @property
    def display_name(self) -> str:
        return f"Stub: {self._engine_id}"

    @property
    def presets(self) -> frozenset[Preset]:
        return self._presets

    def check_available(self, ctx: ScanContext) -> AvailabilityResult:
        if self._available:
            return AvailabilityResult(status=EngineStatus.AVAILABLE)
        return AvailabilityResult(
            status=EngineStatus.UNAVAILABLE,
            message=f"{self._engine_id} not found",
        )

    def execute(self, ctx: ScanContext) -> list[Finding]:
        return list(self._findings)


def _make_finding(
    engine_id: str = "stub",
    layer: Layer = Layer.STATIC,
    severity: Severity = Severity.HIGH,
    category: FindingCategory = FindingCategory.LEAKED_CREDENTIAL,
    title: str = "Test finding",
    suppressed: bool = False,
) -> Finding:
    return Finding(
        engine_id=engine_id,
        layer=layer,
        severity=severity,
        category=category,
        title=title,
        suppressed=suppressed,
    )


def _make_registry(*engines: Engine) -> EngineRegistry:
    """Build a registry with the given engines."""
    reg = EngineRegistry()
    for e in engines:
        reg.register(e)
    return reg


def _no_op_correlation() -> CorrelationEngine:
    """A correlation engine with no rules."""
    return CorrelationEngine(rules=[])


# -----------------------------------------------------------------------
# KNOWN_TOOLS constant
# -----------------------------------------------------------------------


class TestKnownTools:
    """Contract: KNOWN_TOOLS lists the tools the orchestrator looks for."""

    def test_is_tuple(self):
        assert isinstance(KNOWN_TOOLS, tuple)

    def test_contains_core_tools(self):
        assert "trivy" in KNOWN_TOOLS
        assert "bandit" in KNOWN_TOOLS
        assert "semgrep" in KNOWN_TOOLS

    def test_contains_container_tools(self):
        assert "podman" in KNOWN_TOOLS
        assert "docker" in KNOWN_TOOLS


# -----------------------------------------------------------------------
# _detect_environment
# -----------------------------------------------------------------------


class TestDetectEnvironment:
    """Contract: _detect_environment produces EnvironmentInfo with
    detected OS, Python version, and available tools."""

    @patch("plsec.engine.orchestrator.shutil.which")
    @patch("plsec.engine.orchestrator.platform")
    def test_basic_detection(self, mock_platform, mock_which):
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"
        mock_which.return_value = None  # no tools available

        orch = Orchestrator(
            registry=EngineRegistry(),
            correlation=_no_op_correlation(),
        )
        env = orch._detect_environment()

        assert isinstance(env, EnvironmentInfo)
        assert env.os_name == "darwin"
        assert env.os_version == "24.0.0"
        assert env.python_version == "3.12.0"

    @patch("plsec.engine.orchestrator.shutil.which")
    @patch("plsec.engine.orchestrator.platform")
    def test_detects_available_tools(self, mock_platform, mock_which):
        mock_platform.system.return_value = "Linux"
        mock_platform.release.return_value = "6.1"
        mock_platform.python_version.return_value = "3.12.0"

        def which_side_effect(tool):
            return f"/usr/bin/{tool}" if tool in ("trivy", "bandit") else None

        mock_which.side_effect = which_side_effect

        orch = Orchestrator(
            registry=EngineRegistry(),
            correlation=_no_op_correlation(),
        )
        env = orch._detect_environment()

        assert "trivy" in env.available_tools
        assert "bandit" in env.available_tools
        assert "semgrep" not in env.available_tools

    @patch("plsec.engine.orchestrator.shutil.which")
    @patch("plsec.engine.orchestrator.platform")
    def test_detects_podman_container_runtime(self, mock_platform, mock_which):
        mock_platform.system.return_value = "Linux"
        mock_platform.release.return_value = "6.1"
        mock_platform.python_version.return_value = "3.12.0"

        def which_side_effect(tool):
            return f"/usr/bin/{tool}" if tool == "podman" else None

        mock_which.side_effect = which_side_effect

        orch = Orchestrator(
            registry=EngineRegistry(),
            correlation=_no_op_correlation(),
        )
        env = orch._detect_environment()

        assert env.container_runtime == "podman"

    @patch("plsec.engine.orchestrator.shutil.which")
    @patch("plsec.engine.orchestrator.platform")
    def test_detects_docker_container_runtime(self, mock_platform, mock_which):
        mock_platform.system.return_value = "Linux"
        mock_platform.release.return_value = "6.1"
        mock_platform.python_version.return_value = "3.12.0"

        def which_side_effect(tool):
            return f"/usr/bin/{tool}" if tool == "docker" else None

        mock_which.side_effect = which_side_effect

        orch = Orchestrator(
            registry=EngineRegistry(),
            correlation=_no_op_correlation(),
        )
        env = orch._detect_environment()

        assert env.container_runtime == "docker"

    @patch("plsec.engine.orchestrator.shutil.which")
    @patch("plsec.engine.orchestrator.platform")
    def test_podman_preferred_over_docker(self, mock_platform, mock_which):
        """When both are available, podman is preferred."""
        mock_platform.system.return_value = "Linux"
        mock_platform.release.return_value = "6.1"
        mock_platform.python_version.return_value = "3.12.0"

        def which_side_effect(tool):
            if tool in ("podman", "docker"):
                return f"/usr/bin/{tool}"
            return None

        mock_which.side_effect = which_side_effect

        orch = Orchestrator(
            registry=EngineRegistry(),
            correlation=_no_op_correlation(),
        )
        env = orch._detect_environment()

        assert env.container_runtime == "podman"

    @patch("plsec.engine.orchestrator.shutil.which")
    @patch("plsec.engine.orchestrator.platform")
    def test_no_container_runtime(self, mock_platform, mock_which):
        mock_platform.system.return_value = "Linux"
        mock_platform.release.return_value = "6.1"
        mock_platform.python_version.return_value = "3.12.0"
        mock_which.return_value = None

        orch = Orchestrator(
            registry=EngineRegistry(),
            correlation=_no_op_correlation(),
        )
        env = orch._detect_environment()

        assert env.container_runtime is None


# -----------------------------------------------------------------------
# Orchestrator.scan — basic lifecycle
# -----------------------------------------------------------------------


class TestOrchestratorScan:
    """Contract: scan() walks layers, runs correlation, applies policy,
    computes verdict, and returns a ScanResult."""

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_empty_registry_no_engines(self, mock_platform, _mock_which, tmp_path):
        """With no engines, scan completes with ERROR verdict (nothing ran)."""
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        orch = Orchestrator(
            registry=EngineRegistry(),
            correlation=_no_op_correlation(),
        )
        result = orch.scan(tmp_path, Preset.BALANCED)

        assert isinstance(result, ScanResult)
        assert result.verdict is not None
        # ThresholdVerdictStrategy (balanced default) returns ERROR when no engines ran
        assert result.verdict.status == VerdictStatus.ERROR

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_single_engine_no_findings(self, mock_platform, _mock_which, tmp_path):
        """One engine that produces no findings -> PASS."""
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        engine = StubEngine(engine_id="clean-engine", findings=[])
        registry = _make_registry(engine)

        orch = Orchestrator(
            registry=registry,
            correlation=_no_op_correlation(),
        )
        result = orch.scan(tmp_path, Preset.BALANCED)

        assert result.verdict.status == VerdictStatus.PASSED
        assert result.verdict.exit_code == 0
        assert result.engines_ran == 1

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_single_engine_with_findings(self, mock_platform, _mock_which, tmp_path):
        """One engine with HIGH findings -> FAIL (balanced preset)."""
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        finding = _make_finding(severity=Severity.HIGH)
        engine = StubEngine(engine_id="leaky-engine", findings=[finding])
        registry = _make_registry(engine)

        orch = Orchestrator(
            registry=registry,
            correlation=_no_op_correlation(),
        )
        result = orch.scan(tmp_path, Preset.BALANCED)

        assert result.verdict.status == VerdictStatus.FAIL
        assert result.verdict.exit_code == 1

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_unavailable_engine_skipped(self, mock_platform, _mock_which, tmp_path):
        """Unavailable engines are skipped, not executed."""
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        engine = StubEngine(engine_id="missing", available=False)
        registry = _make_registry(engine)

        orch = Orchestrator(
            registry=registry,
            correlation=_no_op_correlation(),
        )
        result = orch.scan(tmp_path, Preset.BALANCED)

        assert result.engines_skipped == 1
        assert result.engines_ran == 0

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_preset_filters_engines(self, mock_platform, _mock_which, tmp_path):
        """Engines not in the active preset are not executed."""
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        # Engine only in STRICT preset
        strict_only = StubEngine(
            engine_id="strict-engine",
            presets=frozenset({Preset.STRICT}),
            findings=[_make_finding(severity=Severity.CRITICAL)],
        )
        registry = _make_registry(strict_only)

        orch = Orchestrator(
            registry=registry,
            correlation=_no_op_correlation(),
        )
        # Scan with BALANCED -- should not run the strict-only engine
        result = orch.scan(tmp_path, Preset.BALANCED)

        assert result.engines_ran == 0
        # No layer_results because no engines were active
        assert result.verdict.status == VerdictStatus.ERROR


# -----------------------------------------------------------------------
# Orchestrator.scan — multi-layer pipeline
# -----------------------------------------------------------------------


class TestOrchestratorMultiLayer:
    """Contract: The orchestrator walks layers in order and forwards
    findings to downstream layers via ctx.prior_findings."""

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_findings_flow_to_downstream_layers(self, mock_platform, _mock_which, tmp_path):
        """Findings from earlier layers appear in prior_findings for later layers."""
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        # Track what prior_findings each engine sees
        seen_prior: dict[str, int] = {}

        class TrackingEngine(Engine):
            def __init__(self, eid: str, layer: Layer, findings: list[Finding]):
                self._eid = eid
                self._layer = layer
                self._findings = findings

            @property
            def engine_id(self) -> str:
                return self._eid

            @property
            def layer(self) -> Layer:
                return self._layer

            @property
            def display_name(self) -> str:
                return self._eid

            def check_available(self, ctx: ScanContext) -> AvailabilityResult:
                return AvailabilityResult(status=EngineStatus.AVAILABLE)

            def execute(self, ctx: ScanContext) -> list[Finding]:
                seen_prior[self._eid] = len(ctx.prior_findings)
                return list(self._findings)

        static_finding = _make_finding(engine_id="static-eng", layer=Layer.STATIC)
        config_finding = _make_finding(
            engine_id="config-eng", layer=Layer.CONFIG, title="config issue"
        )

        static_engine = TrackingEngine("static-eng", Layer.STATIC, [static_finding])
        config_engine = TrackingEngine("config-eng", Layer.CONFIG, [config_finding])
        iso_engine = TrackingEngine("iso-eng", Layer.ISOLATION, [])

        registry = _make_registry(static_engine, config_engine, iso_engine)
        orch = Orchestrator(
            registry=registry,
            correlation=_no_op_correlation(),
        )
        orch.scan(tmp_path, Preset.BALANCED)

        # STATIC engine sees 0 prior findings
        assert seen_prior["static-eng"] == 0
        # CONFIG engine sees 1 prior finding (from STATIC)
        assert seen_prior["config-eng"] == 1
        # ISOLATION engine sees 2 prior findings (from STATIC + CONFIG)
        assert seen_prior["iso-eng"] == 2

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_all_findings_collected(self, mock_platform, _mock_which, tmp_path):
        """ScanResult.all_findings contains findings from all layers."""
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        f1 = _make_finding(engine_id="e1", layer=Layer.STATIC, title="f1")
        f2 = _make_finding(engine_id="e2", layer=Layer.CONFIG, title="f2")

        e1 = StubEngine(engine_id="e1", layer=Layer.STATIC, findings=[f1])
        e2 = StubEngine(engine_id="e2", layer=Layer.CONFIG, findings=[f2])
        registry = _make_registry(e1, e2)

        orch = Orchestrator(
            registry=registry,
            correlation=_no_op_correlation(),
        )
        result = orch.scan(tmp_path, Preset.BALANCED)

        titles = {f.title for f in result.all_findings}
        assert "f1" in titles
        assert "f2" in titles


# -----------------------------------------------------------------------
# Orchestrator.scan — correlation integration
# -----------------------------------------------------------------------


class TestOrchestratorCorrelation:
    """Contract: After layer walk, the orchestrator runs correlation
    rules on the complete finding set."""

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_correlation_findings_in_result(self, mock_platform, _mock_which, tmp_path):
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        synthetic = _make_finding(engine_id="correlation", title="Synthetic risk")
        rule = CorrelationRule(
            rule_id="always",
            description="Always triggers",
            predicate=lambda f: True,
            factory=lambda f: synthetic,
        )
        correlation = CorrelationEngine(rules=[rule])

        engine = StubEngine(engine_id="e1", findings=[_make_finding()])
        registry = _make_registry(engine)

        orch = Orchestrator(
            registry=registry,
            correlation=correlation,
        )
        result = orch.scan(tmp_path, Preset.BALANCED)

        assert len(result.correlation_findings) == 1
        assert result.correlation_findings[0].title == "Synthetic risk"

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_no_correlation_when_no_rules_trigger(self, mock_platform, _mock_which, tmp_path):
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        orch = Orchestrator(
            registry=_make_registry(StubEngine(findings=[])),
            correlation=_no_op_correlation(),
        )
        result = orch.scan(tmp_path, Preset.BALANCED)

        assert result.correlation_findings == []


# -----------------------------------------------------------------------
# Orchestrator.scan — policy integration
# -----------------------------------------------------------------------


class TestOrchestratorPolicy:
    """Contract: After correlation, the orchestrator applies policy
    (severity floor + suppressions) to the combined finding set."""

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_policy_severity_floor_applied(self, mock_platform, _mock_which, tmp_path):
        """Findings below severity floor are dropped from evaluated_findings."""
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        low_finding = _make_finding(severity=Severity.LOW, title="low")
        high_finding = _make_finding(severity=Severity.HIGH, title="high")
        engine = StubEngine(findings=[low_finding, high_finding])
        registry = _make_registry(engine)

        policy = Policy(severity_floor=Severity.HIGH)
        orch = Orchestrator(
            registry=registry,
            policy=policy,
            correlation=_no_op_correlation(),
        )
        result = orch.scan(tmp_path, Preset.BALANCED)

        # evaluated_findings should only contain HIGH (LOW filtered out)
        assert len(result.evaluated_findings) == 1
        assert result.evaluated_findings[0].title == "high"

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_policy_suppression_applied(self, mock_platform, _mock_which, tmp_path):
        """Matching findings are marked as suppressed in evaluated_findings."""
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        finding = _make_finding(engine_id="noisy-engine")
        engine = StubEngine(engine_id="noisy-engine", findings=[finding])
        registry = _make_registry(engine)

        policy = Policy(
            suppressions=[Suppression(engine_id="noisy-engine")],
        )
        orch = Orchestrator(
            registry=registry,
            policy=policy,
            correlation=_no_op_correlation(),
        )
        result = orch.scan(tmp_path, Preset.BALANCED)

        assert len(result.evaluated_findings) == 1
        assert result.evaluated_findings[0].suppressed is True

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_default_policy_minimal_filtering(self, mock_platform, _mock_which, tmp_path):
        """Default Policy (floor=LOW, no suppressions) passes most through."""
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        finding = _make_finding(severity=Severity.MEDIUM)
        engine = StubEngine(findings=[finding])

        orch = Orchestrator(
            registry=_make_registry(engine),
            correlation=_no_op_correlation(),
        )
        result = orch.scan(tmp_path, Preset.BALANCED)

        assert len(result.evaluated_findings) == 1
        assert not result.evaluated_findings[0].suppressed


# -----------------------------------------------------------------------
# Orchestrator.scan — verdict strategy
# -----------------------------------------------------------------------


class TestOrchestratorVerdict:
    """Contract: The orchestrator delegates verdict to the strategy.
    Explicit strategy takes precedence over preset-derived."""

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_explicit_strategy_used(self, mock_platform, _mock_which, tmp_path):
        """When an explicit strategy is provided, it overrides preset default."""
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        finding = _make_finding(severity=Severity.CRITICAL)
        engine = StubEngine(findings=[finding])

        # Audit strategy always passes
        orch = Orchestrator(
            registry=_make_registry(engine),
            correlation=_no_op_correlation(),
            verdict_strategy=AuditVerdictStrategy(),
        )
        result = orch.scan(tmp_path, Preset.BALANCED)

        assert result.verdict.status == VerdictStatus.PASSED
        assert "audit" in result.verdict.metadata.get("mode", "").lower()

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_preset_derived_strategy(self, mock_platform, _mock_which, tmp_path):
        """Without explicit strategy, preset-derived strategy is used."""
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        finding = _make_finding(severity=Severity.LOW)
        engine = StubEngine(findings=[finding])

        # Strict preset uses StrictVerdictStrategy -> FAIL on any finding
        orch = Orchestrator(
            registry=_make_registry(engine),
            correlation=_no_op_correlation(),
        )
        result = orch.scan(tmp_path, Preset.STRICT)

        assert result.verdict.status == VerdictStatus.FAIL

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_verdict_counts_reflect_findings(self, mock_platform, _mock_which, tmp_path):
        """Verdict counts match the evaluated finding set."""
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        findings = [
            _make_finding(severity=Severity.HIGH, title="f1"),
            _make_finding(severity=Severity.MEDIUM, title="f2"),
        ]
        engine = StubEngine(findings=findings)

        orch = Orchestrator(
            registry=_make_registry(engine),
            correlation=_no_op_correlation(),
        )
        result = orch.scan(tmp_path, Preset.BALANCED)

        assert result.verdict.counts.total == 2
        assert result.verdict.counts.engines_ran == 1


# -----------------------------------------------------------------------
# Orchestrator.scan — engine_configs forwarding
# -----------------------------------------------------------------------


class TestOrchestratorEngineConfigs:
    """Contract: engine_configs are forwarded to ScanContext so engines
    can read their configuration."""

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_engine_configs_forwarded(self, mock_platform, _mock_which, tmp_path):
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        received_config = {}

        class ConfigCapture(Engine):
            @property
            def engine_id(self) -> str:
                return "config-capture"

            @property
            def layer(self) -> Layer:
                return Layer.STATIC

            @property
            def display_name(self) -> str:
                return "Config Capture"

            def check_available(self, ctx: ScanContext) -> AvailabilityResult:
                return AvailabilityResult(status=EngineStatus.AVAILABLE)

            def execute(self, ctx: ScanContext) -> list[Finding]:
                received_config.update(ctx.config_for("config-capture"))
                return []

        engine = ConfigCapture()
        registry = _make_registry(engine)

        orch = Orchestrator(
            registry=registry,
            correlation=_no_op_correlation(),
        )
        orch.scan(
            tmp_path,
            Preset.BALANCED,
            engine_configs={"config-capture": {"timeout": 30}},
        )

        assert received_config == {"timeout": 30}


# -----------------------------------------------------------------------
# Orchestrator.scan — full pipeline integration
# -----------------------------------------------------------------------


class TestOrchestratorFullPipeline:
    """Integration tests verifying the complete pipeline end-to-end."""

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_clean_scan(self, mock_platform, _mock_which, tmp_path):
        """No findings, no correlation -> PASS."""
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        engine = StubEngine(findings=[])
        orch = Orchestrator(
            registry=_make_registry(engine),
            correlation=_no_op_correlation(),
        )
        result = orch.scan(tmp_path, Preset.BALANCED)

        assert result.verdict.passed
        assert not result.verdict.failed
        assert result.all_findings == []
        assert result.correlation_findings == []

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_findings_suppressed_by_policy_pass(self, mock_platform, _mock_which, tmp_path):
        """Findings suppressed by policy lead to PASS verdict."""
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        finding = _make_finding(engine_id="e1", severity=Severity.CRITICAL)
        engine = StubEngine(engine_id="e1", findings=[finding])

        policy = Policy(suppressions=[Suppression(engine_id="e1")])
        orch = Orchestrator(
            registry=_make_registry(engine),
            policy=policy,
            correlation=_no_op_correlation(),
        )
        result = orch.scan(tmp_path, Preset.BALANCED)

        # Finding is suppressed, so verdict should be PASS
        assert result.verdict.status == VerdictStatus.PASSED
        assert result.verdict.counts.suppressed == 1

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_correlation_affects_verdict(self, mock_platform, _mock_which, tmp_path):
        """Correlation-produced findings can cause FAIL."""
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        # Engine produces a clean result
        engine = StubEngine(findings=[])

        # But correlation always produces a CRITICAL finding
        critical_synthetic = _make_finding(
            engine_id="correlation",
            severity=Severity.CRITICAL,
            title="Compound risk",
        )
        rule = CorrelationRule(
            rule_id="always-critical",
            description="Always produces critical",
            predicate=lambda f: True,
            factory=lambda f: critical_synthetic,
        )
        correlation = CorrelationEngine(rules=[rule])

        orch = Orchestrator(
            registry=_make_registry(engine),
            correlation=correlation,
        )
        result = orch.scan(tmp_path, Preset.BALANCED)

        assert result.verdict.status == VerdictStatus.FAIL

    @patch("plsec.engine.orchestrator.shutil.which", return_value=None)
    @patch("plsec.engine.orchestrator.platform")
    def test_target_path_resolved(self, mock_platform, _mock_which, tmp_path):
        """ScanContext receives a resolved target path."""
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "24.0.0"
        mock_platform.python_version.return_value = "3.12.0"

        captured_path = []

        class PathCapture(Engine):
            @property
            def engine_id(self) -> str:
                return "path-cap"

            @property
            def layer(self) -> Layer:
                return Layer.STATIC

            @property
            def display_name(self) -> str:
                return "Path Capture"

            def check_available(self, ctx: ScanContext) -> AvailabilityResult:
                return AvailabilityResult(status=EngineStatus.AVAILABLE)

            def execute(self, ctx: ScanContext) -> list[Finding]:
                captured_path.append(ctx.target_path)
                return []

        orch = Orchestrator(
            registry=_make_registry(PathCapture()),
            correlation=_no_op_correlation(),
        )
        orch.scan(tmp_path, Preset.BALANCED)

        assert captured_path[0] == tmp_path.resolve()


# -----------------------------------------------------------------------
# build_orchestrator factory
# -----------------------------------------------------------------------


class TestBuildOrchestrator:
    """Contract: build_orchestrator is the intended construction path."""

    def test_returns_orchestrator(self):
        orch = build_orchestrator(registry=EngineRegistry())
        assert isinstance(orch, Orchestrator)

    def test_accepts_policy(self):
        policy = Policy(severity_floor=Severity.CRITICAL)
        orch = build_orchestrator(registry=EngineRegistry(), policy=policy)
        assert orch._policy.severity_floor == Severity.CRITICAL

    def test_accepts_verdict_strategy(self):
        strategy = AuditVerdictStrategy()
        orch = build_orchestrator(
            registry=EngineRegistry(),
            verdict_strategy=strategy,
        )
        assert orch._verdict_strategy is strategy

    def test_default_policy(self):
        orch = build_orchestrator(registry=EngineRegistry())
        assert isinstance(orch._policy, Policy)
        assert orch._policy.severity_floor == Severity.LOW

    def test_default_correlation(self):
        orch = build_orchestrator(registry=EngineRegistry())
        assert isinstance(orch._correlation, CorrelationEngine)
        # Should have default rules
        assert len(orch._correlation._rules) == 3
