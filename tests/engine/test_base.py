"""Tests for plsec.engine.base -- Engine ABC, EngineGroup, result containers.

Covers the engine contract, group execution with availability gating,
preset filtering, and the result composition hierarchy.

Contract: Engine defines the interface all engines must satisfy.
EngineGroup orchestrates engines within a layer.  Result containers
compose findings from engines -> layers -> full scan.
"""

from pathlib import Path

import pytest

from plsec.engine.base import (
    Engine,
    EngineGroup,
    EngineResult,
    LayerResult,
    ScanResult,
)
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
from plsec.engine.verdict import Verdict, VerdictCounts, VerdictStatus

# -----------------------------------------------------------------------
# Test helpers
# -----------------------------------------------------------------------


def _make_context(**overrides) -> ScanContext:
    defaults = {
        "target_path": Path("/var/project"),
        "preset": Preset.BALANCED,
        "environment": EnvironmentInfo(
            os_name="darwin",
            os_version="24.0.0",
            python_version="3.12.0",
        ),
    }
    defaults.update(overrides)
    return ScanContext(**defaults)


def _make_finding(
    engine_id: str = "stub",
    severity: Severity = Severity.HIGH,
    suppressed: bool = False,
) -> Finding:
    return Finding(
        engine_id=engine_id,
        layer=Layer.STATIC,
        severity=severity,
        category=FindingCategory.LEAKED_CREDENTIAL,
        title=f"Finding from {engine_id}",
        suppressed=suppressed,
    )


class _StubEngine(Engine):
    """Minimal concrete engine for testing the ABC and EngineGroup."""

    def __init__(
        self,
        *,
        engine_id: str = "stub-engine",
        layer: Layer = Layer.STATIC,
        display_name: str = "Stub Engine",
        presets: frozenset[Preset] | None = None,
        availability: AvailabilityResult | None = None,
        findings: list[Finding] | None = None,
    ):
        self._engine_id = engine_id
        self._layer = layer
        self._display_name = display_name
        self._presets = presets if presets is not None else frozenset(Preset)
        self._availability = availability or AvailabilityResult(status=EngineStatus.AVAILABLE)
        self._findings = findings if findings is not None else []

    @property
    def engine_id(self) -> str:
        return self._engine_id

    @property
    def layer(self) -> Layer:
        return self._layer

    @property
    def display_name(self) -> str:
        return self._display_name

    @property
    def presets(self) -> frozenset[Preset]:
        return self._presets

    def check_available(self, ctx: ScanContext) -> AvailabilityResult:
        return self._availability

    def execute(self, ctx: ScanContext) -> list[Finding]:
        return list(self._findings)


# -----------------------------------------------------------------------
# Engine ABC
# -----------------------------------------------------------------------


class TestEngineABC:
    """Contract: Engine is abstract and cannot be instantiated directly.
    Concrete subclasses must implement all abstract methods."""

    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            Engine()  # type: ignore[abstract]

    def test_concrete_subclass_works(self):
        engine = _StubEngine()
        assert engine.engine_id == "stub-engine"
        assert engine.layer == Layer.STATIC
        assert engine.display_name == "Stub Engine"

    def test_default_presets_is_all(self):
        """Default presets property returns all presets."""
        engine = _StubEngine()
        assert engine.presets == frozenset(Preset)

    def test_default_dependencies_is_empty(self):
        engine = _StubEngine()
        assert engine.dependencies == []

    def test_repr(self):
        engine = _StubEngine(engine_id="test", layer=Layer.CONFIG)
        r = repr(engine)
        assert "test" in r
        assert "CONFIG" in r


# -----------------------------------------------------------------------
# EngineGroup
# -----------------------------------------------------------------------


class TestEngineGroup:
    """Contract: EngineGroup manages engines within a single layer.
    It filters by preset, gates on availability, and collects findings."""

    def test_register_matching_layer(self):
        group = EngineGroup(Layer.STATIC)
        engine = _StubEngine(layer=Layer.STATIC)
        group.register(engine)
        assert len(group.engines_for_preset(Preset.BALANCED)) == 1

    def test_register_mismatched_layer_raises(self):
        group = EngineGroup(Layer.STATIC)
        engine = _StubEngine(layer=Layer.CONFIG)
        with pytest.raises(ValueError, match="CONFIG") as exc_info:
            group.register(engine)
        assert "STATIC" in str(exc_info.value)

    def test_engines_for_preset_filters(self):
        """Only engines enabled for the given preset are returned."""
        group = EngineGroup(Layer.STATIC)
        group.register(
            _StubEngine(
                engine_id="all-presets",
                layer=Layer.STATIC,
                presets=frozenset(Preset),
            )
        )
        group.register(
            _StubEngine(
                engine_id="strict-only",
                layer=Layer.STATIC,
                presets=frozenset({Preset.STRICT, Preset.PARANOID}),
            )
        )
        balanced = group.engines_for_preset(Preset.BALANCED)
        strict = group.engines_for_preset(Preset.STRICT)
        assert len(balanced) == 1
        assert balanced[0].engine_id == "all-presets"
        assert len(strict) == 2

    def test_execute_runs_available_engines(self):
        finding = _make_finding(engine_id="available")
        group = EngineGroup(
            Layer.STATIC,
            engines=[
                _StubEngine(
                    engine_id="available",
                    layer=Layer.STATIC,
                    findings=[finding],
                ),
            ],
        )
        ctx = _make_context()
        result = group.execute(ctx)
        assert len(result.findings) == 1
        assert result.engines_ran == 1
        assert result.engines_skipped == 0

    def test_execute_skips_unavailable_engines(self):
        group = EngineGroup(
            Layer.STATIC,
            engines=[
                _StubEngine(
                    engine_id="missing",
                    layer=Layer.STATIC,
                    availability=AvailabilityResult(status=EngineStatus.UNAVAILABLE),
                ),
            ],
        )
        ctx = _make_context()
        result = group.execute(ctx)
        assert len(result.findings) == 0
        assert result.engines_ran == 0
        assert result.engines_skipped == 1

    def test_execute_runs_degraded_engines(self):
        """DEGRADED engines should still run."""
        finding = _make_finding(engine_id="degraded")
        group = EngineGroup(
            Layer.STATIC,
            engines=[
                _StubEngine(
                    engine_id="degraded",
                    layer=Layer.STATIC,
                    availability=AvailabilityResult(status=EngineStatus.DEGRADED),
                    findings=[finding],
                ),
            ],
        )
        ctx = _make_context()
        result = group.execute(ctx)
        assert result.engines_ran == 1
        assert len(result.findings) == 1

    def test_execute_mixed_availability(self):
        """Mix of available and unavailable engines."""
        finding = _make_finding(engine_id="good")
        group = EngineGroup(
            Layer.STATIC,
            engines=[
                _StubEngine(
                    engine_id="good",
                    layer=Layer.STATIC,
                    findings=[finding],
                ),
                _StubEngine(
                    engine_id="missing",
                    layer=Layer.STATIC,
                    availability=AvailabilityResult(status=EngineStatus.UNAVAILABLE),
                ),
            ],
        )
        ctx = _make_context()
        result = group.execute(ctx)
        assert result.engines_ran == 1
        assert result.engines_skipped == 1
        assert len(result.findings) == 1

    def test_execute_respects_preset(self):
        """Only engines enabled for the context preset are executed."""
        strict_finding = _make_finding(engine_id="strict-only")
        group = EngineGroup(
            Layer.STATIC,
            engines=[
                _StubEngine(
                    engine_id="strict-only",
                    layer=Layer.STATIC,
                    presets=frozenset({Preset.STRICT}),
                    findings=[strict_finding],
                ),
            ],
        )
        ctx = _make_context(preset=Preset.BALANCED)
        result = group.execute(ctx)
        assert len(result.findings) == 0

    def test_repr(self):
        group = EngineGroup(Layer.STATIC)
        group.register(_StubEngine(engine_id="e1", layer=Layer.STATIC))
        r = repr(group)
        assert "STATIC" in r
        assert "e1" in r


# -----------------------------------------------------------------------
# EngineResult
# -----------------------------------------------------------------------


class TestEngineResult:
    """Contract: EngineResult wraps a single engine's execution output."""

    def test_ran_when_available(self):
        r = EngineResult(
            engine_id="test",
            availability=AvailabilityResult(status=EngineStatus.AVAILABLE),
            findings=[],
        )
        assert r.ran is True

    def test_ran_when_degraded(self):
        r = EngineResult(
            engine_id="test",
            availability=AvailabilityResult(status=EngineStatus.DEGRADED),
            findings=[],
        )
        assert r.ran is True

    def test_not_ran_when_unavailable(self):
        r = EngineResult(
            engine_id="test",
            availability=AvailabilityResult(status=EngineStatus.UNAVAILABLE),
            findings=[],
        )
        assert r.ran is False

    def test_finding_count_excludes_suppressed(self):
        r = EngineResult(
            engine_id="test",
            availability=AvailabilityResult(status=EngineStatus.AVAILABLE),
            findings=[
                _make_finding(suppressed=False),
                _make_finding(suppressed=True),
                _make_finding(suppressed=False),
            ],
        )
        assert r.finding_count == 2


# -----------------------------------------------------------------------
# LayerResult
# -----------------------------------------------------------------------


class TestLayerResult:
    """Contract: LayerResult aggregates engine results within a layer."""

    def _make_engine_result(
        self,
        ran: bool,
        findings: list[Finding] | None = None,
    ) -> EngineResult:
        status = EngineStatus.AVAILABLE if ran else EngineStatus.UNAVAILABLE
        return EngineResult(
            engine_id="test",
            availability=AvailabilityResult(status=status),
            findings=findings or [],
        )

    def test_engines_ran(self):
        lr = LayerResult(
            layer=Layer.STATIC,
            engine_results=[
                self._make_engine_result(ran=True),
                self._make_engine_result(ran=False),
                self._make_engine_result(ran=True),
            ],
            findings=[],
        )
        assert lr.engines_ran == 2

    def test_engines_skipped(self):
        lr = LayerResult(
            layer=Layer.STATIC,
            engine_results=[
                self._make_engine_result(ran=True),
                self._make_engine_result(ran=False),
            ],
            findings=[],
        )
        assert lr.engines_skipped == 1

    def test_unsuppressed_findings(self):
        findings = [
            _make_finding(suppressed=False),
            _make_finding(suppressed=True),
        ]
        lr = LayerResult(
            layer=Layer.STATIC,
            engine_results=[],
            findings=findings,
        )
        assert len(lr.unsuppressed_findings) == 1


# -----------------------------------------------------------------------
# ScanResult
# -----------------------------------------------------------------------


class TestScanResult:
    """Contract: ScanResult aggregates all layers plus correlation
    findings, and carries the verdict and evaluated findings."""

    def test_all_findings_aggregates_layers_and_correlation(self):
        layer_finding = _make_finding(engine_id="layer")
        correlation_finding = _make_finding(engine_id="correlation")
        lr = LayerResult(
            layer=Layer.STATIC,
            engine_results=[],
            findings=[layer_finding],
        )
        result = ScanResult(
            layer_results=[lr],
            correlation_findings=[correlation_finding],
        )
        assert len(result.all_findings) == 2

    def test_unsuppressed(self):
        findings = [
            _make_finding(suppressed=False),
            _make_finding(suppressed=True),
        ]
        lr = LayerResult(
            layer=Layer.STATIC,
            engine_results=[],
            findings=findings,
        )
        result = ScanResult(layer_results=[lr])
        assert len(result.unsuppressed) == 1

    def test_max_severity_with_findings(self):
        findings = [
            _make_finding(severity=Severity.LOW),
            _make_finding(severity=Severity.CRITICAL),
        ]
        lr = LayerResult(
            layer=Layer.STATIC,
            engine_results=[],
            findings=findings,
        )
        result = ScanResult(layer_results=[lr])
        assert result.max_severity == Severity.CRITICAL

    def test_max_severity_clean(self):
        result = ScanResult()
        assert result.max_severity == -1

    def test_verdict_default_none(self):
        result = ScanResult()
        assert result.verdict is None

    def test_verdict_attached(self):
        verdict = Verdict(
            status=VerdictStatus.PASSED,
            exit_code=0,
            rationale="clean",
            counts=VerdictCounts(),
        )
        result = ScanResult(verdict=verdict)
        assert result.verdict is not None
        assert result.verdict.exit_code == 0

    def test_evaluated_findings_default_empty(self):
        result = ScanResult()
        assert result.evaluated_findings == []

    def test_engines_ran_aggregates_layers(self):
        er_ran = EngineResult(
            engine_id="a",
            availability=AvailabilityResult(status=EngineStatus.AVAILABLE),
            findings=[],
        )
        er_ran2 = EngineResult(
            engine_id="c",
            availability=AvailabilityResult(status=EngineStatus.AVAILABLE),
            findings=[],
        )
        er_skip = EngineResult(
            engine_id="b",
            availability=AvailabilityResult(status=EngineStatus.UNAVAILABLE),
            findings=[],
        )
        lr1 = LayerResult(
            layer=Layer.STATIC,
            engine_results=[er_ran, er_skip],
            findings=[],
        )
        lr2 = LayerResult(
            layer=Layer.CONFIG,
            engine_results=[er_ran2],
            findings=[],
        )
        result = ScanResult(layer_results=[lr1, lr2])
        # lr1: 1 ran + 1 skipped, lr2: 1 ran = 2 ran, 1 skipped
        assert result.engines_ran == 2
        assert result.engines_skipped == 1
