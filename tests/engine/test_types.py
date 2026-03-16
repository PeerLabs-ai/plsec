"""Tests for plsec.engine.types -- core type definitions.

Covers the shared vocabulary: enums, Finding, Location, ScanContext,
and supporting value objects.  All types are pure data with no
external dependencies.

Contract: These types are the stable interface between engines,
the orchestrator, and the reporting layer.  Changes here affect
every consumer.
"""

from pathlib import Path

import pytest

from plsec.engine.types import (
    AvailabilityResult,
    EngineStatus,
    EnvironmentInfo,
    Finding,
    FindingCategory,
    Layer,
    Location,
    Preset,
    ScanContext,
    Severity,
)

# -----------------------------------------------------------------------
# Enum ordering and values
# -----------------------------------------------------------------------


class TestLayer:
    """Contract: Layer is an IntEnum ordered STATIC < CONFIG < ... < AUDIT."""

    def test_ordering(self):
        assert Layer.STATIC < Layer.CONFIG < Layer.ISOLATION < Layer.RUNTIME < Layer.AUDIT

    def test_values(self):
        assert Layer.STATIC == 1
        assert Layer.AUDIT == 5

    def test_all_layers(self):
        assert len(Layer) == 5

    def test_iterable_in_order(self):
        layers = list(Layer)
        assert layers == [
            Layer.STATIC,
            Layer.CONFIG,
            Layer.ISOLATION,
            Layer.RUNTIME,
            Layer.AUDIT,
        ]


class TestSeverity:
    """Contract: Severity is an IntEnum ordered INFO < LOW < ... < CRITICAL."""

    def test_ordering(self):
        assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL

    def test_values(self):
        assert Severity.INFO == 0
        assert Severity.CRITICAL == 4

    def test_comparison(self):
        """Severity comparison enables threshold logic."""
        assert Severity.MEDIUM >= Severity.LOW
        assert not Severity.LOW >= Severity.HIGH


class TestFindingCategory:
    """Contract: FindingCategory covers all detection types."""

    def test_all_categories(self):
        expected = {
            "secret",
            "vulnerability",
            "dependency_vulnerability",
            "misconfiguration",
            "code_issue",
            "policy_violation",
            "missing_control",
            "integrity",
        }
        actual = {c.value for c in FindingCategory}
        assert actual == expected


class TestPreset:
    """Contract: Preset covers the four security levels."""

    def test_all_presets(self):
        expected = {"minimal", "balanced", "strict", "paranoid"}
        actual = {p.value for p in Preset}
        assert actual == expected


class TestEngineStatus:
    """Contract: EngineStatus covers availability states."""

    def test_all_statuses(self):
        expected = {"available", "unavailable", "degraded", "skipped"}
        actual = {s.value for s in EngineStatus}
        assert actual == expected


# -----------------------------------------------------------------------
# Location
# -----------------------------------------------------------------------


class TestLocation:
    """Contract: Location.display() formats available fields into a
    human-readable string."""

    def test_display_with_file_and_line(self):
        loc = Location(file_path=Path("src/main.py"), line_start=42)
        assert loc.display() == "src/main.py:42"

    def test_display_with_file_only(self):
        loc = Location(file_path=Path("README.md"))
        assert loc.display() == "README.md"

    def test_display_with_container(self):
        loc = Location(container="my-container")
        assert loc.display() == "container:my-container"

    def test_display_with_network_endpoint(self):
        loc = Location(network_endpoint="https://api.example.com")
        assert loc.display() == "https://api.example.com"

    def test_display_no_fields(self):
        loc = Location()
        assert loc.display() == "(no location)"

    def test_display_multiple_fields(self):
        loc = Location(
            file_path=Path("src/main.py"),
            line_start=10,
            container="sandbox",
        )
        result = loc.display()
        assert "src/main.py:10" in result
        assert "container:sandbox" in result

    def test_frozen(self):
        loc = Location(file_path=Path("test.py"))
        with pytest.raises(AttributeError):
            loc.file_path = Path("other.py")  # type: ignore[misc]


# -----------------------------------------------------------------------
# Finding
# -----------------------------------------------------------------------


class TestFinding:
    """Contract: Finding is immutable, has deterministic IDs, and
    supports safe copying via with_severity/with_suppressed."""

    def _make_finding(self, **overrides) -> Finding:
        defaults = {
            "engine_id": "test-engine",
            "layer": Layer.STATIC,
            "severity": Severity.HIGH,
            "category": FindingCategory.LEAKED_CREDENTIAL,
            "title": "Test finding",
        }
        defaults.update(overrides)
        return Finding(**defaults)

    def test_creation(self):
        f = self._make_finding()
        assert f.engine_id == "test-engine"
        assert f.layer == Layer.STATIC
        assert f.severity == Severity.HIGH
        assert f.category == FindingCategory.LEAKED_CREDENTIAL
        assert f.title == "Test finding"

    def test_defaults(self):
        f = self._make_finding()
        assert f.description == ""
        assert f.location is None
        assert f.evidence == {}
        assert f.remediation is None
        assert f.suppressed is False
        assert f.metadata == {}

    def test_id_deterministic(self):
        """Same inputs produce same ID."""
        f1 = self._make_finding(title="secret leak")
        f2 = self._make_finding(title="secret leak")
        assert f1.id == f2.id

    def test_id_differs_by_title(self):
        f1 = self._make_finding(title="secret A")
        f2 = self._make_finding(title="secret B")
        assert f1.id != f2.id

    def test_id_differs_by_engine(self):
        f1 = self._make_finding(engine_id="trivy")
        f2 = self._make_finding(engine_id="bandit")
        assert f1.id != f2.id

    def test_id_differs_by_location(self):
        f1 = self._make_finding(location=Location(file_path=Path("a.py")))
        f2 = self._make_finding(location=Location(file_path=Path("b.py")))
        assert f1.id != f2.id

    def test_id_is_hex_string(self):
        f = self._make_finding()
        assert len(f.id) == 16
        int(f.id, 16)  # should not raise

    def test_with_severity(self):
        """with_severity returns a new Finding with updated severity."""
        f = self._make_finding(severity=Severity.LOW)
        upgraded = f.with_severity(Severity.CRITICAL)
        assert upgraded.severity == Severity.CRITICAL
        assert f.severity == Severity.LOW  # original unchanged
        assert upgraded.title == f.title
        assert upgraded.engine_id == f.engine_id

    def test_with_suppressed(self):
        """with_suppressed returns a new Finding marked as suppressed."""
        f = self._make_finding()
        assert f.suppressed is False
        suppressed = f.with_suppressed(True)
        assert suppressed.suppressed is True
        assert f.suppressed is False  # original unchanged

    def test_frozen(self):
        f = self._make_finding()
        with pytest.raises(AttributeError):
            f.title = "modified"  # type: ignore[misc]


# -----------------------------------------------------------------------
# AvailabilityResult
# -----------------------------------------------------------------------


class TestAvailabilityResult:
    """Contract: AvailabilityResult carries engine availability status."""

    def test_creation(self):
        r = AvailabilityResult(status=EngineStatus.AVAILABLE, message="ok")
        assert r.status == EngineStatus.AVAILABLE
        assert r.message == "ok"

    def test_defaults(self):
        r = AvailabilityResult(status=EngineStatus.UNAVAILABLE)
        assert r.message == ""
        assert r.version is None

    def test_with_version(self):
        r = AvailabilityResult(
            status=EngineStatus.AVAILABLE,
            version="0.57.1",
        )
        assert r.version == "0.57.1"

    def test_frozen(self):
        r = AvailabilityResult(status=EngineStatus.AVAILABLE)
        with pytest.raises(AttributeError):
            r.status = EngineStatus.UNAVAILABLE  # type: ignore[misc]


# -----------------------------------------------------------------------
# EnvironmentInfo
# -----------------------------------------------------------------------


class TestEnvironmentInfo:
    """Contract: EnvironmentInfo captures runtime environment detection."""

    def test_creation(self):
        env = EnvironmentInfo(
            os_name="darwin",
            os_version="24.0.0",
            python_version="3.12.0",
        )
        assert env.os_name == "darwin"

    def test_defaults(self):
        env = EnvironmentInfo(
            os_name="linux",
            os_version="6.1",
            python_version="3.12.0",
        )
        assert env.container_runtime is None
        assert env.container_runtime_version is None
        assert env.available_tools == frozenset()

    def test_available_tools_frozenset(self):
        env = EnvironmentInfo(
            os_name="darwin",
            os_version="24.0.0",
            python_version="3.12.0",
            available_tools=frozenset({"trivy", "bandit"}),
        )
        assert "trivy" in env.available_tools
        assert "semgrep" not in env.available_tools

    def test_frozen(self):
        env = EnvironmentInfo(
            os_name="darwin",
            os_version="24.0.0",
            python_version="3.12.0",
        )
        with pytest.raises(AttributeError):
            env.os_name = "linux"  # type: ignore[misc]


# -----------------------------------------------------------------------
# ScanContext
# -----------------------------------------------------------------------


class TestScanContext:
    """Contract: ScanContext carries all state needed by engines."""

    def _make_context(self, **overrides) -> ScanContext:
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

    def test_creation(self):
        ctx = self._make_context()
        assert ctx.preset == Preset.BALANCED

    def test_default_fields(self):
        ctx = self._make_context()
        assert ctx.engine_configs == {}
        assert ctx.prior_findings == []

    def test_config_for_existing_engine(self):
        ctx = self._make_context(
            engine_configs={"trivy-secrets": {"timeout": 60}},
        )
        assert ctx.config_for("trivy-secrets") == {"timeout": 60}

    def test_config_for_missing_engine(self):
        ctx = self._make_context()
        assert ctx.config_for("nonexistent") == {}

    def test_prior_findings_mutable(self):
        """prior_findings grows between layers (orchestrator appends)."""
        ctx = self._make_context()
        finding = Finding(
            engine_id="test",
            layer=Layer.STATIC,
            severity=Severity.HIGH,
            category=FindingCategory.LEAKED_CREDENTIAL,
            title="test",
        )
        ctx.prior_findings.append(finding)
        assert len(ctx.prior_findings) == 1
