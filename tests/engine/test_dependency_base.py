"""Tests for DependencyEngine abstract base class."""

from pathlib import Path

import pytest

from plsec.engine.base import Engine
from plsec.engine.dependency import DependencyEngine
from plsec.engine.types import (
    AvailabilityResult,
    EngineStatus,
    Finding,
    FindingCategory,
    Layer,
    Location,
    ScanContext,
    Severity,
)


# Minimal concrete subclass for testing the ABC
class _StubDependencyEngine(DependencyEngine):
    @property
    def engine_id(self) -> str:
        return "stub-dep"

    @property
    def display_name(self) -> str:
        return "Stub Dependency Engine"

    def check_available(self, ctx: ScanContext) -> AvailabilityResult:
        return AvailabilityResult(status=EngineStatus.AVAILABLE, message="ok")

    def execute(self, ctx: ScanContext) -> list[Finding]:
        return []


class TestDependencyEngineABC:
    """Contract: DependencyEngine extends Engine."""

    def test_is_engine_subclass(self):
        assert issubclass(DependencyEngine, Engine)

    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            DependencyEngine()  # type: ignore[abstract]

    def test_concrete_subclass_works(self):
        engine = _StubDependencyEngine()
        assert engine.engine_id == "stub-dep"


class TestLayerPinned:
    """Contract: DependencyEngine pins layer to STATIC."""

    def test_layer_is_static(self):
        engine = _StubDependencyEngine()
        assert engine.layer == Layer.STATIC

    def test_layer_not_overridable_by_accident(self):
        # The layer property comes from DependencyEngine, not the subclass
        assert _StubDependencyEngine().layer == Layer.STATIC


class TestCveSeverityMapping:
    """Contract: shared CVE severity mapping covers standard levels."""

    def test_critical(self):
        assert DependencyEngine.map_cve_severity("CRITICAL") == Severity.CRITICAL

    def test_high(self):
        assert DependencyEngine.map_cve_severity("HIGH") == Severity.HIGH

    def test_medium(self):
        assert DependencyEngine.map_cve_severity("MEDIUM") == Severity.MEDIUM

    def test_low(self):
        assert DependencyEngine.map_cve_severity("LOW") == Severity.LOW

    def test_unknown_defaults_to_info(self):
        assert DependencyEngine.map_cve_severity("UNKNOWN") == Severity.INFO

    def test_unmapped_defaults_to_info(self):
        assert DependencyEngine.map_cve_severity("NONSENSE") == Severity.INFO

    def test_case_sensitive(self):
        # CVE databases use uppercase; lowercase should fall through to default
        assert DependencyEngine.map_cve_severity("critical") == Severity.INFO


class TestMakeDependencyFinding:
    """Contract: finding builder produces correct category and fields."""

    def test_category_is_dependency_vulnerability(self):
        finding = DependencyEngine.make_dependency_finding(
            engine_id="test-engine",
            title="CVE-2024-1234 in requests",
            severity=Severity.HIGH,
        )
        assert finding.category == FindingCategory.DEPENDENCY_VULNERABILITY

    def test_required_fields(self):
        finding = DependencyEngine.make_dependency_finding(
            engine_id="test-engine",
            title="CVE-2024-1234 in requests",
            severity=Severity.HIGH,
        )
        assert finding.engine_id == "test-engine"
        assert finding.title == "CVE-2024-1234 in requests"
        assert finding.severity == Severity.HIGH
        assert finding.layer == Layer.STATIC

    def test_optional_fields(self):
        loc = Location(file_path=Path("requirements.txt"), line_start=5)
        evidence = {
            "installed_version": "2.28.0",
            "fixed_version": "2.31.0",
        }
        finding = DependencyEngine.make_dependency_finding(
            engine_id="test-engine",
            title="CVE-2024-1234 in requests",
            severity=Severity.HIGH,
            description="Remote code execution via crafted URL",
            location=loc,
            evidence=evidence,
            remediation="Upgrade requests to >= 2.31.0",
        )
        assert finding.description == "Remote code execution via crafted URL"
        assert finding.location == loc
        assert finding.evidence == evidence
        assert finding.remediation == "Upgrade requests to >= 2.31.0"

    def test_finding_id_deterministic(self):
        kwargs = {
            "engine_id": "test-engine",
            "title": "CVE-2024-1234 in requests",
            "severity": Severity.HIGH,
        }
        f1 = DependencyEngine.make_dependency_finding(**kwargs)
        f2 = DependencyEngine.make_dependency_finding(**kwargs)
        assert f1.id == f2.id

    def test_finding_id_differs_by_title(self):
        f1 = DependencyEngine.make_dependency_finding(
            engine_id="test-engine",
            title="CVE-2024-1234",
            severity=Severity.HIGH,
        )
        f2 = DependencyEngine.make_dependency_finding(
            engine_id="test-engine",
            title="CVE-2024-5678",
            severity=Severity.HIGH,
        )
        assert f1.id != f2.id
