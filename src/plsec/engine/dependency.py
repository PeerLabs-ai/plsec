"""
plsec.engine.dependency -- Abstract base for dependency vulnerability engines.

DependencyEngine is the common interface for all Software Composition
Analysis (SCA) engines.  It extends Engine and pins:
- layer = STATIC (SCA analyses manifests and lockfiles)
- FindingCategory = DEPENDENCY_VULNERABILITY

Concrete subclasses include:
- TrivyDependencyEngine (cross-language baseline)
- PipAuditEngine (Python-specific depth, future)

See docs/dependency-vulnerability-scanners.md for the landscape analysis.
"""

import abc
from typing import Any

from plsec.engine.base import Engine
from plsec.engine.types import (
    Finding,
    FindingCategory,
    Layer,
    Location,
    Severity,
)

# CVE severity levels are consistent across vulnerability databases.
# This mapping covers the standard CVSS qualitative ratings used by
# Trivy, OSV, NVD, and ecosystem-native tools.
_CVE_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


class DependencyEngine(Engine, abc.ABC):
    """Abstract base for dependency vulnerability scanners (SCA).

    Pins layer to STATIC and provides shared utilities for
    dependency-oriented engines:
    - CVE severity mapping (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN)
    - Finding construction with DEPENDENCY_VULNERABILITY category

    Concrete subclasses must implement engine_id, display_name,
    check_available(), and execute().
    """

    @property
    def layer(self) -> Layer:
        return Layer.STATIC

    @staticmethod
    def map_cve_severity(severity: str) -> Severity:
        """Map a CVE/CVSS severity string to a plsec Severity.

        Expects uppercase strings (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN).
        Unmapped values default to INFO.
        """
        return _CVE_SEVERITY_MAP.get(severity, Severity.INFO)

    @staticmethod
    def make_dependency_finding(
        *,
        engine_id: str,
        title: str,
        severity: Severity,
        description: str = "",
        location: Location | None = None,
        evidence: dict[str, Any] | None = None,
        remediation: str = "",
    ) -> Finding:
        """Build a Finding with DEPENDENCY_VULNERABILITY category.

        All dependency engines should use this builder to ensure
        consistent category assignment and field population.
        """
        return Finding(
            engine_id=engine_id,
            title=title,
            severity=severity,
            category=FindingCategory.DEPENDENCY_VULNERABILITY,
            layer=Layer.STATIC,
            description=description,
            location=location,
            evidence=evidence if evidence is not None else {},
            remediation=remediation,
        )
