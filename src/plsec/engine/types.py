"""
plsec.engine.types -- Core type definitions.

These are the shared vocabulary across all engines, the orchestrator,
and the reporting layer. Nothing in this module has behavior -- it's
pure data.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Layer(enum.IntEnum):
    """Security layers in execution order.

    IntEnum so layers are naturally orderable: STATIC < CONFIG < ... < AUDIT.
    """

    STATIC = 1
    CONFIG = 2
    ISOLATION = 3
    RUNTIME = 4
    AUDIT = 5


class Severity(enum.IntEnum):
    """Finding severity, ordered low → critical for comparison."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class FindingCategory(enum.Enum):
    """What kind of thing was found."""

    LEAKED_CREDENTIAL = "secret"
    VULNERABILITY = "vulnerability"
    DEPENDENCY_VULNERABILITY = "dependency_vulnerability"
    MISCONFIG = "misconfiguration"
    CODE_ISSUE = "code_issue"
    POLICY_VIOLATION = "policy_violation"
    MISSING_CONTROL = "missing_control"
    INTEGRITY = "integrity"


class Preset(enum.Enum):
    """Security presets. Each maps to a set of enabled engines."""

    MINIMAL = "minimal"
    BALANCED = "balanced"
    STRICT = "strict"
    PARANOID = "paranoid"


class EngineStatus(enum.Enum):
    """Result of an engine availability check."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"  # tool missing, can't run
    DEGRADED = "degraded"  # partially available (e.g., old version)
    SKIPPED = "skipped"  # disabled by policy/preset


# ---------------------------------------------------------------------------
# Data objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Location:
    """Where a finding was observed.

    Not all fields apply to every finding type. A secret has a file
    and line; a missing container control has neither.
    """

    file_path: Path | None = None
    line_start: int | None = None
    line_end: int | None = None
    column: int | None = None
    container: str | None = None
    network_endpoint: str | None = None

    def display(self) -> str:
        parts: list[str] = []
        if self.file_path:
            s = str(self.file_path)
            if self.line_start is not None:
                s += f":{self.line_start}"
            parts.append(s)
        if self.container:
            parts.append(f"container:{self.container}")
        if self.network_endpoint:
            parts.append(self.network_endpoint)
        return " ".join(parts) if parts else "(no location)"


@dataclass(frozen=True)
class Finding:
    """The intermediate representation flowing between all engines.

    Immutable by design — engines produce findings, they never mutate
    them. The correlation engine and policy evaluator produce *new*
    findings (or annotated copies) rather than modifying originals.
    """

    engine_id: str
    layer: Layer
    severity: Severity
    category: FindingCategory
    title: str
    description: str = ""
    location: Location | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str | None = None
    suppressed: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        """Deterministic finding ID for deduplication.

        Based on engine, category, title, and location — so the same
        issue found in the same place always gets the same ID regardless
        of scan timestamp.
        """
        parts = [
            self.engine_id,
            self.category.value,
            self.title,
            self.location.display() if self.location else "",
        ]
        content = "|".join(parts)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def with_severity(self, severity: Severity) -> Finding:
        """Return a copy with updated severity (for correlation uplift)."""
        return Finding(
            engine_id=self.engine_id,
            layer=self.layer,
            severity=severity,
            category=self.category,
            title=self.title,
            description=self.description,
            location=self.location,
            evidence=self.evidence,
            remediation=self.remediation,
            suppressed=self.suppressed,
            metadata=self.metadata,
        )

    def with_suppressed(self, suppressed: bool = True) -> Finding:
        """Return a copy marked as suppressed."""
        return Finding(
            engine_id=self.engine_id,
            layer=self.layer,
            severity=self.severity,
            category=self.category,
            title=self.title,
            description=self.description,
            location=self.location,
            evidence=self.evidence,
            remediation=self.remediation,
            suppressed=suppressed,
            metadata=self.metadata,
        )


@dataclass(frozen=True)
class AvailabilityResult:
    """Result of an engine's availability check."""

    status: EngineStatus
    message: str = ""
    version: str | None = None  # tool version if detectable


@dataclass(frozen=True)
class EnvironmentInfo:
    """Detected runtime environment.

    Built once by the orchestrator, passed to all engines.
    """

    os_name: str  # "darwin", "linux", "windows"
    os_version: str
    python_version: str
    container_runtime: str | None = None  # "podman", "docker", None
    container_runtime_version: str | None = None
    available_tools: frozenset[str] = field(default_factory=frozenset)


@dataclass
class ScanContext:
    """Passed to every engine on execute().

    Mutable only in that prior_findings grows between layers.
    Individual engines should treat it as read-only.
    """

    target_path: Path
    preset: Preset
    environment: EnvironmentInfo
    engine_configs: dict[str, dict[str, Any]] = field(default_factory=dict)
    prior_findings: list[Finding] = field(default_factory=list)

    def config_for(self, engine_id: str) -> dict[str, Any]:
        """Get engine-specific configuration, defaulting to empty dict."""
        return self.engine_configs.get(engine_id, {})
