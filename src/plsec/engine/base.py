"""
plsec.engine.base — Abstract engine interface.

This module defines the contract every engine must satisfy.
The interface is deliberately minimal: configure, check, execute.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from plsec.engine.types import (
    AvailabilityResult,
    EngineStatus,
    Finding,
    Layer,
    Preset,
    ScanContext,
)

if TYPE_CHECKING:
    from plsec.engine.verdict import Verdict

logger = logging.getLogger(__name__)


class Engine(abc.ABC):
    """Abstract base for all plsec engines.

    An engine is a stateless detection unit. It:
    - Declares its identity and layer
    - Checks whether it can run (tool availability)
    - Accepts a ScanContext and produces findings

    Engines MUST NOT hold mutable state between execute() calls.
    All state flows through ScanContext.

    Engines MUST NOT raise exceptions from execute() under normal
    operation. Tool failures, timeouts, and unexpected output are
    caught internally and reported as findings of category
    MISSING_CONTROL or via the AvailabilityResult mechanism.
    """

    @property
    @abc.abstractmethod
    def engine_id(self) -> str:
        """Unique identifier, e.g. 'trivy-secrets', 'bandit'."""

    @property
    @abc.abstractmethod
    def layer(self) -> Layer:
        """Which security layer this engine belongs to."""

    @property
    @abc.abstractmethod
    def display_name(self) -> str:
        """Human-readable name for reports."""

    @property
    def presets(self) -> frozenset[Preset]:
        """Which presets enable this engine.

        Override to restrict. Default: all presets.
        """
        return frozenset(Preset)

    @property
    def dependencies(self) -> list[str]:
        """External tool names required (for doctor/availability check).

        Override to declare. Default: no dependencies.
        """
        return []

    @abc.abstractmethod
    def check_available(self, ctx: ScanContext) -> AvailabilityResult:
        """Check whether this engine can execute.

        Called before execute(). If status is UNAVAILABLE, the
        orchestrator skips this engine and records the gap.

        Should be fast — check tool existence, not full functionality.
        """

    @abc.abstractmethod
    def execute(self, ctx: ScanContext) -> list[Finding]:
        """Run detection and return findings.

        Precondition: check_available() returned AVAILABLE or DEGRADED.

        Must not raise. If the underlying tool fails, return a finding
        of category MISSING_CONTROL describing the failure.
        """

    def __repr__(self) -> str:
        return f"<{type(self).__name__} id={self.engine_id!r} layer={self.layer.name}>"


class EngineGroup:
    """A set of engines belonging to a single security layer.

    The group handles:
    - Filtering engines by preset
    - Running availability checks
    - Executing engines (sequentially for now; parallel later)
    - Collecting findings

    This is not abstract — there's one EngineGroup implementation.
    Layers don't have custom behavior; engines do.
    """

    def __init__(self, layer: Layer, engines: list[Engine] | None = None):
        self.layer = layer
        self._engines: list[Engine] = list(engines) if engines else []

    def register(self, engine: Engine) -> None:
        """Add an engine to this group.

        Raises ValueError if engine.layer doesn't match group layer.
        """
        if engine.layer != self.layer:
            raise ValueError(
                f"Engine {engine.engine_id!r} belongs to layer "
                f"{engine.layer.name}, not {self.layer.name}"
            )
        self._engines.append(engine)

    def engines_for_preset(self, preset: Preset) -> list[Engine]:
        """Return engines enabled for the given preset."""
        return [e for e in self._engines if preset in e.presets]

    def execute(self, ctx: ScanContext) -> LayerResult:
        """Run all applicable engines for the active preset.

        Returns a LayerResult containing findings and availability
        information for all engines in this group.
        """
        active = self.engines_for_preset(ctx.preset)
        engine_results: list[EngineResult] = []

        for engine in active:
            availability = engine.check_available(ctx)

            if availability.status == EngineStatus.UNAVAILABLE:
                logger.info(
                    "Engine %s unavailable: %s",
                    engine.engine_id,
                    availability.message,
                )
                engine_results.append(
                    EngineResult(
                        engine_id=engine.engine_id,
                        availability=availability,
                        findings=[],
                    )
                )
                continue

            if availability.status == EngineStatus.DEGRADED:
                logger.warning(
                    "Engine %s degraded: %s",
                    engine.engine_id,
                    availability.message,
                )

            logger.info("Executing engine: %s", engine.engine_id)
            findings = engine.execute(ctx)
            engine_results.append(
                EngineResult(
                    engine_id=engine.engine_id,
                    availability=availability,
                    findings=findings,
                )
            )

        all_findings = []
        for er in engine_results:
            all_findings.extend(er.findings)

        return LayerResult(
            layer=self.layer,
            engine_results=engine_results,
            findings=all_findings,
        )

    def __repr__(self) -> str:
        return (
            f"<EngineGroup layer={self.layer.name} engines={[e.engine_id for e in self._engines]}>"
        )


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EngineResult:
    """Result of a single engine execution."""

    engine_id: str
    availability: AvailabilityResult
    findings: list[Finding]

    @property
    def ran(self) -> bool:
        return self.availability.status in (
            EngineStatus.AVAILABLE,
            EngineStatus.DEGRADED,
        )

    @property
    def finding_count(self) -> int:
        return len([f for f in self.findings if not f.suppressed])


@dataclass(frozen=True)
class LayerResult:
    """Result of executing all engines in a layer."""

    layer: Layer
    engine_results: list[EngineResult]
    findings: list[Finding]

    @property
    def engines_ran(self) -> int:
        return sum(1 for er in self.engine_results if er.ran)

    @property
    def engines_skipped(self) -> int:
        return sum(1 for er in self.engine_results if not er.ran)

    @property
    def unsuppressed_findings(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed]


@dataclass
class ScanResult:
    """Complete scan result across all layers.

    Built incrementally by the orchestrator:
    - layer_results grow as layers execute
    - correlation_findings added after all layers
    - evaluated_findings set after policy evaluation
    - verdict set after verdict strategy evaluation
    """

    layer_results: list[LayerResult] = field(default_factory=list)
    correlation_findings: list[Finding] = field(default_factory=list)
    evaluated_findings: list[Finding] = field(default_factory=list)
    verdict: Verdict | None = None

    @property
    def all_findings(self) -> list[Finding]:
        """All raw findings from layers and correlation (pre-policy)."""
        findings = []
        for lr in self.layer_results:
            findings.extend(lr.findings)
        findings.extend(self.correlation_findings)
        return findings

    @property
    def unsuppressed(self) -> list[Finding]:
        return [f for f in self.all_findings if not f.suppressed]

    @property
    def max_severity(self) -> int:
        """Highest severity among unsuppressed findings, or -1 if clean."""
        severities = [f.severity for f in self.unsuppressed]
        return max(severities) if severities else -1

    @property
    def engines_ran(self) -> int:
        """Total engines that executed across all layers."""
        return sum(lr.engines_ran for lr in self.layer_results)

    @property
    def engines_skipped(self) -> int:
        """Total engines that were skipped across all layers."""
        return sum(lr.engines_skipped for lr in self.layer_results)
