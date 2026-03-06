"""
plsec.engine.verdict — Scan outcome interpretation.

The verdict strategy answers: "given the policy-evaluated findings,
what is the outcome of this scan?"

This is distinct from Policy (which filters findings) and from
Reporting (which formats output). The verdict is the semantic
bridge between raw findings and actionable decisions.

A verdict carries:
- A status (PASS, WARN, FAIL, ERROR)
- An exit code (for CI integration)
- A human-readable rationale
- Structured counts for machine consumption

The strategy pattern allows different interpretation models:
- CI pipelines may want strict pass/fail on severity thresholds
- Developer workstations may want warn-on-medium, fail-on-critical
- Audit mode may want to always pass but record everything
- Custom strategies can encode organization-specific logic

The orchestrator accepts a VerdictStrategy at construction time.
After policy evaluation, it calls strategy.evaluate(findings) and
attaches the Verdict to the ScanResult. The CLI layer reads the
verdict — it never computes exit logic itself.
"""

import abc
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from plsec.engine.types import (
    Finding,
    Layer,
    Severity,
)

# ---------------------------------------------------------------------------
# Verdict value object
# ---------------------------------------------------------------------------


class VerdictStatus:
    """Scan outcome status.

    Not an enum — intentionally a namespace of constants so the
    set is extensible without subclassing. But the four canonical
    statuses cover known use cases.
    """

    PASSED = "pass"
    WARN = "warn"
    FAIL = "fail"
    ERROR = "error"


# Exit code conventions:
#   0 = clean (PASS)
#   1 = findings at or above threshold (FAIL)
#   2 = scan infrastructure error (ERROR)
#   3 = warnings only, no hard failures (WARN)
#
# These are conventions, not mandates. The verdict carries
# the exit code; the CLI layer uses it verbatim.

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_ERROR = 2
EXIT_WARN = 3


@dataclass(frozen=True)
class VerdictCounts:
    """Structured finding counts for machine consumption."""

    total: int = 0
    suppressed: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    by_layer: dict[str, int] = field(default_factory=dict)
    engines_ran: int = 0
    engines_skipped: int = 0


@dataclass(frozen=True)
class Verdict:
    """The interpreted outcome of a scan.

    Immutable. Produced by a VerdictStrategy, attached to a ScanResult,
    consumed by the reporting layer and CLI.
    """

    status: str  # VerdictStatus constant
    exit_code: int
    rationale: str  # human-readable explanation of why this verdict
    counts: VerdictCounts
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.status == VerdictStatus.PASSED

    @property
    def failed(self) -> bool:
        return self.status == VerdictStatus.FAIL

    @property
    def is_error(self) -> bool:
        return self.status == VerdictStatus.ERROR


# ---------------------------------------------------------------------------
# Strategy interface
# ---------------------------------------------------------------------------


class VerdictStrategy(abc.ABC):
    """Interprets policy-evaluated findings into a Verdict.

    Subclass this to define custom outcome logic. The orchestrator
    calls evaluate() after policy filtering and attaches the result
    to ScanResult.
    """

    @abc.abstractmethod
    def evaluate(
        self,
        findings: list[Finding],
        engines_ran: int,
        engines_skipped: int,
    ) -> Verdict:
        """Produce a verdict from the complete finding set.

        `findings` has already been through policy evaluation
        (suppressions applied, severity floor enforced). The
        strategy sees the filtered set and decides the outcome.

        `engines_ran` and `engines_skipped` allow the strategy
        to reason about coverage gaps (e.g., "3 of 5 engines
        skipped — verdict is unreliable").
        """


# ---------------------------------------------------------------------------
# Built-in strategies
# ---------------------------------------------------------------------------


class ThresholdVerdictStrategy(VerdictStrategy):
    """Verdict based on severity threshold.

    The most common strategy. Configurable via:
    - fail_on: minimum severity to trigger FAIL
    - warn_on: minimum severity to trigger WARN (if below fail_on)
    - coverage_warn: warn if more than N engines were skipped

    This is the strategy most CI pipelines want.
    """

    def __init__(
        self,
        fail_on: Severity = Severity.HIGH,
        warn_on: Severity = Severity.MEDIUM,
        coverage_warn_threshold: int = 2,
    ):
        self._fail_on = fail_on
        self._warn_on = warn_on
        self._coverage_warn_threshold = coverage_warn_threshold

    def evaluate(
        self,
        findings: list[Finding],
        engines_ran: int,
        engines_skipped: int,
    ) -> Verdict:
        counts = _build_counts(findings, engines_ran, engines_skipped)
        active = [f for f in findings if not f.suppressed]

        # Error: nothing ran
        if engines_ran == 0:
            return Verdict(
                status=VerdictStatus.ERROR,
                exit_code=EXIT_ERROR,
                rationale="No engines executed. Check tool availability with: plsec doctor",
                counts=counts,
            )

        # Fail: any unsuppressed finding at or above fail_on
        fail_findings = [f for f in active if f.severity >= self._fail_on]
        if fail_findings:
            worst = Severity(max(f.severity for f in fail_findings))
            return Verdict(
                status=VerdictStatus.FAIL,
                exit_code=EXIT_FAIL,
                rationale=(
                    f"{len(fail_findings)} finding(s) at {worst.name} or above "
                    f"(threshold: {self._fail_on.name})"
                ),
                counts=counts,
            )

        # Warn: findings above warn_on but below fail_on
        warn_findings = [f for f in active if f.severity >= self._warn_on]
        if warn_findings:
            return Verdict(
                status=VerdictStatus.WARN,
                exit_code=EXIT_WARN,
                rationale=(
                    f"{len(warn_findings)} finding(s) at {self._warn_on.name} or above "
                    f"(below fail threshold of {self._fail_on.name})"
                ),
                counts=counts,
            )

        # Warn: coverage gap
        if engines_skipped >= self._coverage_warn_threshold:
            return Verdict(
                status=VerdictStatus.WARN,
                exit_code=EXIT_WARN,
                rationale=(
                    f"{engines_skipped} engine(s) skipped. Scan coverage may be incomplete."
                ),
                counts=counts,
            )

        # Pass
        suffix = ""
        if counts.suppressed > 0:
            suffix = f" ({counts.suppressed} suppressed)"
        return Verdict(
            status=VerdictStatus.PASSED,
            exit_code=EXIT_PASS,
            rationale=f"No findings above {self._warn_on.name}{suffix}",
            counts=counts,
        )


class AuditVerdictStrategy(VerdictStrategy):
    """Always passes. Records everything, blocks nothing.

    For audit/observation mode — the scan runs all engines and
    produces findings, but the verdict is always PASS (exit 0).
    The rationale includes the full count so the audit trail
    captures what was observed.
    """

    def evaluate(
        self,
        findings: list[Finding],
        engines_ran: int,
        engines_skipped: int,
    ) -> Verdict:
        counts = _build_counts(findings, engines_ran, engines_skipped)
        active = [f for f in findings if not f.suppressed]

        if not active:
            rationale = "Audit mode: no findings"
        else:
            worst = Severity(max(f.severity for f in active))
            rationale = (
                f"Audit mode: {len(active)} finding(s) observed "
                f"(max severity: {worst.name}). No enforcement."
            )

        return Verdict(
            status=VerdictStatus.PASSED,
            exit_code=EXIT_PASS,
            rationale=rationale,
            counts=counts,
            metadata={"mode": "audit"},
        )


class StrictVerdictStrategy(VerdictStrategy):
    """Fails on any unsuppressed finding regardless of severity.

    For paranoid preset or regulated environments where any
    finding is unacceptable.
    """

    def evaluate(
        self,
        findings: list[Finding],
        engines_ran: int,
        engines_skipped: int,
    ) -> Verdict:
        counts = _build_counts(findings, engines_ran, engines_skipped)
        active = [f for f in findings if not f.suppressed]

        if engines_ran == 0:
            return Verdict(
                status=VerdictStatus.ERROR,
                exit_code=EXIT_ERROR,
                rationale="No engines executed",
                counts=counts,
            )

        if active:
            return Verdict(
                status=VerdictStatus.FAIL,
                exit_code=EXIT_FAIL,
                rationale=(
                    f"Strict mode: {len(active)} unsuppressed finding(s). "
                    f"All findings must be resolved or explicitly suppressed."
                ),
                counts=counts,
            )

        # Also fail if engines were skipped — strict means full coverage
        if engines_skipped > 0:
            return Verdict(
                status=VerdictStatus.FAIL,
                exit_code=EXIT_FAIL,
                rationale=(
                    f"Strict mode: {engines_skipped} engine(s) could not run. "
                    f"Full coverage required."
                ),
                counts=counts,
            )

        return Verdict(
            status=VerdictStatus.PASSED,
            exit_code=EXIT_PASS,
            rationale="Strict mode: all engines passed, no findings",
            counts=counts,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_counts(
    findings: list[Finding],
    engines_ran: int,
    engines_skipped: int,
) -> VerdictCounts:
    """Build structured counts from a finding list."""
    active = [f for f in findings if not f.suppressed]
    suppressed = [f for f in findings if f.suppressed]

    by_severity: Counter[str] = Counter()
    by_category: Counter[str] = Counter()
    by_layer: Counter[str] = Counter()

    for f in active:
        by_severity[Severity(f.severity).name] += 1
        by_category[f.category.value] += 1
        by_layer[Layer(f.layer).name] += 1

    return VerdictCounts(
        total=len(active),
        suppressed=len(suppressed),
        by_severity=dict(by_severity),
        by_category=dict(by_category),
        by_layer=dict(by_layer),
        engines_ran=engines_ran,
        engines_skipped=engines_skipped,
    )


# ---------------------------------------------------------------------------
# Preset → strategy mapping
# ---------------------------------------------------------------------------


def strategy_for_preset(preset: str) -> VerdictStrategy:
    """Default strategy selection based on preset name.

    This is a convenience -- callers can always construct a
    strategy directly for custom behavior.
    """
    mapping: dict[str, VerdictStrategy] = {
        "minimal": ThresholdVerdictStrategy(
            fail_on=Severity.CRITICAL,
            warn_on=Severity.HIGH,
        ),
        "balanced": ThresholdVerdictStrategy(
            fail_on=Severity.HIGH,
            warn_on=Severity.MEDIUM,
        ),
        "strict": StrictVerdictStrategy(),
        "paranoid": StrictVerdictStrategy(),
    }

    return mapping.get(preset, ThresholdVerdictStrategy())
