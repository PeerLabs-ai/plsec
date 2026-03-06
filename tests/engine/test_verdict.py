"""Tests for plsec.engine.verdict -- scan outcome interpretation.

Covers VerdictCounts, Verdict value object, all three built-in
strategies (Threshold, Strict, Audit), the preset-to-strategy
mapping, and the _build_counts helper.

Contract: The verdict strategy is the ONLY place that decides
pass/warn/fail/error.  Policy filters findings.  Verdict interprets
them.  The CLI reads the verdict; it never computes exit logic.
"""

import pytest

from plsec.engine.types import (
    Finding,
    FindingCategory,
    Layer,
    Severity,
)
from plsec.engine.verdict import (
    EXIT_ERROR,
    EXIT_FAIL,
    EXIT_PASS,
    EXIT_WARN,
    AuditVerdictStrategy,
    StrictVerdictStrategy,
    ThresholdVerdictStrategy,
    Verdict,
    VerdictCounts,
    VerdictStatus,
    _build_counts,
    strategy_for_preset,
)

# -----------------------------------------------------------------------
# Test helpers
# -----------------------------------------------------------------------


def _make_finding(
    severity: Severity = Severity.HIGH,
    suppressed: bool = False,
    engine_id: str = "test",
    category: FindingCategory = FindingCategory.LEAKED_CREDENTIAL,
    layer: Layer = Layer.STATIC,
) -> Finding:
    return Finding(
        engine_id=engine_id,
        layer=layer,
        severity=severity,
        category=category,
        title=f"{severity.name} finding",
        suppressed=suppressed,
    )


# -----------------------------------------------------------------------
# VerdictCounts
# -----------------------------------------------------------------------


class TestVerdictCounts:
    """Contract: VerdictCounts carries structured finding breakdowns."""

    def test_defaults(self):
        c = VerdictCounts()
        assert c.total == 0
        assert c.suppressed == 0
        assert c.by_severity == {}
        assert c.by_category == {}
        assert c.by_layer == {}
        assert c.engines_ran == 0
        assert c.engines_skipped == 0

    def test_frozen(self):
        c = VerdictCounts()
        with pytest.raises(AttributeError):
            c.total = 5  # type: ignore[misc]


# -----------------------------------------------------------------------
# Verdict
# -----------------------------------------------------------------------


class TestVerdict:
    """Contract: Verdict is an immutable scan outcome."""

    def test_passed(self):
        v = Verdict(
            status=VerdictStatus.PASSED,
            exit_code=EXIT_PASS,
            rationale="clean",
            counts=VerdictCounts(),
        )
        assert v.passed is True
        assert v.failed is False
        assert v.is_error is False

    def test_failed(self):
        v = Verdict(
            status=VerdictStatus.FAIL,
            exit_code=EXIT_FAIL,
            rationale="findings",
            counts=VerdictCounts(),
        )
        assert v.passed is False
        assert v.failed is True

    def test_error(self):
        v = Verdict(
            status=VerdictStatus.ERROR,
            exit_code=EXIT_ERROR,
            rationale="no engines ran",
            counts=VerdictCounts(),
        )
        assert v.is_error is True

    def test_frozen(self):
        v = Verdict(
            status=VerdictStatus.PASSED,
            exit_code=0,
            rationale="ok",
            counts=VerdictCounts(),
        )
        with pytest.raises(AttributeError):
            v.status = VerdictStatus.FAIL  # type: ignore[misc]

    def test_metadata_default_empty(self):
        v = Verdict(
            status=VerdictStatus.PASSED,
            exit_code=0,
            rationale="ok",
            counts=VerdictCounts(),
        )
        assert v.metadata == {}


# -----------------------------------------------------------------------
# _build_counts
# -----------------------------------------------------------------------


class TestBuildCounts:
    """Contract: _build_counts produces VerdictCounts from findings."""

    def test_empty(self):
        c = _build_counts([], engines_ran=0, engines_skipped=0)
        assert c.total == 0
        assert c.suppressed == 0

    def test_active_findings_counted(self):
        findings = [
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.MEDIUM),
        ]
        c = _build_counts(findings, engines_ran=2, engines_skipped=0)
        assert c.total == 2
        assert c.suppressed == 0

    def test_suppressed_tracked_separately(self):
        findings = [
            _make_finding(suppressed=False),
            _make_finding(suppressed=True),
        ]
        c = _build_counts(findings, engines_ran=1, engines_skipped=0)
        assert c.total == 1
        assert c.suppressed == 1

    def test_by_severity_breakdown(self):
        findings = [
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.LOW),
        ]
        c = _build_counts(findings, engines_ran=1, engines_skipped=0)
        assert c.by_severity["HIGH"] == 2
        assert c.by_severity["LOW"] == 1

    def test_by_category_breakdown(self):
        findings = [
            _make_finding(category=FindingCategory.LEAKED_CREDENTIAL),
            _make_finding(category=FindingCategory.VULNERABILITY),
        ]
        c = _build_counts(findings, engines_ran=1, engines_skipped=0)
        assert c.by_category["secret"] == 1
        assert c.by_category["vulnerability"] == 1

    def test_by_layer_breakdown(self):
        findings = [
            _make_finding(layer=Layer.STATIC),
            _make_finding(layer=Layer.CONFIG),
            _make_finding(layer=Layer.STATIC),
        ]
        c = _build_counts(findings, engines_ran=2, engines_skipped=0)
        assert c.by_layer["STATIC"] == 2
        assert c.by_layer["CONFIG"] == 1

    def test_engine_counts_passed_through(self):
        c = _build_counts([], engines_ran=3, engines_skipped=2)
        assert c.engines_ran == 3
        assert c.engines_skipped == 2


# -----------------------------------------------------------------------
# ThresholdVerdictStrategy
# -----------------------------------------------------------------------


class TestThresholdVerdictStrategy:
    """Contract: ThresholdVerdictStrategy produces verdicts based on
    configurable severity thresholds and coverage warnings."""

    def test_pass_no_findings(self):
        s = ThresholdVerdictStrategy()
        v = s.evaluate([], engines_ran=1, engines_skipped=0)
        assert v.status == VerdictStatus.PASSED
        assert v.exit_code == EXIT_PASS

    def test_pass_with_suppressed_noted(self):
        s = ThresholdVerdictStrategy()
        findings = [_make_finding(suppressed=True)]
        v = s.evaluate(findings, engines_ran=1, engines_skipped=0)
        assert v.status == VerdictStatus.PASSED
        assert "suppressed" in v.rationale

    def test_fail_on_high(self):
        """Default: fail on HIGH or above."""
        s = ThresholdVerdictStrategy()
        findings = [_make_finding(severity=Severity.HIGH)]
        v = s.evaluate(findings, engines_ran=1, engines_skipped=0)
        assert v.status == VerdictStatus.FAIL
        assert v.exit_code == EXIT_FAIL
        assert "HIGH" in v.rationale

    def test_fail_on_critical(self):
        s = ThresholdVerdictStrategy()
        findings = [_make_finding(severity=Severity.CRITICAL)]
        v = s.evaluate(findings, engines_ran=1, engines_skipped=0)
        assert v.status == VerdictStatus.FAIL

    def test_warn_on_medium(self):
        """Default: warn on MEDIUM (below HIGH fail threshold)."""
        s = ThresholdVerdictStrategy()
        findings = [_make_finding(severity=Severity.MEDIUM)]
        v = s.evaluate(findings, engines_ran=1, engines_skipped=0)
        assert v.status == VerdictStatus.WARN
        assert v.exit_code == EXIT_WARN

    def test_pass_below_warn_threshold(self):
        """LOW findings with default thresholds -> pass."""
        s = ThresholdVerdictStrategy()
        findings = [_make_finding(severity=Severity.LOW)]
        v = s.evaluate(findings, engines_ran=1, engines_skipped=0)
        assert v.status == VerdictStatus.PASSED

    def test_custom_thresholds(self):
        s = ThresholdVerdictStrategy(
            fail_on=Severity.CRITICAL,
            warn_on=Severity.HIGH,
        )
        findings = [_make_finding(severity=Severity.HIGH)]
        v = s.evaluate(findings, engines_ran=1, engines_skipped=0)
        assert v.status == VerdictStatus.WARN  # HIGH is warn, not fail

    def test_error_no_engines_ran(self):
        s = ThresholdVerdictStrategy()
        v = s.evaluate([], engines_ran=0, engines_skipped=3)
        assert v.status == VerdictStatus.ERROR
        assert v.exit_code == EXIT_ERROR

    def test_coverage_warn(self):
        """Too many skipped engines -> warn."""
        s = ThresholdVerdictStrategy(coverage_warn_threshold=2)
        v = s.evaluate([], engines_ran=1, engines_skipped=2)
        assert v.status == VerdictStatus.WARN
        assert "skipped" in v.rationale

    def test_coverage_warn_below_threshold(self):
        """Skipped engines below threshold -> pass."""
        s = ThresholdVerdictStrategy(coverage_warn_threshold=3)
        v = s.evaluate([], engines_ran=2, engines_skipped=1)
        assert v.status == VerdictStatus.PASSED

    def test_fail_takes_priority_over_coverage_warn(self):
        """Findings above fail threshold override coverage warnings."""
        s = ThresholdVerdictStrategy(coverage_warn_threshold=1)
        findings = [_make_finding(severity=Severity.CRITICAL)]
        v = s.evaluate(findings, engines_ran=1, engines_skipped=2)
        assert v.status == VerdictStatus.FAIL


# -----------------------------------------------------------------------
# StrictVerdictStrategy
# -----------------------------------------------------------------------


class TestStrictVerdictStrategy:
    """Contract: StrictVerdictStrategy fails on any unsuppressed finding
    or any skipped engine.  Full coverage required."""

    def test_pass_clean(self):
        s = StrictVerdictStrategy()
        v = s.evaluate([], engines_ran=3, engines_skipped=0)
        assert v.status == VerdictStatus.PASSED
        assert v.exit_code == EXIT_PASS

    def test_fail_any_finding(self):
        s = StrictVerdictStrategy()
        findings = [_make_finding(severity=Severity.LOW)]
        v = s.evaluate(findings, engines_ran=1, engines_skipped=0)
        assert v.status == VerdictStatus.FAIL
        assert "Strict mode" in v.rationale

    def test_fail_skipped_engine(self):
        s = StrictVerdictStrategy()
        v = s.evaluate([], engines_ran=2, engines_skipped=1)
        assert v.status == VerdictStatus.FAIL
        assert "coverage" in v.rationale.lower() or "could not run" in v.rationale

    def test_suppressed_findings_pass(self):
        """Suppressed findings don't count toward failure."""
        s = StrictVerdictStrategy()
        findings = [_make_finding(suppressed=True)]
        v = s.evaluate(findings, engines_ran=1, engines_skipped=0)
        assert v.status == VerdictStatus.PASSED

    def test_error_no_engines_ran(self):
        s = StrictVerdictStrategy()
        v = s.evaluate([], engines_ran=0, engines_skipped=0)
        assert v.status == VerdictStatus.ERROR


# -----------------------------------------------------------------------
# AuditVerdictStrategy
# -----------------------------------------------------------------------


class TestAuditVerdictStrategy:
    """Contract: AuditVerdictStrategy always passes.  Records everything,
    blocks nothing."""

    def test_pass_no_findings(self):
        s = AuditVerdictStrategy()
        v = s.evaluate([], engines_ran=1, engines_skipped=0)
        assert v.status == VerdictStatus.PASSED
        assert v.exit_code == EXIT_PASS

    def test_pass_with_findings(self):
        """Even critical findings pass in audit mode."""
        s = AuditVerdictStrategy()
        findings = [_make_finding(severity=Severity.CRITICAL)]
        v = s.evaluate(findings, engines_ran=1, engines_skipped=0)
        assert v.status == VerdictStatus.PASSED
        assert "audit" in v.rationale.lower()

    def test_rationale_includes_count(self):
        s = AuditVerdictStrategy()
        findings = [
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.CRITICAL),
        ]
        v = s.evaluate(findings, engines_ran=1, engines_skipped=0)
        assert "2" in v.rationale
        assert "CRITICAL" in v.rationale

    def test_metadata_has_audit_mode(self):
        s = AuditVerdictStrategy()
        v = s.evaluate([], engines_ran=1, engines_skipped=0)
        assert v.metadata.get("mode") == "audit"


# -----------------------------------------------------------------------
# strategy_for_preset
# -----------------------------------------------------------------------


class TestStrategyForPreset:
    """Contract: strategy_for_preset maps preset names to appropriate
    verdict strategies."""

    def test_minimal_uses_threshold(self):
        s = strategy_for_preset("minimal")
        assert isinstance(s, ThresholdVerdictStrategy)

    def test_balanced_uses_threshold(self):
        s = strategy_for_preset("balanced")
        assert isinstance(s, ThresholdVerdictStrategy)

    def test_strict_uses_strict(self):
        s = strategy_for_preset("strict")
        assert isinstance(s, StrictVerdictStrategy)

    def test_paranoid_uses_strict(self):
        s = strategy_for_preset("paranoid")
        assert isinstance(s, StrictVerdictStrategy)

    def test_unknown_preset_defaults_to_threshold(self):
        s = strategy_for_preset("custom-unknown")
        assert isinstance(s, ThresholdVerdictStrategy)

    def test_minimal_threshold_higher_than_balanced(self):
        """Minimal should tolerate more than balanced."""
        minimal = strategy_for_preset("minimal")
        balanced = strategy_for_preset("balanced")
        assert isinstance(minimal, ThresholdVerdictStrategy)
        assert isinstance(balanced, ThresholdVerdictStrategy)
        assert minimal._fail_on > balanced._fail_on
