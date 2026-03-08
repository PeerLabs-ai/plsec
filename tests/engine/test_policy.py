"""Tests for plsec.engine.policy -- policy evaluation.

Covers Suppression matching logic and Policy.evaluate() which applies
severity floor filtering and suppression marking to a finding stream.

Contract: Policy is applied *after* detection. Engines produce raw
findings. Policy decides *what matters* — it filters by severity floor
and marks findings matching suppression rules. It does NOT decide
pass/fail (that's VerdictStrategy's job).
"""

from pathlib import Path

import pytest

from plsec.engine.policy import Policy, Suppression
from plsec.engine.types import (
    Finding,
    FindingCategory,
    Layer,
    Location,
    Severity,
)

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _make_finding(
    engine_id: str = "test-engine",
    category: FindingCategory = FindingCategory.LEAKED_CREDENTIAL,
    title: str = "Test finding",
    severity: Severity = Severity.HIGH,
    file_path: str | None = None,
    suppressed: bool = False,
) -> Finding:
    location = Location(file_path=Path(file_path)) if file_path else None
    return Finding(
        engine_id=engine_id,
        layer=Layer.STATIC,
        severity=severity,
        category=category,
        title=title,
        location=location,
        suppressed=suppressed,
    )


# -----------------------------------------------------------------------
# Suppression.matches()
# -----------------------------------------------------------------------


class TestSuppressionMatches:
    """Contract: Suppression.matches() is conjunctive -- all specified
    fields must match. Unspecified fields (None) are wildcards."""

    def test_empty_suppression_matches_everything(self):
        """A suppression with no criteria matches any finding."""
        s = Suppression()
        f = _make_finding()
        assert s.matches(f) is True

    def test_engine_id_match(self):
        s = Suppression(engine_id="trivy-secrets")
        assert s.matches(_make_finding(engine_id="trivy-secrets")) is True

    def test_engine_id_mismatch(self):
        s = Suppression(engine_id="trivy-secrets")
        assert s.matches(_make_finding(engine_id="bandit")) is False

    def test_category_match(self):
        s = Suppression(category=FindingCategory.LEAKED_CREDENTIAL)
        assert s.matches(_make_finding(category=FindingCategory.LEAKED_CREDENTIAL)) is True

    def test_category_mismatch(self):
        s = Suppression(category=FindingCategory.LEAKED_CREDENTIAL)
        assert s.matches(_make_finding(category=FindingCategory.MISCONFIG)) is False

    def test_title_pattern_match_exact(self):
        s = Suppression(title_pattern="AWS Access Key")
        assert s.matches(_make_finding(title="AWS Access Key")) is True

    def test_title_pattern_match_glob(self):
        s = Suppression(title_pattern="AWS*")
        assert s.matches(_make_finding(title="AWS Access Key")) is True

    def test_title_pattern_mismatch(self):
        s = Suppression(title_pattern="GCP*")
        assert s.matches(_make_finding(title="AWS Access Key")) is False

    def test_file_pattern_match(self):
        s = Suppression(file_pattern="tests/*")
        assert s.matches(_make_finding(file_path="tests/test_main.py")) is True

    def test_file_pattern_mismatch(self):
        s = Suppression(file_pattern="tests/*")
        assert s.matches(_make_finding(file_path="src/main.py")) is False

    def test_file_pattern_no_location(self):
        """File pattern with no location on finding: matches (no file to reject)."""
        s = Suppression(file_pattern="tests/*")
        f = _make_finding(file_path=None)
        # No location means the file_pattern check passes (line 46-48:
        # the condition requires finding.location AND finding.location.file_path)
        assert s.matches(f) is True

    def test_file_pattern_location_no_file_path(self):
        """Location exists but file_path is None: matches (wildcard)."""
        s = Suppression(file_pattern="tests/*")
        f = Finding(
            engine_id="test",
            layer=Layer.STATIC,
            severity=Severity.HIGH,
            category=FindingCategory.LEAKED_CREDENTIAL,
            title="test",
            location=Location(),  # no file_path
        )
        assert s.matches(f) is True

    def test_conjunctive_all_match(self):
        """All criteria must match for a True result."""
        s = Suppression(
            engine_id="trivy-secrets",
            category=FindingCategory.LEAKED_CREDENTIAL,
            title_pattern="AWS*",
            file_pattern="*.py",
        )
        f = _make_finding(
            engine_id="trivy-secrets",
            category=FindingCategory.LEAKED_CREDENTIAL,
            title="AWS Key Leak",
            file_path="config.py",
        )
        assert s.matches(f) is True

    def test_conjunctive_one_mismatch(self):
        """If any criterion mismatches, the suppression does not match."""
        s = Suppression(
            engine_id="trivy-secrets",
            category=FindingCategory.LEAKED_CREDENTIAL,
        )
        f = _make_finding(
            engine_id="trivy-secrets",
            category=FindingCategory.MISCONFIG,  # mismatch
        )
        assert s.matches(f) is False

    def test_reason_does_not_affect_matching(self):
        """Reason is informational only, not used in matching."""
        s = Suppression(engine_id="test-engine", reason="Known false positive")
        assert s.matches(_make_finding(engine_id="test-engine")) is True

    def test_frozen(self):
        s = Suppression(engine_id="test")
        with pytest.raises(AttributeError):
            s.engine_id = "other"  # type: ignore[misc]


# -----------------------------------------------------------------------
# Suppression defaults
# -----------------------------------------------------------------------


class TestSuppressionDefaults:
    """Contract: Suppression fields default to None/empty (wildcard)."""

    def test_defaults(self):
        s = Suppression()
        assert s.engine_id is None
        assert s.category is None
        assert s.title_pattern is None
        assert s.file_pattern is None
        assert s.reason == ""


# -----------------------------------------------------------------------
# Policy.evaluate() — severity floor
# -----------------------------------------------------------------------


class TestPolicySeverityFloor:
    """Contract: Findings below the severity floor are removed entirely
    from the output."""

    def test_default_floor_is_low(self):
        p = Policy()
        assert p.severity_floor == Severity.LOW

    def test_info_finding_dropped_by_default(self):
        """Default floor is LOW; INFO findings are dropped."""
        p = Policy()
        findings = [_make_finding(severity=Severity.INFO)]
        result = p.evaluate(findings)
        assert len(result) == 0

    def test_low_finding_kept_by_default(self):
        """LOW findings pass the default LOW floor."""
        p = Policy()
        findings = [_make_finding(severity=Severity.LOW)]
        result = p.evaluate(findings)
        assert len(result) == 1

    def test_custom_floor_medium(self):
        """Custom floor at MEDIUM drops LOW and INFO."""
        p = Policy(severity_floor=Severity.MEDIUM)
        findings = [
            _make_finding(severity=Severity.INFO, title="info"),
            _make_finding(severity=Severity.LOW, title="low"),
            _make_finding(severity=Severity.MEDIUM, title="medium"),
            _make_finding(severity=Severity.HIGH, title="high"),
        ]
        result = p.evaluate(findings)
        assert len(result) == 2
        titles = {f.title for f in result}
        assert titles == {"medium", "high"}

    def test_custom_floor_critical(self):
        """Floor at CRITICAL drops everything below CRITICAL."""
        p = Policy(severity_floor=Severity.CRITICAL)
        findings = [
            _make_finding(severity=Severity.HIGH, title="high"),
            _make_finding(severity=Severity.CRITICAL, title="critical"),
        ]
        result = p.evaluate(findings)
        assert len(result) == 1
        assert result[0].title == "critical"

    def test_floor_info_keeps_everything(self):
        """Floor at INFO keeps all findings."""
        p = Policy(severity_floor=Severity.INFO)
        findings = [
            _make_finding(severity=Severity.INFO, title="info"),
            _make_finding(severity=Severity.LOW, title="low"),
        ]
        result = p.evaluate(findings)
        assert len(result) == 2

    def test_empty_findings(self):
        p = Policy()
        assert p.evaluate([]) == []


# -----------------------------------------------------------------------
# Policy.evaluate() — suppression marking
# -----------------------------------------------------------------------


class TestPolicySuppression:
    """Contract: Findings matching a suppression are kept in the output
    but marked as suppressed (via with_suppressed). They remain visible
    with --show-suppressed but don't count toward the verdict."""

    def test_matching_finding_marked_suppressed(self):
        p = Policy(
            suppressions=[Suppression(engine_id="trivy-secrets")],
        )
        f = _make_finding(engine_id="trivy-secrets")
        result = p.evaluate([f])
        assert len(result) == 1
        assert result[0].suppressed is True

    def test_non_matching_finding_not_suppressed(self):
        p = Policy(
            suppressions=[Suppression(engine_id="trivy-secrets")],
        )
        f = _make_finding(engine_id="bandit")
        result = p.evaluate([f])
        assert len(result) == 1
        assert result[0].suppressed is False

    def test_suppressed_finding_preserves_other_fields(self):
        """Suppression via with_suppressed() should not alter other fields."""
        p = Policy(
            suppressions=[Suppression(engine_id="test-engine")],
        )
        original = _make_finding(
            engine_id="test-engine",
            title="Original Title",
            severity=Severity.CRITICAL,
        )
        result = p.evaluate([original])
        suppressed = result[0]
        assert suppressed.suppressed is True
        assert suppressed.title == "Original Title"
        assert suppressed.severity == Severity.CRITICAL
        assert suppressed.engine_id == "test-engine"

    def test_first_matching_suppression_wins(self):
        """Only the first matching suppression is applied (break)."""
        p = Policy(
            suppressions=[
                Suppression(engine_id="test-engine", reason="First rule"),
                Suppression(engine_id="test-engine", reason="Second rule"),
            ],
        )
        result = p.evaluate([_make_finding(engine_id="test-engine")])
        assert len(result) == 1
        assert result[0].suppressed is True

    def test_multiple_suppressions_different_targets(self):
        """Different suppressions can target different findings."""
        p = Policy(
            suppressions=[
                Suppression(engine_id="trivy-secrets"),
                Suppression(engine_id="bandit"),
            ],
        )
        findings = [
            _make_finding(engine_id="trivy-secrets", title="secret"),
            _make_finding(engine_id="bandit", title="code issue"),
            _make_finding(engine_id="semgrep", title="semgrep issue"),
        ]
        result = p.evaluate(findings)
        assert len(result) == 3
        assert result[0].suppressed is True  # trivy-secrets
        assert result[1].suppressed is True  # bandit
        assert result[2].suppressed is False  # semgrep

    def test_no_suppressions(self):
        """With no suppression rules, findings pass through unchanged."""
        p = Policy(suppressions=[])
        findings = [_make_finding(), _make_finding(title="other")]
        result = p.evaluate(findings)
        assert all(not f.suppressed for f in result)


# -----------------------------------------------------------------------
# Policy.evaluate() — severity floor + suppression interaction
# -----------------------------------------------------------------------


class TestPolicyFloorAndSuppression:
    """Contract: Severity floor is applied BEFORE suppression matching.
    A finding below the floor is dropped entirely — it never reaches
    suppression logic."""

    def test_below_floor_never_suppressed(self):
        """Findings below floor are dropped, not suppressed."""
        p = Policy(
            severity_floor=Severity.HIGH,
            suppressions=[Suppression()],  # matches everything
        )
        findings = [_make_finding(severity=Severity.MEDIUM)]
        result = p.evaluate(findings)
        assert len(result) == 0

    def test_at_floor_can_be_suppressed(self):
        """Findings at exactly the floor pass through and can be suppressed."""
        p = Policy(
            severity_floor=Severity.HIGH,
            suppressions=[Suppression(engine_id="test-engine")],
        )
        findings = [_make_finding(severity=Severity.HIGH)]
        result = p.evaluate(findings)
        assert len(result) == 1
        assert result[0].suppressed is True

    def test_mixed_floor_and_suppression(self):
        """Full pipeline: floor drops some, suppression marks others."""
        p = Policy(
            severity_floor=Severity.MEDIUM,
            suppressions=[Suppression(engine_id="trivy-secrets")],
        )
        findings = [
            _make_finding(severity=Severity.LOW, title="dropped"),
            _make_finding(severity=Severity.MEDIUM, engine_id="trivy-secrets", title="suppressed"),
            _make_finding(severity=Severity.HIGH, engine_id="bandit", title="active"),
        ]
        result = p.evaluate(findings)
        assert len(result) == 2
        suppressed_f = next(f for f in result if f.title == "suppressed")
        active_f = next(f for f in result if f.title == "active")
        assert suppressed_f.suppressed is True
        assert active_f.suppressed is False


# -----------------------------------------------------------------------
# Policy.evaluate() — immutability
# -----------------------------------------------------------------------


class TestPolicyImmutability:
    """Contract: Policy.evaluate() returns new Finding objects; it never
    mutates the input list or original Finding objects."""

    def test_original_findings_unchanged(self):
        p = Policy(
            suppressions=[Suppression(engine_id="test-engine")],
        )
        original = _make_finding()
        p.evaluate([original])
        assert original.suppressed is False  # original untouched

    def test_returns_new_list(self):
        p = Policy()
        input_list = [_make_finding()]
        result = p.evaluate(input_list)
        assert result is not input_list

    def test_unsuppressed_finding_identity(self):
        """Findings that aren't suppressed are passed through as-is
        (same object, since Finding is frozen)."""
        p = Policy()
        original = _make_finding()
        result = p.evaluate([original])
        assert result[0] is original


# -----------------------------------------------------------------------
# Policy defaults
# -----------------------------------------------------------------------


class TestPolicyDefaults:
    """Contract: Policy defaults produce minimal filtering."""

    def test_default_severity_floor(self):
        p = Policy()
        assert p.severity_floor == Severity.LOW

    def test_default_no_suppressions(self):
        p = Policy()
        assert p.suppressions == []
