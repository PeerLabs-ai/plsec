"""Tests for plsec.engine.correlation -- cross-layer finding correlation.

Covers CorrelationRule, CorrelationEngine.correlate(), the helper
functions (_has_finding, _has_missing_control), the three built-in
rules (SECRET_WITHOUT_EGRESS, NETWORK_WITHOUT_ISOLATION,
SECRET_WITHOUT_AUDIT), and the build_default_correlation_engine factory.

Contract: The correlation engine examines findings from detection
engines to identify compound risks invisible to any single engine.
It produces synthetic findings representing compound risks.
"""

import logging

import pytest

from plsec.engine.correlation import (
    NETWORK_WITHOUT_ISOLATION,
    SECRET_WITHOUT_AUDIT,
    SECRET_WITHOUT_EGRESS,
    CorrelationEngine,
    CorrelationRule,
    _has_finding,
    _has_missing_control,
    build_default_correlation_engine,
)
from plsec.engine.types import (
    Finding,
    FindingCategory,
    Layer,
    Severity,
)

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _make_finding(
    engine_id: str = "test-engine",
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


def _secret_finding(suppressed: bool = False) -> Finding:
    """A secret-type finding from trivy-secrets."""
    return _make_finding(
        engine_id="trivy-secrets",
        layer=Layer.STATIC,
        category=FindingCategory.LEAKED_CREDENTIAL,
        title="AWS access key",
        suppressed=suppressed,
    )


def _missing_control(engine_id: str, layer: Layer = Layer.ISOLATION) -> Finding:
    """A MISSING_CONTROL finding from the given engine."""
    return _make_finding(
        engine_id=engine_id,
        layer=layer,
        category=FindingCategory.MISSING_CONTROL,
        title=f"Missing {engine_id} control",
    )


# -----------------------------------------------------------------------
# _has_finding helper
# -----------------------------------------------------------------------


class TestHasFinding:
    """Contract: _has_finding checks whether any non-suppressed finding
    matches the given filters (category, engine_id, layer)."""

    def test_empty_findings(self):
        assert _has_finding([]) is False

    def test_match_by_category(self):
        findings = [_secret_finding()]
        assert _has_finding(findings, category=FindingCategory.LEAKED_CREDENTIAL) is True

    def test_no_match_by_category(self):
        findings = [_secret_finding()]
        assert _has_finding(findings, category=FindingCategory.MISCONFIG) is False

    def test_match_by_engine_id(self):
        findings = [_make_finding(engine_id="bandit")]
        assert _has_finding(findings, engine_id="bandit") is True

    def test_no_match_by_engine_id(self):
        findings = [_make_finding(engine_id="bandit")]
        assert _has_finding(findings, engine_id="semgrep") is False

    def test_match_by_layer(self):
        findings = [_make_finding(layer=Layer.CONFIG)]
        assert _has_finding(findings, layer=Layer.CONFIG) is True

    def test_no_match_by_layer(self):
        findings = [_make_finding(layer=Layer.CONFIG)]
        assert _has_finding(findings, layer=Layer.STATIC) is False

    def test_suppressed_findings_ignored(self):
        """Suppressed findings are skipped by _has_finding."""
        findings = [_secret_finding(suppressed=True)]
        assert _has_finding(findings, category=FindingCategory.LEAKED_CREDENTIAL) is False

    def test_multiple_filters_conjunctive(self):
        """All specified filters must match."""
        f = _make_finding(
            engine_id="trivy-secrets",
            category=FindingCategory.LEAKED_CREDENTIAL,
            layer=Layer.STATIC,
        )
        assert (
            _has_finding(
                [f],
                category=FindingCategory.LEAKED_CREDENTIAL,
                engine_id="trivy-secrets",
                layer=Layer.STATIC,
            )
            is True
        )

    def test_multiple_filters_one_mismatch(self):
        f = _make_finding(
            engine_id="trivy-secrets",
            category=FindingCategory.LEAKED_CREDENTIAL,
            layer=Layer.STATIC,
        )
        assert (
            _has_finding(
                [f],
                category=FindingCategory.LEAKED_CREDENTIAL,
                engine_id="bandit",  # mismatch
            )
            is False
        )

    def test_no_filters_matches_any_unsuppressed(self):
        """With no filters, any unsuppressed finding matches."""
        findings = [_make_finding()]
        assert _has_finding(findings) is True

    def test_no_filters_all_suppressed(self):
        findings = [_make_finding(suppressed=True)]
        assert _has_finding(findings) is False


# -----------------------------------------------------------------------
# _has_missing_control helper
# -----------------------------------------------------------------------


class TestHasMissingControl:
    """Contract: _has_missing_control checks for unsuppressed
    MISSING_CONTROL findings from a specific engine_id."""

    def test_matching_missing_control(self):
        findings = [_missing_control("container-isolation")]
        assert _has_missing_control(findings, "container-isolation") is True

    def test_wrong_engine_id(self):
        findings = [_missing_control("container-isolation")]
        assert _has_missing_control(findings, "egress-proxy") is False

    def test_wrong_category(self):
        """A finding from the right engine but wrong category doesn't match."""
        findings = [
            _make_finding(
                engine_id="container-isolation",
                category=FindingCategory.MISCONFIG,
            )
        ]
        assert _has_missing_control(findings, "container-isolation") is False

    def test_suppressed_missing_control_ignored(self):
        findings = [
            _make_finding(
                engine_id="container-isolation",
                category=FindingCategory.MISSING_CONTROL,
                suppressed=True,
            )
        ]
        assert _has_missing_control(findings, "container-isolation") is False

    def test_empty_findings(self):
        assert _has_missing_control([], "container-isolation") is False


# -----------------------------------------------------------------------
# CorrelationRule
# -----------------------------------------------------------------------


class TestCorrelationRule:
    """Contract: CorrelationRule is a frozen dataclass carrying a
    predicate + factory pair."""

    def test_creation(self):
        rule = CorrelationRule(
            rule_id="test-rule",
            description="A test rule",
            predicate=lambda findings: True,
            factory=lambda findings: _make_finding(title="synthetic"),
        )
        assert rule.rule_id == "test-rule"
        assert rule.description == "A test rule"

    def test_frozen(self):
        rule = CorrelationRule(
            rule_id="test",
            description="test",
            predicate=lambda f: True,
            factory=lambda f: _make_finding(),
        )
        with pytest.raises(AttributeError):
            rule.rule_id = "other"  # type: ignore[misc]


# -----------------------------------------------------------------------
# CorrelationEngine.correlate()
# -----------------------------------------------------------------------


class TestCorrelationEngine:
    """Contract: CorrelationEngine evaluates rules against the complete
    finding set and produces synthetic findings."""

    def test_no_rules_no_findings(self):
        engine = CorrelationEngine()
        assert engine.correlate([]) == []

    def test_no_rules_with_findings(self):
        engine = CorrelationEngine()
        assert engine.correlate([_make_finding()]) == []

    def test_rule_triggers(self):
        """When predicate returns True, factory produces a finding."""
        rule = CorrelationRule(
            rule_id="always-trigger",
            description="Always triggers",
            predicate=lambda findings: True,
            factory=lambda findings: _make_finding(
                engine_id="correlation",
                title="Synthetic finding",
            ),
        )
        engine = CorrelationEngine(rules=[rule])
        result = engine.correlate([_make_finding()])
        assert len(result) == 1
        assert result[0].engine_id == "correlation"
        assert result[0].title == "Synthetic finding"

    def test_rule_does_not_trigger(self):
        """When predicate returns False, no finding is produced."""
        rule = CorrelationRule(
            rule_id="never-trigger",
            description="Never triggers",
            predicate=lambda findings: False,
            factory=lambda findings: _make_finding(),
        )
        engine = CorrelationEngine(rules=[rule])
        result = engine.correlate([_make_finding()])
        assert result == []

    def test_multiple_rules_independent(self):
        """Multiple rules evaluate independently."""
        rule1 = CorrelationRule(
            rule_id="rule-1",
            description="Always",
            predicate=lambda f: True,
            factory=lambda f: _make_finding(title="from-rule-1"),
        )
        rule2 = CorrelationRule(
            rule_id="rule-2",
            description="Never",
            predicate=lambda f: False,
            factory=lambda f: _make_finding(title="from-rule-2"),
        )
        rule3 = CorrelationRule(
            rule_id="rule-3",
            description="Also always",
            predicate=lambda f: True,
            factory=lambda f: _make_finding(title="from-rule-3"),
        )
        engine = CorrelationEngine(rules=[rule1, rule2, rule3])
        result = engine.correlate([_make_finding()])
        assert len(result) == 2
        titles = {f.title for f in result}
        assert titles == {"from-rule-1", "from-rule-3"}

    def test_register_rule(self):
        """register_rule() adds a rule after construction."""
        engine = CorrelationEngine()
        rule = CorrelationRule(
            rule_id="added-later",
            description="Added via register_rule",
            predicate=lambda f: True,
            factory=lambda f: _make_finding(title="registered"),
        )
        engine.register_rule(rule)
        result = engine.correlate([_make_finding()])
        assert len(result) == 1
        assert result[0].title == "registered"

    def test_predicate_receives_full_findings(self):
        """The predicate receives the full list of findings."""
        received_count = []

        def capture_predicate(findings: list[Finding]) -> bool:
            received_count.append(len(findings))
            return False

        rule = CorrelationRule(
            rule_id="capture",
            description="Captures findings count",
            predicate=capture_predicate,
            factory=lambda f: _make_finding(),
        )
        engine = CorrelationEngine(rules=[rule])
        engine.correlate([_make_finding(), _make_finding(title="second")])
        assert received_count == [2]

    def test_factory_receives_full_findings(self):
        """The factory receives the full list of findings."""
        received_count = []

        def capture_factory(findings: list[Finding]) -> Finding:
            received_count.append(len(findings))
            return _make_finding(title="synthetic")

        rule = CorrelationRule(
            rule_id="capture",
            description="Captures findings in factory",
            predicate=lambda f: True,
            factory=capture_factory,
        )
        engine = CorrelationEngine(rules=[rule])
        engine.correlate([_make_finding(), _make_finding(title="second")])
        assert received_count == [2]

    def test_predicate_exception_logged_and_skipped(self, caplog):
        """If a predicate raises, the rule is skipped and logged."""

        def bad_predicate(findings: list[Finding]) -> bool:
            raise ValueError("predicate broke")

        rule = CorrelationRule(
            rule_id="bad-rule",
            description="Broken predicate",
            predicate=bad_predicate,
            factory=lambda f: _make_finding(),
        )
        engine = CorrelationEngine(rules=[rule])
        with caplog.at_level(logging.ERROR):
            result = engine.correlate([_make_finding()])
        assert result == []
        assert "bad-rule" in caplog.text

    def test_factory_exception_logged_and_skipped(self, caplog):
        """If a factory raises, the rule is skipped and logged."""

        def bad_factory(findings: list[Finding]) -> Finding:
            raise TypeError("factory broke")

        rule = CorrelationRule(
            rule_id="bad-factory",
            description="Broken factory",
            predicate=lambda f: True,
            factory=bad_factory,
        )
        engine = CorrelationEngine(rules=[rule])
        with caplog.at_level(logging.ERROR):
            result = engine.correlate([_make_finding()])
        assert result == []
        assert "bad-factory" in caplog.text

    def test_constructor_with_rules_list(self):
        """Constructor accepts a list of rules."""
        rules = [
            CorrelationRule(
                rule_id="r1",
                description="d1",
                predicate=lambda f: False,
                factory=lambda f: _make_finding(),
            ),
        ]
        engine = CorrelationEngine(rules=rules)
        # Modifying original list doesn't affect engine
        rules.clear()
        # Engine still has the rule (it copies)
        assert engine.correlate([_make_finding()]) == []  # rule predicate returns False

    def test_constructor_with_none(self):
        engine = CorrelationEngine(rules=None)
        assert engine.correlate([]) == []


# -----------------------------------------------------------------------
# Built-in rules — SECRET_WITHOUT_EGRESS
# -----------------------------------------------------------------------


class TestSecretWithoutEgress:
    """Contract: Triggers when a secret is found AND no egress-proxy
    control is in place. Produces a CRITICAL synthetic finding."""

    def test_triggers_with_secret_and_missing_egress(self):
        findings = [
            _secret_finding(),
            _missing_control("egress-proxy", layer=Layer.RUNTIME),
        ]
        assert SECRET_WITHOUT_EGRESS.predicate(findings) is True

    def test_does_not_trigger_without_secret(self):
        findings = [_missing_control("egress-proxy")]
        assert SECRET_WITHOUT_EGRESS.predicate(findings) is False

    def test_does_not_trigger_without_missing_egress(self):
        findings = [_secret_finding()]
        assert SECRET_WITHOUT_EGRESS.predicate(findings) is False

    def test_does_not_trigger_with_suppressed_secret(self):
        findings = [
            _secret_finding(suppressed=True),
            _missing_control("egress-proxy"),
        ]
        assert SECRET_WITHOUT_EGRESS.predicate(findings) is False

    def test_factory_produces_critical_finding(self):
        findings = [_secret_finding(), _missing_control("egress-proxy")]
        synthetic = SECRET_WITHOUT_EGRESS.factory(findings)
        assert synthetic.engine_id == "correlation"
        assert synthetic.severity == Severity.CRITICAL
        assert synthetic.category == FindingCategory.POLICY_VIOLATION
        assert synthetic.layer == Layer.RUNTIME
        assert "egress" in synthetic.title.lower()

    def test_rule_metadata(self):
        assert SECRET_WITHOUT_EGRESS.rule_id == "secret-no-egress"


# -----------------------------------------------------------------------
# Built-in rules — NETWORK_WITHOUT_ISOLATION
# -----------------------------------------------------------------------


class TestNetworkWithoutIsolation:
    """Contract: Triggers when container-isolation is missing AND
    egress-proxy IS present (if no egress proxy, the risk is covered
    by SECRET_WITHOUT_EGRESS instead)."""

    def test_triggers_with_missing_isolation_and_no_egress_issue(self):
        findings = [_missing_control("container-isolation")]
        assert NETWORK_WITHOUT_ISOLATION.predicate(findings) is True

    def test_does_not_trigger_if_egress_also_missing(self):
        """If egress-proxy is also missing, this rule defers to
        SECRET_WITHOUT_EGRESS."""
        findings = [
            _missing_control("container-isolation"),
            _missing_control("egress-proxy"),
        ]
        assert NETWORK_WITHOUT_ISOLATION.predicate(findings) is False

    def test_does_not_trigger_without_missing_isolation(self):
        findings = [_secret_finding()]
        assert NETWORK_WITHOUT_ISOLATION.predicate(findings) is False

    def test_factory_produces_high_finding(self):
        findings = [_missing_control("container-isolation")]
        synthetic = NETWORK_WITHOUT_ISOLATION.factory(findings)
        assert synthetic.engine_id == "correlation"
        assert synthetic.severity == Severity.HIGH
        assert synthetic.category == FindingCategory.MISSING_CONTROL
        assert synthetic.layer == Layer.ISOLATION

    def test_rule_metadata(self):
        assert NETWORK_WITHOUT_ISOLATION.rule_id == "network-no-isolation"


# -----------------------------------------------------------------------
# Built-in rules — SECRET_WITHOUT_AUDIT
# -----------------------------------------------------------------------


class TestSecretWithoutAudit:
    """Contract: Triggers when a secret is found AND no audit-log
    control is in place."""

    def test_triggers_with_secret_and_missing_audit(self):
        findings = [
            _secret_finding(),
            _missing_control("audit-log", layer=Layer.AUDIT),
        ]
        assert SECRET_WITHOUT_AUDIT.predicate(findings) is True

    def test_does_not_trigger_without_secret(self):
        findings = [_missing_control("audit-log")]
        assert SECRET_WITHOUT_AUDIT.predicate(findings) is False

    def test_does_not_trigger_without_missing_audit(self):
        findings = [_secret_finding()]
        assert SECRET_WITHOUT_AUDIT.predicate(findings) is False

    def test_does_not_trigger_with_suppressed_secret(self):
        findings = [
            _secret_finding(suppressed=True),
            _missing_control("audit-log"),
        ]
        assert SECRET_WITHOUT_AUDIT.predicate(findings) is False

    def test_factory_produces_high_finding(self):
        findings = [_secret_finding(), _missing_control("audit-log")]
        synthetic = SECRET_WITHOUT_AUDIT.factory(findings)
        assert synthetic.engine_id == "correlation"
        assert synthetic.severity == Severity.HIGH
        assert synthetic.category == FindingCategory.POLICY_VIOLATION
        assert synthetic.layer == Layer.AUDIT
        assert "audit" in synthetic.title.lower()

    def test_rule_metadata(self):
        assert SECRET_WITHOUT_AUDIT.rule_id == "secret-no-audit"


# -----------------------------------------------------------------------
# build_default_correlation_engine
# -----------------------------------------------------------------------


class TestBuildDefaultCorrelationEngine:
    """Contract: Factory creates a CorrelationEngine with the three
    built-in rules registered."""

    def test_returns_correlation_engine(self):
        engine = build_default_correlation_engine()
        assert isinstance(engine, CorrelationEngine)

    def test_has_three_rules(self):
        engine = build_default_correlation_engine()
        assert len(engine._rules) == 3

    def test_rules_are_built_in(self):
        engine = build_default_correlation_engine()
        rule_ids = {r.rule_id for r in engine._rules}
        assert rule_ids == {
            "secret-no-egress",
            "network-no-isolation",
            "secret-no-audit",
        }

    def test_integration_secret_and_missing_egress(self):
        """End-to-end: default engine produces synthetic finding for
        secret + missing egress."""
        engine = build_default_correlation_engine()
        findings = [
            _secret_finding(),
            _missing_control("egress-proxy", layer=Layer.RUNTIME),
        ]
        synthetic = engine.correlate(findings)
        assert len(synthetic) == 1
        assert synthetic[0].severity == Severity.CRITICAL

    def test_integration_no_conditions_met(self):
        """No rules trigger when conditions aren't met."""
        engine = build_default_correlation_engine()
        # Just a code issue finding — no secrets, no missing controls
        findings = [
            _make_finding(
                engine_id="bandit",
                category=FindingCategory.CODE_ISSUE,
            ),
        ]
        synthetic = engine.correlate(findings)
        assert synthetic == []

    def test_integration_multiple_rules_trigger(self):
        """When a secret exists with both missing egress and missing audit,
        two rules trigger."""
        engine = build_default_correlation_engine()
        findings = [
            _secret_finding(),
            _missing_control("egress-proxy", layer=Layer.RUNTIME),
            _missing_control("audit-log", layer=Layer.AUDIT),
        ]
        synthetic = engine.correlate(findings)
        assert len(synthetic) == 2
        rule_ids_triggered = {f.title for f in synthetic}
        assert "Secret detected without egress control" in rule_ids_triggered
        assert "Secret detected without audit trail" in rule_ids_triggered
