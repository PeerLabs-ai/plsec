"""
plsec.engine.correlation — Cross-layer finding correlation.

The correlation engine is structurally different from detection engines.
Detection engines scan artifacts. The correlation engine examines
*findings from other engines* to identify compound risks invisible
to any single engine.

Example compound risks:
- Secret found (Layer 1) + no egress proxy (Layer 4) = CRITICAL uplift
  (the secret is exfiltrable)
- Agent has network access (Layer 2) + no container isolation (Layer 3)
  = HIGH (unconstrained agent)
- Secret found (Layer 1) + no audit logging (Layer 5) = severity uplift
  (breach without detection capability)

These rules are declarative and extensible. The correlation engine
evaluates them and produces synthetic findings representing the
compound risk.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass

from plsec.engine.types import (
    Finding,
    FindingCategory,
    Layer,
    Severity,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CorrelationRule:
    """A declarative rule for cross-finding correlation.

    The predicate receives all findings and returns True if the
    compound condition is met. If met, the rule produces a synthetic
    finding via the factory.

    Rules are evaluated in order. A rule can depend on findings
    from any layer.
    """

    rule_id: str
    description: str
    predicate: Callable[[list[Finding]], bool]
    factory: Callable[[list[Finding]], Finding]


class CorrelationEngine:
    """Evaluates correlation rules against the complete finding set.

    Not an Engine subclass — different lifecycle. Called by the
    orchestrator after all layers have executed.
    """

    def __init__(self, rules: list[CorrelationRule] | None = None):
        self._rules: list[CorrelationRule] = list(rules) if rules else []

    def register_rule(self, rule: CorrelationRule) -> None:
        self._rules.append(rule)

    def correlate(self, findings: list[Finding]) -> list[Finding]:
        """Evaluate all rules and return synthetic findings."""
        synthetic: list[Finding] = []

        for rule in self._rules:
            try:
                if rule.predicate(findings):
                    finding = rule.factory(findings)
                    logger.info(
                        "Correlation rule %s triggered: %s",
                        rule.rule_id,
                        finding.title,
                    )
                    synthetic.append(finding)
            except (TypeError, ValueError, KeyError, AttributeError, IndexError):
                logger.exception("Correlation rule %s failed", rule.rule_id)

        return synthetic


# ---------------------------------------------------------------------------
# Built-in correlation rules
# ---------------------------------------------------------------------------


def _has_finding(
    findings: list[Finding],
    category: FindingCategory | None = None,
    engine_id: str | None = None,
    layer: Layer | None = None,
) -> bool:
    """Helper: check whether any finding matches the given filters."""
    for f in findings:
        if f.suppressed:
            continue
        if category and f.category != category:
            continue
        if engine_id and f.engine_id != engine_id:
            continue
        if layer and f.layer != layer:
            continue
        return True
    return False


def _has_missing_control(findings: list[Finding], engine_id: str) -> bool:
    """Helper: check whether an engine reported a missing control."""
    return any(
        f.engine_id == engine_id
        and f.category == FindingCategory.MISSING_CONTROL
        and not f.suppressed
        for f in findings
    )


# Rule: Secret found + no egress control = CRITICAL
SECRET_WITHOUT_EGRESS = CorrelationRule(
    rule_id="secret-no-egress",
    description=(
        "A secret was detected but no egress proxy is in place. "
        "The secret is potentially exfiltrable by an agent."
    ),
    predicate=lambda findings: (
        _has_finding(findings, category=FindingCategory.LEAKED_CREDENTIAL)
        and _has_missing_control(findings, "egress-proxy")
    ),
    factory=lambda findings: Finding(
        engine_id="correlation",
        layer=Layer.RUNTIME,
        severity=Severity.CRITICAL,
        category=FindingCategory.POLICY_VIOLATION,
        title="Secret detected without egress control",
        description=(
            "One or more secrets were found in the workspace, "
            "but no egress proxy (Pipelock) is configured. An AI agent "
            "with network access could exfiltrate these secrets."
        ),
        remediation="Enable Pipelock egress proxy (preset: strict or higher)",
    ),
)


# Rule: Agent has network + no container isolation
NETWORK_WITHOUT_ISOLATION = CorrelationRule(
    rule_id="network-no-isolation",
    description=(
        "Agent configuration allows network access but no container isolation is in place."
    ),
    predicate=lambda findings: (
        _has_missing_control(findings, "container-isolation")
        and not _has_missing_control(findings, "egress-proxy")
        # If there IS an egress proxy, the network risk is mitigated
    ),
    factory=lambda findings: Finding(
        engine_id="correlation",
        layer=Layer.ISOLATION,
        severity=Severity.HIGH,
        category=FindingCategory.MISSING_CONTROL,
        title="Network access without container isolation",
        description=(
            "The agent has network access but is not running in a "
            "container. A compromised agent has direct host network access."
        ),
        remediation="Enable container isolation (preset: strict or higher)",
    ),
)


# Rule: Secret found + no audit logging
SECRET_WITHOUT_AUDIT = CorrelationRule(
    rule_id="secret-no-audit",
    description="Secret detected but audit logging is not configured.",
    predicate=lambda findings: (
        _has_finding(findings, category=FindingCategory.LEAKED_CREDENTIAL)
        and _has_missing_control(findings, "audit-log")
    ),
    factory=lambda findings: Finding(
        engine_id="correlation",
        layer=Layer.AUDIT,
        severity=Severity.HIGH,
        category=FindingCategory.POLICY_VIOLATION,
        title="Secret detected without audit trail",
        description=(
            "Secrets are present in the workspace but agent sessions "
            "are not being logged. A secret exfiltration would leave "
            "no audit trail."
        ),
        remediation="Enable audit logging (preset: balanced or higher)",
    ),
)


def build_default_correlation_engine() -> CorrelationEngine:
    """Factory for the correlation engine with built-in rules."""
    engine = CorrelationEngine()
    engine.register_rule(SECRET_WITHOUT_EGRESS)
    engine.register_rule(NETWORK_WITHOUT_ISOLATION)
    engine.register_rule(SECRET_WITHOUT_AUDIT)
    return engine
