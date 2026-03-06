"""
plsec.engine.policy — Policy evaluation.

Policy is applied *after* detection, not during. Engines produce
raw findings. The policy evaluator filters, suppresses, and annotates
them based on declarative rules from plsec.yaml.

This is the "evaluator" stage in the general scanner pipeline:
Analyzer → **Evaluator** → Reporter.
"""

import fnmatch
import logging
from dataclasses import dataclass, field

from plsec.engine.types import (
    Finding,
    FindingCategory,
    Severity,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Suppression:
    """A rule for suppressing a finding.

    Matches are conjunctive: all specified fields must match.
    Unspecified fields (None) are wildcards.
    """

    engine_id: str | None = None
    category: FindingCategory | None = None
    title_pattern: str | None = None  # fnmatch glob
    file_pattern: str | None = None  # fnmatch glob on file path
    reason: str = ""  # human-readable justification

    def matches(self, finding: Finding) -> bool:
        if self.engine_id and finding.engine_id != self.engine_id:
            return False
        if self.category and finding.category != self.category:
            return False
        if self.title_pattern and not fnmatch.fnmatch(finding.title, self.title_pattern):
            return False
        if self.file_pattern and finding.location and finding.location.file_path:
            if not fnmatch.fnmatch(str(finding.location.file_path), self.file_pattern):
                return False
        return True


@dataclass
class Policy:
    """Declarative policy applied to scan results.

    Loaded from plsec.yaml. The policy evaluator filters the finding
    stream — it decides *what matters*, not *what to do about it*.

    For exit/fail logic, see VerdictStrategy (verdict.py).
    """

    severity_floor: Severity = Severity.LOW
    suppressions: list[Suppression] = field(default_factory=list)

    def evaluate(self, findings: list[Finding]) -> list[Finding]:
        """Apply policy to a list of findings.

        Returns a new list with:
        - Findings below severity_floor removed entirely
        - Findings matching suppressions marked as suppressed
        - All other findings passed through unchanged
        """
        result: list[Finding] = []

        for finding in findings:
            # Severity floor: drop entirely
            if finding.severity < self.severity_floor:
                continue

            # Suppression: mark but keep (visible in reports with --show-suppressed)
            suppressed = False
            for suppression in self.suppressions:
                if suppression.matches(finding):
                    logger.debug(
                        "Suppressed finding %s: %s",
                        finding.id,
                        suppression.reason,
                    )
                    suppressed = True
                    break

            if suppressed:
                result.append(finding.with_suppressed(True))
            else:
                result.append(finding)

        return result

    # Note: exit/fail logic is NOT here. Policy filters findings.
    # The VerdictStrategy (see verdict.py) interprets filtered
    # findings into pass/warn/fail outcomes. This separation keeps
    # Policy focused on "what matters" and Verdict focused on
    # "what to do about it."
