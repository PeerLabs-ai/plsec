"""
plsec.engine.engines.trivy_secrets — Trivy secret scanning engine.

This is an adapter: it wraps the external `trivy` CLI tool behind
the Engine interface. The adapter handles:
- Availability checking (is trivy installed? right version?)
- Invocation (subprocess, timeout, config passing)
- Output parsing (trivy JSON → Finding objects)
- Error handling (tool failure → MISSING_CONTROL finding)

The engine itself has no detection logic. All intelligence lives
in Trivy and its signature database. plsec's value is orchestration,
normalization, and correlation — not reimplementation.

Exit codes:
    0 -- no findings (or findings below threshold)
    1 -- findings found (with --exit-code 1)
"""

import logging
import subprocess
from pathlib import Path
from typing import Any

from plsec.engine.base import Engine, extract_json
from plsec.engine.types import (
    AvailabilityResult,
    EngineStatus,
    Finding,
    FindingCategory,
    Layer,
    Location,
    Preset,
    ScanContext,
    Severity,
)

logger = logging.getLogger(__name__)

# Trivy severity → plsec Severity mapping
_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}

# Default timeout for trivy subprocess (seconds)
DEFAULT_TIMEOUT = 300


class TrivySecretEngine(Engine):
    """Trivy filesystem secret scanning.

    Wraps `trivy fs --scanners secret` with JSON output, parsing
    results into normalized Finding objects.
    """

    @property
    def engine_id(self) -> str:
        return "trivy-secrets"

    @property
    def layer(self) -> Layer:
        return Layer.STATIC

    @property
    def display_name(self) -> str:
        return "Trivy Secret Scanner"

    @property
    def presets(self) -> frozenset[Preset]:
        # Enabled at every preset level — secrets are always checked
        return frozenset(Preset)

    @property
    def dependencies(self) -> list[str]:
        return ["trivy"]

    def check_available(self, ctx: ScanContext) -> AvailabilityResult:
        if "trivy" not in ctx.environment.available_tools:
            return AvailabilityResult(
                status=EngineStatus.UNAVAILABLE,
                message="trivy not found in PATH",
            )

        # Could check version here for minimum version requirements
        return AvailabilityResult(
            status=EngineStatus.AVAILABLE,
            message="trivy available",
        )

    def execute(self, ctx: ScanContext) -> list[Finding]:
        config = ctx.config_for(self.engine_id)
        timeout = config.get("timeout", DEFAULT_TIMEOUT)
        secret_config_path = config.get("secret_config")

        cmd = [
            "trivy",
            "fs",
            "--scanners",
            "secret",
            "--format",
            "json",
            "--quiet",
            str(ctx.target_path),
        ]

        if secret_config_path:
            cmd.extend(["--secret-config", str(secret_config_path)])

        ignorefile = ctx.target_path / ".trivyignore.yaml"
        if ignorefile.is_file():
            cmd.extend(["--ignorefile", str(ignorefile)])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return [self._tool_failure(f"trivy timed out after {timeout}s")]
        except FileNotFoundError:
            return [self._tool_failure("trivy binary not found at execution time")]
        except OSError as e:
            return [self._tool_failure(f"Failed to execute trivy: {e}")]

        # Defensive JSON extraction (see docs/secure-tool-handling.md)
        data = extract_json(result.stdout, self.engine_id)
        if data is not None:
            return self._parse_results(data, ctx.target_path)

        # No usable JSON — determine whether this is a clean scan or a failure
        if result.returncode == 0 and not result.stderr.strip():
            return []

        stderr_hint = result.stderr.strip()[:200] if result.stderr else "no stderr"
        return [self._tool_failure(f"exited with code {result.returncode}. {stderr_hint}")]

    def _parse_results(self, data: dict[str, Any], target: Path) -> list[Finding]:
        """Convert trivy JSON output to Finding objects.

        Trivy's JSON structure for secret scanning:
        {
            "Results": [
                {
                    "Target": "path/to/file",
                    "Secrets": [
                        {
                            "RuleID": "...",
                            "Category": "...",
                            "Title": "...",
                            "Severity": "HIGH",
                            "StartLine": 42,
                            "EndLine": 42,
                            "Match": "matched text (redacted)"
                        }
                    ]
                }
            ]
        }
        """
        findings: list[Finding] = []

        for result_block in data.get("Results", []):
            target_file = result_block.get("Target", "")

            for secret in result_block.get("Secrets", []):
                severity = _SEVERITY_MAP.get(
                    secret.get("Severity", "UNKNOWN"),
                    Severity.INFO,
                )

                location = Location(
                    file_path=Path(target_file),
                    line_start=secret.get("StartLine"),
                    line_end=secret.get("EndLine"),
                )

                findings.append(
                    Finding(
                        engine_id=self.engine_id,
                        layer=self.layer,
                        severity=severity,
                        category=FindingCategory.LEAKED_CREDENTIAL,
                        title=secret.get("Title", "Secret detected"),
                        description=secret.get("Match", ""),
                        location=location,
                        evidence={
                            "rule_id": secret.get("RuleID", ""),
                            "trivy_category": secret.get("Category", ""),
                        },
                        remediation=(
                            "Remove the secret from source code. "
                            "Rotate the credential. "
                            "Use environment variables or a secrets manager."
                        ),
                    )
                )

        return findings

    def _tool_failure(self, message: str) -> Finding:
        """Produce a finding when the tool itself fails.

        This is NOT a secret detection — it's an indication that
        the security control could not execute. The correlation
        engine may use this to reason about coverage gaps.
        """
        return Finding(
            engine_id=self.engine_id,
            layer=self.layer,
            severity=Severity.MEDIUM,
            category=FindingCategory.MISSING_CONTROL,
            title="Secret scanning unavailable",
            description=f"Trivy secret scanning failed: {message}",
            remediation="Ensure trivy is installed and accessible: brew install trivy",
        )
