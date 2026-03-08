"""
plsec.engine.semgrep -- Semgrep multi-language security scanning engine.

Wraps the semgrep CLI tool behind the Engine interface. Semgrep
performs pattern-based static analysis across multiple languages
using community and custom rules.

Output is parsed from semgrep's JSON format into Finding objects.
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Any

from plsec.engine.base import Engine
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

# Semgrep severity -> plsec Severity mapping
# Semgrep uses ERROR/WARNING/INFO in its extra.severity field
_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

# Default timeout for semgrep subprocess (seconds)
DEFAULT_TIMEOUT = 600


class SemgrepEngine(Engine):
    """Semgrep multi-language security scanner.

    Wraps `semgrep --config auto --json` with community rules.
    """

    @property
    def engine_id(self) -> str:
        return "semgrep"

    @property
    def layer(self) -> Layer:
        return Layer.STATIC

    @property
    def display_name(self) -> str:
        return "Semgrep"

    @property
    def presets(self) -> frozenset[Preset]:
        return frozenset(Preset)

    @property
    def dependencies(self) -> list[str]:
        return ["semgrep"]

    def check_available(self, ctx: ScanContext) -> AvailabilityResult:
        if "semgrep" not in ctx.environment.available_tools:
            return AvailabilityResult(
                status=EngineStatus.UNAVAILABLE,
                message="semgrep not found in PATH",
            )
        return AvailabilityResult(
            status=EngineStatus.AVAILABLE,
            message="semgrep available",
        )

    def execute(self, ctx: ScanContext) -> list[Finding]:
        config = ctx.config_for(self.engine_id)
        timeout = config.get("timeout", DEFAULT_TIMEOUT)
        semgrep_config = config.get("config", "auto")

        cmd = [
            "semgrep",
            "--config",
            semgrep_config,
            "--json",
            "--quiet",
            str(ctx.target_path),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return [self._tool_failure(f"semgrep timed out after {timeout}s")]
        except FileNotFoundError:
            return [self._tool_failure("semgrep binary not found")]
        except OSError as e:
            return [self._tool_failure(f"Failed to execute semgrep: {e}")]

        if not result.stdout.strip():
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse semgrep JSON output: %s", e)
            return [self._tool_failure(f"Failed to parse semgrep output: {e}")]

        return self._parse_results(data)

    def _parse_results(self, data: dict[str, Any]) -> list[Finding]:
        """Convert semgrep JSON output to Finding objects.

        Semgrep JSON structure:
        {
            "results": [
                {
                    "check_id": "python.lang.security...",
                    "path": "src/app.py",
                    "start": {"line": 10, "col": 1},
                    "end": {"line": 10, "col": 45},
                    "extra": {
                        "message": "...",
                        "severity": "WARNING",
                        "metadata": {"cwe": [...], ...},
                        "lines": "matched source line"
                    }
                }
            ]
        }
        """
        findings: list[Finding] = []

        for item in data.get("results", []):
            extra = item.get("extra", {})
            metadata = extra.get("metadata", {})

            severity = _SEVERITY_MAP.get(
                extra.get("severity", ""),
                Severity.INFO,
            )

            start = item.get("start", {})
            end = item.get("end", {})

            location = Location(
                file_path=Path(item.get("path", "")),
                line_start=start.get("line"),
                line_end=end.get("line"),
            )

            check_id = item.get("check_id", "")

            findings.append(
                Finding(
                    engine_id=self.engine_id,
                    layer=self.layer,
                    severity=severity,
                    category=FindingCategory.CODE_ISSUE,
                    title=extra.get("message", check_id),
                    description=extra.get("lines", ""),
                    location=location,
                    evidence={
                        "check_id": check_id,
                        "cwe": metadata.get("cwe", []),
                        "confidence": metadata.get("confidence", ""),
                    },
                    remediation=(
                        f"Review semgrep rule {check_id}. See: https://semgrep.dev/r/{check_id}"
                    ),
                )
            )

        return findings

    def _tool_failure(self, message: str) -> Finding:
        """Produce a finding when semgrep fails to execute."""
        return Finding(
            engine_id=self.engine_id,
            layer=self.layer,
            severity=Severity.MEDIUM,
            category=FindingCategory.MISSING_CONTROL,
            title="Code analysis unavailable",
            description=f"Semgrep analysis failed: {message}",
            remediation="Ensure semgrep is installed: pip install semgrep",
        )
