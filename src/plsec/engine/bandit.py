"""
plsec.engine.bandit -- Bandit Python security scanning engine.

Wraps the bandit CLI tool behind the Engine interface. Bandit
performs static analysis of Python code to find common security
issues (SQL injection, subprocess shell=True, hardcoded passwords,
etc.).

Output is parsed from bandit's JSON format into Finding objects.
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

# Bandit severity -> plsec Severity mapping
_SEVERITY_MAP: dict[str, Severity] = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

# Directories excluded from bandit scans by default.
# These contain third-party or generated code that produces
# hundreds of false positives.
_DEFAULT_EXCLUDE_DIRS: list[str] = [
    ".venv",
    ".tox",
    "node_modules",
    "build",
    "dist",
    ".eggs",
]

# Default timeout for bandit subprocess (seconds)
DEFAULT_TIMEOUT = 300


class BanditEngine(Engine):
    """Bandit Python security scanner.

    Wraps `bandit -r --format json` with severity filtering and
    exclude-dir support.
    """

    @property
    def engine_id(self) -> str:
        return "bandit"

    @property
    def layer(self) -> Layer:
        return Layer.STATIC

    @property
    def display_name(self) -> str:
        return "Bandit"

    @property
    def presets(self) -> frozenset[Preset]:
        return frozenset(Preset)

    @property
    def dependencies(self) -> list[str]:
        return ["bandit"]

    def check_available(self, ctx: ScanContext) -> AvailabilityResult:
        if "bandit" not in ctx.environment.available_tools:
            return AvailabilityResult(
                status=EngineStatus.UNAVAILABLE,
                message="bandit not found in PATH",
            )
        return AvailabilityResult(
            status=EngineStatus.AVAILABLE,
            message="bandit available",
        )

    def execute(self, ctx: ScanContext) -> list[Finding]:
        config = ctx.config_for(self.engine_id)
        timeout = config.get("timeout", DEFAULT_TIMEOUT)
        skip_dirs = config.get("skip_dirs", _DEFAULT_EXCLUDE_DIRS)

        # Skip if no Python files in target
        if not config.get("has_python_files", True):
            return []

        # Build exclude list relative to target
        excludes = ",".join(str(ctx.target_path / d) for d in skip_dirs)

        cmd = [
            "bandit",
            "-r",
            "-ll",
            "--format",
            "json",
            "--exclude",
            excludes,
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
            return [self._tool_failure(f"bandit timed out after {timeout}s")]
        except FileNotFoundError:
            return [self._tool_failure("bandit binary not found")]
        except OSError as e:
            return [self._tool_failure(f"Failed to execute bandit: {e}")]

        if not result.stdout.strip():
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse bandit JSON output: %s", e)
            return [self._tool_failure(f"Failed to parse bandit output: {e}")]

        return self._parse_results(data)

    def _parse_results(self, data: dict[str, Any]) -> list[Finding]:
        """Convert bandit JSON output to Finding objects.

        Bandit JSON structure:
        {
            "results": [
                {
                    "filename": "src/app.py",
                    "issue_severity": "HIGH",
                    "issue_text": "...",
                    "line_number": 42,
                    "test_id": "B608",
                    "test_name": "hardcoded_sql_expressions",
                    "issue_confidence": "HIGH",
                    "issue_cwe": {"id": 89, "link": "..."},
                    "more_info": "..."
                }
            ]
        }
        """
        findings: list[Finding] = []

        for item in data.get("results", []):
            severity = _SEVERITY_MAP.get(
                item.get("issue_severity", ""),
                Severity.INFO,
            )

            location = Location(
                file_path=Path(item.get("filename", "")),
                line_start=item.get("line_number"),
            )

            cwe = item.get("issue_cwe", {})

            findings.append(
                Finding(
                    engine_id=self.engine_id,
                    layer=self.layer,
                    severity=severity,
                    category=FindingCategory.CODE_ISSUE,
                    title=item.get("issue_text", "Bandit finding"),
                    description=item.get("issue_text", ""),
                    location=location,
                    evidence={
                        "test_id": item.get("test_id", ""),
                        "test_name": item.get("test_name", ""),
                        "cwe_id": cwe.get("id"),
                        "confidence": item.get("issue_confidence", ""),
                    },
                    remediation=(
                        f"Review {item.get('test_id', 'this')} finding. "
                        f"See: {item.get('more_info', 'bandit documentation')}"
                    ),
                )
            )

        return findings

    def _tool_failure(self, message: str) -> Finding:
        """Produce a finding when bandit fails to execute."""
        return Finding(
            engine_id=self.engine_id,
            layer=self.layer,
            severity=Severity.MEDIUM,
            category=FindingCategory.MISSING_CONTROL,
            title="Code analysis unavailable",
            description=f"Bandit analysis failed: {message}",
            remediation="Ensure bandit is installed: pip install bandit",
        )
