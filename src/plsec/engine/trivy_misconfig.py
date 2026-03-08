"""
plsec.engine.trivy_misconfig -- Trivy misconfiguration scanning engine.

Wraps the `trivy config` CLI command behind the Engine interface.
Trivy detects misconfigurations in Dockerfiles, Kubernetes manifests,
Terraform files, and other infrastructure-as-code formats.

Output is parsed from trivy's JSON format into Finding objects.
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

# Trivy severity -> plsec Severity mapping
_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}

# Default timeout for trivy subprocess (seconds)
DEFAULT_TIMEOUT = 300


class TrivyMisconfigEngine(Engine):
    """Trivy misconfiguration scanner.

    Wraps `trivy config --format json --quiet <target>` to detect
    misconfigurations in Dockerfiles, Kubernetes manifests, Terraform,
    and other IaC files.
    """

    @property
    def engine_id(self) -> str:
        return "trivy-misconfig"

    @property
    def layer(self) -> Layer:
        return Layer.CONFIG

    @property
    def display_name(self) -> str:
        return "Trivy Misconfiguration Scanner"

    @property
    def presets(self) -> frozenset[Preset]:
        # Not enabled at minimal -- misconfig scanning is balanced+
        return frozenset({Preset.BALANCED, Preset.STRICT, Preset.PARANOID})

    @property
    def dependencies(self) -> list[str]:
        return ["trivy"]

    def check_available(self, ctx: ScanContext) -> AvailabilityResult:
        if "trivy" not in ctx.environment.available_tools:
            return AvailabilityResult(
                status=EngineStatus.UNAVAILABLE,
                message="trivy not found in PATH",
            )
        return AvailabilityResult(
            status=EngineStatus.AVAILABLE,
            message="trivy available",
        )

    def execute(self, ctx: ScanContext) -> list[Finding]:
        config = ctx.config_for(self.engine_id)
        timeout = config.get("timeout", DEFAULT_TIMEOUT)

        cmd = [
            "trivy",
            "config",
            "--format",
            "json",
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
            return [self._tool_failure(f"trivy timed out after {timeout}s")]
        except FileNotFoundError:
            return [self._tool_failure("trivy binary not found")]
        except OSError as e:
            return [self._tool_failure(f"Failed to execute trivy: {e}")]

        if not result.stdout.strip():
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse trivy JSON output: %s", e)
            return [self._tool_failure(f"Failed to parse trivy output: {e}")]

        return self._parse_results(data)

    def _parse_results(self, data: dict[str, Any]) -> list[Finding]:
        """Convert trivy config JSON output to Finding objects.

        Trivy's JSON structure for misconfiguration scanning:
        {
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [
                        {
                            "ID": "DS002",
                            "Title": "Image user should not be root",
                            "Description": "Running as root...",
                            "Severity": "HIGH",
                            "Message": "Specify at least 1 USER command",
                            "Resolution": "Add a USER instruction"
                        }
                    ]
                }
            ]
        }
        """
        findings: list[Finding] = []

        for result_block in data.get("Results", []):
            target_file = result_block.get("Target", "")

            for misconfig in result_block.get("Misconfigurations", []):
                severity = _SEVERITY_MAP.get(
                    misconfig.get("Severity", "UNKNOWN"),
                    Severity.INFO,
                )

                location = Location(file_path=Path(target_file))

                misconfig_id = misconfig.get("ID", "")

                findings.append(
                    Finding(
                        engine_id=self.engine_id,
                        layer=self.layer,
                        severity=severity,
                        category=FindingCategory.MISCONFIG,
                        title=misconfig.get("Title", misconfig_id),
                        description=misconfig.get("Description", ""),
                        location=location,
                        evidence={
                            "misconfig_id": misconfig_id,
                            "message": misconfig.get("Message", ""),
                        },
                        remediation=misconfig.get("Resolution"),
                    )
                )

        return findings

    def _tool_failure(self, message: str) -> Finding:
        """Produce a finding when trivy fails to execute."""
        return Finding(
            engine_id=self.engine_id,
            layer=self.layer,
            severity=Severity.MEDIUM,
            category=FindingCategory.MISSING_CONTROL,
            title="Misconfiguration scanning unavailable",
            description=f"Trivy misconfiguration scanning failed: {message}",
            remediation="Ensure trivy is installed and accessible: brew install trivy",
        )
