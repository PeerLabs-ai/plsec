"""
plsec.engine.trivy_dependency -- Trivy dependency vulnerability scanning.

Wraps `trivy fs --scanners vuln` to detect known vulnerabilities in
project dependencies.  This is the cross-language baseline for Software
Composition Analysis (SCA) -- it covers Python, Node.js, Go, Rust,
Java, Ruby, PHP, and .NET via a single tool invocation.

Output is parsed from Trivy's JSON format into Finding objects with
DEPENDENCY_VULNERABILITY category.

See docs/dependency-vulnerability-scanners.md for the landscape analysis.

Exit codes:
    0 -- no findings
    1 -- findings found (with --exit-code 1)
"""

import logging
import subprocess
from pathlib import Path
from typing import Any

from plsec.engine.base import extract_json
from plsec.engine.dependency import DependencyEngine
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

# Default timeout for trivy subprocess (seconds)
DEFAULT_TIMEOUT = 300


class TrivyDependencyEngine(DependencyEngine):
    """Trivy filesystem dependency vulnerability scanning.

    Cross-language SCA baseline.  Available at balanced, strict, and
    paranoid presets (not minimal -- minimal is secrets-only).
    """

    @property
    def engine_id(self) -> str:
        return "trivy-vuln"

    @property
    def display_name(self) -> str:
        return "Trivy Dependency Scanner"

    @property
    def presets(self) -> frozenset[Preset]:
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
            "fs",
            "--scanners",
            "vuln",
            "--format",
            "json",
            "--quiet",
            str(ctx.target_path),
        ]

        # Wire .trivyignore.yaml if present in target directory
        ignorefile = ctx.target_path / ".trivyignore.yaml"
        if ignorefile.is_file():
            cmd.insert(-1, "--ignorefile")
            cmd.insert(-1, str(ignorefile))

        try:
            result = subprocess.run(  # noqa: S603 -- tool invocation, not user input
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning("trivy vuln scan timed out after %ds", timeout)
            return [self._tool_failure(f"trivy timed out after {timeout}s")]
        except FileNotFoundError:
            logger.warning("trivy binary not found")
            return [self._tool_failure("trivy binary not found")]
        except OSError as e:
            logger.warning("trivy vuln scan failed: %s", e)
            return [self._tool_failure(f"trivy execution error: {e}")]

        data = extract_json(result.stdout, "trivy-vuln")
        if data is None:
            if result.returncode == 0:
                return []
            return [
                self._tool_failure(f"trivy exited {result.returncode} with no parseable output")
            ]

        return self._parse_findings(data)

    def _parse_findings(self, data: dict[str, Any]) -> list[Finding]:
        """Parse Trivy vulnerability JSON into Finding objects."""
        findings: list[Finding] = []

        for result_block in data.get("Results", []):
            target = result_block.get("Target", "")
            vulns = result_block.get("Vulnerabilities") or []

            for vuln in vulns:
                vuln_id = vuln.get("VulnerabilityID", "unknown")
                pkg_name = vuln.get("PkgName", "unknown")
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion", "")
                severity_str = vuln.get("Severity", "UNKNOWN")
                title = vuln.get("Title", "")

                severity = self.map_cve_severity(severity_str)

                if fixed:
                    remediation = f"Upgrade {pkg_name} to >= {fixed}"
                else:
                    remediation = f"No fix available for {vuln_id} in {pkg_name}"

                findings.append(
                    self.make_dependency_finding(
                        engine_id=self.engine_id,
                        title=f"{vuln_id} in {pkg_name}",
                        severity=severity,
                        description=title,
                        location=Location(file_path=Path(target)) if target else None,
                        evidence={
                            "vulnerability_id": vuln_id,
                            "package": pkg_name,
                            "installed_version": installed,
                            "fixed_version": fixed,
                        },
                        remediation=remediation,
                    )
                )

        return findings

    def _tool_failure(self, message: str) -> Finding:
        """Produce a MISSING_CONTROL finding for tool failures."""
        return Finding(
            engine_id=self.engine_id,
            layer=Layer.STATIC,
            severity=Severity.HIGH,
            category=FindingCategory.MISSING_CONTROL,
            title=f"Trivy dependency scan failed: {message}",
            description=message,
            remediation="Ensure trivy is installed and accessible. Run: plsec doctor",
        )
