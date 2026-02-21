"""Scanner registry -- single source of truth for security scanner metadata.

Each scanner plsec manages is declared as a ScannerSpec.  The scan command
iterates the SCANNERS registry rather than hardcoding per-tool functions.

Adding a new scanner: add a Tool entry to core/tools.py if needed, write
command-builder and result-parser functions (or reuse generic ones), then
add one ScannerSpec entry to SCANNERS.
"""

import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from plsec.core.tools import REQUIRED_TOOLS, Tool

# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class ScannerSpec:
    """Everything plsec needs to know about a security scanner."""

    # Unique identifier (e.g., "trivy-secrets", "bandit")
    id: str
    # Human-readable name (e.g., "Trivy Secret Scan", "Bandit")
    display_name: str
    # Category of scan (e.g., "secrets", "code", "misconfig")
    scan_type: str
    # Binary metadata from core/tools.py (availability checks, install hints)
    tool: Tool
    # Given (target_path, config_path), return subprocess argv
    build_command: Callable[[Path, Path | None], list[str]]
    # Given (returncode, combined_output), return (passed, message)
    parse_result: Callable[[int, str], tuple[bool, str]]
    # Relative path under plsec_home for tool config, or None
    config_file: str | None = None
    # Subprocess timeout in seconds
    timeout: int = 300
    # If True, missing binary is a skip (pass), not failure
    skip_when_missing: bool = True
    # Predicate to check for scannable files (e.g., *.py), or None
    file_filter: Callable[[Path], bool] | None = None


# ---------------------------------------------------------------------------
# Tool references -- look up shared Tool objects by command name
# ---------------------------------------------------------------------------

_TOOLS_BY_COMMAND: dict[str, Tool] = {t.command: t for t in REQUIRED_TOOLS}


def _get_tool(command: str) -> Tool:
    """Get a Tool by its command name from REQUIRED_TOOLS."""
    return _TOOLS_BY_COMMAND[command]


# ---------------------------------------------------------------------------
# Command builders
# ---------------------------------------------------------------------------


def _build_trivy_secrets_cmd(target: Path, config: Path | None) -> list[str]:
    """Build trivy secret scanning command."""
    cmd = ["trivy", "fs", "--scanners", "secret"]
    if config and config.exists():
        cmd.extend(["--secret-config", str(config)])
    cmd.extend(["--exit-code", "1", str(target)])
    return cmd


def _build_trivy_misconfig_cmd(target: Path, config: Path | None) -> list[str]:
    """Build trivy misconfiguration scanning command."""
    return ["trivy", "config", "--exit-code", "1", str(target)]


def _build_bandit_cmd(target: Path, config: Path | None) -> list[str]:
    """Build bandit Python security scanner command."""
    return ["bandit", "-r", "-ll", "-q", str(target)]


def _build_semgrep_cmd(target: Path, config: Path | None) -> list[str]:
    """Build semgrep multi-language scanner command."""
    return ["semgrep", "--config", "auto", "--quiet", "--error", str(target)]


# ---------------------------------------------------------------------------
# Result parsers
# ---------------------------------------------------------------------------


def _parse_trivy_secrets_result(returncode: int, output: str) -> tuple[bool, str]:
    """Parse trivy secret scan result."""
    if returncode == 0:
        return True, "No secrets detected"
    if "No secret detected" in output:
        return True, "No secrets detected"
    return False, output


def _parse_trivy_misconfig_result(returncode: int, output: str) -> tuple[bool, str]:
    """Parse trivy misconfiguration scan result."""
    if returncode == 0:
        return True, "No misconfigurations detected"
    if "Detected" not in output:
        return True, "No misconfigurations detected"
    return False, output


def _parse_returncode_result(returncode: int, output: str) -> tuple[bool, str]:
    """Generic parser: returncode 0 is pass, anything else is fail."""
    if returncode == 0:
        return True, "No issues found"
    return False, output


# ---------------------------------------------------------------------------
# File filters
# ---------------------------------------------------------------------------


def _has_python_files(target: Path) -> bool:
    """Check if the target directory contains any Python files."""
    return any(target.rglob("*.py"))


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

SCANNERS: dict[str, ScannerSpec] = {
    "trivy-secrets": ScannerSpec(
        id="trivy-secrets",
        display_name="Trivy Secret Scan",
        scan_type="secrets",
        tool=_get_tool("trivy"),
        build_command=_build_trivy_secrets_cmd,
        parse_result=_parse_trivy_secrets_result,
        config_file="trivy/trivy-secret.yaml",
        skip_when_missing=False,
    ),
    "trivy-misconfig": ScannerSpec(
        id="trivy-misconfig",
        display_name="Trivy Misconfiguration Scan",
        scan_type="misconfig",
        tool=_get_tool("trivy"),
        build_command=_build_trivy_misconfig_cmd,
        parse_result=_parse_trivy_misconfig_result,
        config_file=None,
        skip_when_missing=False,
    ),
    "bandit": ScannerSpec(
        id="bandit",
        display_name="Bandit",
        scan_type="code",
        tool=_get_tool("bandit"),
        build_command=_build_bandit_cmd,
        parse_result=_parse_returncode_result,
        config_file=None,
        skip_when_missing=True,
        file_filter=_has_python_files,
    ),
    "semgrep": ScannerSpec(
        id="semgrep",
        display_name="Semgrep",
        scan_type="code",
        tool=_get_tool("semgrep"),
        build_command=_build_semgrep_cmd,
        parse_result=_parse_returncode_result,
        config_file=None,
        timeout=600,
        skip_when_missing=True,
    ),
}


# ---------------------------------------------------------------------------
# Generic scan runner
# ---------------------------------------------------------------------------


def run_scanner(
    spec: ScannerSpec,
    target: Path,
    plsec_home: Path,
) -> tuple[bool, str]:
    """Run a single scanner against a target path.

    Handles binary availability checks, file filtering, command
    construction, subprocess execution, timeout, and result parsing.

    Returns (passed, message).
    """
    # Check if binary is available
    if not shutil.which(spec.tool.command):
        if spec.skip_when_missing:
            return True, f"{spec.display_name} not installed (skipped)"
        return False, f"{spec.display_name} not found"

    # Check file filter (e.g., bandit only runs if *.py files exist)
    if spec.file_filter and not spec.file_filter(target):
        return True, f"No applicable files found for {spec.display_name}"

    # Build config path if scanner has a config file
    config_path = (plsec_home / spec.config_file) if spec.config_file else None

    # Build and run the command
    cmd = spec.build_command(target, config_path)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=spec.timeout,
        )
        output = result.stdout + result.stderr
        return spec.parse_result(result.returncode, output)
    except subprocess.TimeoutExpired:
        return False, f"{spec.display_name} timed out"
    except FileNotFoundError:
        if spec.skip_when_missing:
            return True, f"{spec.display_name} not installed (skipped)"
        return False, f"{spec.display_name} not found"
