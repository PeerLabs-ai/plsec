"""Scanner registry -- single source of truth for security scanner metadata.

Each scanner plsec manages is declared as a ScannerSpec.  The scan command
iterates the SCANNERS registry rather than hardcoding per-tool functions.

Adding a new scanner: add a Tool entry to core/tools.py if needed, write
command-builder and result-parser functions (or reuse generic ones), then
add one ScannerSpec entry to SCANNERS.

Preset integration: Command builders can optionally accept a StaticLayerConfig
to customize skip_dirs, skip_files, and other scanner-specific parameters.
"""

import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from plsec.core.tools import REQUIRED_TOOLS, Tool

# Import StaticLayerConfig for preset-based scanner configuration
try:
    from plsec.core.config import StaticLayerConfig
except ImportError:
    StaticLayerConfig = None  # type: ignore[misc,assignment]

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Structured result from a single scanner run."""

    # Scanner identifier (e.g., "trivy-secrets", "bandit")
    scanner_id: str
    # Category of scan (e.g., "secrets", "code", "misconfig")
    scan_type: str
    # Outcome: pass, fail, or skip (tool missing / no applicable files)
    verdict: Literal["pass", "fail", "skip"]
    # Subprocess exit code (None if skipped or binary not found)
    exit_code: int | None = None
    # Wall-clock duration in seconds
    duration_seconds: float = 0.0
    # Human-readable summary (e.g., "No secrets detected")
    message: str = ""
    # Truncated scanner output (stdout + stderr)
    output: str = ""

    @property
    def passed(self) -> bool:
        """Whether the scan passed (pass or skip)."""
        return self.verdict in ("pass", "skip")


@dataclass
class ScanSummary:
    """Aggregated results from a full scan run."""

    # Individual scanner results
    results: list[ScanResult] = field(default_factory=list)
    # Target path that was scanned
    target: str = ""
    # Overall pass/fail
    passed: bool = True

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.results if r.verdict == "pass")

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.results if r.verdict == "fail")

    @property
    def skip_count(self) -> int:
        return sum(1 for r in self.results if r.verdict == "skip")


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
    # Given (target_path, config_path, static_config), return subprocess argv
    build_command: Callable[..., list[str]]
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

# Directories skipped by trivy scans -- third-party, generated, and cache
# directories that produce hundreds of false positives.  Applied via
# --skip-dirs flags as a belt-and-suspenders complement to the skip-dirs
# list in trivy.yaml.
_TRIVY_SKIP_DIRS: list[str] = [
    ".venv",
    ".tox",
    "node_modules",
    "build",
    "dist",
    ".eggs",
    "__pycache__",
]

# File glob patterns skipped by trivy scans -- compiled bytecode and
# binary artifacts that trigger false positives on embedded strings.
_TRIVY_SKIP_FILES: list[str] = [
    "**/*.pyc",
]

# Name of the YAML-format trivy ignore file.  When present in the target
# directory it is passed via --ignorefile to suppress known false positives.
_TRIVY_IGNOREFILE = ".trivyignore.yaml"


def _add_trivy_common_flags(
    cmd: list[str], target: Path, preset: "StaticLayerConfig | None" = None
) -> None:
    """Append --skip-dirs, --skip-files, and --ignorefile flags shared by all trivy commands.

    Args:
        cmd: Command list to append flags to
        target: Scan target directory
        preset: Optional StaticLayerConfig to customize skip lists
    """
    # Use preset skip lists if provided, otherwise use defaults
    skip_dirs = preset.skip_dirs if preset else _TRIVY_SKIP_DIRS
    skip_files = preset.skip_files if preset else _TRIVY_SKIP_FILES

    for skip_dir in skip_dirs:
        cmd.extend(["--skip-dirs", skip_dir])
    for skip_file in skip_files:
        cmd.extend(["--skip-files", skip_file])
    ignorefile = target / _TRIVY_IGNOREFILE
    if ignorefile.is_file():
        cmd.extend(["--ignorefile", str(ignorefile)])


def _build_trivy_secrets_cmd(
    target: Path, config: Path | None, preset: "StaticLayerConfig | None" = None
) -> list[str]:
    """Build trivy secret scanning command.

    Args:
        target: Directory to scan
        config: Path to trivy secret config file
        preset: Optional StaticLayerConfig to customize scanning behavior
    """
    cmd = ["trivy", "fs", "--scanners", "secret"]
    if config and config.exists():
        cmd.extend(["--secret-config", str(config)])
    _add_trivy_common_flags(cmd, target, preset)
    cmd.extend(["--exit-code", "1", str(target)])
    return cmd


def _build_trivy_misconfig_cmd(
    target: Path, config: Path | None, preset: "StaticLayerConfig | None" = None
) -> list[str]:
    """Build trivy misconfiguration scanning command.

    Args:
        target: Directory to scan
        config: Path to trivy config file (unused, for signature compatibility)
        preset: Optional StaticLayerConfig to customize scanning behavior
    """
    cmd = ["trivy", "config", "--exit-code", "1"]
    _add_trivy_common_flags(cmd, target, preset)
    cmd.append(str(target))
    return cmd


# Directories excluded from bandit scans -- contain third-party or
# generated code that produces hundreds of false positives.
_BANDIT_EXCLUDE_DIRS: list[str] = [
    ".venv",
    ".tox",
    "node_modules",
    "build",
    "dist",
    ".eggs",
]


def _build_bandit_cmd(
    target: Path, config: Path | None, preset: "StaticLayerConfig | None" = None
) -> list[str]:
    """Build bandit Python security scanner command.

    Args:
        target: Directory to scan
        config: Path to bandit config file (unused, for signature compatibility)
        preset: Optional StaticLayerConfig to customize scanning behavior

    Exclude paths are resolved relative to the target directory because
    bandit's --exclude matching requires paths that align with its
    internal file discovery (bare directory names like '.venv' don't match).
    """
    # Use preset skip_dirs if provided, otherwise use defaults
    skip_dirs = preset.skip_dirs if preset else _BANDIT_EXCLUDE_DIRS
    excludes = ",".join(str(target / d) for d in skip_dirs)
    return ["bandit", "-r", "-ll", "-q", "--exclude", excludes, str(target)]


def _build_semgrep_cmd(
    target: Path, config: Path | None, preset: "StaticLayerConfig | None" = None
) -> list[str]:
    """Build semgrep multi-language scanner command.

    Args:
        target: Directory to scan
        config: Path to semgrep config file (unused, for signature compatibility)
        preset: Optional StaticLayerConfig to customize scanning behavior
    """
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
    static_config: "StaticLayerConfig | None" = None,
) -> ScanResult:
    """Run a single scanner against a target path.

    Handles binary availability checks, file filtering, command
    construction, subprocess execution, timeout, and result parsing.

    Args:
        spec: Scanner specification from the SCANNERS registry
        target: Directory to scan
        plsec_home: Path to ~/.peerlabs/plsec
        static_config: Optional StaticLayerConfig for preset-driven skip dirs/files

    Returns a ScanResult with structured outcome data.
    """
    sid = spec.id
    stype = spec.scan_type

    # Check if binary is available
    if not shutil.which(spec.tool.command):
        if spec.skip_when_missing:
            return ScanResult(
                scanner_id=sid,
                scan_type=stype,
                verdict="skip",
                message=f"{spec.display_name} not installed (skipped)",
            )
        return ScanResult(
            scanner_id=sid,
            scan_type=stype,
            verdict="fail",
            message=f"{spec.display_name} not found",
        )

    # Check file filter (e.g., bandit only runs if *.py files exist)
    if spec.file_filter and not spec.file_filter(target):
        return ScanResult(
            scanner_id=sid,
            scan_type=stype,
            verdict="skip",
            message=f"No applicable files found for {spec.display_name}",
        )

    # Build config path if scanner has a config file
    config_path = (plsec_home / spec.config_file) if spec.config_file else None

    # Build and run the command (pass static_config for skip dirs/files)
    cmd = spec.build_command(target, config_path, static_config)
    timeout = static_config.timeout if static_config else spec.timeout
    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        elapsed = time.monotonic() - start
        output = result.stdout + result.stderr
        passed, message = spec.parse_result(result.returncode, output)
        return ScanResult(
            scanner_id=sid,
            scan_type=stype,
            verdict="pass" if passed else "fail",
            exit_code=result.returncode,
            duration_seconds=round(elapsed, 2),
            message=message,
            output=output[:10_000],
        )
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - start
        return ScanResult(
            scanner_id=sid,
            scan_type=stype,
            verdict="fail",
            duration_seconds=round(elapsed, 2),
            message=f"{spec.display_name} timed out",
        )
    except FileNotFoundError:
        if spec.skip_when_missing:
            return ScanResult(
                scanner_id=sid,
                scan_type=stype,
                verdict="skip",
                message=f"{spec.display_name} not installed (skipped)",
            )
        return ScanResult(
            scanner_id=sid,
            scan_type=stype,
            verdict="fail",
            message=f"{spec.display_name} not found",
        )
