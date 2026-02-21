"""Process registry -- single source of truth for managed background services.

Each background process plsec manages (e.g., Pipelock proxy) is declared
as a ProcessSpec.  The proxy command uses generic functions that operate
on any ProcessSpec rather than hardcoding Pipelock-specific logic.

Adding a new managed process: write command-builder functions, then add
one ProcessSpec entry to PROCESSES.
"""

import os
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ProcessSpec:
    """A managed background process that plsec can start/stop/monitor."""

    # Unique identifier (e.g., "pipelock")
    id: str
    # Human-readable name (e.g., "Pipelock Security Proxy")
    display_name: str
    # Command name for shutil.which() (e.g., "pipelock")
    binary: str
    # PID file path, relative to plsec_home (e.g., "pipelock.pid")
    pid_file: str
    # Log file path, relative to plsec_home (e.g., "logs/pipelock.log")
    log_file: str
    # Config file path, relative to plsec_home (e.g., "pipelock.yaml")
    config_file: str
    # How to install the binary
    install_hint: str
    # Given (binary_path, config_path, port, mode), return run argv
    build_run_cmd: Callable[[Path, Path, int, str], list[str]]
    # Given (binary_path, mode, output_path), return config-gen argv, or None
    build_config_cmd: Callable[[Path, str, Path], list[str]] | None = None


# ---------------------------------------------------------------------------
# Pipelock command builders
# ---------------------------------------------------------------------------


def _build_pipelock_run_cmd(
    binary: Path,
    config: Path,
    port: int,
    mode: str,
) -> list[str]:
    """Build the pipelock run command."""
    return [
        str(binary),
        "run",
        "--config",
        str(config),
        "--listen",
        f"127.0.0.1:{port}",
    ]


def _build_pipelock_config_cmd(
    binary: Path,
    mode: str,
    output: Path,
) -> list[str]:
    """Build the pipelock config generation command."""
    return [
        str(binary),
        "generate",
        "config",
        "--preset",
        mode,
        "-o",
        str(output),
    ]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

PROCESSES: dict[str, ProcessSpec] = {
    "pipelock": ProcessSpec(
        id="pipelock",
        display_name="Pipelock Security Proxy",
        binary="pipelock",
        pid_file="pipelock.pid",
        log_file="logs/pipelock.log",
        config_file="pipelock.yaml",
        install_hint=("go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest"),
        build_run_cmd=_build_pipelock_run_cmd,
        build_config_cmd=_build_pipelock_config_cmd,
    ),
}


# ---------------------------------------------------------------------------
# Generic process management functions
# ---------------------------------------------------------------------------


def find_binary(spec: ProcessSpec) -> Path | None:
    """Find the process binary on PATH."""
    path = shutil.which(spec.binary)
    return Path(path) if path else None


def get_pid_file_path(spec: ProcessSpec, plsec_home: Path) -> Path:
    """Get the full path to the PID file."""
    return plsec_home / spec.pid_file


def get_log_path(spec: ProcessSpec, plsec_home: Path) -> Path:
    """Get the full path to the log file."""
    return plsec_home / spec.log_file


def get_config_path(spec: ProcessSpec, plsec_home: Path) -> Path:
    """Get the full path to the config file."""
    return plsec_home / spec.config_file


def is_running(
    spec: ProcessSpec,
    plsec_home: Path,
) -> tuple[bool, int | None]:
    """Check if a managed process is running.

    Reads the PID file, verifies the process exists via os.kill(pid, 0).
    Cleans up stale PID files if the process is no longer alive.

    Returns (is_running, pid_or_none).
    """
    pid_path = get_pid_file_path(spec, plsec_home)

    if not pid_path.exists():
        return False, None

    try:
        pid = int(pid_path.read_text().strip())
        # Signal 0 checks if process exists without affecting it
        os.kill(pid, 0)
        return True, pid
    except (ValueError, ProcessLookupError, PermissionError):
        # PID file exists but process is dead or PID is invalid
        pid_path.unlink(missing_ok=True)
        return False, None
