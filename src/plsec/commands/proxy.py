"""
plsec proxy - Manage Pipelock runtime proxy.

Start, stop, and monitor the Pipelock security proxy.
"""

import os
import signal
import subprocess
import shutil
from pathlib import Path
from typing import Literal

import typer

from plsec.core.config import get_plsec_home
from plsec.core.output import (
    console,
    print_ok,
    print_error,
    print_warning,
    print_info,
)

app = typer.Typer(
    help="Manage Pipelock runtime proxy.",
    no_args_is_help=True,
)


ProxyMode = Literal["audit", "balanced", "strict"]


def get_pid_file() -> Path:
    """Get path to Pipelock PID file."""
    return get_plsec_home() / "pipelock.pid"


def is_pipelock_running() -> tuple[bool, int | None]:
    """Check if Pipelock is running."""
    pid_file = get_pid_file()

    if not pid_file.exists():
        return False, None

    try:
        pid = int(pid_file.read_text().strip())
        # Check if process exists
        os.kill(pid, 0)
        return True, pid
    except (ValueError, ProcessLookupError, PermissionError):
        # PID file exists but process is dead
        pid_file.unlink(missing_ok=True)
        return False, None


def find_pipelock() -> Path | None:
    """Find Pipelock binary."""
    path = shutil.which("pipelock")
    return Path(path) if path else None


@app.command()
def start(
    mode: ProxyMode = typer.Option(
        "balanced",
        "--mode",
        "-m",
        help="Proxy mode: audit, balanced, strict.",
    ),
    port: int = typer.Option(
        8888,
        "--port",
        "-p",
        help="Port to listen on.",
    ),
    background: bool = typer.Option(
        True,
        "--background/--foreground",
        "-b/-f",
        help="Run in background.",
    ),
    config: Path | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to Pipelock config file.",
    ),
) -> None:
    """Start the Pipelock proxy."""
    console.print("[bold]plsec proxy start[/bold]\n")

    # Check if already running
    running, pid = is_pipelock_running()
    if running:
        print_warning(f"Pipelock already running (PID: {pid})")
        console.print("Run 'plsec proxy stop' first")
        raise typer.Exit(1)

    # Find Pipelock binary
    pipelock = find_pipelock()
    if pipelock is None:
        print_error("Pipelock not found")
        console.print("\nInstall with:")
        console.print("  go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest")
        raise typer.Exit(1)

    # Use default config if not specified
    plsec_home = get_plsec_home()
    if config is None:
        config = plsec_home / "pipelock.yaml"

    if not config.exists():
        print_warning(f"Config not found: {config}")
        print_info("Generating default config...")

        # Generate default config
        result = subprocess.run(
            [str(pipelock), "generate", "config", "--preset", mode, "-o", str(config)],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print_error("Failed to generate config")
            console.print(result.stderr)
            raise typer.Exit(1)

        print_ok(f"Created {config}")

    # Build command
    cmd = [
        str(pipelock),
        "run",
        "--config", str(config),
        "--listen", f"127.0.0.1:{port}",
    ]

    print_info(f"Starting Pipelock in {mode} mode on port {port}...")

    if background:
        # Start in background
        log_file = plsec_home / "logs" / "pipelock.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)

        with open(log_file, "a") as log:
            process = subprocess.Popen(
                cmd,
                stdout=log,
                stderr=log,
                start_new_session=True,
            )

        # Save PID
        pid_file = get_pid_file()
        pid_file.write_text(str(process.pid))

        print_ok(f"Pipelock started (PID: {process.pid})")
        console.print(f"  Log: {log_file}")
        console.print(f"  Proxy: http://127.0.0.1:{port}")
        console.print("\nTo use with Claude Code:")
        console.print(f"  export HTTPS_PROXY=http://127.0.0.1:{port}")
        console.print(f"  export HTTP_PROXY=http://127.0.0.1:{port}")

    else:
        # Run in foreground
        print_info("Running in foreground. Press Ctrl+C to stop.")
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print_info("Stopped")

    raise typer.Exit(0)


@app.command()
def stop() -> None:
    """Stop the Pipelock proxy."""
    console.print("[bold]plsec proxy stop[/bold]\n")

    running, pid = is_pipelock_running()

    if not running:
        print_info("Pipelock is not running")
        raise typer.Exit(0)

    try:
        os.kill(pid, signal.SIGTERM)
        print_ok(f"Stopped Pipelock (PID: {pid})")

        # Clean up PID file
        get_pid_file().unlink(missing_ok=True)

    except Exception as e:
        print_error(f"Failed to stop Pipelock: {e}")
        raise typer.Exit(1)

    raise typer.Exit(0)


@app.command()
def status() -> None:
    """Check Pipelock status."""
    console.print("[bold]plsec proxy status[/bold]\n")

    running, pid = is_pipelock_running()

    if running:
        print_ok(f"Pipelock is running (PID: {pid})")

        # Try to get stats
        plsec_home = get_plsec_home()
        log_file = plsec_home / "logs" / "pipelock.log"

        if log_file.exists():
            console.print(f"\nLog file: {log_file}")
            # Show last few lines
            try:
                lines = log_file.read_text().strip().split("\n")[-5:]
                if lines:
                    console.print("\nRecent log entries:")
                    for line in lines:
                        console.print(f"  {line}", style="dim")
            except Exception:
                pass
    else:
        print_info("Pipelock is not running")
        console.print("\nStart with: plsec proxy start")

    raise typer.Exit(0)


@app.command()
def logs(
    follow: bool = typer.Option(
        False,
        "--follow",
        "-f",
        help="Follow log output.",
    ),
    lines: int = typer.Option(
        50,
        "--lines",
        "-n",
        help="Number of lines to show.",
    ),
) -> None:
    """View Pipelock logs."""
    plsec_home = get_plsec_home()
    log_file = plsec_home / "logs" / "pipelock.log"

    if not log_file.exists():
        print_info("No log file found")
        raise typer.Exit(0)

    if follow:
        # Use tail -f
        try:
            subprocess.run(["tail", "-f", str(log_file)])
        except KeyboardInterrupt:
            pass
    else:
        # Show last N lines
        try:
            result = subprocess.run(
                ["tail", f"-{lines}", str(log_file)],
                capture_output=True,
                text=True,
            )
            console.print(result.stdout)
        except Exception as e:
            print_error(f"Failed to read logs: {e}")
            raise typer.Exit(1)

    raise typer.Exit(0)
