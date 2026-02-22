"""
plsec proxy - Manage security proxy processes.

Start, stop, and monitor managed proxy services (e.g., Pipelock).
Delegates process management to the PROCESSES registry in core/processes.py.
"""

__version__ = "0.1.0"

import os
import signal
import subprocess
from pathlib import Path
from typing import Annotated, Literal

import typer

from plsec.core.config import get_plsec_home
from plsec.core.output import (
    console,
    print_error,
    print_info,
    print_ok,
    print_warning,
)
from plsec.core.processes import (
    PROCESSES,
    find_binary,
    get_config_path,
    get_log_path,
    get_pid_file_path,
    is_running,
)

app = typer.Typer(
    help="Manage Pipelock runtime proxy.",
    no_args_is_help=True,
)


ProxyMode = Literal["audit", "balanced", "strict"]

# The default process managed by the proxy command
_SPEC = PROCESSES["pipelock"]


@app.command()
def start(
    mode: Annotated[
        ProxyMode, typer.Option("--mode", "-m", help="Proxy mode: audit, balanced, strict.")
    ] = "balanced",
    port: Annotated[int, typer.Option("--port", "-p", help="Port to listen on.")] = 8888,
    background: Annotated[
        bool, typer.Option("--background/--foreground", "-b/-f", help="Run in background.")
    ] = True,
    config: Annotated[
        Path | None, typer.Option("--config", "-c", help="Path to config file.")
    ] = None,
) -> None:
    """Start the Pipelock proxy."""
    console.print("[bold]plsec proxy start[/bold]\n")

    plsec_home = get_plsec_home()

    # Check if already running
    running, pid = is_running(_SPEC, plsec_home)
    if running:
        print_warning(f"{_SPEC.display_name} already running (PID: {pid})")
        console.print("Run 'plsec proxy stop' first")
        raise typer.Exit(1)

    # Find binary
    binary = find_binary(_SPEC)
    if binary is None:
        print_error(f"{_SPEC.display_name} not found")
        console.print(f"\nInstall with:\n  {_SPEC.install_hint}")
        raise typer.Exit(1)

    # Use default config if not specified
    if config is None:
        config = get_config_path(_SPEC, plsec_home)

    if not config.exists():
        print_warning(f"Config not found: {config}")
        print_info("Generating default config...")

        # Generate default config
        if _SPEC.build_config_cmd is not None:
            gen_cmd = _SPEC.build_config_cmd(binary, mode, config)
            result = subprocess.run(gen_cmd, capture_output=True, text=True)

            if result.returncode != 0:
                print_error("Failed to generate config")
                console.print(result.stderr)
                raise typer.Exit(1)

            print_ok(f"Created {config}")
        else:
            print_error("No config generator available")
            raise typer.Exit(1)

    # Build run command
    cmd = _SPEC.build_run_cmd(binary, config, port, mode)

    print_info(f"Starting {_SPEC.display_name} in {mode} mode on port {port}...")

    if background:
        # Start in background
        log_file = get_log_path(_SPEC, plsec_home)
        log_file.parent.mkdir(parents=True, exist_ok=True)

        with open(log_file, "a") as log:
            process = subprocess.Popen(
                cmd,
                stdout=log,
                stderr=log,
                start_new_session=True,
            )

        # Save PID
        pid_file = get_pid_file_path(_SPEC, plsec_home)
        pid_file.write_text(str(process.pid))

        print_ok(f"{_SPEC.display_name} started (PID: {process.pid})")
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

    plsec_home = get_plsec_home()
    running, pid = is_running(_SPEC, plsec_home)

    if not running:
        print_info(f"{_SPEC.display_name} is not running")
        raise typer.Exit(0)

    assert pid is not None  # guaranteed by is_running() when running=True
    try:
        os.kill(pid, signal.SIGTERM)
        print_ok(f"Stopped {_SPEC.display_name} (PID: {pid})")

        # Clean up PID file
        get_pid_file_path(_SPEC, plsec_home).unlink(missing_ok=True)

    except ProcessLookupError:
        print_info(f"{_SPEC.display_name} already stopped")
        get_pid_file_path(_SPEC, plsec_home).unlink(missing_ok=True)
    except OSError as e:
        print_error(f"Failed to stop {_SPEC.display_name}: {e}")
        raise typer.Exit(1) from e

    raise typer.Exit(0)


@app.command()
def status() -> None:
    """Check proxy status."""
    console.print("[bold]plsec proxy status[/bold]\n")

    plsec_home = get_plsec_home()
    running, pid = is_running(_SPEC, plsec_home)

    if running:
        print_ok(f"{_SPEC.display_name} is running (PID: {pid})")

        log_file = get_log_path(_SPEC, plsec_home)
        if log_file.exists():
            console.print(f"\nLog file: {log_file}")
            try:
                lines = log_file.read_text().strip().split("\n")[-5:]
                if lines:
                    console.print("\nRecent log entries:")
                    for line in lines:
                        console.print(f"  {line}", style="dim")
            except OSError:
                pass
    else:
        print_info(f"{_SPEC.display_name} is not running")
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
    """View proxy logs."""
    plsec_home = get_plsec_home()
    log_file = get_log_path(_SPEC, plsec_home)

    if not log_file.exists():
        print_info("No log file found")
        raise typer.Exit(0)

    if follow:
        try:
            subprocess.run(["tail", "-f", str(log_file)])
        except KeyboardInterrupt:
            pass
    else:
        try:
            result = subprocess.run(
                ["tail", f"-{lines}", str(log_file)],
                capture_output=True,
                text=True,
            )
            console.print(result.stdout)
        except OSError as e:
            print_error(f"Failed to read logs: {e}")
            raise typer.Exit(1) from e

    raise typer.Exit(0)
