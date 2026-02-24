"""
plsec reset - Factory reset global security configuration.

Stops managed processes, wipes configuration under ``~/.peerlabs/plsec/``
(preserving logs by default), removes external agent configs, redeploys
fresh defaults, and re-injects shell aliases.
"""

__version__ = "0.1.0"

import shutil
from pathlib import Path
from typing import Annotated

import typer

from plsec.commands.install import (
    Preset,
    deploy_global_configs,
    inject_aliases,
    write_installed_metadata,
)
from plsec.core.agents import AGENTS, AgentSpec, resolve_agent_ids
from plsec.core.config import get_plsec_home
from plsec.core.inventory import (
    discover_external_artifacts,
    discover_global_artifacts,
    format_size,
)
from plsec.core.output import (
    console,
    print_error,
    print_header,
    print_info,
    print_ok,
    print_warning,
)
from plsec.core.processes import PROCESSES, is_running

app = typer.Typer(
    help="Factory reset global security configuration.",
    no_args_is_help=False,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _stop_managed_processes(plsec_home: Path) -> None:
    """Stop any running managed processes (e.g., pipelock)."""
    import os
    import signal

    for _pid_name, spec in PROCESSES.items():
        running, pid = is_running(spec, plsec_home)
        if running and pid is not None:
            print_info(f"Stopping {spec.display_name} (PID {pid})...")
            try:
                os.kill(pid, signal.SIGTERM)
                print_ok(f"Stopped {spec.display_name}")
            except ProcessLookupError:
                print_warning(f"{spec.display_name} already stopped")
            except PermissionError:
                print_error(f"Cannot stop {spec.display_name}: permission denied")


# Directories preserved during reset unless explicitly requested.
_PRESERVED_DIRS = frozenset({"logs"})


def _wipe_global_state(
    plsec_home: Path,
    *,
    preserve_logs: bool = True,
) -> int:
    """Remove files and subdirectories under plsec_home.

    By default the ``logs/`` directory is preserved because session and
    scan logs are operational data, not configuration.  Pass
    ``preserve_logs=False`` (CLI ``--wipe-logs``) to remove everything.

    The root directory itself is always preserved.
    Returns the number of items removed.
    """
    count = 0
    if not plsec_home.is_dir():
        return count

    for child in sorted(plsec_home.iterdir()):
        if preserve_logs and child.name in _PRESERVED_DIRS:
            continue
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
        count += 1
    return count


def _remove_external_configs(
    agents: dict[str, AgentSpec],
) -> int:
    """Remove agent configs from native locations (e.g., ~/.config/opencode/).

    Returns the number of files removed.
    """
    count = 0
    for _aid, spec in agents.items():
        if spec.global_config_dir is not None:
            native_path = spec.global_config_dir / spec.config_filename
            if native_path.is_file():
                native_path.unlink()
                print_ok(f"Removed {native_path}")
                count += 1
    return count


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def reset(
    preset: Annotated[
        Preset,
        typer.Option("--preset", "-p", help="Security preset for redeployment."),
    ] = "balanced",
    agent: Annotated[
        str, typer.Option("--agent", "-a", help="Agent type: claude, opencode, both.")
    ] = "both",
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation prompt.")] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", "-n", help="Show what would happen without making changes."),
    ] = False,
    wipe_logs: Annotated[
        bool,
        typer.Option("--wipe-logs", help="Also delete scan and session logs."),
    ] = False,
    no_aliases: Annotated[
        bool,
        typer.Option("--no-aliases", help="Skip shell alias re-injection."),
    ] = False,
) -> None:
    """
    Factory reset global security configuration.

    Stops managed processes, wipes configuration under ~/.peerlabs/plsec/,
    removes external agent configs, redeploys fresh defaults with the
    specified preset, and re-injects shell aliases.

    Session and scan logs are preserved by default.  Use --wipe-logs
    to remove them as well.
    """
    from plsec import __version__

    plsec_home = get_plsec_home()

    console.print(f"[bold]plsec reset[/bold] - Factory reset to preset: {preset}\n")

    # Inventory current state
    global_artifacts = discover_global_artifacts(plsec_home)
    external_artifacts = discover_external_artifacts(AGENTS)
    all_artifacts = global_artifacts + external_artifacts

    total_files = len([a for a in all_artifacts if a.path.is_file()])
    total_size = sum(a.size_bytes for a in all_artifacts)

    print_header("Current State")
    print_info(f"Global artifacts: {len(global_artifacts)} items ({format_size(total_size)})")
    print_info(f"External configs: {len(external_artifacts)} items")
    print_info(f"Will redeploy with preset: {preset}")
    if not wipe_logs:
        print_info("Logs will be preserved (use --wipe-logs to remove)")

    if dry_run:
        console.print("\n[yellow]Dry run -- no changes made.[/yellow]")
        if global_artifacts:
            console.print("\nWould remove:")
            for artifact in all_artifacts:
                if not wipe_logs and artifact.path.parent.name == "logs":
                    continue
                console.print(f"  {artifact.path}")
        console.print(f"\nWould redeploy {total_files} files with preset: {preset}")
        raise typer.Exit(0)

    if not yes:
        confirm = typer.confirm(
            f"\nThis will wipe {total_files} files ({format_size(total_size)}) "
            f"and redeploy with preset '{preset}'. Continue?"
        )
        if not confirm:
            console.print("\n[yellow]Reset cancelled.[/yellow]")
            raise typer.Exit(2)

    # Step 1: Stop managed processes
    print_header("Stopping Processes")
    _stop_managed_processes(plsec_home)

    # Step 2: Remove external agent configs
    print_header("Removing External Configs")
    ext_removed = _remove_external_configs(AGENTS)
    if ext_removed == 0:
        print_info("No external configs to remove")

    # Step 3: Wipe global state (preserving logs unless --wipe-logs)
    print_header("Wiping Global State")
    items_removed = _wipe_global_state(plsec_home, preserve_logs=not wipe_logs)
    print_ok(f"Removed {items_removed} items from {plsec_home}")

    # Step 4: Redeploy
    print_header("Redeploying Configuration")
    agent_ids = resolve_agent_ids(agent)
    deploy_global_configs(plsec_home, preset=preset, agent=agent, force=True)

    # Step 5: Re-inject shell aliases
    if not no_aliases:
        print_header("Shell Aliases")
        rc = inject_aliases(plsec_home, agent_ids, AGENTS, force=True)
        if rc:
            print_info(f"Aliases re-injected into {rc}")

    # Step 6: Write installation metadata
    write_installed_metadata(
        plsec_home,
        preset=preset,
        agent_ids=agent_ids,
        version=__version__,
    )

    console.print("\n[green]Reset complete.[/green]")
    raise typer.Exit(0)
