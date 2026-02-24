"""
plsec uninstall - Clean removal of plsec artifacts from the system.

Discovers plsec-created files (global configs, external agent configs,
project-local files), presents an inventory, and removes selected
artifacts with user confirmation.
"""

__version__ = "0.1.0"

import shutil
from pathlib import Path
from typing import Annotated

import typer

from plsec.commands.install import remove_aliases
from plsec.core.agents import AGENTS
from plsec.core.config import get_plsec_home
from plsec.core.inventory import (
    Artifact,
    discover_external_artifacts,
    discover_global_artifacts,
    discover_project_artifacts,
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
    help="Remove plsec artifacts from the system.",
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


def _remove_artifacts(artifacts: list[Artifact]) -> tuple[int, int]:
    """Remove a list of artifacts from the filesystem.

    Directories are removed recursively. Files are unlinked.
    Returns (files_removed, errors).
    """
    removed = 0
    errors = 0
    # Sort by path depth descending so children are removed before parents
    for artifact in sorted(artifacts, key=lambda a: len(a.path.parts), reverse=True):
        try:
            if artifact.path.is_dir():
                shutil.rmtree(artifact.path)
                removed += 1
            elif artifact.path.is_file():
                artifact.path.unlink()
                removed += 1
            # Skip non-existent paths silently
        except OSError as e:
            print_warning(f"Could not remove {artifact.path}: {e}")
            errors += 1
    return removed, errors


def _remove_global_root(plsec_home: Path) -> None:
    """Remove the plsec_home root directory if empty."""
    if plsec_home.is_dir() and not any(plsec_home.iterdir()):
        plsec_home.rmdir()
        # Also remove .peerlabs if empty
        parent = plsec_home.parent
        if parent.is_dir() and not any(parent.iterdir()):
            parent.rmdir()


def _print_inventory_summary(
    global_artifacts: list[Artifact],
    external_artifacts: list[Artifact],
    project_artifacts: list[Artifact],
    plsec_home: Path,
    project_dir: Path,
) -> None:
    """Print a grouped summary of discovered artifacts."""
    if global_artifacts:
        global_size = sum(a.size_bytes for a in global_artifacts)
        global_files = len([a for a in global_artifacts if a.path.is_file()])
        print_info(
            f"Global configuration ({plsec_home}): "
            f"{global_files} files ({format_size(global_size)})"
        )
    else:
        print_info("Global configuration: none found")

    if external_artifacts:
        for a in external_artifacts:
            print_info(f"External: {a.path} ({format_size(a.size_bytes)})")
    else:
        print_info("External configs: none found")

    if project_artifacts:
        proj_size = sum(a.size_bytes for a in project_artifacts)
        print_info(
            f"Project files ({project_dir}): "
            f"{len(project_artifacts)} files ({format_size(proj_size)})"
        )
        for a in project_artifacts:
            modified = " (customised)" if not a.matches_template else ""
            print_info(f"  {a.path.name}{modified}")
    else:
        print_info("Project files: none found")


def _print_remainder_report() -> None:
    """Print what remains after uninstall (external tools, package itself)."""
    console.print("\nThe following remain on your system:\n")
    console.print("  External tools (not installed by plsec):")
    console.print("    Run 'plsec doctor' to see installed tools\n")
    console.print("  To remove plsec itself:")
    console.print("    pipx uninstall plsec")
    console.print("    # or: uv tool uninstall plsec")


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def uninstall(
    global_only: Annotated[
        bool,
        typer.Option("--global", "-g", help="Remove global configs only."),
    ] = False,
    project_only: Annotated[
        bool,
        typer.Option("--project", "-p", help="Remove project-local files only."),
    ] = False,
    all_artifacts: Annotated[
        bool,
        typer.Option("--all", "-a", help="Remove everything (global + external + project)."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompts."),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", "-n", help="Show what would be removed without making changes."),
    ] = False,
) -> None:
    """
    Remove plsec artifacts from the system.

    Without flags, runs in interactive mode: discovers artifacts and
    asks which scopes to remove.  Use --global, --project, or --all
    to select a scope directly.
    """
    plsec_home = get_plsec_home()
    project_dir = Path.cwd()

    console.print("[bold]plsec uninstall[/bold] - Discovering plsec artifacts...\n")

    # Discover artifacts
    global_arts = discover_global_artifacts(plsec_home)
    external_arts = discover_external_artifacts(AGENTS)
    project_arts = discover_project_artifacts(project_dir, AGENTS)

    all_arts = global_arts + external_arts + project_arts

    if not all_arts:
        print_info("No plsec artifacts found. Nothing to remove.")
        raise typer.Exit(0)

    # Show inventory
    print_header("Discovered Artifacts")
    _print_inventory_summary(global_arts, external_arts, project_arts, plsec_home, project_dir)

    if dry_run:
        console.print("\n[yellow]Dry run -- no changes made.[/yellow]")
        if all_arts:
            console.print("\nWould remove:")
            for a in all_arts:
                console.print(f"  {a.path}")
        raise typer.Exit(0)

    # Determine what to remove based on flags or interactive prompts
    remove_global = False
    remove_external = False
    remove_project = False

    if all_artifacts:
        remove_global = True
        remove_external = True
        remove_project = True
    elif global_only:
        remove_global = True
        remove_external = True
    elif project_only:
        remove_project = True
    else:
        # Interactive mode: ask about each scope
        if global_arts or external_arts:
            if yes:
                remove_global = True
                remove_external = True
            else:
                remove_global = typer.confirm("\nRemove global configuration?", default=True)
                if remove_global and external_arts:
                    remove_external = typer.confirm("Remove external configs?", default=True)
                elif not remove_global:
                    remove_external = False

        if project_arts:
            if yes:
                remove_project = True
            else:
                remove_project = typer.confirm("Remove project files?", default=False)

    # Check if user selected nothing
    if not remove_global and not remove_external and not remove_project:
        console.print("\n[yellow]Nothing selected for removal.[/yellow]")
        raise typer.Exit(2)

    # Final confirmation (unless --yes)
    to_remove: list[Artifact] = []
    if remove_global:
        to_remove.extend(global_arts)
    if remove_external:
        to_remove.extend(external_arts)
    if remove_project:
        # Warn about customised files
        for a in project_arts:
            if not a.matches_template:
                print_warning(f"  {a.path.name} has been customised (not a plsec template)")
        to_remove.extend(project_arts)

    total_size = sum(a.size_bytes for a in to_remove)
    total_files = len([a for a in to_remove if a.path.is_file()])

    if not yes:
        confirm = typer.confirm(f"\nRemove {total_files} files ({format_size(total_size)})?")
        if not confirm:
            console.print("\n[yellow]Uninstall cancelled.[/yellow]")
            raise typer.Exit(2)

    # Execute removal
    _stop_managed_processes(plsec_home)

    # Remove shell aliases before removing global files
    if remove_global:
        remove_aliases()

    removed_count = 0
    error_count = 0

    if remove_global:
        print_header("Removing Global Configuration")
        count, errs = _remove_artifacts(global_arts)
        removed_count += count
        error_count += errs
        _remove_global_root(plsec_home)
        print_ok(f"Removed {count} global items")

    if remove_external:
        print_header("Removing External Configs")
        count, errs = _remove_artifacts(external_arts)
        removed_count += count
        error_count += errs
        if count > 0:
            print_ok(f"Removed {count} external config(s)")
        else:
            print_info("No external configs to remove")

    if remove_project:
        print_header("Removing Project Files")
        count, errs = _remove_artifacts(project_arts)
        removed_count += count
        error_count += errs
        print_ok(f"Removed {count} project file(s)")

    # Summary
    console.print(f"\nRemoved: {removed_count} items ({format_size(total_size)})")

    if error_count > 0:
        print_error(f"Failed to remove {error_count} items")
        raise typer.Exit(1)

    _print_remainder_report()

    console.print("\n[green]Uninstall complete.[/green]")
    raise typer.Exit(0)
