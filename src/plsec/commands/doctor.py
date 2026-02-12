"""
plsec doctor - Check system dependencies and configuration.

Verifies that all required tools are installed and properly configured.
"""

import sys
from pathlib import Path

import typer
from rich.table import Table

from plsec.core.config import get_plsec_home, find_config_file
from plsec.core.tools import (
    ToolChecker,
    ToolStatus,
    REQUIRED_TOOLS,
    OPTIONAL_TOOLS,
)
from plsec.core.output import (
    console,
    print_status,
    print_header,
    print_summary,
    print_ok,
    print_error,
    print_warning,
)

app = typer.Typer(
    help="Check system dependencies and configuration.",
    no_args_is_help=False,
)


@app.callback(invoke_without_command=True)
def doctor(
    install: bool = typer.Option(
        False,
        "--install",
        "-i",
        help="Offer to install missing dependencies.",
    ),
    fix: bool = typer.Option(
        False,
        "--fix",
        "-f",
        help="Attempt to fix configuration issues.",
    ),
    all_tools: bool = typer.Option(
        False,
        "--all",
        "-a",
        help="Check optional tools as well.",
    ),
) -> None:
    """
    Check system dependencies and configuration.

    Verifies:
    - Required tools (Trivy, etc.) are installed
    - Optional tools (Pipelock, Podman) if requested
    - Configuration files are present and valid
    - plsec home directory is set up
    """
    console.print("[bold]plsec doctor[/bold] - System health check\n")

    ok_count = 0
    warn_count = 0
    error_count = 0

    # Check plsec home directory
    print_header("Directory Structure")
    plsec_home = get_plsec_home()

    if plsec_home.exists():
        print_ok(f"plsec home: {plsec_home}")
        ok_count += 1
    else:
        print_warning(f"plsec home not found: {plsec_home}")
        warn_count += 1

    # Check subdirectories
    subdirs = ["configs", "logs", "manifests", "trivy"]
    for subdir in subdirs:
        path = plsec_home / subdir
        if path.exists():
            print_ok(f"  {subdir}/", details=str(path))
            ok_count += 1
        else:
            if fix:
                path.mkdir(parents=True, exist_ok=True)
                print_ok(f"  {subdir}/ (created)", details=str(path))
                ok_count += 1
            else:
                print_warning(f"  {subdir}/ missing", details=f"Run with --fix to create")
                warn_count += 1

    # Check for configuration file
    print_header("Configuration")
    config_file = find_config_file()

    if config_file:
        print_ok(f"Config file: {config_file}")
        ok_count += 1
    else:
        print_status("No plsec.yaml found", "info", details="Run 'plsec init' to create one")

    # Check for agent configs
    claude_md = plsec_home / "configs" / "CLAUDE.md"
    opencode_json = plsec_home / "configs" / "opencode.json"

    if claude_md.exists():
        print_ok(f"CLAUDE.md template: {claude_md}")
        ok_count += 1
    else:
        print_warning("CLAUDE.md template missing", details="Run 'plsec init' to create")
        warn_count += 1

    if opencode_json.exists():
        print_ok(f"opencode.json template: {opencode_json}")
        ok_count += 1
    else:
        print_warning("opencode.json template missing", details="Run 'plsec init' to create")
        warn_count += 1

    # Check required tools
    print_header("Required Tools")
    checker = ToolChecker(REQUIRED_TOOLS.copy())
    checker.check_all()

    for tool in checker.tools:
        if tool.status == ToolStatus.OK:
            version_info = f"v{tool.version}" if tool.version else ""
            print_ok(f"{tool.name} {version_info}", details=tool.path)
            ok_count += 1
        elif tool.status == ToolStatus.MISSING:
            if tool.required:
                print_error(f"{tool.name} not found", details=tool.install_hint)
                error_count += 1
            else:
                print_warning(f"{tool.name} not found (optional)", details=tool.install_hint)
                warn_count += 1
        elif tool.status == ToolStatus.OUTDATED:
            print_warning(
                f"{tool.name} v{tool.version} (outdated)",
                details=f"Minimum: v{tool.min_version}",
            )
            warn_count += 1
        else:
            print_error(f"{tool.name}: {tool.error}")
            error_count += 1

    # Check optional tools if requested
    if all_tools:
        print_header("Optional Tools")
        opt_checker = ToolChecker(OPTIONAL_TOOLS.copy())
        opt_checker.check_all()

        for tool in opt_checker.tools:
            if tool.status == ToolStatus.OK:
                version_info = f"v{tool.version}" if tool.version else ""
                print_ok(f"{tool.name} {version_info}", details=tool.path)
                ok_count += 1
            elif tool.status == ToolStatus.MISSING:
                print_status(
                    f"{tool.name} not installed",
                    "skip",
                    details=tool.install_hint,
                )
            else:
                print_warning(f"{tool.name}: {tool.error}")
                warn_count += 1

    # Check Python version
    print_header("Runtime")
    py_version = sys.version_info
    if py_version >= (3, 12):
        print_ok(f"Python {py_version.major}.{py_version.minor}.{py_version.micro}")
        ok_count += 1
    else:
        print_error(
            f"Python {py_version.major}.{py_version.minor} (requires 3.12+)"
        )
        error_count += 1

    # Summary
    print_summary("Health check", ok=ok_count, warnings=warn_count, errors=error_count)

    if error_count > 0:
        console.print("\n[red]Some required dependencies are missing.[/red]")
        if install:
            console.print("\nInstallation hints:")
            for tool in checker.get_missing():
                console.print(f"  {tool.install_hint}")
        else:
            console.print("Run with --install to see installation hints.")
        raise typer.Exit(1)

    if warn_count > 0:
        console.print("\n[yellow]Some optional items need attention.[/yellow]")
        if fix:
            console.print("Some issues were fixed. Re-run to verify.")
        else:
            console.print("Run with --fix to attempt fixes.")
        raise typer.Exit(0)

    console.print("\n[green]All checks passed![/green]")
    raise typer.Exit(0)
