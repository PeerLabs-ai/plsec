"""
plsec scan - Run security scanners.

Wraps Trivy, Bandit, Semgrep, and other scanners with consistent output.
Delegates to the SCANNERS registry in core/scanners.py.
"""

__version__ = "0.1.0"

from pathlib import Path
from typing import Annotated, Literal

import typer

from plsec.core.config import get_plsec_home
from plsec.core.output import (
    console,
    print_error,
    print_header,
    print_info,
    print_ok,
    print_summary,
    print_warning,
)
from plsec.core.scanners import SCANNERS, run_scanner

app = typer.Typer(
    help="Run security scanners.",
    no_args_is_help=False,
)


ScanType = Literal["secrets", "code", "deps", "misconfig", "all"]


@app.callback(invoke_without_command=True)
def scan(
    path: Annotated[Path, typer.Argument(help="Path to scan (default: current directory).")] = Path(
        "."
    ),
    scan_type: Annotated[
        ScanType,
        typer.Option("--type", "-t", help="Type of scan: secrets, code, deps, misconfig, all."),
    ] = "all",
    secrets: Annotated[
        bool, typer.Option("--secrets", "-s", help="Run secret scanning only.")
    ] = False,
    code: Annotated[
        bool, typer.Option("--code", "-c", help="Run code analysis only (Bandit, Semgrep).")
    ] = False,
    deps: Annotated[bool, typer.Option("--deps", "-d", help="Run dependency audit only.")] = False,
    misconfig: Annotated[
        bool, typer.Option("--misconfig", "-m", help="Run misconfiguration scanning only.")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Output results as JSON.")] = False,
) -> None:
    """
    Run security scanners on the specified path.

    By default, runs all applicable scanners. Use flags to run specific scans.
    """
    console.print(f"[bold]plsec scan[/bold] - Scanning {path}\n")

    # Determine which scan types to run
    if secrets:
        scan_type = "secrets"
    elif code:
        scan_type = "code"
    elif deps:
        scan_type = "deps"
    elif misconfig:
        scan_type = "misconfig"

    path = path.resolve()
    if not path.exists():
        print_error(f"Path not found: {path}")
        raise typer.Exit(1)

    plsec_home = get_plsec_home()
    ok_count = 0
    warn_count = 0
    error_count = 0

    # Group scanners by scan_type for section headers
    current_section: str | None = None

    for _sid, spec in SCANNERS.items():
        # Filter by requested scan type
        if scan_type != "all" and spec.scan_type != scan_type:
            continue

        # Print section header on type change
        if spec.scan_type != current_section:
            current_section = spec.scan_type
            section_titles = {
                "secrets": "Secret Scanning",
                "code": "Code Analysis",
                "misconfig": "Misconfiguration Scanning",
            }
            print_header(section_titles.get(current_section, current_section.title()))

        # Run the scanner
        print_info(f"Running {spec.display_name}...")
        passed, message = run_scanner(spec, path, plsec_home)

        if passed:
            if "skipped" in message.lower() or "not installed" in message.lower():
                print_info(message)
            else:
                print_ok(f"{spec.display_name}: {message}")
            ok_count += 1
        else:
            # Secrets are errors; code/misconfig are warnings
            if spec.scan_type == "secrets":
                print_error(f"{spec.display_name}: Potential issues found")
                console.print(message)
                error_count += 1
            else:
                print_warning(f"{spec.display_name}: Issues found")
                console.print(message)
                warn_count += 1

    # Dependency audit (not yet backed by a scanner registry entry)
    if scan_type in ("deps", "all"):
        print_header("Dependency Audit")
        print_info("Dependency audit not yet implemented")

    # Summary
    print_summary("Scan complete", ok=ok_count, warnings=warn_count, errors=error_count)

    if error_count > 0:
        console.print("\n[red]Critical issues found. Review and fix before committing.[/red]")
        raise typer.Exit(1)

    if warn_count > 0:
        console.print("\n[yellow]Warnings found. Review before committing.[/yellow]")
        raise typer.Exit(0)

    console.print("\n[green]All scans passed![/green]")
    raise typer.Exit(0)
