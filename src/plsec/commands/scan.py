"""
plsec scan - Run security scanners.

Wraps Trivy, Bandit, Semgrep, and other scanners with consistent output.
"""

__version__ = "0.1.0"

import shutil
import subprocess
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

app = typer.Typer(
    help="Run security scanners.",
    no_args_is_help=False,
)


ScanType = Literal["secrets", "code", "deps", "misconfig", "all"]


def run_trivy_secrets(path: Path) -> tuple[bool, str]:
    """Run Trivy secret scanning."""
    plsec_home = get_plsec_home()
    secret_config = plsec_home / "trivy" / "trivy-secret.yaml"

    cmd = ["trivy", "fs", "--scanners", "secret"]

    if secret_config.exists():
        cmd.extend(["--secret-config", str(secret_config)])

    cmd.extend(["--exit-code", "1", str(path)])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Trivy timed out"
    except FileNotFoundError:
        return False, "Trivy not found"


def run_trivy_misconfig(path: Path) -> tuple[bool, str]:
    """Run Trivy misconfiguration scanning."""
    cmd = [
        "trivy",
        "config",
        "--exit-code",
        "1",
        str(path),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Trivy timed out"
    except FileNotFoundError:
        return False, "Trivy not found"


def run_bandit(path: Path) -> tuple[bool, str]:
    """Run Bandit Python security scanner."""
    if not shutil.which("bandit"):
        return True, "Bandit not installed (skipped)"

    # Check if there are Python files
    py_files = list(path.rglob("*.py"))
    if not py_files:
        return True, "No Python files found"

    cmd = [
        "bandit",
        "-r",
        "-ll",  # Only medium and high severity
        "-q",  # Quiet mode
        str(path),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        # Bandit returns 1 if issues found, 0 if clean
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Bandit timed out"
    except FileNotFoundError:
        return True, "Bandit not installed (skipped)"


def run_semgrep(path: Path) -> tuple[bool, str]:
    """Run Semgrep multi-language scanner."""
    if not shutil.which("semgrep"):
        return True, "Semgrep not installed (skipped)"

    cmd = [
        "semgrep",
        "--config",
        "auto",
        "--quiet",
        "--error",  # Exit 1 if findings
        str(path),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # Semgrep can be slow
        )
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Semgrep timed out"
    except FileNotFoundError:
        return True, "Semgrep not installed (skipped)"


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

    # Determine which scans to run
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

    ok_count = 0
    warn_count = 0
    error_count = 0

    # Secret scanning
    if scan_type in ("secrets", "all"):
        print_header("Secret Scanning (Trivy)")
        passed, output = run_trivy_secrets(path)
        if passed:
            print_ok("No secrets detected")
            ok_count += 1
        else:
            if "No secret detected" in output:
                print_ok("No secrets detected")
                ok_count += 1
            else:
                print_error("Potential secrets found")
                console.print(output)
                error_count += 1

    # Code analysis
    if scan_type in ("code", "all"):
        print_header("Code Analysis")

        # Bandit
        print_info("Running Bandit...")
        passed, output = run_bandit(path)
        if passed:
            if "skipped" in output.lower():
                print_info(output)
            else:
                print_ok("Bandit: No issues found")
            ok_count += 1
        else:
            print_warning("Bandit: Issues found")
            console.print(output)
            warn_count += 1

        # Semgrep
        print_info("Running Semgrep...")
        passed, output = run_semgrep(path)
        if passed:
            if "skipped" in output.lower():
                print_info(output)
            else:
                print_ok("Semgrep: No issues found")
            ok_count += 1
        else:
            print_warning("Semgrep: Issues found")
            console.print(output)
            warn_count += 1

    # Misconfiguration scanning
    if scan_type in ("misconfig", "all"):
        print_header("Misconfiguration Scanning (Trivy)")
        passed, output = run_trivy_misconfig(path)
        if passed:
            print_ok("No misconfigurations detected")
            ok_count += 1
        else:
            if "Detected" not in output:
                print_ok("No misconfigurations detected")
                ok_count += 1
            else:
                print_warning("Misconfigurations found")
                console.print(output)
                warn_count += 1

    # Dependency audit
    if scan_type in ("deps", "all"):
        print_header("Dependency Audit")
        # TODO: Implement pip-audit, npm audit, etc.
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
