"""
plsec doctor - Check system dependencies and configuration.

Verifies that all required tools are installed and properly configured.
Delegates health checks to core/health.py and renders results.
"""

__version__ = "0.1.0"

import typer

from plsec.core.agents import AGENTS
from plsec.core.config import find_config_file, get_plsec_home
from plsec.core.health import (
    CheckResult,
    check_agent_configs,
    check_config_file,
    check_directory_structure,
    check_runtime,
    check_scanner_configs,
    check_tools,
    count_verdicts,
    exit_code_for,
)
from plsec.core.output import (
    console,
    print_error,
    print_header,
    print_ok,
    print_status,
    print_summary,
    print_warning,
)
from plsec.core.tools import (
    OPTIONAL_TOOLS,
    REQUIRED_TOOLS,
    ToolChecker,
)

app = typer.Typer(
    help="Check system dependencies and configuration.",
    no_args_is_help=False,
)


def _render_result(result: CheckResult) -> None:
    """Render a single CheckResult using the output helpers."""
    if result.verdict == "ok":
        print_ok(result.name, details=result.detail or None)
    elif result.verdict == "warn":
        print_warning(result.name, details=result.fix_hint or result.detail or None)
    elif result.verdict == "fail":
        print_error(result.name, details=result.fix_hint or result.detail or None)
    elif result.verdict == "skip":
        print_status(result.name, "info", details=result.fix_hint or result.detail or None)


def _render_results(results: list[CheckResult]) -> None:
    """Render a batch of CheckResults."""
    for r in results:
        _render_result(r)


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

    all_results: list[CheckResult] = []
    plsec_home = get_plsec_home()

    # Directory structure
    print_header("Directory Structure")
    results = check_directory_structure(plsec_home, fix=fix)
    _render_results(results)
    all_results.extend(results)

    # Configuration file
    print_header("Configuration")
    results = check_config_file(find_config_file())
    _render_results(results)
    all_results.extend(results)

    # Agent configs
    results = check_agent_configs(plsec_home, AGENTS)
    _render_results(results)
    all_results.extend(results)

    # Scanner configs (trivy rules, pre-commit hook)
    results = check_scanner_configs(plsec_home)
    _render_results(results)
    all_results.extend(results)

    # Required tools
    print_header("Required Tools")
    checker = ToolChecker(REQUIRED_TOOLS.copy())
    checker.check_all()
    results = check_tools(checker.tools)
    _render_results(results)
    all_results.extend(results)

    # Optional tools
    if all_tools:
        print_header("Optional Tools")
        opt_checker = ToolChecker(OPTIONAL_TOOLS.copy())
        opt_checker.check_all()
        results = check_tools(opt_checker.tools)
        _render_results(results)
        all_results.extend(results)

    # Runtime
    print_header("Runtime")
    results = check_runtime()
    _render_results(results)
    all_results.extend(results)

    # Summary
    verdicts = count_verdicts(all_results)
    print_summary(
        "Health check",
        ok=verdicts["ok"],
        warnings=verdicts["warn"],
        errors=verdicts["fail"],
    )

    exit_code = exit_code_for(all_results)

    if exit_code != 0:
        console.print("\n[red]Some required dependencies are missing.[/red]")
        if install:
            console.print("\nInstallation hints:")
            for r in all_results:
                if r.verdict == "fail" and r.fix_hint:
                    console.print(f"  {r.fix_hint}")
        else:
            console.print("Run with --install to see installation hints.")
        raise typer.Exit(1)

    if verdicts["warn"] > 0:
        console.print("\n[yellow]Some optional items need attention.[/yellow]")
        if fix:
            console.print("Some issues were fixed. Re-run to verify.")
        else:
            console.print("Run with --fix to attempt fixes.")
        raise typer.Exit(0)

    console.print("\n[green]All checks passed![/green]")
    raise typer.Exit(0)
