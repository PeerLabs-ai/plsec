"""
plsec validate - Validate configuration files.

Checks syntax and schema of plsec.yaml, agent configs, pre-commit hooks.
"""

__version__ = "0.1.0"

from pathlib import Path
from typing import Annotated

import typer
import yaml

from plsec.core.agents import AGENTS
from plsec.core.config import find_config_file, load_config
from plsec.core.output import (
    console,
    print_error,
    print_header,
    print_ok,
    print_summary,
    print_warning,
)

app = typer.Typer(
    help="Validate configuration files.",
    no_args_is_help=False,
)


def validate_yaml_syntax(path: Path) -> tuple[bool, str | None]:
    """Check if a file has valid YAML syntax."""
    try:
        with open(path) as f:
            yaml.safe_load(f)
        return True, None
    except yaml.YAMLError as e:
        return False, str(e)
    except OSError as e:
        return False, str(e)


def validate_plsec_config(path: Path) -> tuple[bool, str | None]:
    """Validate plsec.yaml against schema."""
    try:
        load_config(path)
        return True, None
    except (ValueError, OSError, yaml.YAMLError) as e:
        return False, str(e)


@app.callback(invoke_without_command=True)
def validate(
    path: Annotated[
        Path, typer.Argument(help="Path to validate (default: current directory).")
    ] = Path("."),
    fix: Annotated[bool, typer.Option("--fix", "-f", help="Attempt to fix issues.")] = False,
) -> None:
    """
    Validate configuration files.

    Checks:
    - plsec.yaml syntax and schema
    - Agent config files (CLAUDE.md, opencode.json, etc.)
    - Pre-commit hooks installation
    """
    console.print("[bold]plsec validate[/bold] - Configuration validation\n")

    path = path.resolve()
    ok_count = 0
    warn_count = 0
    error_count = 0

    # Check plsec.yaml
    print_header("plsec.yaml")
    config_file = find_config_file()

    if config_file:
        valid, error = validate_plsec_config(config_file)
        if valid:
            print_ok(f"Valid: {config_file}")
            ok_count += 1
        else:
            print_error(f"Invalid: {config_file}", details=error)
            error_count += 1
    else:
        print_warning("No plsec.yaml found", details="Run 'plsec init' to create")
        warn_count += 1

    # Check agent config files via registry
    for _aid, spec in AGENTS.items():
        print_header(spec.config_filename)
        config_path = path / spec.config_filename

        if config_path.exists():
            if spec.validate is not None:
                valid, warnings = spec.validate(config_path)
                if valid and not warnings:
                    print_ok(f"Valid: {config_path}")
                    ok_count += 1
                elif valid and warnings:
                    print_warning(f"Valid with warnings: {config_path}")
                    for w in warnings:
                        console.print(f"      {w}", style="dim")
                    warn_count += 1
                else:
                    print_error(f"Invalid: {config_path}")
                    for w in warnings:
                        console.print(f"      {w}", style="dim")
                    error_count += 1
            else:
                print_ok(f"Found: {config_path} (no validator available)")
                ok_count += 1
        else:
            print_warning(
                f"{spec.config_filename} not found",
                details="Run 'plsec init' to create",
            )
            warn_count += 1

    # Check pre-commit hook
    print_header("Pre-commit Hook")
    git_dir = path / ".git"
    pre_commit = git_dir / "hooks" / "pre-commit"

    if not git_dir.exists():
        print_warning("Not a git repository")
    elif pre_commit.exists():
        print_ok(f"Installed: {pre_commit}")
        ok_count += 1
    else:
        print_warning("Pre-commit hook not installed")
        console.print("      Run: cp ~/.peerlabs/plsec/configs/pre-commit .git/hooks/", style="dim")
        warn_count += 1

    # Summary
    print_summary("Validation", ok=ok_count, warnings=warn_count, errors=error_count)

    if error_count > 0:
        console.print("\n[red]Configuration errors found.[/red]")
        raise typer.Exit(1)

    if warn_count > 0:
        console.print("\n[yellow]Configuration warnings. Review recommended.[/yellow]")
        raise typer.Exit(0)

    console.print("\n[green]All configurations valid![/green]")
    raise typer.Exit(0)
