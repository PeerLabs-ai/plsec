"""
plsec validate - Validate configuration files.

Checks syntax and schema of plsec.yaml, CLAUDE.md, opencode.json, etc.
"""

from pathlib import Path

import typer
import yaml

from plsec.core.config import load_config, find_config_file, PlsecConfig
from plsec.core.output import (
    console,
    print_ok,
    print_error,
    print_warning,
    print_header,
    print_summary,
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
    except Exception as e:
        return False, str(e)


def validate_plsec_config(path: Path) -> tuple[bool, str | None]:
    """Validate plsec.yaml against schema."""
    try:
        config = load_config(path)
        return True, None
    except Exception as e:
        return False, str(e)


def validate_claude_md(path: Path) -> tuple[bool, list[str]]:
    """Validate CLAUDE.md has expected sections."""
    warnings = []

    try:
        content = path.read_text()

        # Check for expected sections
        expected = ["NEVER", "ALWAYS"]
        for section in expected:
            if section not in content.upper():
                warnings.append(f"Missing '{section}' section")

        return True, warnings
    except Exception as e:
        return False, [str(e)]


def validate_opencode_json(path: Path) -> tuple[bool, list[str]]:
    """Validate opencode.json syntax and schema."""
    import json

    warnings = []

    try:
        with open(path) as f:
            data = json.load(f)

        # Check for schema reference
        if "$schema" not in data:
            warnings.append("Missing $schema field (recommended: https://opencode.ai/config.json)")

        # Check for permission section (the main security config)
        if "permission" not in data:
            warnings.append("Missing 'permission' section")
        else:
            perm = data["permission"]
            # Check for security-relevant permissions
            if isinstance(perm, dict):
                if "bash" not in perm:
                    warnings.append("No bash permission rules defined")
                if "external_directory" not in perm:
                    warnings.append("No external_directory permission (recommended: deny or ask)")

        return True, warnings
    except json.JSONDecodeError as e:
        return False, [f"Invalid JSON: {e}"]
    except Exception as e:
        return False, [str(e)]


@app.callback(invoke_without_command=True)
def validate(
    path: Path = typer.Argument(
        Path("."),
        help="Path to validate (default: current directory).",
    ),
    fix: bool = typer.Option(
        False,
        "--fix",
        "-f",
        help="Attempt to fix issues.",
    ),
) -> None:
    """
    Validate configuration files.

    Checks:
    - plsec.yaml syntax and schema
    - CLAUDE.md structure
    - opencode.json syntax
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

    # Check CLAUDE.md
    print_header("CLAUDE.md")
    claude_md = path / "CLAUDE.md"

    if claude_md.exists():
        valid, warnings = validate_claude_md(claude_md)
        if valid and not warnings:
            print_ok(f"Valid: {claude_md}")
            ok_count += 1
        elif valid and warnings:
            print_warning(f"Valid with warnings: {claude_md}")
            for w in warnings:
                console.print(f"      {w}", style="dim")
            warn_count += 1
        else:
            print_error(f"Invalid: {claude_md}")
            for w in warnings:
                console.print(f"      {w}", style="dim")
            error_count += 1
    else:
        print_warning("CLAUDE.md not found", details="Run 'plsec init' to create")
        warn_count += 1

    # Check opencode.json
    print_header("opencode.json")
    opencode_json = path / "opencode.json"

    if opencode_json.exists():
        valid, warnings = validate_opencode_json(opencode_json)
        if valid and not warnings:
            print_ok(f"Valid: {opencode_json}")
            ok_count += 1
        elif valid and warnings:
            print_warning(f"Valid with warnings: {opencode_json}")
            for w in warnings:
                console.print(f"      {w}", style="dim")
            warn_count += 1
        else:
            print_error(f"Invalid: {opencode_json}")
            for w in warnings:
                console.print(f"      {w}", style="dim")
            error_count += 1
    else:
        print_warning("opencode.json not found", details="Optional for Claude Code users")

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
        console.print("      Run: cp ~/.plsec/configs/pre-commit .git/hooks/", style="dim")
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
