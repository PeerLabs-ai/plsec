"""
plsec CLI - Main entry point.

Usage:
    plsec <command> [options]

Commands:
    create      Create a new project with security configuration
    secure      Add security configuration to an existing project
    doctor      Check system dependencies and configuration
    init        Initialize security configuration for a project
    install     Deploy global security configuration
    reset       Factory reset global security configuration
    uninstall   Remove plsec artifacts from the system
    scan        Run security scanners
    proxy       Manage Pipelock runtime proxy
    validate    Validate configuration files
    integrity   Workspace integrity monitoring
"""

import typer
from rich.console import Console

from plsec import __version__
from plsec.commands import (
    create,
    doctor,
    init,
    install,
    integrity,
    proxy,
    reset,
    scan,
    secure,
    uninstall,
    validate,
)

# Create main app
app = typer.Typer(
    name="plsec",
    help="Tools to help with mitigating AI coding assistant security risks.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

# Register subcommands
app.add_typer(create.app, name="create")
app.add_typer(secure.app, name="secure")
app.add_typer(doctor.app, name="doctor")
app.add_typer(init.app, name="init")
app.add_typer(install.app, name="install")
app.add_typer(reset.app, name="reset")
app.add_typer(scan.app, name="scan")
app.add_typer(uninstall.app, name="uninstall")
app.add_typer(validate.app, name="validate")
app.add_typer(proxy.app, name="proxy")
app.add_typer(integrity.app, name="integrity")

# Console for rich output
console = Console()


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"plsec version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose output.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Quiet mode (errors only).",
    ),
    config: str = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to plsec.yaml config file.",
    ),
) -> None:
    """plsec - Tools to help with mititgating AI coding assistant security risks.

    Provides defense-in-depth security for Claude Code, Opencode, and other AI
    coding assistants through static analysis, configuration management,
    runtime monitoring, and audit logging.

    """
    # Global options stored for subcommands via typer state
    _ = verbose, quiet, config  # consumed by subcommands via typer context


if __name__ == "__main__":
    app()
