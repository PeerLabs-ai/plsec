"""
plsec install - Deploy global security configuration.

Installs agent configs, scanner configs, and directory structure
to ``~/.peerlabs/plsec/``.  This is the explicit global setup
command -- ``plsec init --global`` is a deprecated alias.
"""

__version__ = "0.1.0"

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

import typer

from plsec.configs.templates import PRE_COMMIT_HOOK, TRIVY_CONFIG_YAML, TRIVY_SCAN_RULES_YAML
from plsec.core.agents import AGENTS, AgentSpec, get_template, resolve_agent_ids
from plsec.core.config import get_plsec_home
from plsec.core.health import PLSEC_EXPECTED_FILES, PLSEC_SUBDIRS
from plsec.core.output import (
    console,
    print_header,
    print_ok,
    print_warning,
)

app = typer.Typer(
    help="Deploy global security configuration.",
    no_args_is_help=False,
)

Preset = Literal["minimal", "balanced", "strict", "paranoid"]

# Name of the installation metadata file.
INSTALLED_JSON = ".installed.json"


# ---------------------------------------------------------------------------
# Shared deployment logic
# ---------------------------------------------------------------------------


def _deploy_file(path: Path, content: str, *, force: bool = False) -> bool:
    """Write a file if missing or force is set.

    Returns True if the file was written, False if it was skipped.
    """
    if not path.exists() or force:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        print_ok(f"Created {path}")
        return True
    print_warning(f"Exists: {path} (use --force to overwrite)")
    return False


def deploy_global_configs(
    plsec_home: Path,
    *,
    preset: Preset = "balanced",
    agent: str = "both",
    force: bool = False,
    agents: dict[str, AgentSpec] | None = None,
) -> None:
    """Deploy the full global configuration to *plsec_home*.

    This is the shared implementation used by both ``plsec install``
    and ``plsec init``.  It creates the directory structure, agent
    configs, scanner configs, and pre-commit hook template.
    """
    if agents is None:
        agents = AGENTS

    agent_ids = resolve_agent_ids(agent)

    # Create directory structure
    for subdir in PLSEC_SUBDIRS:
        (plsec_home / subdir).mkdir(parents=True, exist_ok=True)

    # Deploy agent config templates
    for aid in agent_ids:
        spec = agents[aid]
        template = get_template(aid, preset)
        global_path = plsec_home / "configs" / spec.config_filename
        _deploy_file(global_path, template, force=force)

        # Deploy to agent's native config directory if defined
        if spec.global_config_dir is not None:
            spec.global_config_dir.mkdir(parents=True, exist_ok=True)
            native_path = spec.global_config_dir / spec.config_filename
            _deploy_file(native_path, template, force=force)

    # Deploy scanner configs
    _deploy_file(
        plsec_home / "trivy" / "trivy-secret.yaml",
        TRIVY_SCAN_RULES_YAML.lstrip("\n"),
        force=force,
    )
    _deploy_file(
        plsec_home / "trivy" / "trivy.yaml",
        TRIVY_CONFIG_YAML.lstrip("\n"),
        force=force,
    )

    # Deploy pre-commit hook template
    pre_commit_path = plsec_home / "configs" / "pre-commit"
    _deploy_file(pre_commit_path, PRE_COMMIT_HOOK.lstrip("\n"), force=force)
    if pre_commit_path.exists():
        pre_commit_path.chmod(0o755)


def write_installed_metadata(
    plsec_home: Path,
    *,
    preset: str,
    agent_ids: list[str],
    version: str,
) -> None:
    """Write ``.installed.json`` with installation metadata."""
    metadata = {
        "installed_at": datetime.now(UTC).isoformat(),
        "preset": preset,
        "agents": agent_ids,
        "version": version,
    }
    path = plsec_home / INSTALLED_JSON
    path.write_text(json.dumps(metadata, indent=2) + "\n")


def read_installed_metadata(plsec_home: Path) -> dict | None:
    """Read ``.installed.json`` if it exists.  Returns None otherwise."""
    path = plsec_home / INSTALLED_JSON
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def check_installation(plsec_home: Path) -> bool:
    """Verify that all expected files are present after installation.

    Returns True if all checks pass.
    """
    all_ok = True

    # Check subdirectories
    for subdir in PLSEC_SUBDIRS:
        if not (plsec_home / subdir).is_dir():
            print_warning(f"Missing directory: {subdir}")
            all_ok = False

    # Check expected files
    for rel_path, description in PLSEC_EXPECTED_FILES:
        if not (plsec_home / rel_path).is_file():
            print_warning(f"Missing: {description} ({rel_path})")
            all_ok = False

    if all_ok:
        print_ok("All installation checks passed")
    return all_ok


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def install(
    preset: Annotated[
        Preset,
        typer.Option(
            "--preset", "-p", help="Security preset: minimal, balanced, strict, paranoid."
        ),
    ] = "balanced",
    agent: Annotated[
        str, typer.Option("--agent", "-a", help="Agent type: claude, opencode, both.")
    ] = "both",
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Overwrite existing configuration files.")
    ] = False,
    check: Annotated[
        bool, typer.Option("--check", help="Verify installation after deployment.")
    ] = False,
) -> None:
    """
    Deploy global security configuration to ~/.peerlabs/plsec.

    Creates the directory structure, agent configs, scanner configs,
    and pre-commit hook template.  Without --force, existing files
    are preserved.
    """
    from plsec import __version__

    console.print(f"[bold]plsec install[/bold] - Deploying with preset: {preset}\n")

    plsec_home = get_plsec_home()
    print_header("Global Configuration (~/.peerlabs/plsec)")

    agent_ids = resolve_agent_ids(agent)
    deploy_global_configs(plsec_home, preset=preset, agent=agent, force=force)

    # Write installation metadata
    write_installed_metadata(
        plsec_home,
        preset=preset,
        agent_ids=agent_ids,
        version=__version__,
    )

    if check:
        console.print()
        print_header("Verification")
        check_installation(plsec_home)

    console.print("\n[green]Installation complete.[/green]")
    raise typer.Exit(0)
