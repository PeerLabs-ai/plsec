"""
plsec init - Initialize security configuration for a project.

Sets up CLAUDE.md, opencode.json, plsec.yaml, and related configs.
"""

__version__ = "0.1.0"

from pathlib import Path
from typing import Annotated, Literal

import typer

from plsec.core.agents import AGENTS, get_template, resolve_agent_ids
from plsec.core.config import (
    AgentConfig,
    AuditLayerConfig,
    IsolationLayerConfig,
    LayersConfig,
    PlsecConfig,
    ProjectConfig,
    ProxyLayerConfig,
    StaticLayerConfig,
    get_plsec_home,
    save_config,
)
from plsec.core.output import (
    console,
    print_header,
    print_info,
    print_ok,
    print_warning,
)

app = typer.Typer(
    help="Initialize security configuration for a project.",
    no_args_is_help=False,
)


Preset = Literal["minimal", "balanced", "strict", "paranoid"]

ProjectType = Literal["python", "node", "go", "mixed"]


def detect_project_type(path: Path) -> ProjectType:
    """Detect project type from files present."""
    if (path / "pyproject.toml").exists() or (path / "setup.py").exists():
        return "python"
    if (path / "package.json").exists():
        return "node"
    if (path / "go.mod").exists():
        return "go"
    # Rust and other types fall back to "mixed" for now
    return "mixed"


def get_preset_config(preset: Preset) -> LayersConfig:
    """Get layer configuration for a preset."""
    if preset == "minimal":
        return LayersConfig(
            static=StaticLayerConfig(
                enabled=True,
                scanners=["trivy-secrets"],
            ),
            isolation=IsolationLayerConfig(enabled=False),
            proxy=ProxyLayerConfig(enabled=False),
            audit=AuditLayerConfig(enabled=True, integrity=False),
        )
    elif preset == "balanced":
        return LayersConfig(
            static=StaticLayerConfig(enabled=True),
            isolation=IsolationLayerConfig(enabled=False),
            proxy=ProxyLayerConfig(enabled=False),
            audit=AuditLayerConfig(enabled=True),
        )
    elif preset == "strict":
        return LayersConfig(
            static=StaticLayerConfig(enabled=True),
            isolation=IsolationLayerConfig(enabled=True, runtime="podman"),
            proxy=ProxyLayerConfig(enabled=True, mode="balanced"),
            audit=AuditLayerConfig(enabled=True, integrity=True),
        )
    else:  # paranoid
        return LayersConfig(
            static=StaticLayerConfig(enabled=True),
            isolation=IsolationLayerConfig(enabled=True, runtime="podman"),
            proxy=ProxyLayerConfig(enabled=True, mode="strict"),
            audit=AuditLayerConfig(enabled=True, integrity=True),
        )


@app.callback(invoke_without_command=True)
def init(
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
    global_only: Annotated[
        bool,
        typer.Option("--global", "-g", help="Only set up global configs in ~/.peerlabs/plsec."),
    ] = False,
    with_pipelock: Annotated[
        bool, typer.Option("--with-pipelock", help="Include Pipelock proxy configuration.")
    ] = False,
) -> None:
    """
    Initialize security configuration for a project.

    Creates CLAUDE.md, opencode.json, plsec.yaml, and sets up
    the ~/.peerlabs/plsec directory structure.

    Presets:
    - minimal: Secret scanning only
    - balanced: Full static analysis, audit logging
    - strict: Add container isolation and Pipelock proxy
    - paranoid: Strict mode with network isolation
    """
    console.print(f"[bold]plsec init[/bold] - Initializing with preset: {preset}\n")

    agent_ids = resolve_agent_ids(agent)
    cwd = Path.cwd()
    plsec_home = get_plsec_home()

    # Set up global configs
    print_header("Global Configuration (~/.peerlabs/plsec)")

    # Create directory structure
    for subdir in ["configs", "logs", "manifests", "trivy", "trivy/policies"]:
        (plsec_home / subdir).mkdir(parents=True, exist_ok=True)

    # Write global agent config templates
    for aid in agent_ids:
        spec = AGENTS[aid]
        template = get_template(aid, preset)
        global_path = plsec_home / "configs" / spec.config_filename
        if not global_path.exists() or force:
            global_path.write_text(template)
            print_ok(f"Created {global_path}")
        else:
            print_warning(f"Exists: {global_path} (use --force to overwrite)")

        # Install to agent's global config dir if one is defined
        if spec.global_config_dir is not None:
            spec.global_config_dir.mkdir(parents=True, exist_ok=True)
            global_config = spec.global_config_dir / spec.config_filename
            if not global_config.exists() or force:
                global_config.write_text(template)
                print_ok(f"Created {global_config}")
            else:
                print_warning(f"Exists: {global_config}")

    if global_only:
        console.print("\n[green]Global configuration complete.[/green]")
        raise typer.Exit(0)

    # Set up project configs
    print_header(f"Project Configuration ({cwd})")

    # Detect project type
    project_type = detect_project_type(cwd)
    print_info(f"Detected project type: {project_type}")

    # Write project agent configs
    for aid in agent_ids:
        spec = AGENTS[aid]
        template = get_template(aid, preset)
        project_path = cwd / spec.config_filename
        if not project_path.exists() or force:
            project_path.write_text(template)
            print_ok(f"Created {project_path}")
        else:
            print_warning(f"Exists: {project_path}")

    # Create plsec.yaml -- use the first agent's config_type
    first_spec = AGENTS[agent_ids[0]]
    project_config = cwd / "plsec.yaml"
    if not project_config.exists() or force:
        config = PlsecConfig(
            project=ProjectConfig(
                name=cwd.name,
                type=project_type,
            ),
            agent=AgentConfig(
                type=first_spec.config_type,
            ),
            layers=get_preset_config(preset),
        )

        # Enable pipelock if requested
        if with_pipelock:
            config.layers.proxy.enabled = True

        save_config(config, project_config)
        print_ok(f"Created {project_config}")
    else:
        print_warning(f"Exists: {project_config}")

    # Summary
    console.print("\n[green]Initialization complete.[/green]")
    console.print("\nNext steps:")
    console.print("  1. Review generated configuration files")
    console.print("  2. Run 'plsec doctor' to verify dependencies")
    console.print("  3. Run 'plsec scan' to check for issues")

    if preset in ("strict", "paranoid"):
        console.print("  4. Run 'plsec proxy start' to start Pipelock")

    raise typer.Exit(0)
