"""
plsec init - Initialize security configuration for a project.

Sets up CLAUDE.md, opencode.json, plsec.yaml, and related configs.
"""

from pathlib import Path
from typing import Literal

import typer

from plsec.core.config import (
    PlsecConfig,
    ProjectConfig,
    AgentConfig,
    LayersConfig,
    StaticLayerConfig,
    IsolationLayerConfig,
    ProxyLayerConfig,
    AuditLayerConfig,
    save_config,
    get_plsec_home,
)
from plsec.core.output import (
    console,
    print_ok,
    print_warning,
    print_info,
    print_header,
)
from plsec.configs.templates import (
    CLAUDE_MD_STRICT,
    CLAUDE_MD_BALANCED,
    OPENCODE_JSON_STRICT,
    OPENCODE_JSON_BALANCED,
)

app = typer.Typer(
    help="Initialize security configuration for a project.",
    no_args_is_help=False,
)


Preset = Literal["minimal", "balanced", "strict", "paranoid"]
AgentType = Literal["claude", "opencode", "both"]


def detect_project_type(path: Path) -> str:
    """Detect project type from files present."""
    if (path / "pyproject.toml").exists() or (path / "setup.py").exists():
        return "python"
    if (path / "package.json").exists():
        return "node"
    if (path / "go.mod").exists():
        return "go"
    if (path / "Cargo.toml").exists():
        return "rust"
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
    preset: Preset = typer.Option(
        "balanced",
        "--preset",
        "-p",
        help="Security preset: minimal, balanced, strict, paranoid.",
    ),
    agent: AgentType = typer.Option(
        "both",
        "--agent",
        "-a",
        help="Agent type: claude, opencode, both.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing configuration files.",
    ),
    global_only: bool = typer.Option(
        False,
        "--global",
        "-g",
        help="Only set up global configs in ~/.plsec.",
    ),
    with_pipelock: bool = typer.Option(
        False,
        "--with-pipelock",
        help="Include Pipelock proxy configuration.",
    ),
) -> None:
    """
    Initialize security configuration for a project.

    Creates CLAUDE.md, opencode.json, plsec.yaml, and sets up
    the ~/.plsec directory structure.

    Presets:
    - minimal: Secret scanning only
    - balanced: Full static analysis, audit logging
    - strict: Add container isolation and Pipelock proxy
    - paranoid: Strict mode with network isolation
    """
    console.print(f"[bold]plsec init[/bold] - Initializing with preset: {preset}\n")

    cwd = Path.cwd()
    plsec_home = get_plsec_home()
    is_strict = preset in ("strict", "paranoid")

    # Determine which templates to use
    claude_md = CLAUDE_MD_STRICT if is_strict else CLAUDE_MD_BALANCED
    opencode_json = OPENCODE_JSON_STRICT if is_strict else OPENCODE_JSON_BALANCED

    # Set up global configs
    print_header("Global Configuration (~/.plsec)")

    # Create directory structure
    for subdir in ["configs", "logs", "manifests", "trivy", "trivy/policies"]:
        (plsec_home / subdir).mkdir(parents=True, exist_ok=True)

    # Write global CLAUDE.md template
    if agent in ("claude", "both"):
        claude_path = plsec_home / "configs" / "CLAUDE.md"
        if not claude_path.exists() or force:
            claude_path.write_text(claude_md)
            print_ok(f"Created {claude_path}")
        else:
            print_warning(f"Exists: {claude_path} (use --force to overwrite)")

    # Write global opencode.json template
    if agent in ("opencode", "both"):
        opencode_path = plsec_home / "configs" / "opencode.json"
        if not opencode_path.exists() or force:
            opencode_path.write_text(opencode_json)
            print_ok(f"Created {opencode_path}")
        else:
            print_warning(f"Exists: {opencode_path} (use --force to overwrite)")

        # Also install to ~/.config/opencode/
        opencode_global = Path.home() / ".config" / "opencode"
        opencode_global.mkdir(parents=True, exist_ok=True)
        opencode_global_config = opencode_global / "opencode.json"
        if not opencode_global_config.exists() or force:
            opencode_global_config.write_text(opencode_json)
            print_ok(f"Created {opencode_global_config}")
        else:
            print_warning(f"Exists: {opencode_global_config}")

    if global_only:
        console.print("\n[green]Global configuration complete.[/green]")
        raise typer.Exit(0)

    # Set up project configs
    print_header(f"Project Configuration ({cwd})")

    # Detect project type
    project_type = detect_project_type(cwd)
    print_info(f"Detected project type: {project_type}")

    # Write project CLAUDE.md
    if agent in ("claude", "both"):
        project_claude = cwd / "CLAUDE.md"
        if not project_claude.exists() or force:
            project_claude.write_text(claude_md)
            print_ok(f"Created {project_claude}")
        else:
            print_warning(f"Exists: {project_claude}")

    # Write project opencode.json
    if agent in ("opencode", "both"):
        project_opencode = cwd / "opencode.json"
        if not project_opencode.exists() or force:
            project_opencode.write_text(opencode_json)
            print_ok(f"Created {project_opencode}")
        else:
            print_warning(f"Exists: {project_opencode}")

    # Create plsec.yaml
    project_config = cwd / "plsec.yaml"
    if not project_config.exists() or force:
        config = PlsecConfig(
            project=ProjectConfig(
                name=cwd.name,
                type=project_type,
            ),
            agent=AgentConfig(
                type="claude-code" if agent == "claude" else "opencode",
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
