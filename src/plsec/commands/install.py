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

from plsec.configs.templates import (
    _PLSEC_DIR_PLACEHOLDER,
    PRE_COMMIT_HOOK,
    STANDALONE_SCRIPTS,
    TRIVY_CONFIG_YAML,
    TRIVY_SCAN_RULES_YAML,
    WRAPPER_TEMPLATES,
)
from plsec.core.agents import AGENTS, AgentSpec, get_template, resolve_agent_ids
from plsec.core.config import get_plsec_home
from plsec.core.health import PLSEC_EXPECTED_FILES, PLSEC_EXPECTED_SCRIPTS, PLSEC_SUBDIRS
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


def _deploy_script(
    path: Path,
    content: str,
    plsec_dir: str,
    *,
    force: bool = False,
) -> bool:
    """Write an executable script with PLSEC_DIR substitution.

    Replaces ``@@PLSEC_DIR@@`` in *content* with *plsec_dir*, writes
    the file, and sets it executable (0o755).

    Returns True if the file was written, False if skipped.
    """
    resolved = content.replace(_PLSEC_DIR_PLACEHOLDER, plsec_dir)
    written = _deploy_file(path, resolved, force=force)
    if written or path.exists():
        path.chmod(0o755)
    return written


# ---------------------------------------------------------------------------
# Shell alias injection / removal
# ---------------------------------------------------------------------------

# Markers that delimit the alias block in shell RC files.
ALIAS_BLOCK_START = "# --- plsec aliases (do not edit) ---"
ALIAS_BLOCK_END = "# --- end plsec aliases ---"

# Legacy marker from bootstrap.sh (used for detection only).
_LEGACY_ALIAS_MARKER = "# Peerlabs Security aliases"


def _detect_shell_rc(home: Path | None = None) -> Path:
    """Detect the user's shell RC file.

    Priority: ~/.zshrc > ~/.bashrc > ~/.profile (created if needed).
    """
    if home is None:
        home = Path.home()
    for name in (".zshrc", ".bashrc"):
        candidate = home / name
        if candidate.exists():
            return candidate
    return home / ".profile"


def _build_alias_block(
    plsec_home: Path,
    agent_ids: list[str],
    agents: dict[str, AgentSpec],
) -> str:
    """Build the alias block string with start/end markers."""
    lines = [ALIAS_BLOCK_START]
    lines.append(f'alias plsec-logs="tail -f {plsec_home}/logs/*.log"')

    for aid in sorted(agent_ids):
        spec = agents[aid]
        if spec.wrapper_template:
            lines.append(f'alias {spec.id}-safe="{plsec_home}/{spec.id}-wrapper.sh"')

    lines.append(ALIAS_BLOCK_END)
    return "\n".join(lines) + "\n"


def _has_alias_block(rc_content: str) -> bool:
    """Check whether the RC file already contains a plsec alias block."""
    return ALIAS_BLOCK_START in rc_content or _LEGACY_ALIAS_MARKER in rc_content


def _remove_alias_block(rc_content: str) -> str:
    """Remove the plsec alias block (and legacy block) from RC content.

    Returns the content with the block stripped.  Preserves all other
    content, including blank lines outside the block.
    """
    lines = rc_content.splitlines(keepends=True)
    result: list[str] = []
    in_modern_block = False
    in_legacy_block = False

    for line in lines:
        stripped = line.rstrip("\n\r")

        # Modern delimited block: start/end markers
        if stripped == ALIAS_BLOCK_START:
            in_modern_block = True
            continue
        if stripped == ALIAS_BLOCK_END:
            in_modern_block = False
            continue
        if in_modern_block:
            continue

        # Legacy block: starts at marker, ends at first non-alias blank line
        if stripped == _LEGACY_ALIAS_MARKER:
            in_legacy_block = True
            continue
        if in_legacy_block:
            if stripped.startswith("alias "):
                continue
            if stripped == "":
                # Blank line terminates the legacy block
                in_legacy_block = False
                continue
            # Non-alias, non-blank line: legacy block ended, keep this line
            in_legacy_block = False

        result.append(line)

    return "".join(result)


def inject_aliases(
    plsec_home: Path,
    agent_ids: list[str],
    agents: dict[str, AgentSpec],
    *,
    force: bool = False,
    rc_path: Path | None = None,
) -> Path | None:
    """Inject plsec aliases into the user's shell RC file.

    If *force* is True, the existing alias block is replaced.
    If *rc_path* is given, it overrides auto-detection.

    Returns the RC path that was modified, or None if skipped.
    """
    if rc_path is None:
        rc_path = _detect_shell_rc()

    block = _build_alias_block(plsec_home, agent_ids, agents)

    if rc_path.exists():
        existing = rc_path.read_text()
    else:
        existing = ""

    if _has_alias_block(existing):
        if not force:
            print_warning(f"Aliases already in {rc_path} (use --force to update)")
            return None
        # Replace existing block
        cleaned = _remove_alias_block(existing)
        rc_path.write_text(cleaned + block)
        print_ok(f"Updated aliases in {rc_path}")
    else:
        rc_path.write_text(existing + block)
        print_ok(f"Added aliases to {rc_path}")

    return rc_path


def remove_aliases(rc_path: Path | None = None) -> bool:
    """Remove plsec aliases from the shell RC file.

    Returns True if aliases were found and removed.
    """
    if rc_path is None:
        rc_path = _detect_shell_rc()

    if not rc_path.exists():
        return False

    content = rc_path.read_text()
    if not _has_alias_block(content):
        return False

    cleaned = _remove_alias_block(content)
    rc_path.write_text(cleaned)
    print_ok(f"Removed plsec aliases from {rc_path}")
    return True


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

    # Deploy wrapper scripts (per-agent)
    plsec_dir_str = str(plsec_home)
    for aid in agent_ids:
        spec = agents[aid]
        if spec.wrapper_template and spec.wrapper_template in WRAPPER_TEMPLATES:
            wrapper_content = WRAPPER_TEMPLATES[spec.wrapper_template]
            wrapper_path = plsec_home / f"{spec.id}-wrapper.sh"
            _deploy_script(
                wrapper_path,
                wrapper_content.lstrip("\n"),
                plsec_dir_str,
                force=force,
            )

    # Deploy standalone scripts (not agent-specific)
    for filename, content in STANDALONE_SCRIPTS:
        _deploy_script(
            plsec_home / filename,
            content.lstrip("\n"),
            plsec_dir_str,
            force=force,
        )


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
    import os

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

    # Check expected executable scripts
    for rel_path, description in PLSEC_EXPECTED_SCRIPTS:
        full_path = plsec_home / rel_path
        if not full_path.is_file():
            print_warning(f"Missing: {description} ({rel_path})")
            all_ok = False
        elif not os.access(full_path, os.X_OK):
            print_warning(f"Not executable: {description} ({rel_path})")
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
    no_aliases: Annotated[
        bool, typer.Option("--no-aliases", help="Skip shell alias injection.")
    ] = False,
) -> None:
    """
    Deploy global security configuration to ~/.peerlabs/plsec.

    Creates the directory structure, agent configs, scanner configs,
    wrapper scripts, and pre-commit hook template.  Injects shell
    aliases (claude-safe, opencode-safe, plsec-logs) into the shell
    RC file unless --no-aliases is given.  Without --force, existing
    files are preserved.
    """
    from plsec import __version__

    console.print(f"[bold]plsec install[/bold] - Deploying with preset: {preset}\n")

    plsec_home = get_plsec_home()
    print_header("Global Configuration (~/.peerlabs/plsec)")

    agent_ids = resolve_agent_ids(agent)
    deploy_global_configs(plsec_home, preset=preset, agent=agent, force=force)

    # Inject shell aliases
    if not no_aliases:
        print_header("Shell Aliases")
        rc = inject_aliases(plsec_home, agent_ids, AGENTS, force=force)
        if rc:
            print_warning(f"Run 'source {rc}' or restart terminal to use aliases")

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
