"""Agent registry -- single source of truth for AI coding agent metadata.

Each agent plsec manages is declared as an AgentSpec.  Commands iterate
the AGENTS registry rather than hardcoding per-agent logic.

Adding a new agent: create template strings in configs/templates.py,
optionally add a validator, then add one AgentSpec entry to AGENTS.
"""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from plsec.configs.templates import (
    CLAUDE_MD_BALANCED,
    CLAUDE_MD_STRICT,
    OPENCODE_JSON_BALANCED,
    OPENCODE_JSON_STRICT,
)


@dataclass
class AgentSpec:
    """Everything plsec needs to know about an AI coding agent."""

    # Short identifier used in CLI and config (e.g., "claude", "opencode")
    id: str
    # Human-readable name (e.g., "Claude Code", "OpenCode")
    display_name: str
    # Config file this agent expects in the project root (e.g., "CLAUDE.md")
    config_filename: str
    # Map from security mode ("strict", "balanced") to template content
    templates: dict[str, str]
    # Agent type value used in plsec.yaml serialization (e.g., "claude-code")
    config_type: str
    # Validation function: takes file path, returns (ok, list of warnings).
    # None if no validator exists yet.
    validate: Callable[[Path], tuple[bool, list[str]]] | None = None
    # Additional global install location (e.g., ~/.config/opencode/), or None
    global_config_dir: Path | None = None
    # Bootstrap wrapper script template name (e.g., "wrapper-claude.sh"), or None
    wrapper_template: str | None = None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

# Validators are imported lazily to avoid circular imports between
# core/ and commands/.  The validate.py functions have signature:
#   (Path) -> tuple[bool, list[str]]
# We wire them up here with late imports inside thin wrappers.


def _validate_claude_md(path: Path) -> tuple[bool, list[str]]:
    """Validate CLAUDE.md by delegating to commands.validate."""
    from plsec.commands.validate import validate_claude_md

    return validate_claude_md(path)


def _validate_opencode_json(path: Path) -> tuple[bool, list[str]]:
    """Validate opencode.json by delegating to commands.validate."""
    from plsec.commands.validate import validate_opencode_json

    return validate_opencode_json(path)


AGENTS: dict[str, AgentSpec] = {
    "claude": AgentSpec(
        id="claude",
        display_name="Claude Code",
        config_filename="CLAUDE.md",
        templates={
            "strict": CLAUDE_MD_STRICT,
            "balanced": CLAUDE_MD_BALANCED,
        },
        config_type="claude-code",
        validate=_validate_claude_md,
        global_config_dir=None,
        wrapper_template="wrapper-claude.sh",
    ),
    "opencode": AgentSpec(
        id="opencode",
        display_name="OpenCode",
        config_filename="opencode.json",
        templates={
            "strict": OPENCODE_JSON_STRICT,
            "balanced": OPENCODE_JSON_BALANCED,
        },
        config_type="opencode",
        validate=_validate_opencode_json,
        global_config_dir=Path.home() / ".config" / "opencode",
        wrapper_template="wrapper-opencode.sh",
    ),
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def is_strict(preset: str) -> bool:
    """Whether a preset uses strict security mode."""
    return preset in ("strict", "paranoid")


def security_mode(preset: str) -> str:
    """Map a preset name to its security mode key ("strict" or "balanced")."""
    return "strict" if is_strict(preset) else "balanced"


def get_template(agent_id: str, preset: str) -> str:
    """Get template content for an agent at a given preset level.

    The preset is mapped to a security mode: "strict" and "paranoid"
    map to "strict"; "minimal" and "balanced" map to "balanced".

    Raises KeyError if agent_id is not in the registry.
    """
    spec = AGENTS[agent_id]
    return spec.templates[security_mode(preset)]


def resolve_agent_ids(agent_arg: str) -> list[str]:
    """Expand the CLI --agent argument to a list of agent IDs.

    "both" and "all" expand to all registered agent IDs.
    A single agent ID is returned as a one-element list.

    Raises ValueError if the agent ID is not recognized.
    """
    if agent_arg in ("both", "all"):
        return list(AGENTS.keys())

    if agent_arg not in AGENTS:
        valid = ", ".join(sorted(AGENTS.keys()))
        msg = f"Unknown agent: {agent_arg!r}. Valid agents: {valid}, both, all"
        raise ValueError(msg)

    return [agent_arg]
