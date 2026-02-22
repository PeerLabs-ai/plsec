"""Tests for the agent registry module (core/agents.py).

Covers:
- AgentSpec dataclass structure and field completeness
- AGENTS registry integrity (keys, required fields, template presence)
- is_strict() preset classification
- security_mode() preset-to-mode mapping
- get_template() template retrieval and error cases
- resolve_agent_ids() expansion and validation

Validator function tests (_validate_claude_md, _validate_opencode_json) are
in test_validate.py. This file focuses on registry structure and helper
functions.
"""

import pytest

from plsec.core.agents import (
    AGENTS,
    AgentSpec,
    get_template,
    is_strict,
    resolve_agent_ids,
    security_mode,
)

# -----------------------------------------------------------------------
# AgentSpec and AGENTS registry
# -----------------------------------------------------------------------


class TestAgentSpec:
    """Contract: AgentSpec holds all metadata needed to manage an agent.
    The AGENTS dict maps agent IDs to complete specs."""

    def test_registry_has_claude(self):
        """Claude agent must be in the registry."""
        assert "claude" in AGENTS

    def test_registry_has_opencode(self):
        """OpenCode agent must be in the registry."""
        assert "opencode" in AGENTS

    def test_registry_keys_match_spec_ids(self):
        """Registry keys must match the spec's id field."""
        for key, spec in AGENTS.items():
            assert key == spec.id, f"Key {key!r} != spec.id {spec.id!r}"

    def test_all_specs_have_display_name(self):
        """Every spec must have a non-empty display_name."""
        for spec in AGENTS.values():
            assert spec.display_name, f"Agent {spec.id!r} missing display_name"

    def test_all_specs_have_config_filename(self):
        """Every spec must have a non-empty config_filename."""
        for spec in AGENTS.values():
            assert spec.config_filename, f"Agent {spec.id!r} missing config_filename"

    def test_all_specs_have_config_type(self):
        """Every spec must have a config_type for YAML serialization."""
        for spec in AGENTS.values():
            assert spec.config_type, f"Agent {spec.id!r} missing config_type"

    def test_all_specs_have_templates(self):
        """Every spec must have both strict and balanced templates."""
        for spec in AGENTS.values():
            assert "strict" in spec.templates, f"Agent {spec.id!r} missing strict template"
            assert "balanced" in spec.templates, f"Agent {spec.id!r} missing balanced template"

    def test_all_templates_are_non_empty(self):
        """Template content must not be empty."""
        for spec in AGENTS.values():
            for mode, content in spec.templates.items():
                assert content, f"Agent {spec.id!r} has empty {mode} template"

    def test_claude_specific_fields(self):
        """Claude spec has expected field values."""
        spec = AGENTS["claude"]
        assert spec.display_name == "Claude Code"
        assert spec.config_filename == "CLAUDE.md"
        assert spec.config_type == "claude-code"
        assert spec.validate is not None
        assert spec.global_config_dir is None
        assert spec.wrapper_template == "wrapper-claude.sh"

    def test_opencode_specific_fields(self):
        """OpenCode spec has expected field values."""
        spec = AGENTS["opencode"]
        assert spec.display_name == "OpenCode"
        assert spec.config_filename == "opencode.json"
        assert spec.config_type == "opencode"
        assert spec.validate is not None
        assert spec.global_config_dir is not None
        assert spec.wrapper_template == "wrapper-opencode.sh"

    def test_dataclass_creation(self):
        """AgentSpec can be created with minimal required fields."""
        spec = AgentSpec(
            id="test",
            display_name="Test Agent",
            config_filename="test.yaml",
            templates={"strict": "s", "balanced": "b"},
            config_type="test-agent",
        )
        assert spec.id == "test"
        assert spec.validate is None
        assert spec.global_config_dir is None
        assert spec.wrapper_template is None


# -----------------------------------------------------------------------
# is_strict
# -----------------------------------------------------------------------


class TestIsStrict:
    """Contract: is_strict(preset) returns True for 'strict' and 'paranoid',
    False for everything else."""

    def test_strict_preset(self):
        assert is_strict("strict") is True

    def test_paranoid_preset(self):
        assert is_strict("paranoid") is True

    def test_balanced_preset(self):
        assert is_strict("balanced") is False

    def test_minimal_preset(self):
        assert is_strict("minimal") is False

    def test_unknown_preset(self):
        """Unknown presets are treated as non-strict."""
        assert is_strict("custom") is False

    def test_empty_string(self):
        assert is_strict("") is False


# -----------------------------------------------------------------------
# security_mode
# -----------------------------------------------------------------------


class TestSecurityMode:
    """Contract: security_mode(preset) returns 'strict' for strict/paranoid
    presets, 'balanced' for all others."""

    def test_strict_mode(self):
        assert security_mode("strict") == "strict"

    def test_paranoid_mode(self):
        assert security_mode("paranoid") == "strict"

    def test_balanced_mode(self):
        assert security_mode("balanced") == "balanced"

    def test_minimal_mode(self):
        assert security_mode("minimal") == "balanced"

    def test_unknown_mode(self):
        """Unknown presets default to balanced."""
        assert security_mode("whatever") == "balanced"


# -----------------------------------------------------------------------
# get_template
# -----------------------------------------------------------------------


class TestGetTemplate:
    """Contract: get_template(agent_id, preset) returns template content
    for the agent at the given preset's security mode. Raises KeyError
    for unknown agents."""

    def test_claude_balanced(self):
        """Claude balanced template should be non-empty string."""
        content = get_template("claude", "balanced")
        assert isinstance(content, str)
        assert len(content) > 0

    def test_claude_strict(self):
        """Claude strict template should be non-empty string."""
        content = get_template("claude", "strict")
        assert isinstance(content, str)
        assert len(content) > 0

    def test_opencode_balanced(self):
        content = get_template("opencode", "balanced")
        assert isinstance(content, str)
        assert len(content) > 0

    def test_opencode_strict(self):
        content = get_template("opencode", "strict")
        assert isinstance(content, str)
        assert len(content) > 0

    def test_paranoid_maps_to_strict(self):
        """Paranoid preset should return the same as strict."""
        assert get_template("claude", "paranoid") == get_template("claude", "strict")

    def test_minimal_maps_to_balanced(self):
        """Minimal preset should return the same as balanced."""
        assert get_template("claude", "minimal") == get_template("claude", "balanced")

    def test_unknown_agent_raises_key_error(self):
        """Unknown agent ID should raise KeyError."""
        with pytest.raises(KeyError):
            get_template("nonexistent", "balanced")

    def test_strict_differs_from_balanced(self):
        """Strict and balanced templates should differ for each agent."""
        for spec in AGENTS.values():
            strict = get_template(spec.id, "strict")
            balanced = get_template(spec.id, "balanced")
            assert strict != balanced, f"Agent {spec.id!r} has identical strict/balanced templates"


# -----------------------------------------------------------------------
# resolve_agent_ids
# -----------------------------------------------------------------------


class TestResolveAgentIds:
    """Contract: resolve_agent_ids(agent_arg) expands 'both'/'all' to all
    agent IDs, returns a single-element list for valid agents, and raises
    ValueError for unknown agents."""

    def test_single_agent_claude(self):
        assert resolve_agent_ids("claude") == ["claude"]

    def test_single_agent_opencode(self):
        assert resolve_agent_ids("opencode") == ["opencode"]

    def test_both_expands_to_all(self):
        """'both' should expand to all registered agent IDs."""
        result = resolve_agent_ids("both")
        assert set(result) == set(AGENTS.keys())

    def test_all_expands_to_all(self):
        """'all' should expand to all registered agent IDs."""
        result = resolve_agent_ids("all")
        assert set(result) == set(AGENTS.keys())

    def test_both_and_all_are_equivalent(self):
        """'both' and 'all' should return the same result."""
        assert resolve_agent_ids("both") == resolve_agent_ids("all")

    def test_unknown_agent_raises_value_error(self):
        """Unknown agent ID should raise ValueError."""
        with pytest.raises(ValueError, match="Unknown agent"):
            resolve_agent_ids("gemini")

    def test_error_message_lists_valid_agents(self):
        """Error message should list valid agent names."""
        with pytest.raises(ValueError, match="claude") as exc_info:
            resolve_agent_ids("nonexistent")
        assert "opencode" in str(exc_info.value)

    def test_returns_list_type(self):
        """Result should always be a list."""
        result = resolve_agent_ids("claude")
        assert isinstance(result, list)

    def test_both_preserves_registry_order(self):
        """'both' should preserve the order of AGENTS.keys()."""
        result = resolve_agent_ids("both")
        assert result == list(AGENTS.keys())
