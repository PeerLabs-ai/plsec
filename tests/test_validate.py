"""Tests for validation functions.

Covers:
- validate_yaml_syntax (commands/validate.py): checks YAML parseability
- Agent validators via AGENTS registry (core/agents.py): each AgentSpec
  carries a `validate` callable that checks the agent's config file.

These functions take a Path and return (bool, error_or_warnings).
They do not touch the console or raise SystemExit, making them
straightforward to test as pure logic.
"""

import json
from pathlib import Path

from plsec.commands.validate import validate_yaml_syntax
from plsec.core.agents import AGENTS

# Agent validators accessed through the registry.
# Both are guaranteed non-None for "claude" and "opencode".
assert AGENTS["claude"].validate is not None
assert AGENTS["opencode"].validate is not None
validate_claude_md = AGENTS["claude"].validate
validate_opencode_json = AGENTS["opencode"].validate

# -----------------------------------------------------------------------
# validate_yaml_syntax
# -----------------------------------------------------------------------


class TestValidateYamlSyntax:
    """Contract: validate_yaml_syntax(path) -> (True, None) for valid YAML,
    (False, error_message) for invalid YAML or missing file."""

    def test_valid_yaml(self, tmp_path: Path):
        """Well-formed YAML should return (True, None)."""
        path = tmp_path / "valid.yaml"
        path.write_text("key: value\nlist:\n  - one\n  - two\n")
        ok, err = validate_yaml_syntax(path)
        assert ok is True
        assert err is None

    def test_empty_yaml(self, tmp_path: Path):
        """Empty file is valid YAML (safe_load returns None)."""
        path = tmp_path / "empty.yaml"
        path.write_text("")
        ok, err = validate_yaml_syntax(path)
        assert ok is True
        assert err is None

    def test_invalid_yaml(self, tmp_path: Path):
        """Malformed YAML should return (False, error_string)."""
        path = tmp_path / "bad.yaml"
        path.write_text("key: [unclosed bracket\n")
        ok, err = validate_yaml_syntax(path)
        assert ok is False
        assert err is not None
        assert isinstance(err, str)

    def test_missing_file(self, tmp_path: Path):
        """Nonexistent file should return (False, error_string)."""
        path = tmp_path / "does_not_exist.yaml"
        ok, err = validate_yaml_syntax(path)
        assert ok is False
        assert err is not None


# -----------------------------------------------------------------------
# validate_claude_md
# -----------------------------------------------------------------------


class TestValidateClaude:
    """Contract: validate_claude_md(path) -> (True, warnings_list) when file
    is readable, (False, [error]) when file cannot be read.

    Warnings are generated when expected sections (NEVER, ALWAYS) are missing.
    """

    def test_complete_claude_md(self, tmp_path: Path):
        """CLAUDE.md with both NEVER and ALWAYS sections should pass clean."""
        path = tmp_path / "CLAUDE.md"
        path.write_text("# Rules\n\n## NEVER\n- do bad things\n\n## ALWAYS\n- do good things\n")
        ok, warnings = validate_claude_md(path)
        assert ok is True
        assert warnings == []

    def test_missing_never_section(self, tmp_path: Path):
        """Missing NEVER section should produce a warning."""
        path = tmp_path / "CLAUDE.md"
        path.write_text("# Rules\n\n## ALWAYS\n- do good things\n")
        ok, warnings = validate_claude_md(path)
        assert ok is True
        assert any("NEVER" in w for w in warnings)

    def test_missing_always_section(self, tmp_path: Path):
        """Missing ALWAYS section should produce a warning."""
        path = tmp_path / "CLAUDE.md"
        path.write_text("# Rules\n\n## NEVER\n- do bad things\n")
        ok, warnings = validate_claude_md(path)
        assert ok is True
        assert any("ALWAYS" in w for w in warnings)

    def test_missing_both_sections(self, tmp_path: Path):
        """Missing both sections should produce two warnings."""
        path = tmp_path / "CLAUDE.md"
        path.write_text("# Just a title\n\nSome generic content.\n")
        ok, warnings = validate_claude_md(path)
        assert ok is True
        assert len(warnings) == 2

    def test_missing_file(self, tmp_path: Path):
        """Nonexistent file should return (False, [error])."""
        path = tmp_path / "nonexistent.md"
        ok, warnings = validate_claude_md(path)
        assert ok is False
        assert len(warnings) == 1

    def test_case_insensitive_check(self, tmp_path: Path):
        """Section detection should be case-insensitive."""
        path = tmp_path / "CLAUDE.md"
        path.write_text("## never do this\n\n## always do that\n")
        ok, warnings = validate_claude_md(path)
        assert ok is True
        assert warnings == []


# -----------------------------------------------------------------------
# validate_opencode_json
# -----------------------------------------------------------------------


class TestValidateOpencodeJson:
    """Contract: validate_opencode_json(path) -> (True, warnings_list) for
    valid JSON, (False, [error]) for invalid JSON or missing file.

    Warnings are generated for missing $schema, permission, bash, or
    external_directory fields.
    """

    def test_complete_opencode_json(self, tmp_path: Path):
        """Fully populated opencode.json should pass with no warnings."""
        path = tmp_path / "opencode.json"
        data = {
            "$schema": "https://opencode.ai/config.json",
            "permission": {
                "bash": {"mode": "ask"},
                "external_directory": "deny",
            },
        }
        path.write_text(json.dumps(data))
        ok, warnings = validate_opencode_json(path)
        assert ok is True
        assert warnings == []

    def test_missing_schema_field(self, tmp_path: Path):
        """Missing $schema should produce a warning."""
        path = tmp_path / "opencode.json"
        data = {"permission": {"bash": {"mode": "ask"}, "external_directory": "deny"}}
        path.write_text(json.dumps(data))
        ok, warnings = validate_opencode_json(path)
        assert ok is True
        assert any("$schema" in w for w in warnings)

    def test_missing_permission_section(self, tmp_path: Path):
        """Missing permission section should produce a warning."""
        path = tmp_path / "opencode.json"
        data = {"$schema": "https://opencode.ai/config.json"}
        path.write_text(json.dumps(data))
        ok, warnings = validate_opencode_json(path)
        assert ok is True
        assert any("permission" in w for w in warnings)

    def test_missing_bash_rule(self, tmp_path: Path):
        """Permission section without bash rule should warn."""
        path = tmp_path / "opencode.json"
        data = {
            "$schema": "https://opencode.ai/config.json",
            "permission": {"external_directory": "deny"},
        }
        path.write_text(json.dumps(data))
        ok, warnings = validate_opencode_json(path)
        assert ok is True
        assert any("bash" in w for w in warnings)

    def test_missing_external_directory(self, tmp_path: Path):
        """Permission section without external_directory should warn."""
        path = tmp_path / "opencode.json"
        data = {
            "$schema": "https://opencode.ai/config.json",
            "permission": {"bash": {"mode": "ask"}},
        }
        path.write_text(json.dumps(data))
        ok, warnings = validate_opencode_json(path)
        assert ok is True
        assert any("external_directory" in w for w in warnings)

    def test_invalid_json(self, tmp_path: Path):
        """Malformed JSON should return (False, [error])."""
        path = tmp_path / "opencode.json"
        path.write_text("{invalid json content")
        ok, warnings = validate_opencode_json(path)
        assert ok is False
        assert len(warnings) == 1
        assert "Invalid JSON" in warnings[0]

    def test_missing_file(self, tmp_path: Path):
        """Nonexistent file should return (False, [error])."""
        path = tmp_path / "nonexistent.json"
        ok, warnings = validate_opencode_json(path)
        assert ok is False
        assert len(warnings) == 1
