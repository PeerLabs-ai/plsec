"""Tests for embedded configuration templates (configs/templates.py).

Verifies that all template constants are well-formed, non-empty,
and contain the expected structural elements.
"""

import json

import yaml

from plsec.configs.templates import (
    CLAUDE_MD_BALANCED,
    CLAUDE_MD_STRICT,
    OPENCODE_JSON_BALANCED,
    OPENCODE_JSON_STRICT,
    PLSEC_YAML_TEMPLATE,
    PRE_COMMIT_HOOK,
    TRIVY_SECRET_YAML,
)


class TestAllTemplatesNonEmpty:
    """Every template constant should be a non-empty string."""

    def test_claude_md_strict(self):
        assert isinstance(CLAUDE_MD_STRICT, str) and len(CLAUDE_MD_STRICT) > 0

    def test_claude_md_balanced(self):
        assert isinstance(CLAUDE_MD_BALANCED, str) and len(CLAUDE_MD_BALANCED) > 0

    def test_opencode_json_strict(self):
        assert isinstance(OPENCODE_JSON_STRICT, str) and len(OPENCODE_JSON_STRICT) > 0

    def test_opencode_json_balanced(self):
        assert isinstance(OPENCODE_JSON_BALANCED, str) and len(OPENCODE_JSON_BALANCED) > 0

    def test_plsec_yaml_template(self):
        assert isinstance(PLSEC_YAML_TEMPLATE, str) and len(PLSEC_YAML_TEMPLATE) > 0

    def test_trivy_secret_yaml(self):
        assert isinstance(TRIVY_SECRET_YAML, str) and len(TRIVY_SECRET_YAML) > 0

    def test_pre_commit_hook(self):
        assert isinstance(PRE_COMMIT_HOOK, str) and len(PRE_COMMIT_HOOK) > 0


class TestClaudeMdTemplates:
    """Verify CLAUDE.md templates have required security sections."""

    def test_strict_has_never_section(self):
        assert "NEVER" in CLAUDE_MD_STRICT

    def test_strict_has_always_section(self):
        assert "ALWAYS" in CLAUDE_MD_STRICT

    def test_strict_is_restricted(self):
        """Strict template should explicitly state RESTRICTED environment."""
        assert "RESTRICTED" in CLAUDE_MD_STRICT

    def test_balanced_has_never_section(self):
        assert "NEVER" in CLAUDE_MD_BALANCED

    def test_balanced_has_always_section(self):
        assert "ALWAYS" in CLAUDE_MD_BALANCED

    def test_balanced_is_not_restricted(self):
        """Balanced template should not claim RESTRICTED environment."""
        assert "RESTRICTED" not in CLAUDE_MD_BALANCED

    def test_strict_more_restrictive_than_balanced(self):
        """Strict template should be longer (more rules) than balanced."""
        assert len(CLAUDE_MD_STRICT) > len(CLAUDE_MD_BALANCED)


class TestOpencodeJsonTemplates:
    """Verify opencode.json templates are valid JSON with required fields."""

    def test_strict_is_valid_json(self):
        data = json.loads(OPENCODE_JSON_STRICT)
        assert isinstance(data, dict)

    def test_balanced_is_valid_json(self):
        data = json.loads(OPENCODE_JSON_BALANCED)
        assert isinstance(data, dict)

    def test_strict_has_schema(self):
        data = json.loads(OPENCODE_JSON_STRICT)
        assert "$schema" in data

    def test_strict_has_permission(self):
        data = json.loads(OPENCODE_JSON_STRICT)
        assert "permission" in data

    def test_balanced_has_permission(self):
        data = json.loads(OPENCODE_JSON_BALANCED)
        assert "permission" in data

    def test_strict_denies_env_files(self):
        """Strict template should deny .env file access."""
        data = json.loads(OPENCODE_JSON_STRICT)
        assert data["permission"]["read"][".env"] == "deny"

    def test_balanced_denies_env_files(self):
        """Balanced template should also deny .env file access."""
        data = json.loads(OPENCODE_JSON_BALANCED)
        assert data["permission"]["read"][".env"] == "deny"


class TestPlsecYamlTemplate:
    """Verify the plsec.yaml template has all expected placeholders."""

    def test_has_project_name_placeholder(self):
        assert "{project_name}" in PLSEC_YAML_TEMPLATE

    def test_has_project_type_placeholder(self):
        assert "{project_type}" in PLSEC_YAML_TEMPLATE

    def test_has_agent_type_placeholder(self):
        assert "{agent_type}" in PLSEC_YAML_TEMPLATE

    def test_has_proxy_mode_placeholder(self):
        assert "{proxy_mode}" in PLSEC_YAML_TEMPLATE

    def test_has_version_field(self):
        assert "version:" in PLSEC_YAML_TEMPLATE


class TestTrivySecretYaml:
    """Verify trivy-secret.yaml template is valid YAML with expected rules."""

    def test_is_valid_yaml(self):
        data = yaml.safe_load(TRIVY_SECRET_YAML)
        assert isinstance(data, dict)

    def test_has_rules(self):
        data = yaml.safe_load(TRIVY_SECRET_YAML)
        assert "rules" in data
        assert len(data["rules"]) > 0

    def test_has_expected_rule_ids(self):
        """Should include rules for common secret types."""
        data = yaml.safe_load(TRIVY_SECRET_YAML)
        rule_ids = {rule["id"] for rule in data["rules"]}
        assert "generic-api-key" in rule_ids
        assert "anthropic-api-key" in rule_ids
        assert "aws-access-key" in rule_ids


class TestPreCommitHook:
    """Verify pre-commit hook template is a valid shell script."""

    def test_has_shebang(self):
        assert PRE_COMMIT_HOOK.startswith("#!/bin/bash")

    def test_references_trivy(self):
        """Pre-commit hook should use trivy for secret scanning."""
        assert "trivy" in PRE_COMMIT_HOOK

    def test_references_plsec_dir(self):
        """Hook should reference the plsec config directory."""
        assert ".peerlabs/plsec" in PRE_COMMIT_HOOK
