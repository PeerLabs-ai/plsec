"""Tests for embedded configuration templates (configs/templates.py).

Verifies that all template constants are well-formed, non-empty,
and contain the expected structural elements.
"""

import json

import yaml

from plsec.configs.templates import (
    _PLSEC_DIR_PLACEHOLDER,
    CLAUDE_MD_BALANCED,
    CLAUDE_MD_STRICT,
    OPENCODE_JSON_BALANCED,
    OPENCODE_JSON_STRICT,
    PLSEC_AUDIT_SH,
    PLSEC_STATUS_SH,
    PLSEC_YAML_TEMPLATE,
    PRE_COMMIT_HOOK,
    STANDALONE_SCRIPTS,
    TRIVY_CONFIG_YAML,
    TRIVY_SCAN_RULES_YAML,
    WRAPPER_CLAUDE_SH,
    WRAPPER_OPENCODE_SH,
    WRAPPER_TEMPLATES,
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
        assert isinstance(TRIVY_SCAN_RULES_YAML, str) and len(TRIVY_SCAN_RULES_YAML) > 0

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

    def test_balanced_has_schema(self):
        data = json.loads(OPENCODE_JSON_BALANCED)
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
        data = yaml.safe_load(TRIVY_SCAN_RULES_YAML)
        assert isinstance(data, dict)

    def test_has_rules(self):
        data = yaml.safe_load(TRIVY_SCAN_RULES_YAML)
        assert "rules" in data
        assert len(data["rules"]) > 0

    def test_has_expected_rule_ids(self):
        """Should include rules for common secret types."""
        data = yaml.safe_load(TRIVY_SCAN_RULES_YAML)
        rule_ids = {rule["id"] for rule in data["rules"]}
        assert "generic-api-key" in rule_ids
        assert "anthropic-api-key" in rule_ids
        assert "aws-access-key" in rule_ids

    def test_has_openai_legacy_rule(self):
        """Must include the openai-legacy rule (was missing from Python template)."""
        data = yaml.safe_load(TRIVY_SCAN_RULES_YAML)
        rule_ids = {rule["id"] for rule in data["rules"]}
        assert "openai-legacy" in rule_ids

    def test_has_aws_secret_key_rule(self):
        """Must include the aws-secret-key rule (was missing from Python template)."""
        data = yaml.safe_load(TRIVY_SCAN_RULES_YAML)
        rule_ids = {rule["id"] for rule in data["rules"]}
        assert "aws-secret-key" in rule_ids

    def test_no_re2_incompatible_lookahead(self):
        """Must not contain (?! negative lookahead -- RE2 does not support it."""
        assert "(?!" not in TRIVY_SCAN_RULES_YAML

    def test_rule_count_matches_bootstrap(self):
        """Python template should have 9 rules, matching bootstrap template."""
        data = yaml.safe_load(TRIVY_SCAN_RULES_YAML)
        assert len(data["rules"]) == 9


class TestTrivyConfigYaml:
    """Verify trivy.yaml template is valid YAML with expected structure."""

    def test_is_valid_yaml(self):
        data = yaml.safe_load(TRIVY_CONFIG_YAML)
        assert isinstance(data, dict)

    def test_has_scan_section(self):
        data = yaml.safe_load(TRIVY_CONFIG_YAML)
        assert "scan" in data

    def test_has_secret_config_reference(self):
        data = yaml.safe_load(TRIVY_CONFIG_YAML)
        assert data["secret"]["config"] == "trivy-secret.yaml"

    def test_has_severity_levels(self):
        data = yaml.safe_load(TRIVY_CONFIG_YAML)
        assert "CRITICAL" in data["severity"]
        assert "HIGH" in data["severity"]

    def test_has_skip_dirs(self):
        """trivy.yaml must exclude third-party directories."""
        data = yaml.safe_load(TRIVY_CONFIG_YAML)
        skip_dirs = data["scan"]["skip-dirs"]
        assert ".venv" in skip_dirs
        assert "node_modules" in skip_dirs
        assert "__pycache__" in skip_dirs

    def test_skip_dirs_complete(self):
        """trivy.yaml skip-dirs should include all standard exclusions."""
        expected = [".venv", ".tox", "node_modules", "build", "dist", ".eggs", "__pycache__"]
        data = yaml.safe_load(TRIVY_CONFIG_YAML)
        assert sorted(data["scan"]["skip-dirs"]) == sorted(expected)

    def test_has_skip_files(self):
        """trivy.yaml must skip compiled bytecode files."""
        data = yaml.safe_load(TRIVY_CONFIG_YAML)
        skip_files = data["scan"]["skip-files"]
        assert "**/*.pyc" in skip_files

    def test_skip_files_complete(self):
        """trivy.yaml skip-files should include all standard exclusions."""
        expected = ["**/*.pyc"]
        data = yaml.safe_load(TRIVY_CONFIG_YAML)
        assert sorted(data["scan"]["skip-files"]) == sorted(expected)


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


# -----------------------------------------------------------------------
# Wrapper script templates
# -----------------------------------------------------------------------


class TestWrapperTemplatesNonEmpty:
    """All wrapper template constants must be non-empty strings."""

    def test_wrapper_claude_sh(self):
        assert isinstance(WRAPPER_CLAUDE_SH, str) and len(WRAPPER_CLAUDE_SH) > 0

    def test_wrapper_opencode_sh(self):
        assert isinstance(WRAPPER_OPENCODE_SH, str) and len(WRAPPER_OPENCODE_SH) > 0

    def test_plsec_audit_sh(self):
        assert isinstance(PLSEC_AUDIT_SH, str) and len(PLSEC_AUDIT_SH) > 0

    def test_plsec_status_sh(self):
        assert isinstance(PLSEC_STATUS_SH, str) and len(PLSEC_STATUS_SH) > 0


class TestWrapperClaudeSh:
    """Verify claude wrapper template has expected structural elements."""

    def test_has_shebang(self):
        assert WRAPPER_CLAUDE_SH.lstrip().startswith("#!/bin/bash")

    def test_has_plsec_dir_placeholder(self):
        assert _PLSEC_DIR_PLACEHOLDER in WRAPPER_CLAUDE_SH

    def test_has_log_function(self):
        assert "log()" in WRAPPER_CLAUDE_SH or "log () " in WRAPPER_CLAUDE_SH

    def test_has_tier1_git_info(self):
        assert "git rev-parse" in WRAPPER_CLAUDE_SH

    def test_has_tier2_shell_prefix(self):
        assert "CLAUDE_CODE_SHELL_PREFIX" in WRAPPER_CLAUDE_SH

    def test_has_preset_detection(self):
        assert "_detect_preset" in WRAPPER_CLAUDE_SH

    def test_has_session_duration(self):
        assert "SECONDS" in WRAPPER_CLAUDE_SH

    def test_executes_claude(self):
        """Wrapper must invoke the real claude binary."""
        assert 'claude "$@"' in WRAPPER_CLAUDE_SH

    def test_preserves_exit_code(self):
        assert "EXIT_CODE" in WRAPPER_CLAUDE_SH
        assert "exit $EXIT_CODE" in WRAPPER_CLAUDE_SH


class TestWrapperOpencodeSh:
    """Verify opencode wrapper template has expected structural elements."""

    def test_has_shebang(self):
        assert WRAPPER_OPENCODE_SH.lstrip().startswith("#!/bin/bash")

    def test_has_plsec_dir_placeholder(self):
        assert _PLSEC_DIR_PLACEHOLDER in WRAPPER_OPENCODE_SH

    def test_has_tier1_git_info(self):
        assert "git rev-parse" in WRAPPER_OPENCODE_SH

    def test_does_not_have_shell_prefix(self):
        """OpenCode does not support CLAUDE_CODE_SHELL_PREFIX."""
        assert "CLAUDE_CODE_SHELL_PREFIX" not in WRAPPER_OPENCODE_SH

    def test_copies_opencode_json(self):
        assert "opencode.json" in WRAPPER_OPENCODE_SH

    def test_copies_claude_md_too(self):
        """OpenCode also reads CLAUDE.md for system prompts."""
        assert "CLAUDE.md" in WRAPPER_OPENCODE_SH

    def test_executes_opencode(self):
        assert 'opencode "$@"' in WRAPPER_OPENCODE_SH

    def test_preserves_exit_code(self):
        assert "EXIT_CODE" in WRAPPER_OPENCODE_SH
        assert "exit $EXIT_CODE" in WRAPPER_OPENCODE_SH


class TestPlsecAuditSh:
    """Verify audit script template has expected structural elements."""

    def test_has_shebang(self):
        assert PLSEC_AUDIT_SH.lstrip().startswith("#!/bin/bash")

    def test_has_plsec_dir_placeholder(self):
        assert _PLSEC_DIR_PLACEHOLDER in PLSEC_AUDIT_SH

    def test_uses_exec(self):
        """Audit script must use exec to preserve exit codes."""
        assert 'exec "$@"' in PLSEC_AUDIT_SH

    def test_fire_and_forget_logging(self):
        """Log failures must not block command execution."""
        assert "2>/dev/null" in PLSEC_AUDIT_SH


class TestPlsecStatusSh:
    """Verify status script template has expected structural elements."""

    def test_has_shebang(self):
        assert PLSEC_STATUS_SH.lstrip().startswith("#!/bin/bash")

    def test_has_plsec_dir_placeholder(self):
        assert _PLSEC_DIR_PLACEHOLDER in PLSEC_STATUS_SH

    def test_has_help_flag(self):
        assert "--help" in PLSEC_STATUS_SH

    def test_has_json_mode(self):
        assert "--json" in PLSEC_STATUS_SH
        assert "print_json" in PLSEC_STATUS_SH

    def test_has_quiet_mode(self):
        assert "--quiet" in PLSEC_STATUS_SH

    def test_has_check_functions(self):
        """Status script must have health check functions."""
        assert "check_plsec_dir" in PLSEC_STATUS_SH
        assert "check_agent_config" in PLSEC_STATUS_SH
        assert "check_tool" in PLSEC_STATUS_SH
        assert "check_log_freshness" in PLSEC_STATUS_SH

    def test_has_verdict_helpers(self):
        """Status script must have verdict computation logic."""
        assert "compute_overall" in PLSEC_STATUS_SH
        assert "format_verdict" in PLSEC_STATUS_SH

    def test_has_json_escape(self):
        """Status script must have JSON escaping for safe output."""
        assert "json_escape" in PLSEC_STATUS_SH

    def test_has_source_guard(self):
        """Status script must have source guard to allow unit testing."""
        assert 'if [[ "${BASH_SOURCE[0]}" == "${0}" ]]' in PLSEC_STATUS_SH

    def test_has_exit_codes(self):
        """Status script must exit 0 for ok, 1 for fail."""
        assert "exit 0" in PLSEC_STATUS_SH
        assert "exit 1" in PLSEC_STATUS_SH


class TestWrapperRegistries:
    """Verify WRAPPER_TEMPLATES and STANDALONE_SCRIPTS are consistent."""

    def test_wrapper_templates_has_both_agents(self):
        assert "wrapper-claude.sh" in WRAPPER_TEMPLATES
        assert "wrapper-opencode.sh" in WRAPPER_TEMPLATES

    def test_wrapper_templates_values_are_nonempty(self):
        for name, content in WRAPPER_TEMPLATES.items():
            assert len(content) > 0, f"Empty content for {name}"

    def test_standalone_scripts_has_audit(self):
        names = [name for name, _ in STANDALONE_SCRIPTS]
        assert "plsec-audit.sh" in names

    def test_standalone_scripts_has_status(self):
        names = [name for name, _ in STANDALONE_SCRIPTS]
        assert "plsec-status.sh" in names

    def test_all_templates_have_placeholder(self):
        """All wrapper templates must use @@PLSEC_DIR@@ placeholder."""
        for name, content in WRAPPER_TEMPLATES.items():
            assert _PLSEC_DIR_PLACEHOLDER in content, f"Missing placeholder in {name}"
        for name, content in STANDALONE_SCRIPTS:
            assert _PLSEC_DIR_PLACEHOLDER in content, f"Missing placeholder in {name}"
