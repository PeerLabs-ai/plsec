"""Tests for plsec install command (commands/install.py).

Covers the shared deployment functions (_deploy_file, _deploy_script,
deploy_global_configs, write_installed_metadata, read_installed_metadata,
check_installation), shell alias injection/removal functions, and the
install CLI command via CliRunner with monkeypatched paths.
"""

import json
import os
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from plsec.commands.install import (
    ALIAS_BLOCK_END,
    ALIAS_BLOCK_START,
    INSTALLED_JSON,
    _build_alias_block,
    _deploy_file,
    _deploy_script,
    _detect_shell_rc,
    _has_alias_block,
    _remove_alias_block,
    app,
    check_installation,
    deploy_global_configs,
    inject_aliases,
    read_installed_metadata,
    remove_aliases,
    write_installed_metadata,
)
from plsec.configs.templates import _PLSEC_DIR_PLACEHOLDER
from plsec.core.agents import AGENTS
from plsec.core.health import PLSEC_SUBDIRS

runner = CliRunner()


# -----------------------------------------------------------------------
# _deploy_file
# -----------------------------------------------------------------------


class TestDeployFile:
    """Contract: _deploy_file writes content to path, respecting
    force flag and existing files."""

    def test_creates_file_when_missing(self, tmp_path: Path):
        target = tmp_path / "test.yaml"
        result = _deploy_file(target, "content\n")
        assert target.read_text() == "content\n"
        assert result is True

    def test_creates_parent_directories(self, tmp_path: Path):
        target = tmp_path / "nested" / "dir" / "test.yaml"
        result = _deploy_file(target, "content\n")
        assert target.read_text() == "content\n"
        assert result is True

    def test_does_not_overwrite_without_force(self, tmp_path: Path):
        target = tmp_path / "test.yaml"
        target.write_text("original\n")
        result = _deploy_file(target, "new content\n")
        assert target.read_text() == "original\n"
        assert result is False

    def test_overwrites_with_force(self, tmp_path: Path):
        target = tmp_path / "test.yaml"
        target.write_text("original\n")
        result = _deploy_file(target, "new content\n", force=True)
        assert target.read_text() == "new content\n"
        assert result is True


# -----------------------------------------------------------------------
# deploy_global_configs
# -----------------------------------------------------------------------


class TestDeployGlobalConfigs:
    """Contract: deploy_global_configs creates the full directory
    structure, agent configs, scanner configs, and pre-commit hook."""

    def test_creates_all_subdirectories(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agents=AGENTS)
        for subdir in PLSEC_SUBDIRS:
            assert (plsec_home / subdir).is_dir(), f"Missing subdir: {subdir}"

    def test_deploys_agent_configs_for_both(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agent="both", agents=AGENTS)
        for spec in AGENTS.values():
            config_path = plsec_home / "configs" / spec.config_filename
            assert config_path.exists(), f"Missing agent config: {spec.config_filename}"

    def test_deploys_only_claude_when_requested(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agent="claude", agents=AGENTS)
        assert (plsec_home / "configs" / "CLAUDE.md").exists()
        assert not (plsec_home / "configs" / "opencode.json").exists()

    def test_deploys_scanner_configs(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agents=AGENTS)
        assert (plsec_home / "trivy" / "trivy-secret.yaml").exists()
        assert (plsec_home / "trivy" / "trivy.yaml").exists()

    def test_deploys_pre_commit_hook(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agents=AGENTS)
        hook = plsec_home / "configs" / "pre-commit"
        assert hook.exists()
        assert hook.stat().st_mode & 0o111  # executable

    def test_idempotent_without_force(self, tmp_path: Path):
        """Running deploy twice without force preserves original files."""
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agents=AGENTS)
        # Write a marker into an existing file
        marker_file = plsec_home / "trivy" / "trivy-secret.yaml"
        marker_file.write_text("custom content\n")
        # Second deploy without force should preserve the marker
        deploy_global_configs(plsec_home, agents=AGENTS)
        assert marker_file.read_text() == "custom content\n"

    def test_force_overwrites_existing(self, tmp_path: Path):
        """Running deploy with force replaces all files."""
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agents=AGENTS)
        # Write a marker into an existing file
        marker_file = plsec_home / "trivy" / "trivy-secret.yaml"
        marker_file.write_text("custom content\n")
        # Second deploy with force should overwrite the marker
        deploy_global_configs(plsec_home, force=True, agents=AGENTS)
        assert marker_file.read_text() != "custom content\n"

    def test_strict_preset_uses_strict_templates(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, preset="strict", agents=AGENTS)
        claude_md = plsec_home / "configs" / "CLAUDE.md"
        content = claude_md.read_text()
        # Strict templates contain "NEVER" sections with more restrictions
        assert "NEVER" in content


# -----------------------------------------------------------------------
# write_installed_metadata / read_installed_metadata
# -----------------------------------------------------------------------


class TestInstalledMetadata:
    """Contract: write/read_installed_metadata manage .installed.json
    as a JSON file with installation details."""

    def test_write_creates_metadata_file(self, tmp_path: Path):
        write_installed_metadata(
            tmp_path, preset="balanced", agent_ids=["claude", "opencode"], version="0.1.0"
        )
        path = tmp_path / INSTALLED_JSON
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["preset"] == "balanced"
        assert data["agents"] == ["claude", "opencode"]
        assert data["version"] == "0.1.0"
        assert "installed_at" in data

    def test_read_returns_metadata(self, tmp_path: Path):
        write_installed_metadata(tmp_path, preset="strict", agent_ids=["claude"], version="0.2.0")
        data = read_installed_metadata(tmp_path)
        assert data is not None
        assert data["preset"] == "strict"
        assert data["agents"] == ["claude"]
        assert data["version"] == "0.2.0"

    def test_read_returns_none_when_missing(self, tmp_path: Path):
        assert read_installed_metadata(tmp_path) is None

    def test_read_returns_none_for_invalid_json(self, tmp_path: Path):
        (tmp_path / INSTALLED_JSON).write_text("not json{{{")
        assert read_installed_metadata(tmp_path) is None

    def test_write_overwrites_previous(self, tmp_path: Path):
        write_installed_metadata(tmp_path, preset="minimal", agent_ids=["claude"], version="0.1.0")
        write_installed_metadata(
            tmp_path, preset="strict", agent_ids=["claude", "opencode"], version="0.2.0"
        )
        data = read_installed_metadata(tmp_path)
        assert data is not None
        assert data["preset"] == "strict"
        assert data["version"] == "0.2.0"


# -----------------------------------------------------------------------
# check_installation
# -----------------------------------------------------------------------


class TestCheckInstallation:
    """Contract: check_installation verifies subdirectories and expected
    files exist, returning True when all checks pass."""

    def test_returns_true_after_deploy(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agents=AGENTS)
        assert check_installation(plsec_home) is True

    def test_returns_false_when_empty(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        plsec_home.mkdir(parents=True)
        assert check_installation(plsec_home) is False

    def test_returns_false_when_file_missing(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agents=AGENTS)
        # Remove one expected file
        (plsec_home / "trivy" / "trivy-secret.yaml").unlink()
        assert check_installation(plsec_home) is False


# -----------------------------------------------------------------------
# plsec install CLI command
# -----------------------------------------------------------------------


class TestInstallCLI:
    """Contract: the plsec install CLI command deploys global configs
    and writes .installed.json metadata."""

    def test_install_exits_zero(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        with patch("plsec.commands.install.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, [])
        assert result.exit_code == 0

    def test_install_creates_configs(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        with patch("plsec.commands.install.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, [])
        assert result.exit_code == 0
        assert (plsec_home / "trivy" / "trivy-secret.yaml").exists()
        assert (plsec_home / "trivy" / "trivy.yaml").exists()
        assert (plsec_home / "configs" / "pre-commit").exists()

    def test_install_writes_installed_json(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        with patch("plsec.commands.install.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, [])
        assert result.exit_code == 0
        metadata = read_installed_metadata(plsec_home)
        assert metadata is not None
        assert metadata["preset"] == "balanced"
        assert "claude" in metadata["agents"]
        assert "opencode" in metadata["agents"]

    def test_install_with_preset(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        with patch("plsec.commands.install.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--preset", "strict"])
        assert result.exit_code == 0
        metadata = read_installed_metadata(plsec_home)
        assert metadata is not None
        assert metadata["preset"] == "strict"

    def test_install_with_agent_flag(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        with patch("plsec.commands.install.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--agent", "claude"])
        assert result.exit_code == 0
        assert (plsec_home / "configs" / "CLAUDE.md").exists()
        assert not (plsec_home / "configs" / "opencode.json").exists()
        metadata = read_installed_metadata(plsec_home)
        assert metadata is not None
        assert metadata["agents"] == ["claude"]

    def test_install_with_force(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        # First install
        with patch("plsec.commands.install.get_plsec_home", return_value=plsec_home):
            runner.invoke(app, [])
        # Write marker
        marker = plsec_home / "trivy" / "trivy-secret.yaml"
        marker.write_text("stale\n")
        # Force reinstall
        with patch("plsec.commands.install.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--force"])
        assert result.exit_code == 0
        assert marker.read_text() != "stale\n"

    def test_install_with_check(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        with patch("plsec.commands.install.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--check"])
        assert result.exit_code == 0
        assert "Verification" in result.output or "checks passed" in result.output

    def test_install_shows_preset_in_output(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        with patch("plsec.commands.install.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--preset", "paranoid"])
        assert result.exit_code == 0
        assert "paranoid" in result.output

    def test_install_idempotent_metadata_update(self, tmp_path: Path):
        """Running install twice updates .installed.json each time."""
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        with patch("plsec.commands.install.get_plsec_home", return_value=plsec_home):
            runner.invoke(app, ["--preset", "minimal"])
        first = read_installed_metadata(plsec_home)
        with patch("plsec.commands.install.get_plsec_home", return_value=plsec_home):
            runner.invoke(app, ["--preset", "strict"])
        second = read_installed_metadata(plsec_home)
        assert first is not None
        assert second is not None
        assert first["preset"] == "minimal"
        assert second["preset"] == "strict"

    def test_install_with_no_aliases(self, tmp_path: Path):
        """--no-aliases skips shell RC file modification."""
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        home = tmp_path / "home"
        home.mkdir()
        zshrc = home / ".zshrc"
        zshrc.write_text("")
        with (
            patch("plsec.commands.install.get_plsec_home", return_value=plsec_home),
            patch("plsec.commands.install._detect_shell_rc", return_value=zshrc),
        ):
            result = runner.invoke(app, ["--no-aliases"])
        assert result.exit_code == 0
        assert zshrc.read_text() == ""


# -----------------------------------------------------------------------
# _deploy_script
# -----------------------------------------------------------------------


class TestDeployScript:
    """Contract: _deploy_script writes executable content with
    @@PLSEC_DIR@@ substitution and 0o755 permissions."""

    def test_substitutes_plsec_dir(self, tmp_path: Path):
        target = tmp_path / "wrapper.sh"
        content = f'PLSEC_DIR="{_PLSEC_DIR_PLACEHOLDER}"\necho test'
        _deploy_script(target, content, "/opt/plsec")
        result = target.read_text()
        assert _PLSEC_DIR_PLACEHOLDER not in result
        assert 'PLSEC_DIR="/opt/plsec"' in result

    def test_sets_executable_permission(self, tmp_path: Path):
        target = tmp_path / "wrapper.sh"
        _deploy_script(target, "#!/bin/bash", "/opt/plsec")
        assert os.access(target, os.X_OK)

    def test_respects_force_flag(self, tmp_path: Path):
        target = tmp_path / "wrapper.sh"
        target.write_text("original")
        _deploy_script(target, "#!/bin/bash", "/opt/plsec")
        assert target.read_text() == "original"

    def test_overwrites_with_force(self, tmp_path: Path):
        target = tmp_path / "wrapper.sh"
        target.write_text("original")
        _deploy_script(target, "#!/bin/bash\nnew", "/opt/plsec", force=True)
        assert target.read_text() == "#!/bin/bash\nnew"


# -----------------------------------------------------------------------
# deploy_global_configs -- wrapper scripts
# -----------------------------------------------------------------------


class TestDeployGlobalConfigsWrappers:
    """Contract: deploy_global_configs deploys wrapper scripts and the
    audit script with @@PLSEC_DIR@@ substituted and executable perms."""

    def test_deploys_both_wrapper_scripts(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agents=AGENTS)
        assert (plsec_home / "claude-wrapper.sh").exists()
        assert (plsec_home / "opencode-wrapper.sh").exists()

    def test_deploys_audit_script(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agents=AGENTS)
        assert (plsec_home / "plsec-audit.sh").exists()

    def test_wrappers_are_executable(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agents=AGENTS)
        for script in ("claude-wrapper.sh", "opencode-wrapper.sh", "plsec-audit.sh"):
            assert os.access(plsec_home / script, os.X_OK), f"{script} not executable"

    def test_plsec_dir_substituted(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agents=AGENTS)
        content = (plsec_home / "claude-wrapper.sh").read_text()
        assert _PLSEC_DIR_PLACEHOLDER not in content
        assert str(plsec_home) in content

    def test_only_claude_wrapper_when_agent_is_claude(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agent="claude", agents=AGENTS)
        assert (plsec_home / "claude-wrapper.sh").exists()
        assert not (plsec_home / "opencode-wrapper.sh").exists()

    def test_only_opencode_wrapper_when_agent_is_opencode(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agent="opencode", agents=AGENTS)
        assert not (plsec_home / "claude-wrapper.sh").exists()
        assert (plsec_home / "opencode-wrapper.sh").exists()

    def test_audit_script_always_deployed(self, tmp_path: Path):
        """plsec-audit.sh is a standalone script, deployed regardless of agent."""
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agent="opencode", agents=AGENTS)
        assert (plsec_home / "plsec-audit.sh").exists()

    def test_check_installation_passes_with_wrappers(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agents=AGENTS)
        assert check_installation(plsec_home) is True


# -----------------------------------------------------------------------
# _detect_shell_rc
# -----------------------------------------------------------------------


class TestDetectShellRc:
    """Contract: _detect_shell_rc returns the most appropriate shell
    RC file, prioritising .zshrc > .bashrc > .profile."""

    def test_prefers_zshrc(self, tmp_path: Path):
        (tmp_path / ".zshrc").write_text("")
        (tmp_path / ".bashrc").write_text("")
        assert _detect_shell_rc(tmp_path) == tmp_path / ".zshrc"

    def test_falls_back_to_bashrc(self, tmp_path: Path):
        (tmp_path / ".bashrc").write_text("")
        assert _detect_shell_rc(tmp_path) == tmp_path / ".bashrc"

    def test_falls_back_to_profile(self, tmp_path: Path):
        assert _detect_shell_rc(tmp_path) == tmp_path / ".profile"

    def test_default_uses_home(self):
        """Without explicit home, uses Path.home()."""
        rc = _detect_shell_rc()
        assert rc.parent == Path.home()


# -----------------------------------------------------------------------
# _build_alias_block
# -----------------------------------------------------------------------


class TestBuildAliasBlock:
    """Contract: _build_alias_block creates a delimited alias block
    with correct aliases for the given agents."""

    def test_block_has_start_end_markers(self, tmp_path: Path):
        block = _build_alias_block(tmp_path, ["claude"], AGENTS)
        assert block.startswith(ALIAS_BLOCK_START)
        assert ALIAS_BLOCK_END in block

    def test_block_has_plsec_logs_alias(self, tmp_path: Path):
        block = _build_alias_block(tmp_path, ["claude"], AGENTS)
        assert "plsec-logs" in block

    def test_block_has_claude_safe_alias(self, tmp_path: Path):
        block = _build_alias_block(tmp_path, ["claude"], AGENTS)
        assert "claude-safe" in block
        assert "claude-wrapper.sh" in block

    def test_block_has_opencode_safe_alias(self, tmp_path: Path):
        block = _build_alias_block(tmp_path, ["opencode"], AGENTS)
        assert "opencode-safe" in block
        assert "opencode-wrapper.sh" in block

    def test_both_agents_produce_both_aliases(self, tmp_path: Path):
        block = _build_alias_block(tmp_path, ["claude", "opencode"], AGENTS)
        assert "claude-safe" in block
        assert "opencode-safe" in block

    def test_block_uses_plsec_home_path(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        block = _build_alias_block(plsec_home, ["claude"], AGENTS)
        assert str(plsec_home) in block


# -----------------------------------------------------------------------
# _has_alias_block / _remove_alias_block
# -----------------------------------------------------------------------


class TestHasAliasBlock:
    """Contract: _has_alias_block detects both modern and legacy markers."""

    def test_detects_modern_block(self):
        content = f"some stuff\n{ALIAS_BLOCK_START}\nalias x\n{ALIAS_BLOCK_END}\n"
        assert _has_alias_block(content) is True

    def test_detects_legacy_marker(self):
        content = "# Peerlabs Security aliases\nalias claude-safe=...\n"
        assert _has_alias_block(content) is True

    def test_returns_false_when_absent(self):
        assert _has_alias_block("just normal rc content\n") is False


class TestRemoveAliasBlock:
    """Contract: _remove_alias_block strips the plsec alias section
    without affecting other RC content."""

    def test_removes_modern_block(self):
        content = (
            "export FOO=bar\n"
            f"{ALIAS_BLOCK_START}\n"
            'alias claude-safe="/path"\n'
            f"{ALIAS_BLOCK_END}\n"
            "export BAZ=qux\n"
        )
        result = _remove_alias_block(content)
        assert ALIAS_BLOCK_START not in result
        assert "claude-safe" not in result
        assert "export FOO=bar" in result
        assert "export BAZ=qux" in result

    def test_removes_legacy_block(self):
        content = (
            "export FOO=bar\n"
            "# Peerlabs Security aliases\n"
            'alias claude-safe="/path"\n'
            'alias plsec-logs="tail -f"\n'
            "\n"
            "export BAZ=qux\n"
        )
        result = _remove_alias_block(content)
        assert "claude-safe" not in result
        assert "plsec-logs" not in result
        assert "export FOO=bar" in result
        assert "export BAZ=qux" in result

    def test_preserves_non_alias_content(self):
        content = "line 1\nline 2\n"
        assert _remove_alias_block(content) == content


# -----------------------------------------------------------------------
# inject_aliases / remove_aliases
# -----------------------------------------------------------------------


class TestInjectAliases:
    """Contract: inject_aliases appends the alias block to the shell
    RC file, with idempotency and force support."""

    def test_injects_into_empty_file(self, tmp_path: Path):
        rc = tmp_path / ".zshrc"
        rc.write_text("")
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        result = inject_aliases(plsec_home, ["claude"], AGENTS, rc_path=rc)
        assert result == rc
        content = rc.read_text()
        assert ALIAS_BLOCK_START in content
        assert "claude-safe" in content

    def test_injects_into_existing_content(self, tmp_path: Path):
        rc = tmp_path / ".zshrc"
        rc.write_text("export PATH=/usr/bin\n")
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        inject_aliases(plsec_home, ["claude", "opencode"], AGENTS, rc_path=rc)
        content = rc.read_text()
        assert content.startswith("export PATH=/usr/bin\n")
        assert "claude-safe" in content
        assert "opencode-safe" in content

    def test_skips_when_already_present(self, tmp_path: Path):
        rc = tmp_path / ".zshrc"
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        inject_aliases(plsec_home, ["claude"], AGENTS, rc_path=rc)
        first_content = rc.read_text()
        # Second inject without force should skip
        result = inject_aliases(plsec_home, ["claude"], AGENTS, rc_path=rc)
        assert result is None
        assert rc.read_text() == first_content

    def test_force_replaces_existing_block(self, tmp_path: Path):
        rc = tmp_path / ".zshrc"
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        inject_aliases(plsec_home, ["claude"], AGENTS, rc_path=rc)
        # Force with different agents should update
        inject_aliases(plsec_home, ["claude", "opencode"], AGENTS, force=True, rc_path=rc)
        content = rc.read_text()
        assert "opencode-safe" in content
        # Should not have duplicate start markers
        assert content.count(ALIAS_BLOCK_START) == 1

    def test_creates_rc_file_if_missing(self, tmp_path: Path):
        rc = tmp_path / ".profile"
        assert not rc.exists()
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        inject_aliases(plsec_home, ["claude"], AGENTS, rc_path=rc)
        assert rc.exists()
        assert "claude-safe" in rc.read_text()


class TestRemoveAliases:
    """Contract: remove_aliases strips the alias block from the
    shell RC file."""

    def test_removes_injected_aliases(self, tmp_path: Path):
        rc = tmp_path / ".zshrc"
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        inject_aliases(plsec_home, ["claude"], AGENTS, rc_path=rc)
        assert _has_alias_block(rc.read_text())
        removed = remove_aliases(rc_path=rc)
        assert removed is True
        assert not _has_alias_block(rc.read_text())

    def test_returns_false_when_no_aliases(self, tmp_path: Path):
        rc = tmp_path / ".zshrc"
        rc.write_text("normal content\n")
        assert remove_aliases(rc_path=rc) is False

    def test_returns_false_when_file_missing(self, tmp_path: Path):
        rc = tmp_path / ".nonexistent"
        assert remove_aliases(rc_path=rc) is False

    def test_preserves_other_content(self, tmp_path: Path):
        rc = tmp_path / ".zshrc"
        rc.write_text("export FOO=bar\n")
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        inject_aliases(plsec_home, ["claude"], AGENTS, rc_path=rc)
        remove_aliases(rc_path=rc)
        content = rc.read_text()
        assert "export FOO=bar" in content
        assert "claude-safe" not in content
