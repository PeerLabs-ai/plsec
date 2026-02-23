"""Tests for plsec install command (commands/install.py).

Covers the shared deployment functions (_deploy_file, deploy_global_configs,
write_installed_metadata, read_installed_metadata, check_installation)
and the install CLI command via CliRunner with monkeypatched paths.
"""

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from plsec.commands.install import (
    INSTALLED_JSON,
    _deploy_file,
    app,
    check_installation,
    deploy_global_configs,
    read_installed_metadata,
    write_installed_metadata,
)
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
