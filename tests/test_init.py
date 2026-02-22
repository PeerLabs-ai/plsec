"""Tests for plsec init command (commands/init.py).

Covers the pure functions (detect_project_type, get_preset_config)
and the init CLI command via CliRunner with monkeypatched paths.
"""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from plsec.commands.init import _deploy_global_file, app, detect_project_type, get_preset_config

runner = CliRunner()

# -----------------------------------------------------------------------
# detect_project_type
# -----------------------------------------------------------------------


class TestDetectProjectType:
    """Contract: detect_project_type(path) returns a ProjectType string
    based on which marker files exist in the directory."""

    def test_python_from_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n")
        assert detect_project_type(tmp_path) == "python"

    def test_python_from_setup_py(self, tmp_path: Path):
        (tmp_path / "setup.py").write_text("from setuptools import setup\n")
        assert detect_project_type(tmp_path) == "python"

    def test_node_from_package_json(self, tmp_path: Path):
        (tmp_path / "package.json").write_text('{"name": "x"}\n')
        assert detect_project_type(tmp_path) == "node"

    def test_go_from_go_mod(self, tmp_path: Path):
        (tmp_path / "go.mod").write_text("module example.com/x\n\ngo 1.22\n")
        assert detect_project_type(tmp_path) == "go"

    def test_empty_directory_returns_mixed(self, tmp_path: Path):
        """No marker files should fall back to 'mixed'."""
        assert detect_project_type(tmp_path) == "mixed"

    def test_python_takes_priority_over_node(self, tmp_path: Path):
        """When both pyproject.toml and package.json exist, python wins
        because pyproject.toml is checked first."""
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        (tmp_path / "package.json").write_text("{}\n")
        assert detect_project_type(tmp_path) == "python"


# -----------------------------------------------------------------------
# get_preset_config
# -----------------------------------------------------------------------


class TestGetPresetConfig:
    """Contract: get_preset_config(preset) returns a LayersConfig
    with the correct enable/disable states for each security layer."""

    def test_minimal_preset(self):
        config = get_preset_config("minimal")
        assert config.static.enabled is True
        assert config.static.scanners == ["trivy-secrets"]
        assert config.isolation.enabled is False
        assert config.proxy.enabled is False
        assert config.audit.enabled is True
        assert config.audit.integrity is False

    def test_balanced_preset(self):
        config = get_preset_config("balanced")
        assert config.static.enabled is True
        assert len(config.static.scanners) > 1  # more than just trivy-secrets
        assert config.isolation.enabled is False
        assert config.proxy.enabled is False
        assert config.audit.enabled is True

    def test_strict_preset(self):
        config = get_preset_config("strict")
        assert config.static.enabled is True
        assert config.isolation.enabled is True
        assert config.isolation.runtime == "podman"
        assert config.proxy.enabled is True
        assert config.proxy.mode == "balanced"
        assert config.audit.enabled is True
        assert config.audit.integrity is True

    def test_paranoid_preset(self):
        config = get_preset_config("paranoid")
        assert config.static.enabled is True
        assert config.isolation.enabled is True
        assert config.proxy.enabled is True
        assert config.proxy.mode == "strict"
        assert config.audit.integrity is True

    def test_strict_is_stricter_than_balanced(self):
        """Strict should enable more layers than balanced."""
        balanced = get_preset_config("balanced")
        strict = get_preset_config("strict")
        # Strict enables isolation and proxy; balanced does not
        assert strict.isolation.enabled and not balanced.isolation.enabled
        assert strict.proxy.enabled and not balanced.proxy.enabled


# -----------------------------------------------------------------------
# _deploy_global_file
# -----------------------------------------------------------------------


class TestDeployGlobalFile:
    """Contract: _deploy_global_file writes content to path, respecting
    force flag and existing files."""

    def test_creates_file_when_missing(self, tmp_path: Path):
        target = tmp_path / "test.yaml"
        _deploy_global_file(target, "content\n")
        assert target.read_text() == "content\n"

    def test_does_not_overwrite_without_force(self, tmp_path: Path):
        target = tmp_path / "test.yaml"
        target.write_text("original\n")
        _deploy_global_file(target, "new content\n")
        assert target.read_text() == "original\n"

    def test_overwrites_with_force(self, tmp_path: Path):
        target = tmp_path / "test.yaml"
        target.write_text("original\n")
        _deploy_global_file(target, "new content\n", force=True)
        assert target.read_text() == "new content\n"


# -----------------------------------------------------------------------
# plsec init --global (trivy config deployment)
# -----------------------------------------------------------------------


class TestInitDeploysScannerConfigs:
    """Contract: plsec init deploys trivy-secret.yaml, trivy.yaml,
    and pre-commit hook to the plsec home directory."""

    def test_deploys_trivy_secret_yaml(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        with patch("plsec.commands.init.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--global"])
        assert result.exit_code == 0
        trivy_config = plsec_home / "trivy" / "trivy-secret.yaml"
        assert trivy_config.exists()
        content = trivy_config.read_text()
        assert "openai-legacy" in content
        assert "(?!" not in content

    def test_deploys_trivy_yaml(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        with patch("plsec.commands.init.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--global"])
        assert result.exit_code == 0
        trivy_yaml = plsec_home / "trivy" / "trivy.yaml"
        assert trivy_yaml.exists()
        assert "trivy-secret.yaml" in trivy_yaml.read_text()

    def test_deploys_pre_commit_hook(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        with patch("plsec.commands.init.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--global"])
        assert result.exit_code == 0
        hook = plsec_home / "configs" / "pre-commit"
        assert hook.exists()
        assert hook.stat().st_mode & 0o111  # executable

    def test_force_overwrites_trivy_config(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        trivy_dir = plsec_home / "trivy"
        trivy_dir.mkdir(parents=True)
        stale = trivy_dir / "trivy-secret.yaml"
        stale.write_text("old content\n")
        with patch("plsec.commands.init.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--global", "--force"])
        assert result.exit_code == 0
        assert "old content" not in stale.read_text()
        assert "openai-legacy" in stale.read_text()
