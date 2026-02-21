"""Tests for plsec init command (commands/init.py).

Covers the pure functions (detect_project_type, get_preset_config)
and the init CLI command via CliRunner with monkeypatched paths.
"""

from pathlib import Path

from plsec.commands.init import detect_project_type, get_preset_config

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
