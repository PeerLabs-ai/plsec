"""Basic tests for plsec package."""

import pytest
from pathlib import Path
from typer.testing import CliRunner

from plsec import __version__
from plsec.cli import app
from plsec.core.config import PlsecConfig, load_config, save_config
from plsec.core.tools import ToolChecker, Tool, ToolStatus


runner = CliRunner()


class TestVersion:
    """Test version information."""

    def test_version_exists(self):
        """Version string should be defined."""
        assert __version__ is not None
        assert isinstance(__version__, str)

    def test_version_format(self):
        """Version should be semantic versioning."""
        parts = __version__.split(".")
        assert len(parts) >= 2
        assert all(p.isdigit() for p in parts[:2])


class TestCLI:
    """Test CLI commands."""

    def test_help(self):
        """--help should work."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "plsec" in result.stdout

    def test_version(self):
        """--version should show version."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.stdout

    def test_doctor_runs(self):
        """doctor command should run."""
        result = runner.invoke(app, ["doctor"])
        # May fail if deps missing, but should not crash
        assert result.exit_code in (0, 1)


class TestConfig:
    """Test configuration handling."""

    def test_default_config(self):
        """Default config should be valid."""
        config = PlsecConfig()
        assert config.version == 1
        assert config.project.name == "unknown"
        assert config.layers.static.enabled is True

    def test_config_roundtrip(self, tmp_path: Path):
        """Config should survive save/load."""
        config = PlsecConfig()
        config.project.name = "test-project"
        config.layers.proxy.enabled = True

        config_path = tmp_path / "plsec.yaml"
        save_config(config, config_path)

        loaded = load_config(config_path)
        assert loaded.project.name == "test-project"
        assert loaded.layers.proxy.enabled is True

    def test_missing_config(self, tmp_path: Path):
        """Missing config should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nonexistent.yaml")


class TestToolChecker:
    """Test tool checking."""

    def test_check_missing_tool(self):
        """Missing tool should be detected."""
        tool = Tool(
            name="NonexistentTool",
            command="plsec-nonexistent-tool-12345",
            required=True,
        )
        checker = ToolChecker([tool])
        checker.check_all()

        assert tool.status == ToolStatus.MISSING

    def test_version_comparison(self):
        """Version comparison should work."""
        assert ToolChecker._version_gte("1.2.3", "1.2.0")
        assert ToolChecker._version_gte("1.2.3", "1.2.3")
        assert not ToolChecker._version_gte("1.2.0", "1.2.3")
        assert ToolChecker._version_gte("2.0.0", "1.9.9")


class TestTemplates:
    """Test embedded templates."""

    def test_templates_exist(self):
        """Templates should be importable."""
        from plsec.configs.templates import (
            CLAUDE_MD_STRICT,
            CLAUDE_MD_BALANCED,
            OPENCODE_JSON_STRICT,
            OPENCODE_JSON_BALANCED,
        )

        assert "NEVER" in CLAUDE_MD_STRICT
        assert "NEVER" in CLAUDE_MD_BALANCED
        assert '"$schema"' in OPENCODE_JSON_STRICT
        assert '"$schema"' in OPENCODE_JSON_BALANCED
        assert '"permission"' in OPENCODE_JSON_STRICT
        assert '"permission"' in OPENCODE_JSON_BALANCED

    def test_strict_more_restrictive(self):
        """Strict templates should be more restrictive."""
        from plsec.configs.templates import (
            CLAUDE_MD_STRICT,
            CLAUDE_MD_BALANCED,
        )

        # Strict should have more restrictions
        assert "RESTRICTED" in CLAUDE_MD_STRICT
        assert "RESTRICTED" not in CLAUDE_MD_BALANCED
