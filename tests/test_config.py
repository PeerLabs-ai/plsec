"""Tests for plsec configuration management (core/config.py).

Covers the public API (load_config, save_config, PlsecConfig construction)
and the internal boundary validation logic that replaced Pydantic.
"""

from pathlib import Path

import pytest
import yaml

from plsec import __version__
from plsec.core.config import (
    _LITERAL_CONSTRAINTS,
    PlsecConfig,
    ProjectConfig,
    _from_dict,
    _resolve_constraint,
    _to_dict,
    _validate_config,
    _validate_literal,
    load_config,
    save_config,
)

# -----------------------------------------------------------------------
# Version tests
# -----------------------------------------------------------------------


class TestVersion:
    """Test package version information.

    Contract: __version__ is defined via importlib.metadata and follows
    semantic versioning. Tested here because version originates from the
    package metadata managed alongside config.
    """

    def test_version_exists(self):
        """Version string should be defined."""
        assert __version__ is not None
        assert isinstance(__version__, str)

    def test_version_format(self):
        """Version should follow semantic versioning (at least major.minor)."""
        parts = __version__.split(".")
        assert len(parts) >= 2
        assert all(p.isdigit() for p in parts[:2])


# -----------------------------------------------------------------------
# Public API tests
# -----------------------------------------------------------------------


class TestConfigPublicAPI:
    """Integration tests for load_config / save_config / PlsecConfig.

    These test the public interface and should rarely need updating.
    """

    def test_default_config(self):
        """PlsecConfig() should produce valid defaults for all fields."""
        config = PlsecConfig()
        assert config.version == 1
        assert config.project.name == "unknown"
        assert config.project.type == "python"
        assert config.agent.type == "claude-code"
        assert config.layers.static.enabled is True
        assert config.layers.isolation.enabled is False
        assert config.layers.proxy.enabled is False
        assert config.layers.audit.enabled is True
        assert config.credentials.storage == "keychain"
        assert config.credentials.keys == []

    def test_default_scanners(self):
        """Default scanner list should include the expected tools."""
        config = PlsecConfig()
        assert "trivy-secrets" in config.layers.static.scanners
        assert "bandit" in config.layers.static.scanners
        assert len(config.layers.static.scanners) == 4

    def test_mutable_defaults_are_independent(self):
        """Each PlsecConfig instance should have its own mutable collections."""
        a = PlsecConfig()
        b = PlsecConfig()
        a.credentials.keys.append("test-key")
        assert "test-key" not in b.credentials.keys

    def test_config_roundtrip(self, tmp_path: Path):
        """Config should survive save -> load without data loss."""
        config = PlsecConfig()
        config.project.name = "roundtrip-test"
        config.layers.proxy.enabled = True
        config.layers.proxy.mode = "strict"

        config_path = tmp_path / "plsec.yaml"
        save_config(config, config_path)

        loaded = load_config(config_path)
        assert loaded.project.name == "roundtrip-test"
        assert loaded.layers.proxy.enabled is True
        assert loaded.layers.proxy.mode == "strict"

    def test_load_missing_explicit_path(self, tmp_path: Path):
        """load_config with a nonexistent explicit path should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nonexistent.yaml")

    def test_load_empty_yaml(self, tmp_path: Path):
        """An empty YAML file should produce default config (yaml.safe_load returns None)."""
        config_path = tmp_path / "plsec.yaml"
        config_path.write_text("")

        config = load_config(config_path)
        assert config.version == 1
        assert config.project.name == "unknown"

    def test_load_partial_yaml(self, tmp_path: Path):
        """YAML with only some fields should fill in defaults for the rest."""
        config_path = tmp_path / "plsec.yaml"
        config_path.write_text("project:\n  name: partial-test\n")

        config = load_config(config_path)
        assert config.project.name == "partial-test"
        assert config.project.type == "python"  # default
        assert config.layers.static.enabled is True  # default

    def test_load_invalid_literal_raises_valueerror(self, tmp_path: Path):
        """YAML with an invalid Literal value should raise ValueError at load time."""
        config_path = tmp_path / "plsec.yaml"
        config_path.write_text("project:\n  type: invalid-type\n")

        with pytest.raises(ValueError, match="Invalid project.type"):
            load_config(config_path)

    def test_save_creates_parent_dirs(self, tmp_path: Path):
        """save_config should create parent directories if they don't exist."""
        config = PlsecConfig()
        deep_path = tmp_path / "a" / "b" / "c" / "plsec.yaml"
        save_config(config, deep_path)
        assert deep_path.exists()

    def test_save_produces_valid_yaml(self, tmp_path: Path):
        """Saved config file should be parseable YAML."""
        config = PlsecConfig()
        config_path = tmp_path / "plsec.yaml"
        save_config(config, config_path)

        with open(config_path) as f:
            data = yaml.safe_load(f)

        assert isinstance(data, dict)
        assert data["version"] == 1
        assert data["project"]["name"] == "unknown"


# -----------------------------------------------------------------------
# Boundary validation unit tests
# -----------------------------------------------------------------------


class TestConfigBoundaryValidation:
    """Unit tests for config validation at the load boundary.

    These test the internal validation logic that enforces Literal
    constraints when loading external YAML data. They replaced Pydantic's
    model_validate(). If a test here fails, it likely means a Literal
    type alias or _LITERAL_CONSTRAINTS was updated without updating
    the corresponding test.

    See: _validate_config(), _validate_literal(), _from_dict()
    """

    # -- _validate_literal --

    def test_validate_literal_accepts_valid_value(self):
        """Valid values should pass through unchanged."""
        result = _validate_literal("python", "test", {"python", "node"})
        assert result == "python"

    def test_validate_literal_rejects_invalid_value(self):
        """Invalid values should raise ValueError with the field name and allowed set."""
        with pytest.raises(ValueError, match="Invalid test_field") as exc_info:
            _validate_literal("invalid", "test_field", {"a", "b"})
        # The error message should include the allowed values for clarity
        assert "allowed" in str(exc_info.value)

    # -- _validate_config --

    def test_validate_config_accepts_valid_data(self):
        """A fully valid config dict should not raise."""
        data = {
            "project": {"type": "python"},
            "agent": {"type": "claude-code"},
            "layers": {
                "isolation": {"runtime": "podman"},
                "proxy": {"mode": "balanced"},
            },
            "credentials": {"storage": "keychain"},
        }
        _validate_config(data)  # should not raise

    def test_validate_config_rejects_invalid_project_type(self):
        """Invalid project.type should raise ValueError."""
        with pytest.raises(ValueError, match="project.type"):
            _validate_config({"project": {"type": "ruby"}})

    def test_validate_config_rejects_invalid_agent_type(self):
        """Invalid agent.type should raise ValueError."""
        with pytest.raises(ValueError, match="agent.type"):
            _validate_config({"agent": {"type": "gemini"}})

    def test_validate_config_rejects_invalid_runtime(self):
        """Invalid isolation runtime should raise ValueError."""
        with pytest.raises(ValueError, match="layers.isolation.runtime"):
            _validate_config({"layers": {"isolation": {"runtime": "lxc"}}})

    def test_validate_config_rejects_invalid_proxy_mode(self):
        """Invalid proxy mode should raise ValueError."""
        with pytest.raises(ValueError, match="layers.proxy.mode"):
            _validate_config({"layers": {"proxy": {"mode": "paranoid"}}})

    def test_validate_config_rejects_invalid_storage(self):
        """Invalid credentials storage should raise ValueError."""
        with pytest.raises(ValueError, match="credentials.storage"):
            _validate_config({"credentials": {"storage": "vault"}})

    def test_validate_config_skips_missing_sections(self):
        """Sections not present in the dict should not be validated."""
        _validate_config({})  # should not raise
        _validate_config({"project": {"name": "test"}})  # no type key, should not raise

    # -- _from_dict --

    def test_from_dict_builds_nested_dataclasses(self):
        """_from_dict should recursively build nested dataclass instances."""
        data = {
            "project": {"name": "test-project", "type": "node"},
            "agent": {"type": "opencode"},
        }
        config = _from_dict(PlsecConfig, data)
        assert isinstance(config, PlsecConfig)
        assert isinstance(config.project, ProjectConfig)
        assert config.project.name == "test-project"
        assert config.project.type == "node"
        assert config.agent.type == "opencode"

    def test_from_dict_uses_defaults_for_missing_keys(self):
        """Fields absent from the dict should get their dataclass defaults."""
        config = _from_dict(PlsecConfig, {"project": {"name": "sparse"}})
        assert config.project.name == "sparse"
        assert config.project.type == "python"  # default
        assert config.version == 1  # default

    def test_from_dict_rejects_unknown_keys(self):
        """Extra keys not in the dataclass should raise TypeError."""
        with pytest.raises(TypeError):
            _from_dict(PlsecConfig, {"nonexistent_field": "value"})

    # -- _to_dict --

    def test_to_dict_produces_plain_dict(self):
        """_to_dict should return a plain dict with no dataclass instances."""
        config = PlsecConfig()
        data = _to_dict(config)
        assert isinstance(data, dict)
        assert isinstance(data["project"], dict)
        assert isinstance(data["layers"]["static"], dict)
        assert data["project"]["name"] == "unknown"

    # -- _LITERAL_CONSTRAINTS consistency --

    def test_literal_constraints_cover_all_constrained_fields(self):
        """Static constraints + dynamic resolvers cover all Literal-typed fields."""
        # Static constraints in _LITERAL_CONSTRAINTS
        static_keys = {"runtime", "mode", "project_type", "storage", "severity_threshold"}
        assert set(_LITERAL_CONSTRAINTS.keys()) == static_keys
        # Dynamic constraint resolved from AGENTS registry
        agent_types = _resolve_constraint("agent_type")
        assert "claude-code" in agent_types
        assert "opencode" in agent_types

    def test_literal_constraints_are_nonempty(self):
        """Every constraint set should have at least 2 allowed values."""
        for key, allowed in _LITERAL_CONSTRAINTS.items():
            assert len(allowed) >= 2, f"Constraint {key!r} has fewer than 2 values"
        # Dynamic agent_type constraint
        agent_types = _resolve_constraint("agent_type")
        assert len(agent_types) >= 2, "agent_type constraint has fewer than 2 values"


# ---------------------------------------------------------------------------
# TOML support tests
# ---------------------------------------------------------------------------


class TestTomlSupport:
    """Test TOML file format support."""

    def test_load_toml_config(self, tmp_path):
        """Load configuration from TOML file."""
        config_file = tmp_path / "plsec.toml"
        config_file.write_text("""
version = 1
preset = "strict"

[project]
name = "test-project"
type = "python"

[agent]
type = "claude-code"
config_path = "./CLAUDE.md"
""")
        config = load_config(config_file)
        assert config.version == 1
        assert config.preset == "strict"
        assert config.project.name == "test-project"
        assert config.project.type == "python"

    def test_save_toml_config(self, tmp_path):
        """Save configuration to TOML file."""
        config = PlsecConfig(version=1, preset="paranoid")
        config.project.name = "test-project"

        config_file = tmp_path / "plsec.toml"
        save_config(config, config_file)

        assert config_file.exists()
        content = config_file.read_text()
        assert "version = 1" in content
        assert 'preset = "paranoid"' in content
        assert 'name = "test-project"' in content

    def test_toml_roundtrip(self, tmp_path):
        """Save and load TOML produces equivalent config."""
        original = PlsecConfig(version=1, preset="minimal")
        original.project.name = "roundtrip-test"
        original.project.type = "node"

        config_file = tmp_path / "plsec.toml"
        save_config(original, config_file)
        loaded = load_config(config_file)

        assert loaded.version == original.version
        assert loaded.preset == original.preset
        assert loaded.project.name == original.project.name
        assert loaded.project.type == original.project.type

    def test_save_format_autodetect_toml(self, tmp_path):
        """save_config autodetects TOML format from .toml extension."""
        config = PlsecConfig(preset="balanced")
        config_file = tmp_path / "config.toml"
        save_config(config, config_file)

        content = config_file.read_text()
        assert 'preset = "balanced"' in content  # TOML format

    def test_save_format_autodetect_yaml(self, tmp_path):
        """save_config autodetects YAML format from .yaml extension."""
        config = PlsecConfig(preset="strict")
        config_file = tmp_path / "config.yaml"
        save_config(config, config_file)

        content = config_file.read_text()
        assert "preset: strict" in content  # YAML format

    def test_save_format_explicit_toml(self, tmp_path):
        """save_config respects explicit format=toml."""
        config = PlsecConfig(preset="paranoid")
        config_file = tmp_path / "config.txt"  # Non-standard extension
        save_config(config, config_file, format="toml")

        content = config_file.read_text()
        assert 'preset = "paranoid"' in content

    def test_save_format_explicit_yaml(self, tmp_path):
        """save_config respects explicit format=yaml."""
        config = PlsecConfig(preset="minimal")
        config_file = tmp_path / "config.txt"  # Non-standard extension
        save_config(config, config_file, format="yaml")

        content = config_file.read_text()
        assert "preset: minimal" in content

    def test_save_format_unknown_extension_raises(self, tmp_path):
        """save_config raises for unknown extension without explicit format."""
        config = PlsecConfig()
        config_file = tmp_path / "config.txt"
        with pytest.raises(ValueError, match="Cannot determine format"):
            save_config(config, config_file)

    def test_save_format_invalid_format_raises(self, tmp_path):
        """save_config raises for invalid format parameter."""
        config = PlsecConfig()
        config_file = tmp_path / "config.toml"
        with pytest.raises(ValueError, match="Unsupported format"):
            save_config(config, config_file, format="json")


class TestFindConfigFile:
    """Test config file discovery with TOML preference."""

    def test_prefers_toml_over_yaml_in_cwd(self, tmp_path, monkeypatch):
        """When both exist in cwd, prefer TOML."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "plsec.toml").write_text("version = 1")
        (tmp_path / "plsec.yaml").write_text("version: 1")

        from plsec.core.config import find_config_file

        found = find_config_file()
        assert found == tmp_path / "plsec.toml"

    def test_finds_yaml_when_no_toml(self, tmp_path, monkeypatch):
        """Find YAML when no TOML exists."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "plsec.yaml").write_text("version: 1")

        from plsec.core.config import find_config_file

        found = find_config_file()
        assert found == tmp_path / "plsec.yaml"

    def test_finds_toml_in_parent(self, tmp_path, monkeypatch):
        """Find TOML in parent directory."""
        (tmp_path / "plsec.toml").write_text("version = 1")
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        monkeypatch.chdir(subdir)

        from plsec.core.config import find_config_file

        found = find_config_file()
        assert found == tmp_path / "plsec.toml"

    def test_finds_global_toml(self, tmp_path, monkeypatch):
        """Find global TOML config."""
        global_home = tmp_path / ".peerlabs" / "plsec"
        global_home.mkdir(parents=True)
        (global_home / "plsec.toml").write_text("version = 1")

        # Mock home directory and change to a subdirectory without config
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        project_dir = tmp_path / "some" / "project"
        project_dir.mkdir(parents=True)
        monkeypatch.chdir(project_dir)

        from plsec.core.config import find_config_file

        found = find_config_file()
        assert found == global_home / "plsec.toml"


class TestLoadConfig:
    """Test load_config with TOML support."""

    def test_loads_toml_file(self, tmp_path):
        """load_config detects and loads TOML files."""
        config_file = tmp_path / "test.toml"
        config_file.write_text("""
version = 1
preset = "balanced"

[project]
name = "toml-test"
type = "go"
""")
        config = load_config(config_file)
        assert config.version == 1
        assert config.preset == "balanced"
        assert config.project.name == "toml-test"
        assert config.project.type == "go"

    def test_loads_yaml_file(self, tmp_path):
        """load_config still loads YAML files."""
        config_file = tmp_path / "test.yaml"
        config_file.write_text("""
version: 1
preset: strict

project:
  name: yaml-test
  type: python
""")
        config = load_config(config_file)
        assert config.version == 1
        assert config.preset == "strict"
        assert config.project.name == "yaml-test"
        assert config.project.type == "python"

    def test_unsupported_extension_raises(self, tmp_path):
        """load_config raises for unsupported file extensions."""
        config_file = tmp_path / "config.json"
        config_file.write_text('{"version": 1}')
        with pytest.raises(ValueError, match="Unsupported config file format"):
            load_config(config_file)


# ---------------------------------------------------------------------------
# Configuration hierarchy tests
# ---------------------------------------------------------------------------


class TestResolveConfig:
    """Test configuration hierarchy resolution."""

    def test_cli_preset_overrides_all(self, tmp_path):
        """CLI preset has highest priority."""
        from plsec.core.config import resolve_config

        # Create project config with balanced preset
        project_config = tmp_path / "plsec.toml"
        project_config.write_text('preset = "balanced"')

        # CLI preset should override
        config, preset = resolve_config(
            cli_preset="strict",
            project_config_path=project_config,
        )
        assert preset == "strict"
        assert config.preset == "strict"

    def test_project_preset_overrides_global(self, tmp_path):
        """Project config overrides global config."""
        from plsec.core.config import resolve_config

        # Create global config
        global_config = tmp_path / "global.toml"
        global_config.write_text('preset = "minimal"')

        # Create project config
        project_config = tmp_path / "project.toml"
        project_config.write_text('preset = "paranoid"')

        config, preset = resolve_config(
            project_config_path=project_config,
            global_config_path=global_config,
        )
        assert preset == "paranoid"
        assert config.preset == "paranoid"

    def test_global_preset_when_no_project(self, tmp_path):
        """Global config used when no project config."""
        from plsec.core.config import resolve_config

        global_config = tmp_path / "global.toml"
        global_config.write_text('preset = "strict"')

        config, preset = resolve_config(
            global_config_path=global_config,
        )
        assert preset == "strict"
        assert config.preset == "strict"

    def test_default_preset_when_none_specified(self):
        """Falls back to 'balanced' when no config found."""
        from plsec.core.config import resolve_config

        config, preset = resolve_config()
        assert preset == "balanced"
        assert config.preset == "balanced"

    def test_merges_project_and_global_config(self, tmp_path):
        """Project config values override global config values."""
        from plsec.core.config import resolve_config

        # Global config has project name
        global_config = tmp_path / "global.toml"
        global_config.write_text("""
preset = "balanced"

[project]
name = "global-project"
type = "python"
""")

        # Project config overrides name but not type
        project_config = tmp_path / "project.toml"
        project_config.write_text("""
preset = "strict"

[project]
name = "local-project"
""")

        config, preset = resolve_config(
            project_config_path=project_config,
            global_config_path=global_config,
        )
        # Project preset wins
        assert preset == "strict"
        # Project name wins
        assert config.project.name == "local-project"
        # Note: Full merging of nested fields is not implemented yet,
        # so type will come from whichever config is loaded


class TestPresetField:
    """Test preset field in PlsecConfig."""

    def test_default_preset_is_balanced(self):
        """Default preset should be 'balanced'."""
        config = PlsecConfig()
        assert config.preset == "balanced"

    def test_preset_in_dict_roundtrip(self):
        """Preset field survives dict conversion."""
        config = PlsecConfig(preset="paranoid")
        data = _to_dict(config)
        assert data["preset"] == "paranoid"

        restored = _from_dict(PlsecConfig, data)
        assert restored.preset == "paranoid"

    def test_preset_saved_to_yaml(self, tmp_path):
        """Preset field is saved to YAML."""
        config = PlsecConfig(preset="minimal")
        config_file = tmp_path / "test.yaml"
        save_config(config, config_file)

        content = config_file.read_text()
        assert "preset:" in content
        assert "minimal" in content

    def test_preset_saved_to_toml(self, tmp_path):
        """Preset field is saved to TOML."""
        config = PlsecConfig(preset="strict")
        config_file = tmp_path / "test.toml"
        save_config(config, config_file)

        content = config_file.read_text()
        assert "preset" in content
        assert "strict" in content
