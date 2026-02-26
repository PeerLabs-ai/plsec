"""Tests for preset loading and management."""

import pytest

from plsec.core.presets import (
    find_preset_file,
    get_builtin_preset_dir,
    get_user_preset_dir,
    list_presets,
    load_preset,
)


class TestPresetDiscovery:
    """Test preset file discovery and listing."""

    def test_builtin_preset_dir_exists(self):
        """Built-in preset directory should exist."""
        preset_dir = get_builtin_preset_dir()
        assert preset_dir.exists()
        assert preset_dir.is_dir()

    def test_user_preset_dir_path(self):
        """User preset directory should be under plsec home."""
        user_dir = get_user_preset_dir()
        assert ".peerlabs" in str(user_dir)
        assert "plsec" in str(user_dir)
        assert "presets" in str(user_dir)

    def test_list_presets_includes_all_builtins(self):
        """list_presets() should include all 4 built-in presets."""
        presets = list_presets()
        assert "minimal" in presets
        assert "balanced" in presets
        assert "strict" in presets
        assert "paranoid" in presets

    def test_find_preset_file_finds_balanced(self):
        """find_preset_file() should find balanced preset."""
        path = find_preset_file("balanced")
        assert path is not None
        assert path.exists()
        assert path.suffix == ".toml"

    def test_find_preset_file_returns_none_for_missing(self):
        """find_preset_file() should return None for non-existent preset."""
        path = find_preset_file("nonexistent")
        assert path is None


class TestPresetLoading:
    """Test loading preset TOML files."""

    def test_load_balanced_preset(self):
        """Load balanced preset returns valid dict."""
        preset = load_preset("balanced")
        assert isinstance(preset, dict)
        assert preset["version"] == 1
        assert preset["preset"] == "balanced"
        assert "layers" in preset

    def test_load_minimal_preset(self):
        """Load minimal preset returns valid dict."""
        preset = load_preset("minimal")
        assert isinstance(preset, dict)
        assert preset["preset"] == "minimal"
        assert "layers" in preset

    def test_load_strict_preset(self):
        """Load strict preset returns valid dict."""
        preset = load_preset("strict")
        assert isinstance(preset, dict)
        assert preset["preset"] == "strict"

    def test_load_paranoid_preset(self):
        """Load paranoid preset returns valid dict."""
        preset = load_preset("paranoid")
        assert isinstance(preset, dict)
        assert preset["preset"] == "paranoid"

    def test_load_missing_preset_raises_filenotfound(self):
        """Loading missing preset raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="Preset 'missing' not found"):
            load_preset("missing")
