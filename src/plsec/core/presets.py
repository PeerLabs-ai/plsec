"""Preset configurations for security scanning.

Presets define scanner behavior and layer enablement for different security
postures. Users can select presets via CLI (--preset) or config files
(plsec.toml or plsec.yaml).

Presets are stored as TOML files in two locations:
  1. Built-in presets: src/plsec/configs/presets/ (shipped with package)
  2. User presets: ~/.peerlabs/plsec/config/presets/ (custom user presets)

User presets take precedence over built-in presets with the same name.

Available built-in presets:
  - minimal: Secret scanning only, aggressive false-positive suppression
  - balanced: Full static analysis, reasonable defaults (default)
  - strict: Container isolation, aggressive scanning
  - paranoid: Maximum security, network isolation, scan everything
"""

import tomllib
from pathlib import Path
from typing import Any, Literal

# ---------------------------------------------------------------------------
# Preset types
# ---------------------------------------------------------------------------

PresetLevel = Literal["minimal", "balanced", "strict", "paranoid"]

DEFAULT_PRESET: PresetLevel = "balanced"


# ---------------------------------------------------------------------------
# Preset file discovery
# ---------------------------------------------------------------------------


def get_builtin_preset_dir() -> Path:
    """Return the path to built-in preset TOML files shipped with plsec."""
    from plsec.configs.presets import BUILTIN_PRESET_DIR

    return BUILTIN_PRESET_DIR


def get_user_preset_dir() -> Path:
    """Return the path to user custom preset directory."""
    from plsec.core.config import get_plsec_home

    return get_plsec_home() / "config" / "presets"


def find_preset_file(name: str) -> Path | None:
    """
    Find a preset TOML file by name.

    Search order:
      1. User preset directory (~/.peerlabs/plsec/config/presets/{name}.toml)
      2. Built-in preset directory (src/plsec/configs/presets/{name}.toml)

    Args:
        name: Preset name (e.g., "balanced", "minimal")

    Returns:
        Path to preset file, or None if not found
    """
    # Try user presets first
    user_dir = get_user_preset_dir()
    user_preset = user_dir / f"{name}.toml"
    if user_preset.exists():
        return user_preset

    # Fall back to built-in presets
    builtin_dir = get_builtin_preset_dir()
    builtin_preset = builtin_dir / f"{name}.toml"
    if builtin_preset.exists():
        return builtin_preset

    return None


def list_presets() -> list[str]:
    """
    List all available preset names (built-in + user custom).

    Returns:
        Sorted list of preset names without .toml extension
    """
    presets = set()

    # Built-in presets
    builtin_dir = get_builtin_preset_dir()
    if builtin_dir.exists():
        for path in builtin_dir.glob("*.toml"):
            if path.stem != "__init__":
                presets.add(path.stem)

    # User presets
    user_dir = get_user_preset_dir()
    if user_dir.exists():
        for path in user_dir.glob("*.toml"):
            presets.add(path.stem)

    return sorted(presets)


# ---------------------------------------------------------------------------
# Preset loading
# ---------------------------------------------------------------------------


def load_preset(name: str) -> dict[str, Any]:
    """
    Load a preset by name, returning raw dict for merging.

    This function loads the preset TOML file and returns it as a plain dict,
    suitable for merging with other config sources using merge_configs().

    Args:
        name: Preset name (e.g., "balanced", "minimal", "strict", "paranoid")

    Returns:
        Raw configuration dict from the preset TOML file

    Raises:
        FileNotFoundError: If preset file doesn't exist
        ValueError: If preset TOML is invalid or malformed

    Example:
        >>> preset_dict = load_preset("balanced")
        >>> preset_dict["layers"]["static"]["scanners"]
        ['trivy-secrets', 'trivy-misconfig', 'bandit', 'semgrep']
    """
    preset_path = find_preset_file(name)
    if preset_path is None:
        available = list_presets()
        raise FileNotFoundError(f"Preset '{name}' not found. Available presets: {available}")

    try:
        with open(preset_path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"Invalid TOML in preset file {preset_path}: {e}") from e
    except Exception as e:
        raise ValueError(f"Failed to load preset {preset_path}: {e}") from e

    # Validate that preset has required top-level keys
    if "version" not in data:
        raise ValueError(f"Preset {preset_path} missing required field: version")

    return data


def validate_preset_level(level: str) -> str:
    """
    Validate a preset level string.

    Args:
        level: Preset level to validate

    Returns:
        The validated preset level (unchanged)

    Raises:
        ValueError: If level is not a valid preset name

    Example:
        >>> validate_preset_level("balanced")
        'balanced'
        >>> validate_preset_level("invalid")
        ValueError: Invalid preset level: 'invalid' ...
    """
    available = list_presets()
    if level not in available:
        raise ValueError(f"Invalid preset level: {level!r} (available: {sorted(available)})")
    return level


__all__ = [
    "PresetLevel",
    "DEFAULT_PRESET",
    "get_builtin_preset_dir",
    "get_user_preset_dir",
    "find_preset_file",
    "list_presets",
    "load_preset",
    "validate_preset_level",
]
