"""Built-in security presets for plsec.

This package contains the built-in security preset TOML files that ship with plsec.
"""

from pathlib import Path

BUILTIN_PRESET_DIR = Path(__file__).parent

__all__ = ["BUILTIN_PRESET_DIR"]
