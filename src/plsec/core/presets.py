"""Preset configurations for security scanning.

Presets define scanner behavior and layer enablement for different security
postures. Users can select presets via CLI (--preset) or config files
(plsec.toml or plsec.yaml).

The hierarchy is: CLI args > Project config > Global config > Preset defaults

Available presets:
  - minimal: Secret scanning only, aggressive false-positive suppression
  - balanced: Full static analysis, reasonable defaults (default)
  - strict: Container isolation, aggressive scanning
  - paranoid: Maximum security, network isolation, scan everything
"""

from dataclasses import dataclass, field
from typing import Literal

# ---------------------------------------------------------------------------
# Preset types
# ---------------------------------------------------------------------------

PresetLevel = Literal["minimal", "balanced", "strict", "paranoid"]

# ---------------------------------------------------------------------------
# Scanner configuration
# ---------------------------------------------------------------------------


@dataclass
class ScannerPreset:
    """Scanner behavior configuration for a preset level.

    Controls what gets scanned, how aggressively, and which rules apply.
    """

    # Scanner IDs to enable (e.g., ["trivy-secrets"], or ["trivy-secrets", "semgrep"])
    enabled_scanners: list[str] = field(default_factory=list)

    # Directories to skip during scanning (e.g., [".venv", "node_modules"])
    skip_dirs: list[str] = field(default_factory=list)

    # File patterns to skip (e.g., ["**/*.pyc", "**/*.so"])
    skip_files: list[str] = field(default_factory=list)

    # Minimum severity to report (e.g., "HIGH", "MEDIUM", "LOW")
    # Note: Not all scanners support severity filtering yet
    severity_threshold: str = "MEDIUM"

    # Rule IDs to suppress (used to generate .trivyignore.yaml)
    # Format: list of {"id": "generic-secret", "paths": ["..."]}
    suppress_rules: list[dict[str, str | list[str]]] = field(default_factory=list)

    # Scanner-specific timeout in seconds
    timeout: int = 300

    # Skip scanning when files don't match expected patterns
    # (e.g., skip bandit if no .py files)
    skip_when_no_files: bool = True


# ---------------------------------------------------------------------------
# Layer configuration
# ---------------------------------------------------------------------------


@dataclass
class LayerPreset:
    """Layer enablement configuration for a preset level.

    Controls which security layers are active: wrappers, hooks, isolation, etc.
    """

    # Enable runtime wrappers (claude-safe, opencode-safe)
    runtime_wrappers: bool = True

    # Enable pre-commit hooks for automatic scanning
    pre_commit_hooks: bool = True

    # Enable container isolation (Docker/Podman)
    container_isolation: bool = False

    # Enable network proxy filtering (pipelock)
    network_proxy: bool = False

    # Enable activity monitoring and audit logging
    audit_logging: bool = True


# ---------------------------------------------------------------------------
# Complete preset configuration
# ---------------------------------------------------------------------------


@dataclass
class Preset:
    """Complete preset configuration combining scanner and layer settings."""

    # Preset identifier
    level: PresetLevel

    # Human-readable description
    description: str

    # Scanner configuration
    scanner: ScannerPreset

    # Layer configuration
    layers: LayerPreset


# ---------------------------------------------------------------------------
# Preset definitions
# ---------------------------------------------------------------------------

MINIMAL_PRESET = Preset(
    level="minimal",
    description="Secret scanning only, aggressive false-positive suppression",
    scanner=ScannerPreset(
        enabled_scanners=["trivy-secrets"],
        skip_dirs=[
            ".venv",
            ".tox",
            "node_modules",
            "build",
            "dist",
            ".eggs",
            "__pycache__",
            ".git",
            ".cache",
            "vendor",
            "target",  # Rust/Java build output
        ],
        skip_files=["**/*.pyc", "**/*.so", "**/*.dylib", "**/*.dll"],
        severity_threshold="HIGH",
        suppress_rules=[],
        timeout=180,  # Shorter timeout for minimal scans
        skip_when_no_files=True,
    ),
    layers=LayerPreset(
        runtime_wrappers=True,
        pre_commit_hooks=False,  # Minimal: no hooks
        container_isolation=False,
        network_proxy=False,
        audit_logging=False,  # Minimal: no audit logs
    ),
)

BALANCED_PRESET = Preset(
    level="balanced",
    description="Full static analysis with reasonable defaults (default)",
    scanner=ScannerPreset(
        enabled_scanners=[
            "trivy-secrets",
            "trivy-misconfig",
            "bandit",
            "semgrep",
        ],
        skip_dirs=[
            ".venv",
            ".tox",
            "node_modules",
            "build",
            "dist",
            ".eggs",
            "__pycache__",
        ],
        skip_files=["**/*.pyc"],
        severity_threshold="MEDIUM",
        suppress_rules=[],
        timeout=300,
        skip_when_no_files=True,
    ),
    layers=LayerPreset(
        runtime_wrappers=True,
        pre_commit_hooks=True,
        container_isolation=False,
        network_proxy=False,
        audit_logging=True,
    ),
)

STRICT_PRESET = Preset(
    level="strict",
    description="Container isolation with aggressive scanning",
    scanner=ScannerPreset(
        enabled_scanners=[
            "trivy-secrets",
            "trivy-misconfig",
            "bandit",
            "semgrep",
        ],
        skip_dirs=[
            ".venv",
            ".tox",
            "node_modules",
            "__pycache__",
        ],
        skip_files=[],  # Scan everything
        severity_threshold="LOW",  # Report all severities
        suppress_rules=[],
        timeout=600,  # Longer timeout for thorough scans
        skip_when_no_files=True,
    ),
    layers=LayerPreset(
        runtime_wrappers=True,
        pre_commit_hooks=True,
        container_isolation=True,
        network_proxy=False,
        audit_logging=True,
    ),
)

PARANOID_PRESET = Preset(
    level="paranoid",
    description="Maximum security with network isolation and comprehensive scanning",
    scanner=ScannerPreset(
        enabled_scanners=[
            "trivy-secrets",
            "trivy-misconfig",
            "bandit",
            "semgrep",
        ],
        skip_dirs=[],  # Scan everything, even .venv
        skip_files=[],  # Scan everything
        severity_threshold="LOW",
        suppress_rules=[],
        timeout=900,  # Very long timeout for exhaustive scans
        skip_when_no_files=False,  # Run all scanners regardless
    ),
    layers=LayerPreset(
        runtime_wrappers=True,
        pre_commit_hooks=True,
        container_isolation=True,
        network_proxy=True,
        audit_logging=True,
    ),
)

# Preset registry for lookup by level
PRESETS: dict[PresetLevel, Preset] = {
    "minimal": MINIMAL_PRESET,
    "balanced": BALANCED_PRESET,
    "strict": STRICT_PRESET,
    "paranoid": PARANOID_PRESET,
}

# Default preset when none specified
DEFAULT_PRESET: PresetLevel = "balanced"


# ---------------------------------------------------------------------------
# Preset resolution
# ---------------------------------------------------------------------------


def get_preset(level: PresetLevel | None = None) -> Preset:
    """Get preset configuration by level.

    Args:
        level: Preset level ("minimal", "balanced", "strict", "paranoid")
               If None, returns the default preset (balanced).

    Returns:
        Preset configuration

    Raises:
        KeyError: If level is not a valid preset level
    """
    if level is None:
        level = DEFAULT_PRESET
    return PRESETS[level]


def validate_preset_level(level: str) -> PresetLevel:
    """Validate a preset level string.

    Args:
        level: String to validate

    Returns:
        Validated PresetLevel

    Raises:
        ValueError: If level is not valid
    """
    valid_levels = {"minimal", "balanced", "strict", "paranoid"}
    if level not in valid_levels:
        raise ValueError(
            f"Invalid preset level: {level!r}. Valid levels: {', '.join(sorted(valid_levels))}"
        )
    return level  # type: ignore[return-value]
