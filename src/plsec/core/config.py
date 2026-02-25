"""
Configuration management for plsec.

Handles loading, validating, and accessing configuration files.
Supports both TOML (plsec.toml) and YAML (plsec.yaml) formats.
TOML is preferred when both exist.

Uses plain dataclasses - Pydantic is not needed for this use case.
"""

import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

import tomli_w
import yaml

# ---------------------------------------------------------------------------
# Literal types for constrained fields
# ---------------------------------------------------------------------------

RuntimeType = Literal["podman", "docker", "sandbox"]
ProxyMode = Literal["audit", "balanced", "strict"]
ProjectType = Literal["python", "node", "go", "mixed"]
StorageType = Literal["keychain", "env", "file"]


def _valid_agent_types() -> set[str]:
    """Build the set of valid agent config_type values from the AGENTS registry.

    Imported lazily to avoid circular imports (agents.py -> templates.py is safe,
    but config.py is imported by many modules).
    """
    from plsec.core.agents import AGENTS

    return {spec.config_type for spec in AGENTS.values()}


_LITERAL_CONSTRAINTS: dict[str, set[str]] = {
    "runtime": {"podman", "docker", "sandbox"},
    "mode": {"audit", "balanced", "strict"},
    # agent_type is resolved dynamically — see _resolve_constraint()
    "project_type": {"python", "node", "go", "mixed"},
    "storage": {"keychain", "env", "file"},
}


def _resolve_constraint(field_name: str) -> set[str]:
    """Resolve a constraint set, handling dynamically-generated ones."""
    if field_name == "agent_type":
        return _valid_agent_types()
    return _LITERAL_CONSTRAINTS[field_name]


def _validate_literal(value: str, field_name: str, allowed: set[str]) -> str:
    """Validate a string value against allowed Literal values at load boundary."""
    if value not in allowed:
        raise ValueError(f"Invalid {field_name}: {value!r} (allowed: {sorted(allowed)})")
    return value


# ---------------------------------------------------------------------------
# Configuration dataclasses
# ---------------------------------------------------------------------------


@dataclass
class StaticLayerConfig:
    """Static analysis layer configuration."""

    enabled: bool = True
    scanners: list[str] = field(
        default_factory=lambda: [
            "trivy-secrets",
            "trivy-misconfig",
            "bandit",
            "semgrep",
        ]
    )


@dataclass
class IsolationLayerConfig:
    """Container/sandbox isolation layer configuration."""

    enabled: bool = False
    runtime: RuntimeType = "podman"


@dataclass
class ProxyLayerConfig:
    """Runtime proxy layer configuration."""

    enabled: bool = False
    binary: str = "pipelock"
    mode: ProxyMode = "balanced"
    config: str = "./pipelock.yaml"


@dataclass
class AuditLayerConfig:
    """Audit logging layer configuration."""

    enabled: bool = True
    log_dir: str = "~/.peerlabs/plsec/logs"
    integrity: bool = True


@dataclass
class LayersConfig:
    """All security layers configuration."""

    static: StaticLayerConfig = field(default_factory=StaticLayerConfig)
    isolation: IsolationLayerConfig = field(default_factory=IsolationLayerConfig)
    proxy: ProxyLayerConfig = field(default_factory=ProxyLayerConfig)
    audit: AuditLayerConfig = field(default_factory=AuditLayerConfig)


@dataclass
class AgentConfig:
    """AI agent configuration."""

    # Validated at load time against AGENTS registry config_type values
    type: str = "claude-code"
    config_path: str = "./CLAUDE.md"


@dataclass
class ProjectConfig:
    """Project metadata configuration."""

    name: str = "unknown"
    type: ProjectType = "python"


@dataclass
class CredentialsConfig:
    """Credentials storage configuration."""

    storage: StorageType = "keychain"
    keys: list[str] = field(default_factory=list)


@dataclass
class PlsecConfig:
    """Main plsec configuration model."""

    version: int = 1
    preset: str = "balanced"  # Preset level: minimal, balanced, strict, paranoid
    project: ProjectConfig = field(default_factory=ProjectConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    layers: LayersConfig = field(default_factory=LayersConfig)
    credentials: CredentialsConfig = field(default_factory=CredentialsConfig)


# ---------------------------------------------------------------------------
# Serialization: dataclass <-> dict
# ---------------------------------------------------------------------------

# Maps top-level dict keys to (dataclass, nested_fields) for reconstruction.
# nested_fields maps field names to their dataclass type for recursive loading.
_NESTED_FIELDS: dict[type, dict[str, type]] = {
    PlsecConfig: {
        "project": ProjectConfig,
        "agent": AgentConfig,
        "layers": LayersConfig,
        "credentials": CredentialsConfig,
    },
    LayersConfig: {
        "static": StaticLayerConfig,
        "isolation": IsolationLayerConfig,
        "proxy": ProxyLayerConfig,
        "audit": AuditLayerConfig,
    },
}


def _from_dict(cls: type, data: dict) -> Any:
    """Recursively construct a dataclass from a dict, using defaults for missing keys."""
    nested = _NESTED_FIELDS.get(cls, {})
    kwargs = {}
    for k, v in data.items():
        if k in nested and isinstance(v, dict):
            kwargs[k] = _from_dict(nested[k], v)
        else:
            kwargs[k] = v
    return cls(**kwargs)


def _to_dict(config: PlsecConfig) -> dict[str, Any]:
    """Convert a PlsecConfig to a plain dict for YAML serialization."""
    return asdict(config)


def _validate_config(data: dict) -> None:
    """Validate constrained fields at load boundary.

    Raises ValueError for invalid Literal values.
    """
    # Project type
    if "project" in data and "type" in data["project"]:
        _validate_literal(
            data["project"]["type"], "project.type", _LITERAL_CONSTRAINTS["project_type"]
        )

    # Agent type -- resolved dynamically from AGENTS registry
    if "agent" in data and "type" in data["agent"]:
        _validate_literal(data["agent"]["type"], "agent.type", _resolve_constraint("agent_type"))

    # Layers
    layers = data.get("layers", {})
    if "isolation" in layers and "runtime" in layers["isolation"]:
        _validate_literal(
            layers["isolation"]["runtime"],
            "layers.isolation.runtime",
            _LITERAL_CONSTRAINTS["runtime"],
        )
    if "proxy" in layers and "mode" in layers["proxy"]:
        _validate_literal(
            layers["proxy"]["mode"], "layers.proxy.mode", _LITERAL_CONSTRAINTS["mode"]
        )

    # Credentials
    if "credentials" in data and "storage" in data["credentials"]:
        _validate_literal(
            data["credentials"]["storage"], "credentials.storage", _LITERAL_CONSTRAINTS["storage"]
        )


# ---------------------------------------------------------------------------
# Public API: find, load, save, home
# ---------------------------------------------------------------------------


def find_config_file() -> Path | None:
    """
    Find plsec config file (TOML or YAML) in current directory or parents.

    Search order (TOML preferred over YAML):
    1. ./plsec.toml or ./plsec.yaml
    2. Parent directories up to home
    3. ~/.peerlabs/plsec/plsec.toml or ~/.peerlabs/plsec/plsec.yaml
    """
    cwd = Path.cwd()

    # Check current and parent directories
    for parent in [cwd, *cwd.parents]:
        # Prefer TOML over YAML
        toml_path = parent / "plsec.toml"
        if toml_path.exists():
            return toml_path

        yaml_path = parent / "plsec.yaml"
        if yaml_path.exists():
            return yaml_path

        # Stop at home directory
        if parent == Path.home():
            break

    # Check global config (prefer TOML)
    global_toml = Path.home() / ".peerlabs" / "plsec" / "plsec.toml"
    if global_toml.exists():
        return global_toml

    global_yaml = Path.home() / ".peerlabs" / "plsec" / "plsec.yaml"
    if global_yaml.exists():
        return global_yaml

    return None


def load_config(config_path: Path | str | None = None) -> PlsecConfig:
    """
    Load and validate plsec configuration from TOML or YAML.

    Args:
        config_path: Explicit path to config file, or None to search.

    Returns:
        Validated PlsecConfig object.

    Raises:
        FileNotFoundError: If config file not found.
        ValueError: If config is invalid.
    """
    if config_path is None:
        config_path = find_config_file()

    if config_path is None:
        # Return defaults if no config found
        return PlsecConfig()

    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    # Determine format from extension
    if path.suffix == ".toml":
        with open(path, "rb") as f:
            data = tomllib.load(f)
    elif path.suffix in {".yaml", ".yml"}:
        with open(path) as f:
            data = yaml.safe_load(f)
    else:
        raise ValueError(f"Unsupported config file format: {path.suffix} (use .toml or .yaml)")

    if data is None:
        return PlsecConfig()

    _validate_config(data)
    return _from_dict(PlsecConfig, data)


def save_config(config: PlsecConfig, path: Path | str, *, format: str | None = None) -> None:
    """
    Save configuration to file in TOML or YAML format.

    Args:
        config: PlsecConfig object to save.
        path: Destination path.
        format: Output format ("toml" or "yaml"). If None, determined from path extension.

    Raises:
        ValueError: If format cannot be determined or is unsupported.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = _to_dict(config)

    # Determine format
    if format is None:
        if path.suffix == ".toml":
            format = "toml"
        elif path.suffix in {".yaml", ".yml"}:
            format = "yaml"
        else:
            raise ValueError(f"Cannot determine format from extension: {path.suffix}")

    # Write in requested format
    if format == "toml":
        with open(path, "wb") as f:
            tomli_w.dump(data, f)
    elif format == "yaml":
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    else:
        raise ValueError(f"Unsupported format: {format!r} (use 'toml' or 'yaml')")


def resolve_config(
    *,
    cli_preset: str | None = None,
    project_config_path: Path | None = None,
    global_config_path: Path | None = None,
) -> tuple[PlsecConfig, str]:
    """
    Resolve configuration hierarchy: CLI > Project > Global > Preset defaults.

    Args:
        cli_preset: Preset level from CLI --preset flag (highest priority)
        project_config_path: Path to project config file (or None to search cwd)
        global_config_path: Path to global config file (or None to use default)

    Returns:
        Tuple of (resolved PlsecConfig, effective preset level string)

    Resolution order:
    1. If cli_preset provided, use that preset level
    2. Else if project config exists and has preset field, use that
    3. Else if global config exists and has preset field, use that
    4. Else use "balanced" (default)

    The returned PlsecConfig contains the merged configuration with the
    effective preset level set in the .preset field.
    """
    # Load project config (search from cwd if not specified)
    if project_config_path is None:
        # Find config starting from cwd, but stop before going to global
        cwd = Path.cwd()
        for parent in [cwd, *cwd.parents]:
            toml_path = parent / "plsec.toml"
            if toml_path.exists():
                project_config_path = toml_path
                break
            yaml_path = parent / "plsec.yaml"
            if yaml_path.exists():
                project_config_path = yaml_path
                break
            if parent == Path.home():
                break

    project_config = None
    if project_config_path and Path(project_config_path).exists():
        project_config = load_config(project_config_path)

    # Load global config
    if global_config_path is None:
        global_home = get_plsec_home()
        global_toml = global_home / "plsec.toml"
        global_yaml = global_home / "plsec.yaml"
        if global_toml.exists():
            global_config_path = global_toml
        elif global_yaml.exists():
            global_config_path = global_yaml

    global_config = None
    if global_config_path and Path(global_config_path).exists():
        global_config = load_config(global_config_path)

    # Resolve preset level (CLI > Project > Global > Default)
    if cli_preset is not None:
        effective_preset = cli_preset
    elif project_config is not None and project_config.preset:
        effective_preset = project_config.preset
    elif global_config is not None and global_config.preset:
        effective_preset = global_config.preset
    else:
        effective_preset = "balanced"

    # Start with project config or global config or defaults
    if project_config is not None:
        resolved = project_config
    elif global_config is not None:
        resolved = global_config
    else:
        resolved = PlsecConfig()

    # Set the effective preset
    resolved.preset = effective_preset

    return resolved, effective_preset


def get_plsec_home() -> Path:
    """Get plsec home directory, creating if needed."""
    home = Path.home() / ".peerlabs" / "plsec"
    home.mkdir(parents=True, exist_ok=True)
    return home
