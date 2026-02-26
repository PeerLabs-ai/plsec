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
    "severity_threshold": {"LOW", "MEDIUM", "HIGH", "CRITICAL"},
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
    skip_dirs: list[str] = field(
        default_factory=lambda: [
            ".venv",
            ".tox",
            "node_modules",
            "build",
            "dist",
            ".eggs",
            "__pycache__",
        ]
    )
    skip_files: list[str] = field(default_factory=lambda: ["**/*.pyc"])
    severity_threshold: str = "MEDIUM"
    timeout: int = 300
    skip_when_no_files: bool = True


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
class RuntimeLayerConfig:
    """Runtime wrappers and hooks layer configuration."""

    wrappers: bool = True
    hooks: bool = True


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
    runtime: RuntimeLayerConfig = field(default_factory=RuntimeLayerConfig)
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

    # Provenance tracking for --verbose output (field path -> source)
    _provenance: dict[str, str] = field(default_factory=dict, repr=False)


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
        "runtime": RuntimeLayerConfig,
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
    if "static" in layers and "severity_threshold" in layers["static"]:
        _validate_literal(
            layers["static"]["severity_threshold"],
            "layers.static.severity_threshold",
            _LITERAL_CONSTRAINTS["severity_threshold"],
        )

    # Credentials
    if "credentials" in data and "storage" in data["credentials"]:
        _validate_literal(
            data["credentials"]["storage"], "credentials.storage", _LITERAL_CONSTRAINTS["storage"]
        )


def _merge_dicts(
    base: dict[str, Any],
    override: dict[str, Any],
    source: str,
    path: str = "",
    provenance: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Merge two raw config dicts with union semantics.

    Rules:
    - Lists: Union + deduplicate (preserve base order, append unique override items)
    - Scalars/Booleans: override value wins (last-in-chain)
    - Nested dicts: Recursive merge

    Args:
        base: Base configuration dict (lower priority)
        override: Override configuration dict (higher priority)
        source: Human-readable source label for provenance tracking
        path: Dotted path for provenance (e.g., "layers.static.scanners")
        provenance: Provenance tracking dict (mutated in place)

    Returns:
        Merged configuration dict
    """
    if provenance is None:
        provenance = {}

    result = base.copy()

    for key, override_value in override.items():
        current_path = f"{path}.{key}" if path else key

        if key not in result:
            # New key from override
            result[key] = override_value
            provenance[current_path] = source
        else:
            base_value = result[key]

            # Determine merge strategy based on type
            if isinstance(base_value, dict) and isinstance(override_value, dict):
                # Nested dict: recurse
                result[key] = _merge_dicts(
                    base_value, override_value, source, current_path, provenance
                )
            elif isinstance(base_value, list) and isinstance(override_value, list):
                # List: union + deduplicate (preserve order)
                merged_list = base_value.copy()
                for item in override_value:
                    if item not in merged_list:
                        merged_list.append(item)
                result[key] = merged_list
                if merged_list != base_value:
                    provenance[current_path] = source
            else:
                # Scalar/bool: override wins
                result[key] = override_value
                if override_value != base_value:
                    provenance[current_path] = source

    return result


def merge_configs(
    base: PlsecConfig,
    override: PlsecConfig,
    source: str = "unknown",
) -> PlsecConfig:
    """
    Merge two PlsecConfig instances with union semantics.

    Rules:
    - Lists: Union + deduplicate (base + unique items from override)
    - Scalars/Booleans: override wins (last-in-chain)
    - Nested objects: Recursive merge layer-by-layer
    - Provenance: Track which source provided each value

    Args:
        base: Base configuration (lower priority)
        override: Override configuration (higher priority)
        source: Human-readable source label for provenance

    Returns:
        Merged PlsecConfig with provenance tracking

    Example:
        >>> base = load_preset("balanced")
        >>> project = load_config("./plsec.toml")
        >>> merged = merge_configs(base, project, source="project")
        >>> merged._provenance["layers.static.scanners"]
        'project'
    """
    # Convert to dicts
    base_dict = _to_dict(base)
    override_dict = _to_dict(override)

    # Remove _provenance from dicts before merge (it's metadata, not config)
    base_dict.pop("_provenance", None)
    override_dict.pop("_provenance", None)

    # Merge dicts with provenance tracking
    provenance: dict[str, str] = {}
    merged_dict = _merge_dicts(base_dict, override_dict, source, provenance=provenance)

    # Carry forward base provenance, then update with new provenance
    merged_provenance = base._provenance.copy()
    merged_provenance.update(provenance)

    # Reconstruct PlsecConfig from merged dict
    merged = _from_dict(PlsecConfig, merged_dict)
    merged._provenance = merged_provenance

    return merged


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
    cli_overrides: dict[str, Any] | None = None,
    project_config_path: Path | None = None,
    global_config_path: Path | None = None,
) -> tuple[PlsecConfig, str]:
    """
    Resolve configuration from all sources with merge semantics.

    Resolution hierarchy (low to high priority):
    1. Defaults (PlsecConfig factory defaults)
    2. Preset file (~/.peerlabs/plsec/config/presets/{preset}.toml or built-in)
    3. Global config (~/.peerlabs/plsec/plsec.toml)
    4. Project config (./plsec.toml or ancestor directories)
    5. CLI arguments (highest priority)

    Merge semantics:
    - Lists: Union + deduplicate (base + unique items from higher priority)
    - Scalars/Booleans: Last-in-chain wins
    - Nested objects: Recursive merge

    Args:
        cli_preset: Preset level from CLI --preset flag (highest priority for preset selection)
        cli_overrides: Dict of CLI flag values (e.g., {"layers": {"static": {"scanners": [...]}}})
        project_config_path: Path to project config file (or None to search cwd)
        global_config_path: Path to global config file (or None to use default)

    Returns:
        Tuple of (resolved PlsecConfig with provenance tracking, effective preset level string)

    Example:
        >>> config, preset = resolve_config(cli_preset="strict")
        >>> config.layers.static.scanners
        ['trivy-secrets', 'trivy-misconfig', 'bandit', 'semgrep']
        >>> config._provenance["layers.static.scanners"]
        'preset:strict'
    """
    from plsec.core.presets import load_preset

    # 1. Determine which preset to load (CLI > project > global > default "balanced")
    # We need to peek at project/global configs to check their preset field
    project_config_raw = None
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

    if project_config_path and Path(project_config_path).exists():
        project_config_raw = load_config(project_config_path)

    global_config_raw = None
    if global_config_path is None:
        global_home = get_plsec_home()
        global_toml = global_home / "plsec.toml"
        global_yaml = global_home / "plsec.yaml"
        if global_toml.exists():
            global_config_path = global_toml
        elif global_yaml.exists():
            global_config_path = global_yaml

    if global_config_path and Path(global_config_path).exists():
        global_config_raw = load_config(global_config_path)

    # Determine preset name
    if cli_preset is not None:
        effective_preset = cli_preset
    elif project_config_raw is not None and project_config_raw.preset:
        effective_preset = project_config_raw.preset
    elif global_config_raw is not None and global_config_raw.preset:
        effective_preset = global_config_raw.preset
    else:
        effective_preset = "balanced"

    # 2. Load preset as the base configuration (preset IS the defaults)
    try:
        preset_dict = load_preset(effective_preset)
        # Convert preset dict to PlsecConfig
        config = _from_dict(PlsecConfig, preset_dict)
        config._provenance = {f"preset:{effective_preset}": effective_preset}
    except FileNotFoundError:
        # Preset not found, fall back to factory defaults
        config = PlsecConfig()

    # 3. Merge global config (layers on top of preset)
    if global_config_raw is not None:
        config = merge_configs(config, global_config_raw, source="global")

    # 4. Merge project config (layers on top of global + preset)
    if project_config_raw is not None:
        config = merge_configs(config, project_config_raw, source="project")

    # 5. Apply CLI overrides (highest priority)
    if cli_overrides:
        cli_config = _from_dict(PlsecConfig, cli_overrides)
        config = merge_configs(config, cli_config, source="cli")

    # Set the effective preset name
    config.preset = effective_preset

    return config, effective_preset


def get_plsec_home() -> Path:
    """Get plsec home directory, creating if needed."""
    home = Path.home() / ".peerlabs" / "plsec"
    home.mkdir(parents=True, exist_ok=True)
    return home
