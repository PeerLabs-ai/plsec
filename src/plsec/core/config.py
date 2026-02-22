"""
Configuration management for plsec.

Handles loading, validating, and accessing plsec.yaml configuration.
Uses plain dataclasses - Pydantic is not needed for this use case.
"""

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

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
    Find plsec.yaml in current directory or parents.

    Search order:
    1. ./plsec.yaml
    2. Parent directories up to home
    3. ~/.peerlabs/plsec/plsec.yaml
    """
    cwd = Path.cwd()

    # Check current and parent directories
    for parent in [cwd, *cwd.parents]:
        config_path = parent / "plsec.yaml"
        if config_path.exists():
            return config_path
        # Stop at home directory
        if parent == Path.home():
            break

    # Check global config
    global_config = Path.home() / ".peerlabs" / "plsec" / "plsec.yaml"
    if global_config.exists():
        return global_config

    return None


def load_config(config_path: Path | str | None = None) -> PlsecConfig:
    """
    Load and validate plsec configuration.

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

    with open(path) as f:
        data = yaml.safe_load(f)

    if data is None:
        return PlsecConfig()

    _validate_config(data)
    return _from_dict(PlsecConfig, data)


def save_config(config: PlsecConfig, path: Path | str) -> None:
    """
    Save configuration to file.

    Args:
        config: PlsecConfig object to save.
        path: Destination path.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = _to_dict(config)

    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def get_plsec_home() -> Path:
    """Get plsec home directory, creating if needed."""
    home = Path.home() / ".peerlabs" / "plsec"
    home.mkdir(parents=True, exist_ok=True)
    return home
