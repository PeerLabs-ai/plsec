"""
Configuration management for plsec.

Handles loading, validating, and accessing plsec.yaml configuration.
"""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class StaticLayerConfig(BaseModel):
    """Static analysis layer configuration."""

    enabled: bool = True
    scanners: list[str] = Field(
        default_factory=lambda: [
            "trivy-secrets",
            "trivy-misconfig",
            "bandit",
            "semgrep",
        ]
    )


class IsolationLayerConfig(BaseModel):
    """Container/sandbox isolation layer configuration."""

    enabled: bool = False
    runtime: Literal["podman", "docker", "sandbox"] = "podman"


class ProxyLayerConfig(BaseModel):
    """Runtime proxy layer configuration."""

    enabled: bool = False
    binary: str = "pipelock"
    mode: Literal["audit", "balanced", "strict"] = "balanced"
    config: str = "./pipelock.yaml"


class AuditLayerConfig(BaseModel):
    """Audit logging layer configuration."""

    enabled: bool = True
    log_dir: str = "~/.peerlabs/plsec/logs"
    integrity: bool = True


class LayersConfig(BaseModel):
    """All security layers configuration."""

    static: StaticLayerConfig = Field(default_factory=StaticLayerConfig)
    isolation: IsolationLayerConfig = Field(default_factory=IsolationLayerConfig)
    proxy: ProxyLayerConfig = Field(default_factory=ProxyLayerConfig)
    audit: AuditLayerConfig = Field(default_factory=AuditLayerConfig)


class AgentConfig(BaseModel):
    """AI agent configuration."""

    type: Literal["claude-code", "opencode", "codex"] = "claude-code"
    config_path: str = "./CLAUDE.md"


class ProjectConfig(BaseModel):
    """Project metadata configuration."""

    name: str = "unknown"
    type: Literal["python", "node", "go", "mixed"] = "python"


class CredentialsConfig(BaseModel):
    """Credentials storage configuration."""

    storage: Literal["keychain", "env", "file"] = "keychain"
    keys: list[str] = Field(default_factory=list)


class PlsecConfig(BaseModel):
    """Main plsec configuration model."""

    version: int = 1
    project: ProjectConfig = Field(default_factory=ProjectConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    layers: LayersConfig = Field(default_factory=LayersConfig)
    credentials: CredentialsConfig = Field(default_factory=CredentialsConfig)


class PlsecSettings(BaseSettings):
    """Environment-based settings."""

    plsec_config: Path = Path("./plsec.yaml")
    plsec_home: Path = Path.home() / ".peerlabs" / "plsec"
    plsec_verbose: bool = False
    plsec_quiet: bool = False

    class Config:
        env_prefix = ""
        case_sensitive = False


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

    return PlsecConfig.model_validate(data)


def save_config(config: PlsecConfig, path: Path | str) -> None:
    """
    Save configuration to file.

    Args:
        config: PlsecConfig object to save.
        path: Destination path.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = config.model_dump()

    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def get_plsec_home() -> Path:
    """Get plsec home directory, creating if needed."""
    home = Path.home() / ".peerlabs" / "plsec"
    home.mkdir(parents=True, exist_ok=True)
    return home
