"""Agent data adapters -- version detection and data access.

This package provides version probing and (in future milestones) full
data access for AI coding agent data stores.  Each agent has a dedicated
module that understands its storage format.

Milestone 14a: Version probing only (probe_*_data_version functions).
Milestone 15:  Full AgentDataAdapter implementations.

See docs/DESIGN-AGENT-MONITORING.md for the complete architecture.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

# ---------------------------------------------------------------------------
# Shared data types
# ---------------------------------------------------------------------------


@dataclass
class ValidatedVersion:
    """A single entry from the compatibility registry's validated list."""

    version: str
    date: str
    status: str  # "compatible" | "incompatible"


@dataclass
class AdapterCompat:
    """Compatibility metadata for one agent's data adapter.

    Loaded from compatibility.yaml.  Describes the agent's data format,
    binary command, and which versions have been validated.
    """

    agent_id: str
    data_dir: str
    format: str  # "sqlite" | "jsonl"
    binary_command: str
    version_flag: str
    validated: list[ValidatedVersion]
    untested_range: str  # semver range, e.g., ">=1.3.0"
    known_incompatible: list[str]
    min_supported: str
    stats_cache_format_version: int | None = None


@dataclass
class VersionProbe:
    """Result of probing an agent's installed versions.

    Captures both the binary version (from running the command) and
    the data store version (from reading the agent's local data).
    """

    agent_id: str
    binary_version: str | None = None
    data_version: str | None = None
    data_dir_exists: bool = False
    binary_found: bool = False


@dataclass
class CompatResult:
    """Compatibility assessment for one agent.

    Produced by check_version_compatibility() after comparing a
    VersionProbe against the AdapterCompat registry entry.
    """

    agent_id: str
    probe: VersionProbe
    verdict: Literal["ok", "warn", "fail", "skip"]
    detail: str
    effective_version: str | None = None


# ---------------------------------------------------------------------------
# Protocol stub for full adapters (milestone 15)
# ---------------------------------------------------------------------------


@dataclass
class SessionSummary:
    """Lightweight session metadata returned by adapters."""

    session_id: str
    title: str
    directory: str
    agent_version: str
    time_created: int  # Unix timestamp ms
    time_updated: int
    message_count: int = 0
    tool_call_count: int = 0
    file_changes: int = 0
    total_tokens: int = 0


@dataclass
class ToolCall:
    """A single tool invocation record."""

    tool: str  # "bash", "read", "edit", etc.
    input_summary: str  # Truncated input (first 200 chars)
    status: str  # "completed", "error"
    timestamp: int = 0


@dataclass
class TokenUsage:
    """Aggregated token usage for a session or time period."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    reasoning_tokens: int = 0


@dataclass
class ErrorRecord:
    """An error event from the agent."""

    error_type: str  # "APIError", "timeout", etc.
    message: str
    timestamp: int = 0
    is_retryable: bool = False


class AgentDataAdapter(Protocol):
    """Protocol for reading agent operational data.

    Implementations live in per-agent modules (opencode.py, claude.py).
    Each adapter understands one agent's storage format and provides a
    uniform interface for version detection, session listing, tool call
    auditing, and token tracking.

    Milestone 14a implements only detect() and version().
    Full implementations come in milestone 15.
    """

    def detect(self) -> bool:
        """Is this agent's data store present on disk?"""
        ...

    def version(self) -> str | None:
        """Agent version that last wrote to the data store."""
        ...

    def sessions(self, project_dir: Path | None = None) -> list[SessionSummary]:
        """List sessions, optionally filtered to a project directory."""
        ...

    def tool_calls(self, session_id: str) -> list[ToolCall]:
        """Get tool call audit trail for a session."""
        ...

    def bash_commands(self, session_id: str) -> list[ToolCall]:
        """Get bash/shell commands only (security audit focus)."""
        ...

    def token_usage(self, session_id: str | None = None) -> TokenUsage:
        """Token usage for a session (or total if session_id is None)."""
        ...

    def errors(self, since_timestamp: int | None = None) -> list[ErrorRecord]:
        """Error records, optionally filtered by time."""
        ...
