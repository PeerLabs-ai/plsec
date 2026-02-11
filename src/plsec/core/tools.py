"""
Tool checking and dependency management.

Provides utilities for checking if required tools are installed
and functional.
"""

import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class ToolStatus(Enum):
    """Status of a tool check."""

    OK = "ok"
    MISSING = "missing"
    OUTDATED = "outdated"
    ERROR = "error"


@dataclass
class Tool:
    """Represents an external tool dependency."""

    name: str
    command: str
    required: bool = True
    min_version: str | None = None
    install_hint: str = ""
    version_flag: str = "--version"
    version_parser: Callable[[str], str] | None = None

    # Populated after check
    status: ToolStatus = field(default=ToolStatus.MISSING, init=False)
    version: str | None = field(default=None, init=False)
    path: str | None = field(default=None, init=False)
    error: str | None = field(default=None, init=False)


# Default tools required by plsec
REQUIRED_TOOLS: list[Tool] = [
    Tool(
        name="Trivy",
        command="trivy",
        required=True,
        min_version="0.50.0",
        install_hint="brew install trivy",
        version_flag="version",
    ),
    Tool(
        name="Bandit",
        command="bandit",
        required=False,
        install_hint="pip install bandit",
    ),
    Tool(
        name="Semgrep",
        command="semgrep",
        required=False,
        install_hint="pip install semgrep",
    ),
    Tool(
        name="detect-secrets",
        command="detect-secrets",
        required=False,
        install_hint="pip install detect-secrets",
    ),
]

OPTIONAL_TOOLS: list[Tool] = [
    Tool(
        name="Pipelock",
        command="pipelock",
        required=False,
        install_hint="go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest",
    ),
    Tool(
        name="Podman",
        command="podman",
        required=False,
        install_hint="brew install podman",
    ),
    Tool(
        name="Docker",
        command="docker",
        required=False,
        install_hint="brew install --cask docker",
    ),
]


class ToolChecker:
    """Checks for required and optional tool dependencies."""

    def __init__(self, tools: list[Tool] | None = None) -> None:
        """
        Initialize tool checker.

        Args:
            tools: List of tools to check. Defaults to REQUIRED_TOOLS.
        """
        self.tools = tools or REQUIRED_TOOLS.copy()

    def check_tool(self, tool: Tool) -> Tool:
        """
        Check if a single tool is available.

        Args:
            tool: Tool to check.

        Returns:
            Tool with status updated.
        """
        # Check if command exists
        path = shutil.which(tool.command)
        if path is None:
            tool.status = ToolStatus.MISSING
            tool.error = f"Command '{tool.command}' not found in PATH"
            return tool

        tool.path = path

        # Try to get version
        try:
            result = subprocess.run(
                [tool.command, tool.version_flag],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout or result.stderr

            # Parse version if parser provided
            if tool.version_parser:
                tool.version = tool.version_parser(output)
            else:
                # Simple extraction: first line, first word that looks like version
                for line in output.split("\n"):
                    for word in line.split():
                        if any(c.isdigit() for c in word):
                            # Strip common prefixes
                            version = word.lstrip("v").rstrip(",")
                            if version[0].isdigit():
                                tool.version = version
                                break
                    if tool.version:
                        break

            tool.status = ToolStatus.OK

            # Check minimum version if specified
            if tool.min_version and tool.version:
                if not self._version_gte(tool.version, tool.min_version):
                    tool.status = ToolStatus.OUTDATED
                    tool.error = f"Version {tool.version} < {tool.min_version}"

        except subprocess.TimeoutExpired:
            tool.status = ToolStatus.ERROR
            tool.error = "Command timed out"
        except Exception as e:
            tool.status = ToolStatus.ERROR
            tool.error = str(e)

        return tool

    def check_all(self) -> list[Tool]:
        """
        Check all tools.

        Returns:
            List of tools with status updated.
        """
        for tool in self.tools:
            self.check_tool(tool)
        return self.tools

    def get_missing(self) -> list[Tool]:
        """Get list of missing required tools."""
        return [
            t for t in self.tools if t.required and t.status == ToolStatus.MISSING
        ]

    def get_outdated(self) -> list[Tool]:
        """Get list of outdated tools."""
        return [t for t in self.tools if t.status == ToolStatus.OUTDATED]

    def all_required_ok(self) -> bool:
        """Check if all required tools are OK."""
        return all(
            t.status == ToolStatus.OK for t in self.tools if t.required
        )

    @staticmethod
    def _version_gte(version: str, minimum: str) -> bool:
        """
        Check if version >= minimum using simple comparison.

        Args:
            version: Version string (e.g., "1.2.3")
            minimum: Minimum version string

        Returns:
            True if version >= minimum
        """
        try:
            # Split into parts and compare numerically
            v_parts = [int(x) for x in version.split(".")[:3]]
            m_parts = [int(x) for x in minimum.split(".")[:3]]

            # Pad to same length
            while len(v_parts) < len(m_parts):
                v_parts.append(0)
            while len(m_parts) < len(v_parts):
                m_parts.append(0)

            return v_parts >= m_parts
        except ValueError:
            # If parsing fails, assume OK
            return True
