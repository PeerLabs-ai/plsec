"""Claude Code data adapter -- version probing from JSONL data store.

Claude Code stores session data as JSONL files under
~/.claude/projects/{path-hash}/.  Each line is a JSON object;
message and system event lines include a ``version`` field recording
the Claude Code binary version (e.g., "2.1.39").

Not every JSONL line has a ``version`` field (e.g., file-history-snapshot
lines omit it), so we scan backwards from the end of the most recent
file until we find one.

Milestone 14a: Version probing only.
Milestone 15:  Full AgentDataAdapter implementation.
"""

import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)

# Subdirectory under ~/.claude/ that contains project data.
PROJECTS_SUBDIR = "projects"


def _find_most_recent_jsonl(projects_dir: Path) -> Path | None:
    """Find the most recently modified top-level JSONL file.

    Searches all project directories under ``projects_dir`` for
    ``*.jsonl`` files at the top level (not inside subagent dirs).
    Returns the most recently modified one, or None.
    """
    if not projects_dir.is_dir():
        return None

    candidates: list[tuple[float, Path]] = []
    for project_dir in projects_dir.iterdir():
        if not project_dir.is_dir():
            continue
        for jsonl_file in project_dir.glob("*.jsonl"):
            if jsonl_file.is_file():
                try:
                    mtime = jsonl_file.stat().st_mtime
                    candidates.append((mtime, jsonl_file))
                except OSError:
                    continue

    if not candidates:
        return None

    # Sort by mtime descending, return the most recent
    candidates.sort(key=lambda pair: pair[0], reverse=True)
    return candidates[0][1]


def _extract_version_from_tail(jsonl_path: Path, max_lines: int = 50) -> str | None:
    """Read the last N lines of a JSONL file and extract the version field.

    Scans backwards from the end of the file to find the first line
    containing a ``"version"`` key.  Returns the version string or None.
    """
    try:
        # Read the file in binary, seek from end for efficiency
        size = jsonl_path.stat().st_size
        if size == 0:
            return None

        # Read at most the last 64KB (sufficient for ~50 lines of JSONL)
        read_size = min(size, 65536)
        with open(jsonl_path, "rb") as fh:
            fh.seek(max(0, size - read_size))
            tail_bytes = fh.read()

        lines = tail_bytes.decode("utf-8", errors="replace").splitlines()

        # Scan from the end to find a line with "version"
        for line in reversed(lines[-max_lines:]):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict) and "version" in obj:
                    version = obj["version"]
                    if isinstance(version, str) and version:
                        return version
            except (json.JSONDecodeError, KeyError):
                continue

    except OSError as exc:
        log.debug("Claude JSONL read error: %s", exc)

    return None


def probe_claude_data_version(data_dir: Path) -> str | None:
    """Read the Claude Code version from the most recent JSONL session.

    Args:
        data_dir: Path to the Claude Code data directory
                  (e.g., ~/.claude/).

    Returns:
        Version string (e.g., "2.1.39") or None if no JSONL files
        are found or none contain a version field.
    """
    projects_dir = data_dir / PROJECTS_SUBDIR
    if not projects_dir.is_dir():
        log.debug("Claude projects directory not found: %s", projects_dir)
        return None

    jsonl_path = _find_most_recent_jsonl(projects_dir)
    if jsonl_path is None:
        log.debug("No Claude JSONL files found under %s", projects_dir)
        return None

    version = _extract_version_from_tail(jsonl_path)
    if version is None:
        log.debug("No version field in %s", jsonl_path)
    return version
