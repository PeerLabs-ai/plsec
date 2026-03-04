"""Tests for agent compatibility checking (core/compatibility.py + adapters).

Covers:
- load_compatibility_registry() -- YAML parsing, both agents present
- probe_binary_version() -- subprocess mocking, version extraction
- probe_opencode_data_version() -- fixture SQLite databases
- probe_claude_data_version() -- fixture JSONL files
- probe_agent() -- combined binary + data store probing
- check_version_compatibility() -- all verdict paths (ok/warn/fail/skip, drift)
- check_all_agents() -- end-to-end with mocked probes
- _parse_version() -- semver parsing edge cases
- _parse_range_minimum() -- range string parsing

Tests use tmp_path fixtures for filesystem operations and mock
subprocess/shutil for binary detection.  No network access required.
"""

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

from plsec.core.adapters import AdapterCompat, CompatResult, ValidatedVersion, VersionProbe
from plsec.core.adapters.claude import (
    _extract_version_from_tail,
    _find_most_recent_jsonl,
    probe_claude_data_version,
)
from plsec.core.adapters.opencode import probe_opencode_data_version
from plsec.core.compatibility import (
    _parse_range_minimum,
    _parse_version,
    check_all_agents,
    check_version_compatibility,
    load_compatibility_registry,
    probe_agent,
    probe_binary_version,
)

_COMPAT_MODULE = "plsec.core.compatibility"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_compat(
    agent_id: str = "test-agent",
    *,
    data_dir: str = "~/.test",
    fmt: str = "sqlite",
    binary_command: str = "test",
    version_flag: str = "--version",
    validated: list[ValidatedVersion] | None = None,
    untested_range: str = ">=2.0.0",
    known_incompatible: list[str] | None = None,
    min_supported: str = "1.0.0",
) -> AdapterCompat:
    """Build an AdapterCompat for testing."""
    return AdapterCompat(
        agent_id=agent_id,
        data_dir=data_dir,
        format=fmt,
        binary_command=binary_command,
        version_flag=version_flag,
        validated=validated
        or [
            ValidatedVersion(version="1.2.15", date="2026-03-01", status="compatible"),
        ],
        untested_range=untested_range,
        known_incompatible=known_incompatible or [],
        min_supported=min_supported,
    )


def _make_probe(
    agent_id: str = "test-agent",
    *,
    binary_version: str | None = None,
    data_version: str | None = None,
    data_dir_exists: bool = False,
    binary_found: bool = False,
) -> VersionProbe:
    """Build a VersionProbe for testing."""
    return VersionProbe(
        agent_id=agent_id,
        binary_version=binary_version,
        data_version=data_version,
        data_dir_exists=data_dir_exists,
        binary_found=binary_found,
    )


def _create_opencode_db(db_path: Path, sessions: list[tuple[str, int]]) -> None:
    """Create a minimal OpenCode SQLite database with session data.

    Args:
        db_path: Path to create the database at.
        sessions: List of (version, time_created_ms) tuples.
    """
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE session ("
        "  id TEXT PRIMARY KEY,"
        "  version TEXT NOT NULL,"
        "  title TEXT NOT NULL DEFAULT '',"
        "  directory TEXT NOT NULL DEFAULT '',"
        "  time_created INTEGER NOT NULL,"
        "  time_updated INTEGER NOT NULL"
        ")"
    )
    for i, (version, ts) in enumerate(sessions):
        conn.execute(
            "INSERT INTO session (id, version, title, directory, time_created, time_updated)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (f"session-{i}", version, f"Session {i}", "/var/test", ts, ts),
        )
    conn.commit()
    conn.close()


def _create_jsonl_file(path: Path, lines: list[dict]) -> None:
    """Create a JSONL file from a list of dicts."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as fh:
        for obj in lines:
            fh.write(json.dumps(obj) + "\n")


# -----------------------------------------------------------------------
# load_compatibility_registry
# -----------------------------------------------------------------------


class TestLoadRegistry:
    """Contract: load_compatibility_registry() loads compatibility.yaml
    and returns a dict mapping agent_id -> AdapterCompat."""

    def test_returns_both_agents(self):
        registry = load_compatibility_registry()
        assert "opencode" in registry
        assert "claude-code" in registry

    def test_opencode_entry_shape(self):
        registry = load_compatibility_registry()
        oc = registry["opencode"]
        assert isinstance(oc, AdapterCompat)
        assert oc.agent_id == "opencode"
        assert oc.format == "sqlite"
        assert oc.binary_command == "opencode"
        assert len(oc.validated) >= 1

    def test_claude_entry_shape(self):
        registry = load_compatibility_registry()
        cc = registry["claude-code"]
        assert isinstance(cc, AdapterCompat)
        assert cc.agent_id == "claude-code"
        assert cc.format == "jsonl"
        assert cc.binary_command == "claude"
        assert cc.stats_cache_format_version == 2

    def test_validated_entries_have_required_fields(self):
        registry = load_compatibility_registry()
        for compat in registry.values():
            for v in compat.validated:
                assert isinstance(v, ValidatedVersion)
                assert v.version
                assert v.date
                assert v.status in ("compatible", "incompatible")

    def test_min_supported_is_set(self):
        registry = load_compatibility_registry()
        for compat in registry.values():
            assert compat.min_supported
            # Should be parseable as semver
            parsed = _parse_version(compat.min_supported)
            assert parsed is not None


# -----------------------------------------------------------------------
# probe_binary_version
# -----------------------------------------------------------------------


class TestProbeBinaryVersion:
    """Contract: probe_binary_version(command, flag) runs the command
    and extracts a version string from stdout."""

    def test_returns_none_when_not_found(self):
        with patch(f"{_COMPAT_MODULE}.shutil") as mock_shutil:
            mock_shutil.which.return_value = None
            result = probe_binary_version("nonexistent", "--version")
        assert result is None

    def test_extracts_version_from_stdout(self):
        with (
            patch(f"{_COMPAT_MODULE}.shutil") as mock_shutil,
            patch(f"{_COMPAT_MODULE}.subprocess") as mock_subprocess,
        ):
            mock_shutil.which.return_value = "/usr/bin/test"
            mock_result = MagicMock()
            mock_result.stdout = "test-tool v1.2.15\n"
            mock_result.stderr = ""
            mock_subprocess.run.return_value = mock_result
            result = probe_binary_version("test-tool", "--version")
        assert result == "1.2.15"

    def test_strips_v_prefix(self):
        with (
            patch(f"{_COMPAT_MODULE}.shutil") as mock_shutil,
            patch(f"{_COMPAT_MODULE}.subprocess") as mock_subprocess,
        ):
            mock_shutil.which.return_value = "/usr/bin/test"
            mock_result = MagicMock()
            mock_result.stdout = "v2.1.39\n"
            mock_result.stderr = ""
            mock_subprocess.run.return_value = mock_result
            result = probe_binary_version("test-tool", "--version")
        assert result == "2.1.39"

    def test_handles_stderr_output(self):
        with (
            patch(f"{_COMPAT_MODULE}.shutil") as mock_shutil,
            patch(f"{_COMPAT_MODULE}.subprocess") as mock_subprocess,
        ):
            mock_shutil.which.return_value = "/usr/bin/test"
            mock_result = MagicMock()
            mock_result.stdout = ""
            mock_result.stderr = "opencode 1.2.15\n"
            mock_subprocess.run.return_value = mock_result
            result = probe_binary_version("opencode", "--version")
        assert result == "1.2.15"

    def test_returns_none_on_empty_output(self):
        with (
            patch(f"{_COMPAT_MODULE}.shutil") as mock_shutil,
            patch(f"{_COMPAT_MODULE}.subprocess") as mock_subprocess,
        ):
            mock_shutil.which.return_value = "/usr/bin/test"
            mock_result = MagicMock()
            mock_result.stdout = ""
            mock_result.stderr = ""
            mock_subprocess.run.return_value = mock_result
            result = probe_binary_version("test-tool", "--version")
        assert result is None

    def test_returns_none_on_timeout(self):
        import subprocess as real_subprocess

        with (
            patch(f"{_COMPAT_MODULE}.shutil") as mock_shutil,
            patch(f"{_COMPAT_MODULE}.subprocess") as mock_subprocess,
        ):
            mock_shutil.which.return_value = "/usr/bin/test"
            mock_subprocess.run.side_effect = real_subprocess.TimeoutExpired("test", 10)
            mock_subprocess.TimeoutExpired = real_subprocess.TimeoutExpired
            result = probe_binary_version("test-tool", "--version")
        assert result is None

    def test_returns_none_on_oserror(self):
        with (
            patch(f"{_COMPAT_MODULE}.shutil") as mock_shutil,
            patch(f"{_COMPAT_MODULE}.subprocess.run", side_effect=OSError("permission denied")),
        ):
            mock_shutil.which.return_value = "/usr/bin/test"
            result = probe_binary_version("test-tool", "--version")
        assert result is None

    def test_handles_multiline_output(self):
        """Only the first line should be considered for version extraction."""
        with (
            patch(f"{_COMPAT_MODULE}.shutil") as mock_shutil,
            patch(f"{_COMPAT_MODULE}.subprocess") as mock_subprocess,
        ):
            mock_shutil.which.return_value = "/usr/bin/test"
            mock_result = MagicMock()
            mock_result.stdout = "Tool v3.0.1\nBuilt with Go 1.21\n"
            mock_result.stderr = ""
            mock_subprocess.run.return_value = mock_result
            result = probe_binary_version("test-tool", "--version")
        assert result == "3.0.1"


# -----------------------------------------------------------------------
# probe_opencode_data_version (SQLite)
# -----------------------------------------------------------------------


class TestProbeOpenCodeDataVersion:
    """Contract: probe_opencode_data_version(data_dir) reads the version
    from the most recent session in the OpenCode SQLite database."""

    def test_returns_version_from_most_recent_session(self, tmp_path: Path):
        db_path = tmp_path / "opencode.db"
        _create_opencode_db(
            db_path,
            [
                ("1.2.10", 1000),
                ("1.2.15", 2000),  # most recent
            ],
        )
        result = probe_opencode_data_version(tmp_path)
        assert result == "1.2.15"

    def test_returns_none_when_no_database(self, tmp_path: Path):
        result = probe_opencode_data_version(tmp_path)
        assert result is None

    def test_returns_none_when_no_sessions(self, tmp_path: Path):
        db_path = tmp_path / "opencode.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "CREATE TABLE session ("
            "  id TEXT PRIMARY KEY,"
            "  version TEXT NOT NULL,"
            "  time_created INTEGER NOT NULL,"
            "  time_updated INTEGER NOT NULL"
            ")"
        )
        conn.commit()
        conn.close()
        result = probe_opencode_data_version(tmp_path)
        assert result is None

    def test_returns_none_when_wrong_schema(self, tmp_path: Path):
        """Database exists but has no session table."""
        db_path = tmp_path / "opencode.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE other_table (id TEXT)")
        conn.commit()
        conn.close()
        result = probe_opencode_data_version(tmp_path)
        assert result is None

    def test_returns_none_for_corrupt_database(self, tmp_path: Path):
        """Non-SQLite file should not crash."""
        db_path = tmp_path / "opencode.db"
        db_path.write_text("this is not a database")
        result = probe_opencode_data_version(tmp_path)
        assert result is None

    def test_strips_whitespace_from_version(self, tmp_path: Path):
        db_path = tmp_path / "opencode.db"
        _create_opencode_db(db_path, [("  1.2.15  ", 1000)])
        result = probe_opencode_data_version(tmp_path)
        assert result == "1.2.15"


# -----------------------------------------------------------------------
# probe_claude_data_version (JSONL)
# -----------------------------------------------------------------------


class TestProbClaudeDataVersion:
    """Contract: probe_claude_data_version(data_dir) reads the version
    from the most recently modified JSONL file under data_dir/projects/."""

    def test_returns_version_from_jsonl(self, tmp_path: Path):
        projects_dir = tmp_path / "projects" / "test-project"
        projects_dir.mkdir(parents=True)
        _create_jsonl_file(
            projects_dir / "session-1.jsonl",
            [
                {"type": "message", "version": "2.1.39", "content": "hello"},
                {"type": "file-history-snapshot"},  # no version
            ],
        )
        result = probe_claude_data_version(tmp_path)
        assert result == "2.1.39"

    def test_returns_none_when_no_projects_dir(self, tmp_path: Path):
        result = probe_claude_data_version(tmp_path)
        assert result is None

    def test_returns_none_when_no_jsonl_files(self, tmp_path: Path):
        (tmp_path / "projects" / "test-project").mkdir(parents=True)
        result = probe_claude_data_version(tmp_path)
        assert result is None

    def test_returns_none_when_no_version_field(self, tmp_path: Path):
        projects_dir = tmp_path / "projects" / "test-project"
        projects_dir.mkdir(parents=True)
        _create_jsonl_file(
            projects_dir / "session-1.jsonl",
            [
                {"type": "file-history-snapshot", "data": "stuff"},
                {"type": "other", "data": "more stuff"},
            ],
        )
        result = probe_claude_data_version(tmp_path)
        assert result is None

    def test_scans_tail_of_file(self, tmp_path: Path):
        """Version at end of file should be found (scanning backwards)."""
        projects_dir = tmp_path / "projects" / "test-project"
        projects_dir.mkdir(parents=True)
        lines = [{"type": "filler", "i": i} for i in range(40)]
        lines.append({"type": "message", "version": "2.1.40"})
        _create_jsonl_file(projects_dir / "session-1.jsonl", lines)
        result = probe_claude_data_version(tmp_path)
        assert result == "2.1.40"

    def test_ignores_subagent_files(self, tmp_path: Path):
        """Files in subagent subdirectories should not be considered."""
        projects_dir = tmp_path / "projects" / "test-project"
        projects_dir.mkdir(parents=True)
        # Subagent file
        subagent_dir = projects_dir / "uuid-1" / "subagents"
        subagent_dir.mkdir(parents=True)
        _create_jsonl_file(
            subagent_dir / "agent-abc.jsonl",
            [{"type": "message", "version": "2.1.39"}],
        )
        # No top-level JSONL
        result = probe_claude_data_version(tmp_path)
        assert result is None

    def test_returns_none_for_empty_jsonl(self, tmp_path: Path):
        projects_dir = tmp_path / "projects" / "test-project"
        projects_dir.mkdir(parents=True)
        (projects_dir / "session-1.jsonl").write_text("")
        result = probe_claude_data_version(tmp_path)
        assert result is None


# -----------------------------------------------------------------------
# _find_most_recent_jsonl
# -----------------------------------------------------------------------


class TestFindMostRecentJsonl:
    """Contract: _find_most_recent_jsonl returns the most recently
    modified JSONL file under the projects directory."""

    def test_returns_most_recent(self, tmp_path: Path):
        projects_dir = tmp_path / "projects"
        proj1 = projects_dir / "proj1"
        proj2 = projects_dir / "proj2"
        proj1.mkdir(parents=True)
        proj2.mkdir(parents=True)

        older = proj1 / "old.jsonl"
        newer = proj2 / "new.jsonl"
        _create_jsonl_file(older, [{"version": "1.0.0"}])
        _create_jsonl_file(newer, [{"version": "2.0.0"}])

        # Ensure newer has a later mtime
        import os
        import time

        os.utime(older, (time.time() - 100, time.time() - 100))

        result = _find_most_recent_jsonl(projects_dir)
        assert result == newer

    def test_returns_none_for_nonexistent_dir(self, tmp_path: Path):
        result = _find_most_recent_jsonl(tmp_path / "nonexistent")
        assert result is None

    def test_returns_none_when_no_jsonl_files(self, tmp_path: Path):
        proj = tmp_path / "proj1"
        proj.mkdir(parents=True)
        (proj / "readme.txt").write_text("not jsonl")
        result = _find_most_recent_jsonl(tmp_path)
        assert result is None


# -----------------------------------------------------------------------
# _extract_version_from_tail
# -----------------------------------------------------------------------


class TestExtractVersionFromTail:
    """Contract: _extract_version_from_tail reads the last N lines of
    a JSONL file and returns the first version field found (scanning
    backwards)."""

    def test_extracts_version_from_last_line(self, tmp_path: Path):
        path = tmp_path / "test.jsonl"
        _create_jsonl_file(
            path,
            [
                {"type": "other"},
                {"type": "message", "version": "2.1.39"},
            ],
        )
        assert _extract_version_from_tail(path) == "2.1.39"

    def test_returns_none_for_empty_file(self, tmp_path: Path):
        path = tmp_path / "test.jsonl"
        path.write_text("")
        assert _extract_version_from_tail(path) is None

    def test_returns_none_when_no_version(self, tmp_path: Path):
        path = tmp_path / "test.jsonl"
        _create_jsonl_file(path, [{"type": "filler"}, {"type": "other"}])
        assert _extract_version_from_tail(path) is None

    def test_skips_non_string_version(self, tmp_path: Path):
        """Integer version (e.g., stats-cache format version) should be skipped."""
        path = tmp_path / "test.jsonl"
        _create_jsonl_file(
            path,
            [
                {"type": "message", "version": "2.1.39"},
                {"version": 2},  # integer, should be skipped
            ],
        )
        assert _extract_version_from_tail(path) == "2.1.39"


# -----------------------------------------------------------------------
# _parse_version
# -----------------------------------------------------------------------


class TestParseVersion:
    """Contract: _parse_version parses semver strings, including
    partial versions like '1.2'."""

    def test_full_semver(self):
        v = _parse_version("1.2.15")
        assert v is not None
        assert v.major == 1
        assert v.minor == 2
        assert v.patch == 15

    def test_two_part_version(self):
        """'1.2' should be treated as '1.2.0'."""
        v = _parse_version("1.2")
        assert v is not None
        assert v.major == 1
        assert v.minor == 2
        assert v.patch == 0

    def test_returns_none_for_garbage(self):
        assert _parse_version("not-a-version") is None

    def test_returns_none_for_empty(self):
        assert _parse_version("") is None

    def test_prerelease(self):
        v = _parse_version("1.2.3-beta.1")
        assert v is not None
        assert v.prerelease == "beta.1"


# -----------------------------------------------------------------------
# _parse_range_minimum
# -----------------------------------------------------------------------


class TestParseRangeMinimum:
    """Contract: _parse_range_minimum parses '>=X.Y.Z' strings."""

    def test_simple_range(self):
        v = _parse_range_minimum(">=1.3.0")
        assert v is not None
        assert v.major == 1
        assert v.minor == 3
        assert v.patch == 0

    def test_with_spaces(self):
        v = _parse_range_minimum("  >=2.0.0  ")
        assert v is not None
        assert v.major == 2

    def test_returns_none_for_other_formats(self):
        assert _parse_range_minimum("<1.0.0") is None
        assert _parse_range_minimum("~1.0.0") is None
        assert _parse_range_minimum("1.0.0") is None

    def test_returns_none_for_empty(self):
        assert _parse_range_minimum("") is None


# -----------------------------------------------------------------------
# probe_agent
# -----------------------------------------------------------------------


class TestProbeAgent:
    """Contract: probe_agent(agent_id, compat) combines binary and
    data store probing into a single VersionProbe."""

    def test_both_found(self, tmp_path: Path):
        """Binary and data dir both present."""
        # Create a minimal OpenCode DB
        db_path = tmp_path / "opencode.db"
        _create_opencode_db(db_path, [("1.2.15", 1000)])

        compat = _make_compat(
            agent_id="opencode",
            data_dir=str(tmp_path),
            binary_command="opencode",
        )
        with patch(f"{_COMPAT_MODULE}.probe_binary_version", return_value="1.2.15"):
            probe = probe_agent("opencode", compat)

        assert probe.binary_found is True
        assert probe.binary_version == "1.2.15"
        assert probe.data_dir_exists is True
        assert probe.data_version == "1.2.15"

    def test_binary_only(self, tmp_path: Path):
        """Binary found but no data directory."""
        compat = _make_compat(
            agent_id="opencode",
            data_dir=str(tmp_path / "nonexistent"),
            binary_command="opencode",
        )
        with patch(f"{_COMPAT_MODULE}.probe_binary_version", return_value="1.2.15"):
            probe = probe_agent("opencode", compat)

        assert probe.binary_found is True
        assert probe.data_dir_exists is False

    def test_neither_found(self, tmp_path: Path):
        """Neither binary nor data directory found."""
        compat = _make_compat(
            agent_id="opencode",
            data_dir=str(tmp_path / "nonexistent"),
            binary_command="opencode",
        )
        with patch(f"{_COMPAT_MODULE}.probe_binary_version", return_value=None):
            probe = probe_agent("opencode", compat)

        assert probe.binary_found is False
        assert probe.data_dir_exists is False

    def test_data_only(self, tmp_path: Path):
        """Data directory present but binary not found."""
        db_path = tmp_path / "opencode.db"
        _create_opencode_db(db_path, [("1.2.15", 1000)])

        compat = _make_compat(
            agent_id="opencode",
            data_dir=str(tmp_path),
            binary_command="opencode",
        )
        with patch(f"{_COMPAT_MODULE}.probe_binary_version", return_value=None):
            probe = probe_agent("opencode", compat)

        assert probe.binary_found is False
        assert probe.data_dir_exists is True
        assert probe.data_version == "1.2.15"

    def test_expands_tilde(self, tmp_path: Path):
        """data_dir with ~ should be expanded."""
        compat = _make_compat(
            agent_id="opencode",
            data_dir="~/nonexistent-test-dir-plsec",
            binary_command="opencode",
        )
        with patch(f"{_COMPAT_MODULE}.probe_binary_version", return_value=None):
            probe = probe_agent("opencode", compat)
        # Should not crash; the dir just won't exist
        assert probe.data_dir_exists is False


# -----------------------------------------------------------------------
# check_version_compatibility
# -----------------------------------------------------------------------


class TestCheckVersionCompatibility:
    """Contract: check_version_compatibility(probe, compat) returns a
    CompatResult with the correct verdict based on the probe data."""

    def test_skip_when_not_installed(self):
        """Neither binary nor data -> skip."""
        probe = _make_probe(binary_found=False, data_dir_exists=False)
        compat = _make_compat()
        result = check_version_compatibility(probe, compat)
        assert result.verdict == "skip"
        assert "not installed" in result.detail

    def test_warn_binary_no_data_dir(self):
        """Binary found but no data directory -> warn."""
        probe = _make_probe(binary_found=True, binary_version="1.2.15", data_dir_exists=False)
        compat = _make_compat()
        result = check_version_compatibility(probe, compat)
        assert result.verdict == "warn"
        assert "no data directory" in result.detail

    def test_warn_no_version_determinable(self):
        """Data dir exists but version can't be determined -> warn."""
        probe = _make_probe(data_dir_exists=True)
        compat = _make_compat()
        result = check_version_compatibility(probe, compat)
        assert result.verdict == "warn"
        assert "could not be determined" in result.detail

    def test_ok_validated_version(self):
        """Version is in validated list -> ok."""
        probe = _make_probe(
            binary_found=True,
            binary_version="1.2.15",
            data_version="1.2.15",
            data_dir_exists=True,
        )
        compat = _make_compat(validated=[ValidatedVersion("1.2.15", "2026-03-01", "compatible")])
        result = check_version_compatibility(probe, compat)
        assert result.verdict == "ok"
        assert "1.2.15" in result.detail
        assert "validated" in result.detail
        assert result.effective_version == "1.2.15"

    def test_fail_below_minimum(self):
        """Version below min_supported -> fail."""
        probe = _make_probe(data_version="0.9.0", data_dir_exists=True)
        compat = _make_compat(min_supported="1.0.0")
        result = check_version_compatibility(probe, compat)
        assert result.verdict == "fail"
        assert "below minimum" in result.detail

    def test_fail_known_incompatible(self):
        """Version in known_incompatible list -> fail."""
        probe = _make_probe(data_version="1.5.0", data_dir_exists=True)
        compat = _make_compat(known_incompatible=["1.5.0"])
        result = check_version_compatibility(probe, compat)
        assert result.verdict == "fail"
        assert "known incompatible" in result.detail

    def test_warn_untested_range(self):
        """Version in untested range -> warn."""
        probe = _make_probe(data_version="2.0.0", data_dir_exists=True)
        compat = _make_compat(
            untested_range=">=2.0.0",
            validated=[ValidatedVersion("1.2.15", "2026-03-01", "compatible")],
        )
        result = check_version_compatibility(probe, compat)
        assert result.verdict == "warn"
        assert "untested" in result.detail
        assert "1.2.15" in result.detail  # latest validated shown

    def test_warn_not_in_registry(self):
        """Version not in any category -> warn."""
        probe = _make_probe(data_version="1.5.0", data_dir_exists=True)
        compat = _make_compat(
            untested_range=">=2.0.0",
            validated=[ValidatedVersion("1.2.15", "2026-03-01", "compatible")],
        )
        result = check_version_compatibility(probe, compat)
        assert result.verdict == "warn"
        assert "not in compatibility registry" in result.detail

    def test_data_version_preferred_over_binary(self):
        """Data version should be used as effective version when available."""
        probe = _make_probe(
            binary_found=True,
            binary_version="1.2.10",
            data_version="1.2.15",
            data_dir_exists=True,
        )
        compat = _make_compat(validated=[ValidatedVersion("1.2.15", "2026-03-01", "compatible")])
        result = check_version_compatibility(probe, compat)
        assert result.verdict == "ok"
        assert result.effective_version == "1.2.15"

    def test_binary_fallback_when_no_data_version(self):
        """Binary version used as fallback when data version unavailable."""
        probe = _make_probe(
            binary_found=True,
            binary_version="1.2.15",
            data_dir_exists=True,
        )
        compat = _make_compat(validated=[ValidatedVersion("1.2.15", "2026-03-01", "compatible")])
        result = check_version_compatibility(probe, compat)
        assert result.verdict == "ok"
        assert result.effective_version == "1.2.15"

    def test_drift_detected(self):
        """Binary != data version should include drift annotation."""
        probe = _make_probe(
            binary_found=True,
            binary_version="1.2.10",
            data_version="1.2.15",
            data_dir_exists=True,
        )
        compat = _make_compat(validated=[ValidatedVersion("1.2.15", "2026-03-01", "compatible")])
        result = check_version_compatibility(probe, compat)
        assert "drift" in result.detail

    def test_no_drift_when_versions_match(self):
        """Same binary and data version should not mention drift."""
        probe = _make_probe(
            binary_found=True,
            binary_version="1.2.15",
            data_version="1.2.15",
            data_dir_exists=True,
        )
        compat = _make_compat(validated=[ValidatedVersion("1.2.15", "2026-03-01", "compatible")])
        result = check_version_compatibility(probe, compat)
        assert "drift" not in result.detail

    def test_warn_unparseable_version(self):
        """Version string that can't be parsed -> warn."""
        probe = _make_probe(data_version="not-a-version", data_dir_exists=True)
        compat = _make_compat()
        result = check_version_compatibility(probe, compat)
        assert result.verdict == "warn"
        assert "could not be parsed" in result.detail


# -----------------------------------------------------------------------
# check_all_agents
# -----------------------------------------------------------------------


class TestCheckAllAgents:
    """Contract: check_all_agents() probes all agents in the registry
    and returns a list of CompatResult."""

    def test_returns_results_for_all_agents(self):
        """Should return one result per agent in the registry."""
        mock_probe = _make_probe(binary_found=False, data_dir_exists=False)
        mock_result = CompatResult(
            agent_id="test",
            probe=mock_probe,
            verdict="skip",
            detail="not installed",
        )
        with (
            patch(f"{_COMPAT_MODULE}.probe_agent", return_value=mock_probe),
            patch(f"{_COMPAT_MODULE}.check_version_compatibility", return_value=mock_result),
        ):
            results = check_all_agents()

        registry = load_compatibility_registry()
        assert len(results) == len(registry)

    def test_calls_probe_for_each_agent(self):
        """probe_agent should be called once per agent."""
        mock_probe = _make_probe()
        mock_result = CompatResult(
            agent_id="test",
            probe=mock_probe,
            verdict="skip",
            detail="not installed",
        )
        with (
            patch(f"{_COMPAT_MODULE}.probe_agent", return_value=mock_probe) as mock_pa,
            patch(f"{_COMPAT_MODULE}.check_version_compatibility", return_value=mock_result),
        ):
            check_all_agents()

        registry = load_compatibility_registry()
        assert mock_pa.call_count == len(registry)


# -----------------------------------------------------------------------
# Integration: CompatResult dataclass
# -----------------------------------------------------------------------


class TestCompatResult:
    """Contract: CompatResult holds compatibility assessment data."""

    def test_required_fields(self):
        probe = _make_probe()
        r = CompatResult(
            agent_id="test",
            probe=probe,
            verdict="ok",
            detail="all good",
        )
        assert r.agent_id == "test"
        assert r.verdict == "ok"
        assert r.detail == "all good"

    def test_default_effective_version(self):
        probe = _make_probe()
        r = CompatResult(agent_id="test", probe=probe, verdict="skip", detail="")
        assert r.effective_version is None
