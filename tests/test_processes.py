"""Tests for the process registry module (core/processes.py).

Covers:
- ProcessSpec dataclass and PROCESSES registry integrity
- Command builders (_build_pipelock_run_cmd, _build_pipelock_config_cmd)
- find_binary() with mocked shutil.which
- Path helper functions (get_pid_file_path, get_log_path, get_config_path)
- is_running() with filesystem fixtures and mocked os.kill

Private command builder functions are tested directly because they are
pure functions with clear contracts: given (binary, config, port, mode)
or (binary, mode, output), produce a list[str] argv.

If a private function is renamed, update the import in this file.
"""

from pathlib import Path
from unittest.mock import patch

from plsec.core.processes import (
    PROCESSES,
    ProcessSpec,
    _build_pipelock_config_cmd,
    _build_pipelock_run_cmd,
    find_binary,
    get_config_path,
    get_log_path,
    get_pid_file_path,
    is_running,
)

# -----------------------------------------------------------------------
# ProcessSpec and PROCESSES registry
# -----------------------------------------------------------------------


class TestProcessSpec:
    """Contract: ProcessSpec holds all metadata needed to manage a
    background process. The PROCESSES dict maps IDs to complete specs."""

    def test_registry_has_pipelock(self):
        assert "pipelock" in PROCESSES

    def test_registry_key_matches_spec_id(self):
        for key, spec in PROCESSES.items():
            assert key == spec.id

    def test_pipelock_fields(self):
        spec = PROCESSES["pipelock"]
        assert spec.display_name == "Pipelock Security Proxy"
        assert spec.binary == "pipelock"
        assert spec.pid_file == "pipelock.pid"
        assert spec.log_file == "logs/pipelock.log"
        assert spec.config_file == "pipelock.yaml"
        assert spec.install_hint  # non-empty
        assert callable(spec.build_run_cmd)
        assert callable(spec.build_config_cmd)

    def test_all_specs_have_required_fields(self):
        for spec in PROCESSES.values():
            assert spec.display_name
            assert spec.binary
            assert spec.pid_file
            assert spec.log_file
            assert spec.config_file
            assert spec.install_hint


# -----------------------------------------------------------------------
# Command builders
# -----------------------------------------------------------------------


class TestBuildPipelockRunCmd:
    """Contract: _build_pipelock_run_cmd(binary, config, port, mode)
    returns argv with the binary, 'run', config, and listen address."""

    def test_basic_command(self):
        binary = Path("/usr/local/bin/pipelock")
        config = Path("/home/user/.peerlabs/plsec/pipelock.yaml")
        cmd = _build_pipelock_run_cmd(binary, config, 8080, "balanced")
        assert cmd[0] == str(binary)
        assert "run" in cmd
        assert "--config" in cmd
        assert str(config) in cmd
        assert "127.0.0.1:8080" in cmd

    def test_port_in_listen_address(self):
        cmd = _build_pipelock_run_cmd(Path("pipelock"), Path("c.yaml"), 9999, "strict")
        assert "127.0.0.1:9999" in cmd

    def test_returns_list_of_strings(self):
        cmd = _build_pipelock_run_cmd(Path("pl"), Path("c"), 80, "b")
        assert isinstance(cmd, list)
        assert all(isinstance(s, str) for s in cmd)


class TestBuildPipelockConfigCmd:
    """Contract: _build_pipelock_config_cmd(binary, mode, output)
    returns argv with the binary, 'generate config', preset, and output."""

    def test_basic_command(self):
        binary = Path("/usr/local/bin/pipelock")
        output = Path("/home/user/.peerlabs/plsec/pipelock.yaml")
        cmd = _build_pipelock_config_cmd(binary, "strict", output)
        assert cmd[0] == str(binary)
        assert "generate" in cmd
        assert "config" in cmd
        assert "--preset" in cmd
        assert "strict" in cmd
        assert "-o" in cmd
        assert str(output) in cmd

    def test_balanced_mode(self):
        cmd = _build_pipelock_config_cmd(Path("pl"), "balanced", Path("out"))
        assert "balanced" in cmd


# -----------------------------------------------------------------------
# find_binary
# -----------------------------------------------------------------------


class TestFindBinary:
    """Contract: find_binary(spec) wraps shutil.which() and returns
    Path when found, None when not found."""

    def test_binary_found(self):
        spec = PROCESSES["pipelock"]
        with patch("plsec.core.processes.shutil.which", return_value="/usr/local/bin/pipelock"):
            result = find_binary(spec)
        assert result == Path("/usr/local/bin/pipelock")

    def test_binary_not_found(self):
        spec = PROCESSES["pipelock"]
        with patch("plsec.core.processes.shutil.which", return_value=None):
            result = find_binary(spec)
        assert result is None

    def test_returns_path_type(self):
        spec = PROCESSES["pipelock"]
        with patch("plsec.core.processes.shutil.which", return_value="/bin/pipelock"):
            result = find_binary(spec)
        assert isinstance(result, Path)


# -----------------------------------------------------------------------
# Path helpers
# -----------------------------------------------------------------------


class TestPathHelpers:
    """Contract: path helpers join plsec_home with spec-defined
    relative paths."""

    def test_get_pid_file_path(self, tmp_path: Path):
        spec = PROCESSES["pipelock"]
        result = get_pid_file_path(spec, tmp_path)
        assert result == tmp_path / "pipelock.pid"

    def test_get_log_path(self, tmp_path: Path):
        spec = PROCESSES["pipelock"]
        result = get_log_path(spec, tmp_path)
        assert result == tmp_path / "logs" / "pipelock.log"

    def test_get_config_path(self, tmp_path: Path):
        spec = PROCESSES["pipelock"]
        result = get_config_path(spec, tmp_path)
        assert result == tmp_path / "pipelock.yaml"

    def test_custom_spec_paths(self, tmp_path: Path):
        """Path helpers work with arbitrary spec values."""
        spec = ProcessSpec(
            id="test",
            display_name="Test",
            binary="test",
            pid_file="run/test.pid",
            log_file="var/log/test.log",
            config_file="etc/test.conf",
            install_hint="install test",
            build_run_cmd=lambda b, c, p, m: [],
        )
        assert get_pid_file_path(spec, tmp_path) == tmp_path / "run" / "test.pid"
        assert get_log_path(spec, tmp_path) == tmp_path / "var" / "log" / "test.log"
        assert get_config_path(spec, tmp_path) == tmp_path / "etc" / "test.conf"


# -----------------------------------------------------------------------
# is_running
# -----------------------------------------------------------------------


class TestIsRunning:
    """Contract: is_running(spec, plsec_home) reads the PID file, verifies
    the process via os.kill(pid, 0), and cleans up stale PID files.
    Returns (is_running, pid_or_none)."""

    def test_no_pid_file(self, tmp_path: Path):
        """No PID file means process is not running."""
        spec = PROCESSES["pipelock"]
        running, pid = is_running(spec, tmp_path)
        assert running is False
        assert pid is None

    def test_valid_pid_process_running(self, tmp_path: Path):
        """PID file with valid PID and running process."""
        spec = PROCESSES["pipelock"]
        pid_path = tmp_path / spec.pid_file
        pid_path.write_text("12345\n")
        with patch("plsec.core.processes.os.kill") as mock_kill:
            mock_kill.return_value = None  # no exception = process exists
            running, pid = is_running(spec, tmp_path)
        assert running is True
        assert pid == 12345
        mock_kill.assert_called_once_with(12345, 0)

    def test_stale_pid_process_gone(self, tmp_path: Path):
        """PID file exists but process is dead -- should clean up."""
        spec = PROCESSES["pipelock"]
        pid_path = tmp_path / spec.pid_file
        pid_path.write_text("99999\n")
        with patch("plsec.core.processes.os.kill", side_effect=ProcessLookupError):
            running, pid = is_running(spec, tmp_path)
        assert running is False
        assert pid is None
        assert not pid_path.exists(), "Stale PID file should be removed"

    def test_invalid_pid_content(self, tmp_path: Path):
        """PID file with non-numeric content should be cleaned up."""
        spec = PROCESSES["pipelock"]
        pid_path = tmp_path / spec.pid_file
        pid_path.write_text("not-a-number\n")
        running, pid = is_running(spec, tmp_path)
        assert running is False
        assert pid is None
        assert not pid_path.exists(), "Invalid PID file should be removed"

    def test_permission_error_treated_as_not_running(self, tmp_path: Path):
        """PermissionError on os.kill should clean up and report not running."""
        spec = PROCESSES["pipelock"]
        pid_path = tmp_path / spec.pid_file
        pid_path.write_text("1\n")
        with patch("plsec.core.processes.os.kill", side_effect=PermissionError):
            running, pid = is_running(spec, tmp_path)
        assert running is False
        assert pid is None

    def test_pid_with_whitespace(self, tmp_path: Path):
        """PID file with leading/trailing whitespace should be handled."""
        spec = PROCESSES["pipelock"]
        pid_path = tmp_path / spec.pid_file
        pid_path.write_text("  42  \n")
        with patch("plsec.core.processes.os.kill") as mock_kill:
            mock_kill.return_value = None
            running, pid = is_running(spec, tmp_path)
        assert running is True
        assert pid == 42
