"""Tests for the proxy command module (commands/proxy.py).

Covers:
- start: already running, binary missing, config generation, background mode
- stop: not running, successful stop, process already gone, OS error
- status: running with logs, not running
- logs: no log file, non-follow mode

Tests mock is_running, find_binary, subprocess, and os.kill to avoid
actual process management. Uses the typer CLI runner.
"""

from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from plsec.commands.proxy import app

runner = CliRunner()

_MODULE = "plsec.commands.proxy"


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _patch_home(tmp_path: Path):
    """Patch get_plsec_home to return tmp_path."""
    return patch(f"{_MODULE}.get_plsec_home", return_value=tmp_path)


def _patches(*pairs) -> ExitStack:
    """Apply multiple patches from (target_suffix, mock) pairs."""
    stack = ExitStack()
    for target, mock_obj in pairs:
        stack.enter_context(patch(f"{_MODULE}.{target}", mock_obj))
    return stack


# -----------------------------------------------------------------------
# start
# -----------------------------------------------------------------------


class TestProxyStart:
    """Contract: 'proxy start' checks if already running, finds binary,
    handles config, and starts the process."""

    def test_already_running(self, tmp_path: Path):
        """Already running -> warning + exit 1."""
        with (
            _patch_home(tmp_path),
            patch(f"{_MODULE}.is_running", return_value=(True, 12345)),
        ):
            result = runner.invoke(app, ["start"])
        assert result.exit_code == 1
        assert "already running" in result.output.lower()

    def test_binary_not_found(self, tmp_path: Path):
        """Binary not on PATH -> error + exit 1."""
        with (
            _patch_home(tmp_path),
            patch(f"{_MODULE}.is_running", return_value=(False, None)),
            patch(f"{_MODULE}.find_binary", return_value=None),
        ):
            result = runner.invoke(app, ["start"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_config_generation_failure(self, tmp_path: Path):
        """Config generation fails -> error + exit 1."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "gen error"
        with (
            _patch_home(tmp_path),
            patch(f"{_MODULE}.is_running", return_value=(False, None)),
            patch(f"{_MODULE}.find_binary", return_value=Path("/usr/bin/pipelock")),
            patch(f"{_MODULE}.get_config_path", return_value=tmp_path / "nonexistent.yaml"),
            patch(f"{_MODULE}.subprocess.run", return_value=mock_result),
        ):
            result = runner.invoke(app, ["start"])
        assert result.exit_code == 1

    def test_background_start_success(self, tmp_path: Path):
        """Successful background start -> saves PID, exit 0."""
        config_path = tmp_path / "pipelock.yaml"
        config_path.write_text("config: test\n")
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_path = log_dir / "pipelock.log"

        mock_process = MagicMock()
        mock_process.pid = 54321

        with (
            _patch_home(tmp_path),
            patch(f"{_MODULE}.is_running", return_value=(False, None)),
            patch(f"{_MODULE}.find_binary", return_value=Path("/usr/bin/pipelock")),
            patch(f"{_MODULE}.get_config_path", return_value=config_path),
            patch(f"{_MODULE}.get_log_path", return_value=log_path),
            patch(f"{_MODULE}.get_pid_file_path", return_value=tmp_path / "pipelock.pid"),
            patch(f"{_MODULE}.subprocess.Popen", return_value=mock_process),
        ):
            result = runner.invoke(app, ["start"])
        assert result.exit_code == 0
        assert "54321" in result.output
        assert (tmp_path / "pipelock.pid").read_text() == "54321"


# -----------------------------------------------------------------------
# stop
# -----------------------------------------------------------------------


class TestProxyStop:
    """Contract: 'proxy stop' sends SIGTERM, cleans up PID file."""

    def test_not_running(self, tmp_path: Path):
        """Not running -> info + exit 0."""
        with (
            _patch_home(tmp_path),
            patch(f"{_MODULE}.is_running", return_value=(False, None)),
        ):
            result = runner.invoke(app, ["stop"])
        assert result.exit_code == 0
        assert "not running" in result.output.lower()

    def test_successful_stop(self, tmp_path: Path):
        """Running process -> SIGTERM + clean up PID + exit 0."""
        pid_file = tmp_path / "pipelock.pid"
        pid_file.write_text("12345")
        with (
            _patch_home(tmp_path),
            patch(f"{_MODULE}.is_running", return_value=(True, 12345)),
            patch(f"{_MODULE}.os.kill") as mock_kill,
            patch(f"{_MODULE}.get_pid_file_path", return_value=pid_file),
        ):
            result = runner.invoke(app, ["stop"])
        assert result.exit_code == 0
        assert "stopped" in result.output.lower()
        mock_kill.assert_called_once()

    def test_process_already_gone(self, tmp_path: Path):
        """ProcessLookupError -> info + clean up PID."""
        pid_file = tmp_path / "pipelock.pid"
        pid_file.write_text("99999")
        with (
            _patch_home(tmp_path),
            patch(f"{_MODULE}.is_running", return_value=(True, 99999)),
            patch(f"{_MODULE}.os.kill", side_effect=ProcessLookupError),
            patch(f"{_MODULE}.get_pid_file_path", return_value=pid_file),
        ):
            result = runner.invoke(app, ["stop"])
        assert result.exit_code == 0
        assert "already stopped" in result.output.lower()

    def test_os_error_on_kill(self, tmp_path: Path):
        """OSError on kill -> error + exit 1."""
        with (
            _patch_home(tmp_path),
            patch(f"{_MODULE}.is_running", return_value=(True, 12345)),
            patch(f"{_MODULE}.os.kill", side_effect=OSError("Permission denied")),
            patch(f"{_MODULE}.get_pid_file_path", return_value=tmp_path / "pipelock.pid"),
        ):
            result = runner.invoke(app, ["stop"])
        assert result.exit_code == 1


# -----------------------------------------------------------------------
# status
# -----------------------------------------------------------------------


class TestProxyStatus:
    """Contract: 'proxy status' checks running state and shows info."""

    def test_running_with_log(self, tmp_path: Path):
        """Running process with log file -> shows PID and recent logs."""
        log_file = tmp_path / "logs" / "pipelock.log"
        log_file.parent.mkdir(parents=True)
        log_file.write_text("line1\nline2\nline3\n")
        with (
            _patch_home(tmp_path),
            patch(f"{_MODULE}.is_running", return_value=(True, 12345)),
            patch(f"{_MODULE}.get_log_path", return_value=log_file),
        ):
            result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "12345" in result.output
        assert "running" in result.output.lower()

    def test_not_running(self, tmp_path: Path):
        """Not running -> shows 'not running' + start hint."""
        with (
            _patch_home(tmp_path),
            patch(f"{_MODULE}.is_running", return_value=(False, None)),
        ):
            result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "not running" in result.output.lower()


# -----------------------------------------------------------------------
# logs
# -----------------------------------------------------------------------


class TestProxyLogs:
    """Contract: 'proxy logs' shows log file content via tail."""

    def test_no_log_file(self, tmp_path: Path):
        """No log file -> info + exit 0."""
        with (
            _patch_home(tmp_path),
            patch(f"{_MODULE}.get_log_path", return_value=tmp_path / "nonexistent.log"),
        ):
            result = runner.invoke(app, ["logs"])
        assert result.exit_code == 0
        assert "no log file" in result.output.lower()

    def test_show_logs(self, tmp_path: Path):
        """Log file exists -> shows content via tail."""
        log_file = tmp_path / "pipelock.log"
        log_file.write_text("log entry 1\nlog entry 2\n")
        mock_tail = MagicMock()
        mock_tail.stdout = "log entry 1\nlog entry 2\n"
        with (
            _patch_home(tmp_path),
            patch(f"{_MODULE}.get_log_path", return_value=log_file),
            patch(f"{_MODULE}.subprocess.run", return_value=mock_tail),
        ):
            result = runner.invoke(app, ["logs"])
        assert result.exit_code == 0

    def test_log_read_error(self, tmp_path: Path):
        """OSError on tail -> error + exit 1."""
        log_file = tmp_path / "pipelock.log"
        log_file.write_text("data")
        with (
            _patch_home(tmp_path),
            patch(f"{_MODULE}.get_log_path", return_value=log_file),
            patch(f"{_MODULE}.subprocess.run", side_effect=OSError("no tail")),
        ):
            result = runner.invoke(app, ["logs"])
        assert result.exit_code == 1
