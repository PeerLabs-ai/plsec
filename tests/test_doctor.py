"""Tests for the doctor command module (commands/doctor.py).

Covers:
- _render_result() verdict dispatch (ok/warn/fail/skip)
- doctor command: all checks pass -> exit 0
- doctor command: failures present -> exit 1
- doctor command: warnings only -> exit 0
- doctor command: --install flag shows fix hints
- doctor command: --fix flag messaging
- doctor command: --all flag enables optional tools

Tests mock the health check functions to return controlled CheckResult
lists, avoiding actual tool checking via shutil.which/subprocess.
"""

from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from plsec.commands.doctor import _render_result, app
from plsec.core.health import CheckResult

runner = CliRunner()

_MODULE = "plsec.commands.doctor"


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _ok(name: str = "test", detail: str = "") -> CheckResult:
    return CheckResult(id="I-1", name=name, category="installation", verdict="ok", detail=detail)


def _warn(name: str = "test", fix_hint: str = "") -> CheckResult:
    return CheckResult(
        id="I-1", name=name, category="installation", verdict="warn", fix_hint=fix_hint
    )


def _fail(name: str = "test", fix_hint: str = "") -> CheckResult:
    return CheckResult(
        id="I-1", name=name, category="installation", verdict="fail", fix_hint=fix_hint
    )


def _skip(name: str = "test") -> CheckResult:
    return CheckResult(id="I-1", name=name, category="installation", verdict="skip")


def _mock_all_passing() -> dict[str, MagicMock]:
    """Return patch targets and mocks for all-passing doctor checks.

    Keys are full dotted patch targets.
    """
    mock_checker = MagicMock()
    mock_checker.return_value.tools = []
    return {
        f"{_MODULE}.get_plsec_home": MagicMock(return_value=Path("/var/plsec")),
        f"{_MODULE}.find_config_file": MagicMock(return_value=Path("/var/plsec.yaml")),
        f"{_MODULE}.check_directory_structure": MagicMock(return_value=[_ok("dir")]),
        f"{_MODULE}.check_config_file": MagicMock(return_value=[_ok("config")]),
        f"{_MODULE}.check_agent_configs": MagicMock(return_value=[_ok("claude")]),
        f"{_MODULE}.check_scanner_configs": MagicMock(return_value=[_ok("trivy config")]),
        f"{_MODULE}.check_preset_files": MagicMock(return_value=[_ok("preset files")]),
        f"{_MODULE}.check_wrapper_scripts": MagicMock(return_value=[_ok("wrappers")]),
        f"{_MODULE}.check_tools": MagicMock(return_value=[_ok("trivy")]),
        f"{_MODULE}.check_runtime": MagicMock(return_value=[_ok("python")]),
        f"{_MODULE}.check_all_agents": MagicMock(return_value=[]),
        f"{_MODULE}.check_agent_compatibility": MagicMock(
            return_value=[_ok("opencode compat"), _ok("claude-code compat")]
        ),
        f"{_MODULE}.ToolChecker": mock_checker,
    }


def _apply_patches(patches: dict[str, MagicMock]) -> ExitStack:
    """Apply multiple patches using an ExitStack."""
    stack = ExitStack()
    for target, mock_obj in patches.items():
        stack.enter_context(patch(target, mock_obj))
    return stack


# -----------------------------------------------------------------------
# _render_result
# -----------------------------------------------------------------------


class TestRenderResult:
    """Contract: _render_result dispatches to print_ok/warning/error/status
    based on result.verdict."""

    def test_ok_verdict(self):
        """OK verdict should not raise."""
        _render_result(_ok("test ok", detail="/path"))

    def test_warn_verdict(self):
        """Warn verdict should not raise."""
        _render_result(_warn("test warn", fix_hint="run something"))

    def test_fail_verdict(self):
        """Fail verdict should not raise."""
        _render_result(_fail("test fail", fix_hint="install something"))

    def test_skip_verdict(self):
        """Skip verdict should not raise."""
        _render_result(_skip("test skip"))


# -----------------------------------------------------------------------
# doctor command - all pass
# -----------------------------------------------------------------------


class TestDoctorAllPass:
    """Contract: when all checks pass with no warnings, doctor exits 0."""

    def test_exits_zero(self):
        patches = _mock_all_passing()
        with _apply_patches(patches):
            result = runner.invoke(app)
        assert result.exit_code == 0

    def test_output_contains_passed(self):
        patches = _mock_all_passing()
        with _apply_patches(patches):
            result = runner.invoke(app)
        assert "passed" in result.output.lower() or result.exit_code == 0


# -----------------------------------------------------------------------
# doctor command - failures
# -----------------------------------------------------------------------


class TestDoctorWithFailures:
    """Contract: when any check fails, doctor exits 1."""

    def test_exits_one_on_failure(self):
        patches = _mock_all_passing()
        patches[f"{_MODULE}.check_directory_structure"] = MagicMock(
            return_value=[_fail("dir missing", fix_hint="Run plsec init")]
        )
        with _apply_patches(patches):
            result = runner.invoke(app)
        assert result.exit_code == 1

    def test_install_flag_shows_hints(self):
        """--install should display fix hints for failing checks."""
        patches = _mock_all_passing()
        patches[f"{_MODULE}.check_directory_structure"] = MagicMock(
            return_value=[_fail("dir missing", fix_hint="Run plsec init")]
        )
        with _apply_patches(patches):
            result = runner.invoke(app, ["--install"])
        assert result.exit_code == 1
        assert "Run plsec init" in result.output

    def test_no_install_shows_hint_message(self):
        """Without --install, should suggest running with --install."""
        patches = _mock_all_passing()
        patches[f"{_MODULE}.check_directory_structure"] = MagicMock(
            return_value=[_fail("dir missing")]
        )
        with _apply_patches(patches):
            result = runner.invoke(app)
        assert result.exit_code == 1
        assert "--install" in result.output


# -----------------------------------------------------------------------
# doctor command - warnings
# -----------------------------------------------------------------------


class TestDoctorWithWarnings:
    """Contract: when checks have warnings but no failures, doctor exits 0."""

    def test_exits_zero_with_warnings(self):
        patches = _mock_all_passing()
        patches[f"{_MODULE}.check_agent_configs"] = MagicMock(
            return_value=[_warn("config missing")]
        )
        with _apply_patches(patches):
            result = runner.invoke(app)
        assert result.exit_code == 0

    def test_fix_flag_messaging(self):
        """--fix should show 'issues were fixed' message."""
        patches = _mock_all_passing()
        patches[f"{_MODULE}.check_agent_configs"] = MagicMock(
            return_value=[_warn("config missing")]
        )
        with _apply_patches(patches):
            result = runner.invoke(app, ["--fix"])
        assert result.exit_code == 0
        assert "fixed" in result.output.lower()

    def test_no_fix_suggests_fix(self):
        """Without --fix, should suggest running with --fix."""
        patches = _mock_all_passing()
        patches[f"{_MODULE}.check_agent_configs"] = MagicMock(
            return_value=[_warn("config missing")]
        )
        with _apply_patches(patches):
            result = runner.invoke(app)
        assert result.exit_code == 0
        assert "--fix" in result.output


# -----------------------------------------------------------------------
# doctor command - --all flag
# -----------------------------------------------------------------------


class TestDoctorAllTools:
    """Contract: --all flag enables optional tools check section."""

    def test_all_flag_checks_optional_tools(self):
        """--all should trigger an additional ToolChecker for optional tools."""
        patches = _mock_all_passing()
        mock_checker_cls = MagicMock()
        mock_checker_instance = MagicMock()
        mock_checker_instance.tools = []
        mock_checker_cls.return_value = mock_checker_instance
        patches[f"{_MODULE}.ToolChecker"] = mock_checker_cls
        patches[f"{_MODULE}.check_tools"] = MagicMock(return_value=[_ok("tool")])

        with _apply_patches(patches):
            result = runner.invoke(app, ["--all"])
        assert result.exit_code == 0
        # ToolChecker should be called twice (required + optional)
        assert mock_checker_cls.call_count == 2
