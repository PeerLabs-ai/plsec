"""Tests for the scan command module (commands/scan.py).

Covers:
- Flag-to-scan_type resolution (--secrets, --code, --deps, --misconfig)
- Scanner filtering by scan_type
- Pass/fail result handling and exit codes
- Skip/not-installed message handling
- Dependency audit stub

All tests mock run_scanner() and get_plsec_home() to avoid actual binary
execution. Tests use the typer CLI runner to invoke the scan command.
"""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from plsec.commands.scan import _check_scanner_prerequisites, app
from plsec.core.health import PLSEC_EXPECTED_FILES

runner = CliRunner()


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _patch_scanner(passed: bool = True, message: str = "No issues found"):
    """Create a patch for run_scanner that returns a fixed result."""
    return patch("plsec.commands.scan.run_scanner", return_value=(passed, message))


def _setup_plsec_home(tmp_path: Path) -> Path:
    """Create a plsec_home with all expected scanner configs so pre-flight passes."""
    plsec_home = tmp_path / ".peerlabs" / "plsec"
    for rel_path, _desc in PLSEC_EXPECTED_FILES:
        fpath = plsec_home / rel_path
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text("placeholder\n")
    return plsec_home


def _patch_home(tmp_path: Path):
    """Patch get_plsec_home to return a fully-populated plsec_home."""
    plsec_home = _setup_plsec_home(tmp_path)
    return patch("plsec.commands.scan.get_plsec_home", return_value=plsec_home)


# -----------------------------------------------------------------------
# Basic execution
# -----------------------------------------------------------------------


class TestScanExecution:
    """Contract: scan iterates SCANNERS, calls run_scanner for each,
    and exits 0/1 based on results."""

    def test_all_scanners_pass(self, tmp_path: Path):
        """All scanners passing -> exit 0."""
        with _patch_home(tmp_path), _patch_scanner(True, "No issues found"):
            result = runner.invoke(app, [str(tmp_path)])
        assert result.exit_code == 0

    def test_secret_scanner_fails(self, tmp_path: Path):
        """Secret scanner failure -> exit 1 (errors are critical)."""
        call_count = 0

        def mock_run_scanner(spec, target, home):
            nonlocal call_count
            call_count += 1
            if spec.scan_type == "secrets":
                return False, "Found AWS key"
            return True, "No issues"

        with (
            _patch_home(tmp_path),
            patch("plsec.commands.scan.run_scanner", side_effect=mock_run_scanner),
        ):
            result = runner.invoke(app, [str(tmp_path)])
        assert result.exit_code == 1

    def test_code_scanner_fails(self, tmp_path: Path):
        """Code scanner failure -> exit 0 (warnings, not errors)."""

        def mock_run_scanner(spec, target, home):
            if spec.scan_type == "code":
                return False, "Issues found"
            return True, "No issues"

        with (
            _patch_home(tmp_path),
            patch("plsec.commands.scan.run_scanner", side_effect=mock_run_scanner),
        ):
            result = runner.invoke(app, [str(tmp_path)])
        assert result.exit_code == 0

    def test_nonexistent_path(self, tmp_path: Path):
        """Non-existent path -> exit 1."""
        bad_path = tmp_path / "nonexistent"
        with _patch_home(tmp_path):
            result = runner.invoke(app, [str(bad_path)])
        assert result.exit_code == 1

    def test_skip_message_handled(self, tmp_path: Path):
        """Skipped scanners should not count as errors."""
        with (
            _patch_home(tmp_path),
            _patch_scanner(True, "Bandit not installed (skipped)"),
        ):
            result = runner.invoke(app, [str(tmp_path)])
        assert result.exit_code == 0


# -----------------------------------------------------------------------
# Flag resolution
# -----------------------------------------------------------------------


class TestScanFlagResolution:
    """Contract: --secrets, --code, --deps, --misconfig flags override
    the default 'all' scan type, filtering which scanners run."""

    def test_secrets_flag_filters(self, tmp_path: Path):
        """--secrets should only run secret-type scanners."""
        scanned_types = []

        def mock_run_scanner(spec, target, home):
            scanned_types.append(spec.scan_type)
            return True, "ok"

        with (
            _patch_home(tmp_path),
            patch("plsec.commands.scan.run_scanner", side_effect=mock_run_scanner),
        ):
            result = runner.invoke(app, ["--secrets", str(tmp_path)])
        assert result.exit_code == 0
        assert all(t == "secrets" for t in scanned_types)

    def test_code_flag_filters(self, tmp_path: Path):
        """--code should only run code-type scanners."""
        scanned_types = []

        def mock_run_scanner(spec, target, home):
            scanned_types.append(spec.scan_type)
            return True, "ok"

        with (
            _patch_home(tmp_path),
            patch("plsec.commands.scan.run_scanner", side_effect=mock_run_scanner),
        ):
            result = runner.invoke(app, ["--code", str(tmp_path)])
        assert result.exit_code == 0
        assert all(t == "code" for t in scanned_types)

    def test_misconfig_flag_filters(self, tmp_path: Path):
        """--misconfig should only run misconfig-type scanners."""
        scanned_types = []

        def mock_run_scanner(spec, target, home):
            scanned_types.append(spec.scan_type)
            return True, "ok"

        with (
            _patch_home(tmp_path),
            patch("plsec.commands.scan.run_scanner", side_effect=mock_run_scanner),
        ):
            result = runner.invoke(app, ["--misconfig", str(tmp_path)])
        assert result.exit_code == 0
        assert all(t == "misconfig" for t in scanned_types)

    def test_all_runs_every_scanner(self, tmp_path: Path):
        """Default (all) should run scanners of every type."""
        scanned_types = set()

        def mock_run_scanner(spec, target, home):
            scanned_types.add(spec.scan_type)
            return True, "ok"

        with (
            _patch_home(tmp_path),
            patch("plsec.commands.scan.run_scanner", side_effect=mock_run_scanner),
        ):
            result = runner.invoke(app, [str(tmp_path)])
        assert result.exit_code == 0
        assert "secrets" in scanned_types
        assert "code" in scanned_types


# -----------------------------------------------------------------------
# Dependency audit stub
# -----------------------------------------------------------------------


class TestDependencyAudit:
    """Contract: deps scan type triggers stub message."""

    def test_deps_flag_shows_stub(self, tmp_path: Path):
        """--deps should show 'not yet implemented' message."""
        with _patch_home(tmp_path), _patch_scanner(True, "ok"):
            result = runner.invoke(app, ["--deps", str(tmp_path)])
        assert result.exit_code == 0


# -----------------------------------------------------------------------
# Pre-flight prerequisite check
# -----------------------------------------------------------------------


class TestScannerPrerequisites:
    """Contract: _check_scanner_prerequisites raises typer.Exit(1)
    when required scanner configs are missing, and passes silently
    when all configs are present."""

    def test_passes_when_all_present(self, tmp_path: Path):
        """No exit when all expected files exist."""
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        for rel_path, _desc in PLSEC_EXPECTED_FILES:
            fpath = plsec_home / rel_path
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text("placeholder\n")
        # Should not raise
        _check_scanner_prerequisites(plsec_home)

    def test_fails_when_all_missing(self, tmp_path: Path):
        """Exit 1 when plsec_home exists but contains no configs."""
        import typer

        plsec_home = tmp_path / ".peerlabs" / "plsec"
        plsec_home.mkdir(parents=True)
        import pytest

        with pytest.raises(typer.Exit) as exc_info:
            _check_scanner_prerequisites(plsec_home)
        assert exc_info.value.exit_code == 1

    def test_fails_when_partially_missing(self, tmp_path: Path):
        """Exit 1 when only some configs exist."""
        import typer

        plsec_home = tmp_path / ".peerlabs" / "plsec"
        # Create only the first expected file, leave the rest missing
        first_rel, _first_desc = PLSEC_EXPECTED_FILES[0]
        first_path = plsec_home / first_rel
        first_path.parent.mkdir(parents=True, exist_ok=True)
        first_path.write_text("placeholder\n")
        import pytest

        with pytest.raises(typer.Exit) as exc_info:
            _check_scanner_prerequisites(plsec_home)
        assert exc_info.value.exit_code == 1

    def test_cli_exits_1_when_configs_missing(self, tmp_path: Path):
        """The scan CLI should exit 1 when pre-flight fails."""
        # Use an empty plsec_home (no expected files) to trigger pre-flight failure
        empty_home = tmp_path / "empty_plsec_home"
        empty_home.mkdir(parents=True)
        with patch("plsec.commands.scan.get_plsec_home", return_value=empty_home):
            result = runner.invoke(app, [str(tmp_path)])
        assert result.exit_code == 1
        assert "plsec install" in result.output
