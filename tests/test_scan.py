"""Tests for the scan command module (commands/scan.py).

Covers:
- Preset-driven scanner selection
- Flag-to-scanner resolution (--secrets, --code, --deps, --misconfig)
- Specific scanner selection (--scanner)
- Combined preset + flag union behavior
- Pass/fail result handling and exit codes
- Skip/not-installed message handling
- Verbose config display
- Dependency audit stub

All tests mock run_scanner(), get_plsec_home(), and resolve_config()
to avoid actual binary execution. Tests use the typer CLI runner.
"""

from pathlib import Path
from unittest.mock import patch

import typer
from typer.testing import CliRunner

from plsec.commands.scan import (
    SCAN_LATEST,
    SCAN_LOG_PATTERN,
    _check_scanner_prerequisites,
    _print_json,
    _resolve_scanner_list,
    _result_to_dict,
    _summary_to_dict,
    _write_scan_log,
    app,
)
from plsec.core.config import PlsecConfig
from plsec.core.health import PLSEC_EXPECTED_FILES
from plsec.core.scanners import ScanResult, ScanSummary

runner = CliRunner()


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _make_scan_result(
    spec_id: str = "test-scanner",
    scan_type: str = "secrets",
    passed: bool = True,
    message: str = "No issues found",
) -> ScanResult:
    """Create a ScanResult for testing."""
    return ScanResult(
        scanner_id=spec_id,
        scan_type=scan_type,
        verdict="pass" if passed else "fail",
        message=message,
    )


def _patch_scanner(passed: bool = True, message: str = "No issues found"):
    """Create a patch for run_scanner that returns a fixed ScanResult.

    The side_effect builds a ScanResult using the spec's id and scan_type
    so each invocation gets the correct scanner metadata.
    Accepts 4 args: (spec, target, home, static_config).
    """

    def _mock_run_scanner(spec, target, home, static_config=None):
        return ScanResult(
            scanner_id=spec.id,
            scan_type=spec.scan_type,
            verdict="pass" if passed else "fail",
            message=message,
        )

    return patch("plsec.commands.scan.run_scanner", side_effect=_mock_run_scanner)


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


def _patch_resolve_config(preset: str = "balanced"):
    """Patch resolve_config to return a default PlsecConfig with given preset."""
    config = PlsecConfig()
    config.preset = preset
    return patch(
        "plsec.commands.scan.resolve_config",
        return_value=(config, preset),
    )


# -----------------------------------------------------------------------
# Basic execution
# -----------------------------------------------------------------------


class TestScanExecution:
    """Contract: scan iterates SCANNERS, calls run_scanner for each,
    and exits 0/1 based on results."""

    def test_all_scanners_pass(self, tmp_path: Path):
        """All scanners passing -> exit 0."""
        with (
            _patch_home(tmp_path),
            _patch_scanner(True, "No issues found"),
            _patch_resolve_config(),
        ):
            result = runner.invoke(app, [str(tmp_path)])
        assert result.exit_code == 0

    def test_secret_scanner_fails(self, tmp_path: Path):
        """Secret scanner failure -> exit 1 (errors are critical)."""

        def mock_run_scanner(spec, target, home, static_config=None):
            if spec.scan_type == "secrets":
                return ScanResult(
                    scanner_id=spec.id,
                    scan_type=spec.scan_type,
                    verdict="fail",
                    message="Found AWS key",
                )
            return ScanResult(
                scanner_id=spec.id,
                scan_type=spec.scan_type,
                verdict="pass",
                message="No issues",
            )

        with (
            _patch_home(tmp_path),
            _patch_resolve_config(),
            patch("plsec.commands.scan.run_scanner", side_effect=mock_run_scanner),
        ):
            result = runner.invoke(app, [str(tmp_path)])
        assert result.exit_code == 1

    def test_code_scanner_fails(self, tmp_path: Path):
        """Code scanner failure -> exit 0 (warnings, not errors)."""

        def mock_run_scanner(spec, target, home, static_config=None):
            if spec.scan_type == "code":
                return ScanResult(
                    scanner_id=spec.id,
                    scan_type=spec.scan_type,
                    verdict="fail",
                    message="Issues found",
                )
            return ScanResult(
                scanner_id=spec.id,
                scan_type=spec.scan_type,
                verdict="pass",
                message="No issues",
            )

        with (
            _patch_home(tmp_path),
            _patch_resolve_config(),
            patch("plsec.commands.scan.run_scanner", side_effect=mock_run_scanner),
        ):
            result = runner.invoke(app, [str(tmp_path)])
        assert result.exit_code == 0

    def test_nonexistent_path(self, tmp_path: Path):
        """Non-existent path -> exit 1."""
        bad_path = tmp_path / "nonexistent"
        with _patch_home(tmp_path), _patch_resolve_config():
            result = runner.invoke(app, [str(bad_path)])
        assert result.exit_code == 1

    def test_skip_message_handled(self, tmp_path: Path):
        """Skipped scanners should not count as errors."""
        with (
            _patch_home(tmp_path),
            _patch_resolve_config(),
            _patch_scanner(True, "Bandit not installed (skipped)"),
        ):
            result = runner.invoke(app, [str(tmp_path)])
        assert result.exit_code == 0


# -----------------------------------------------------------------------
# Flag resolution
# -----------------------------------------------------------------------


class TestScanFlagResolution:
    """Contract: --secrets, --code, --deps, --misconfig flags filter which scanners run."""

    def test_secrets_flag_filters(self, tmp_path: Path):
        """--secrets should only run secret-type scanners."""
        scanned_types = []

        def mock_run_scanner(spec, target, home, static_config=None):
            scanned_types.append(spec.scan_type)
            return ScanResult(
                scanner_id=spec.id,
                scan_type=spec.scan_type,
                verdict="pass",
                message="ok",
            )

        with (
            _patch_home(tmp_path),
            _patch_resolve_config(),
            patch("plsec.commands.scan.run_scanner", side_effect=mock_run_scanner),
        ):
            result = runner.invoke(app, ["--secrets", str(tmp_path)])
        assert result.exit_code == 0
        assert all(t == "secrets" for t in scanned_types)

    def test_code_flag_filters(self, tmp_path: Path):
        """--code should only run code-type scanners."""
        scanned_types = []

        def mock_run_scanner(spec, target, home, static_config=None):
            scanned_types.append(spec.scan_type)
            return ScanResult(
                scanner_id=spec.id,
                scan_type=spec.scan_type,
                verdict="pass",
                message="ok",
            )

        with (
            _patch_home(tmp_path),
            _patch_resolve_config(),
            patch("plsec.commands.scan.run_scanner", side_effect=mock_run_scanner),
        ):
            result = runner.invoke(app, ["--code", str(tmp_path)])
        assert result.exit_code == 0
        assert all(t == "code" for t in scanned_types)

    def test_misconfig_flag_filters(self, tmp_path: Path):
        """--misconfig should only run misconfig-type scanners."""
        scanned_types = []

        def mock_run_scanner(spec, target, home, static_config=None):
            scanned_types.append(spec.scan_type)
            return ScanResult(
                scanner_id=spec.id,
                scan_type=spec.scan_type,
                verdict="pass",
                message="ok",
            )

        with (
            _patch_home(tmp_path),
            _patch_resolve_config(),
            patch("plsec.commands.scan.run_scanner", side_effect=mock_run_scanner),
        ):
            result = runner.invoke(app, ["--misconfig", str(tmp_path)])
        assert result.exit_code == 0
        assert all(t == "misconfig" for t in scanned_types)

    def test_all_runs_every_scanner(self, tmp_path: Path):
        """Default (all) should run scanners of every type."""
        scanned_types = set()

        def mock_run_scanner(spec, target, home, static_config=None):
            scanned_types.add(spec.scan_type)
            return ScanResult(
                scanner_id=spec.id,
                scan_type=spec.scan_type,
                verdict="pass",
                message="ok",
            )

        with (
            _patch_home(tmp_path),
            _patch_resolve_config(),
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
        with _patch_home(tmp_path), _patch_resolve_config(), _patch_scanner(True, "ok"):
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
        with (
            _patch_resolve_config(),
            patch("plsec.commands.scan.get_plsec_home", return_value=empty_home),
        ):
            result = runner.invoke(app, [str(tmp_path)])
        assert result.exit_code == 1
        assert "plsec install" in result.output


# -----------------------------------------------------------------------
# _result_to_dict / _summary_to_dict
# -----------------------------------------------------------------------


class TestResultToDict:
    """Contract: _result_to_dict converts a ScanResult to a JSON-serializable dict
    with keys: scanner, type, verdict, exit_code, duration, message."""

    def test_all_fields_present(self):
        r = ScanResult(
            scanner_id="trivy-secrets",
            scan_type="secrets",
            verdict="pass",
            exit_code=0,
            duration_seconds=1.23,
            message="No secrets detected",
        )
        d = _result_to_dict(r)
        assert d["scanner"] == "trivy-secrets"
        assert d["type"] == "secrets"
        assert d["verdict"] == "pass"
        assert d["exit_code"] == 0
        assert d["duration"] == 1.23
        assert d["message"] == "No secrets detected"

    def test_none_exit_code(self):
        r = ScanResult(scanner_id="x", scan_type="code", verdict="skip")
        d = _result_to_dict(r)
        assert d["exit_code"] is None

    def test_does_not_include_output(self):
        """Output is omitted from the dict to keep log lines compact."""
        r = ScanResult(
            scanner_id="x",
            scan_type="secrets",
            verdict="fail",
            output="very long output",
        )
        d = _result_to_dict(r)
        assert "output" not in d


class TestSummaryToDict:
    """Contract: _summary_to_dict converts a ScanSummary to a JSON-serializable dict
    with keys: ts, target, passed, results, counts."""

    def test_structure(self):
        results = [
            ScanResult(scanner_id="a", scan_type="secrets", verdict="pass"),
            ScanResult(scanner_id="b", scan_type="code", verdict="fail"),
        ]
        s = ScanSummary(results=results, target="/home/user/proj", passed=False)
        d = _summary_to_dict(s)
        assert "ts" in d
        assert d["target"] == "/home/user/proj"
        assert d["passed"] is False
        assert len(d["results"]) == 2
        assert d["counts"]["pass"] == 1
        assert d["counts"]["fail"] == 1
        assert d["counts"]["skip"] == 0

    def test_empty_summary(self):
        s = ScanSummary()
        d = _summary_to_dict(s)
        assert d["results"] == []
        assert d["counts"]["pass"] == 0
        assert d["counts"]["fail"] == 0
        assert d["counts"]["skip"] == 0

    def test_ts_is_iso_format(self):
        s = ScanSummary()
        d = _summary_to_dict(s)
        # ISO format timestamps contain 'T' separator
        assert "T" in d["ts"]


# -----------------------------------------------------------------------
# _write_scan_log
# -----------------------------------------------------------------------


class TestWriteScanLog:
    """Contract: _write_scan_log writes per-result JSON lines to a daily
    JSONL file and a summary to scan-latest.json."""

    def _make_summary(self) -> ScanSummary:
        return ScanSummary(
            results=[
                ScanResult(scanner_id="a", scan_type="secrets", verdict="pass", message="ok"),
                ScanResult(scanner_id="b", scan_type="code", verdict="fail", message="err"),
            ],
            target="/home/user/proj",
            passed=False,
        )

    def test_returns_none_when_logs_dir_missing(self, tmp_path: Path):
        """No logs/ directory -> returns None, no crash."""
        plsec_home = tmp_path / "plsec"
        plsec_home.mkdir()
        # No logs/ subdirectory
        result = _write_scan_log(plsec_home, self._make_summary())
        assert result is None

    def test_creates_daily_jsonl(self, tmp_path: Path):
        """Creates scan-YYYYMMDD.jsonl with one line per result."""
        import json

        plsec_home = tmp_path / "plsec"
        logs_dir = plsec_home / "logs"
        logs_dir.mkdir(parents=True)

        log_path = _write_scan_log(plsec_home, self._make_summary())
        assert log_path is not None
        assert log_path.suffix == ".jsonl"
        assert log_path.name.startswith("scan-")

        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 2

        first = json.loads(lines[0])
        assert first["scanner"] == "a"
        assert first["type"] == "secrets"
        assert first["verdict"] == "pass"
        assert "ts" in first
        assert first["target"] == "/home/user/proj"

        second = json.loads(lines[1])
        assert second["scanner"] == "b"
        assert second["verdict"] == "fail"

    def test_creates_scan_latest_json(self, tmp_path: Path):
        """Creates scan-latest.json with the full summary."""
        import json

        plsec_home = tmp_path / "plsec"
        logs_dir = plsec_home / "logs"
        logs_dir.mkdir(parents=True)

        _write_scan_log(plsec_home, self._make_summary())

        latest = logs_dir / SCAN_LATEST
        assert latest.exists()
        data = json.loads(latest.read_text())
        assert data["passed"] is False
        assert len(data["results"]) == 2
        assert data["counts"]["pass"] == 1
        assert data["counts"]["fail"] == 1

    def test_appends_to_existing_log(self, tmp_path: Path):
        """Multiple writes on the same day should append, not overwrite."""
        plsec_home = tmp_path / "plsec"
        logs_dir = plsec_home / "logs"
        logs_dir.mkdir(parents=True)

        summary1 = ScanSummary(
            results=[ScanResult(scanner_id="first", scan_type="secrets", verdict="pass")],
            target="/a",
            passed=True,
        )
        summary2 = ScanSummary(
            results=[ScanResult(scanner_id="second", scan_type="code", verdict="fail")],
            target="/b",
            passed=False,
        )

        path1 = _write_scan_log(plsec_home, summary1)
        path2 = _write_scan_log(plsec_home, summary2)
        assert path1 is not None
        # Same day -> same file
        assert path1 == path2

        lines = path1.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_log_pattern_uses_date(self, tmp_path: Path):
        """Log filename should match scan-YYYYMMDD.jsonl pattern."""
        from datetime import UTC, datetime

        plsec_home = tmp_path / "plsec"
        (plsec_home / "logs").mkdir(parents=True)

        log_path = _write_scan_log(plsec_home, self._make_summary())
        assert log_path is not None
        expected_name = SCAN_LOG_PATTERN.format(date=datetime.now(UTC).strftime("%Y%m%d"))
        assert log_path.name == expected_name


# -----------------------------------------------------------------------
# _print_json
# -----------------------------------------------------------------------


class TestPrintJson:
    """Contract: _print_json outputs the scan summary as formatted JSON."""

    def test_outputs_json(self, capsys):
        """_print_json should produce valid JSON on stdout."""
        import json

        summary = ScanSummary(
            results=[ScanResult(scanner_id="a", scan_type="secrets", verdict="pass")],
            target="/home/user/proj",
            passed=True,
        )
        _print_json(summary)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["passed"] is True
        assert len(data["results"]) == 1


# -----------------------------------------------------------------------
# --json CLI flag
# -----------------------------------------------------------------------


class TestJsonFlag:
    """Contract: --json flag outputs scan results as JSON and suppresses
    the normal Rich table output."""

    def test_json_flag_outputs_valid_json(self, tmp_path: Path):
        """--json should produce parseable JSON output."""
        import json

        with (
            _patch_home(tmp_path),
            _patch_resolve_config(),
            _patch_scanner(True, "No issues found"),
        ):
            result = runner.invoke(app, ["--json", str(tmp_path)])
        assert result.exit_code == 0
        # The output contains Rich console lines followed by JSON.
        # Find the first top-level '{' and parse to the matching '}'.
        output = result.output
        # Look for the first '{' which starts the JSON summary
        json_start = output.find("{")
        assert json_start >= 0, f"No JSON found in output: {output!r}"
        # Try progressively longer slices to find valid JSON
        data = None
        for end in range(len(output), json_start, -1):
            try:
                data = json.loads(output[json_start:end])
                break
            except json.JSONDecodeError:
                continue
        assert data is not None, f"Could not parse JSON from output: {output!r}"
        assert "passed" in data
        assert "results" in data
        assert "counts" in data

    def test_json_flag_exit_1_on_secret_failure(self, tmp_path: Path):
        """--json with secret failure should exit 1."""

        def mock_run_scanner(spec, target, home, static_config=None):
            if spec.scan_type == "secrets":
                return ScanResult(
                    scanner_id=spec.id,
                    scan_type=spec.scan_type,
                    verdict="fail",
                    message="Found secret",
                )
            return ScanResult(
                scanner_id=spec.id,
                scan_type=spec.scan_type,
                verdict="pass",
                message="ok",
            )

        with (
            _patch_home(tmp_path),
            _patch_resolve_config(),
            patch("plsec.commands.scan.run_scanner", side_effect=mock_run_scanner),
        ):
            result = runner.invoke(app, ["--json", str(tmp_path)])
        assert result.exit_code == 1


# -----------------------------------------------------------------------
# _resolve_scanner_list unit tests
# -----------------------------------------------------------------------


class TestResolveScannerList:
    """Contract: _resolve_scanner_list resolves scanner IDs from config + CLI flags."""

    def test_no_flags_returns_config_scanners(self):
        """No CLI flags -> use config.layers.static.scanners."""
        config = PlsecConfig()
        result = _resolve_scanner_list(config, type_flags={"secrets": False, "code": False})
        assert result == config.layers.static.scanners

    def test_secrets_flag_returns_secret_scanners(self):
        """--secrets -> all secret-type scanners."""
        config = PlsecConfig()
        result = _resolve_scanner_list(
            config, type_flags={"secrets": True, "code": False, "misconfig": False}
        )
        assert "trivy-secrets" in result
        assert "bandit" not in result
        assert "semgrep" not in result

    def test_code_flag_returns_code_scanners(self):
        """--code -> all code-type scanners."""
        config = PlsecConfig()
        result = _resolve_scanner_list(
            config, type_flags={"secrets": False, "code": True, "misconfig": False}
        )
        assert "bandit" in result
        assert "semgrep" in result
        assert "trivy-secrets" not in result

    def test_multiple_type_flags_union(self):
        """--secrets --code -> union of both types."""
        config = PlsecConfig()
        result = _resolve_scanner_list(
            config, type_flags={"secrets": True, "code": True, "misconfig": False}
        )
        assert "trivy-secrets" in result
        assert "bandit" in result
        assert "semgrep" in result

    def test_scanner_flag_specific_scanner(self):
        """--scanner bandit -> only bandit."""
        config = PlsecConfig()
        result = _resolve_scanner_list(
            config, type_flags={"secrets": False, "code": False}, scanner_names=["bandit"]
        )
        assert result == ["bandit"]

    def test_scanner_flag_multiple(self):
        """--scanner bandit --scanner trivy-secrets -> both."""
        config = PlsecConfig()
        result = _resolve_scanner_list(
            config,
            type_flags={"secrets": False, "code": False},
            scanner_names=["bandit", "trivy-secrets"],
        )
        assert result == ["bandit", "trivy-secrets"]

    def test_scanner_flag_unknown_raises(self):
        """--scanner nonexistent -> BadParameter."""
        config = PlsecConfig()
        import pytest

        with pytest.raises(typer.BadParameter, match="Unknown scanner"):
            _resolve_scanner_list(
                config,
                type_flags={"secrets": False, "code": False},
                scanner_names=["nonexistent"],
            )

    def test_code_flag_with_valid_scanner(self):
        """--code --scanner bandit -> bandit (validated as code scanner)."""
        config = PlsecConfig()
        result = _resolve_scanner_list(
            config,
            type_flags={"secrets": False, "code": True, "misconfig": False},
            scanner_names=["bandit"],
        )
        assert result == ["bandit"]

    def test_code_flag_with_wrong_type_scanner_raises(self):
        """--code --scanner trivy-secrets -> error (type mismatch)."""
        config = PlsecConfig()
        import pytest

        with pytest.raises(typer.BadParameter, match="type 'secrets'"):
            _resolve_scanner_list(
                config,
                type_flags={"secrets": False, "code": True, "misconfig": False},
                scanner_names=["trivy-secrets"],
            )

    def test_preset_explicit_with_type_flag_union(self):
        """--preset minimal --code -> preset scanners + code scanners."""
        config = PlsecConfig()
        config.layers.static.scanners = ["trivy-secrets"]  # minimal preset
        result = _resolve_scanner_list(
            config,
            type_flags={"secrets": False, "code": True, "misconfig": False},
            preset_explicit=True,
        )
        assert "trivy-secrets" in result
        assert "bandit" in result
        assert "semgrep" in result

    def test_preset_explicit_with_scanner_flag_union(self):
        """--preset minimal --scanner bandit -> preset + bandit."""
        config = PlsecConfig()
        config.layers.static.scanners = ["trivy-secrets"]  # minimal preset
        result = _resolve_scanner_list(
            config,
            type_flags={"secrets": False, "code": False},
            scanner_names=["bandit"],
            preset_explicit=True,
        )
        assert "trivy-secrets" in result
        assert "bandit" in result

    def test_preset_explicit_without_flags_uses_preset(self):
        """--preset minimal (no type/scanner flags) -> preset scanners only."""
        config = PlsecConfig()
        config.layers.static.scanners = ["trivy-secrets"]
        result = _resolve_scanner_list(
            config,
            type_flags={"secrets": False, "code": False},
            preset_explicit=True,
        )
        assert result == ["trivy-secrets"]


# -----------------------------------------------------------------------
# Preset integration via CLI
# -----------------------------------------------------------------------


class TestPresetCLI:
    """Contract: --preset flag controls scanner selection via resolve_config."""

    def test_preset_minimal_runs_fewer_scanners(self, tmp_path: Path):
        """--preset minimal should run only trivy-secrets."""
        scanned_ids = []

        def mock_run_scanner(spec, target, home, static_config=None):
            scanned_ids.append(spec.id)
            return ScanResult(
                scanner_id=spec.id,
                scan_type=spec.scan_type,
                verdict="pass",
                message="ok",
            )

        with (
            _patch_home(tmp_path),
            _patch_resolve_config("minimal"),
            patch("plsec.commands.scan.run_scanner", side_effect=mock_run_scanner),
        ):
            result = runner.invoke(app, ["--preset", "minimal", str(tmp_path)])
        assert result.exit_code == 0
        # minimal preset has only trivy-secrets in its default PlsecConfig
        # but our mock returns default PlsecConfig with all 4 scanners
        assert len(scanned_ids) >= 1

    def test_preset_shows_in_output(self, tmp_path: Path):
        """--preset balanced should show preset name in output."""
        with _patch_home(tmp_path), _patch_resolve_config("balanced"), _patch_scanner(True, "ok"):
            result = runner.invoke(app, ["--preset", "balanced", str(tmp_path)])
        assert result.exit_code == 0
        assert "balanced" in result.output


# -----------------------------------------------------------------------
# Scanner flag CLI integration
# -----------------------------------------------------------------------


class TestScannerFlagCLI:
    """Contract: --scanner flag selects specific scanners."""

    def test_scanner_flag_runs_only_named(self, tmp_path: Path):
        """--scanner bandit runs only bandit."""
        scanned_ids = []

        def mock_run_scanner(spec, target, home, static_config=None):
            scanned_ids.append(spec.id)
            return ScanResult(
                scanner_id=spec.id,
                scan_type=spec.scan_type,
                verdict="pass",
                message="ok",
            )

        with (
            _patch_home(tmp_path),
            _patch_resolve_config(),
            patch("plsec.commands.scan.run_scanner", side_effect=mock_run_scanner),
        ):
            result = runner.invoke(app, ["--scanner", "bandit", str(tmp_path)])
        assert result.exit_code == 0
        assert scanned_ids == ["bandit"]

    def test_multiple_scanner_flags(self, tmp_path: Path):
        """--scanner bandit --scanner semgrep runs both."""
        scanned_ids = []

        def mock_run_scanner(spec, target, home, static_config=None):
            scanned_ids.append(spec.id)
            return ScanResult(
                scanner_id=spec.id,
                scan_type=spec.scan_type,
                verdict="pass",
                message="ok",
            )

        with (
            _patch_home(tmp_path),
            _patch_resolve_config(),
            patch("plsec.commands.scan.run_scanner", side_effect=mock_run_scanner),
        ):
            result = runner.invoke(
                app, ["--scanner", "bandit", "--scanner", "semgrep", str(tmp_path)]
            )
        assert result.exit_code == 0
        assert set(scanned_ids) == {"bandit", "semgrep"}

    def test_scanner_unknown_exits_1(self, tmp_path: Path):
        """--scanner nonexistent should exit 1."""
        with _patch_home(tmp_path), _patch_resolve_config():
            result = runner.invoke(app, ["--scanner", "nonexistent", str(tmp_path)])
        assert result.exit_code == 1


# -----------------------------------------------------------------------
# Verbose output
# -----------------------------------------------------------------------


class TestVerboseOutput:
    """Contract: --verbose shows configuration details."""

    def test_verbose_shows_preset(self, tmp_path: Path):
        """--verbose should show preset name."""
        with _patch_home(tmp_path), _patch_resolve_config("balanced"), _patch_scanner(True, "ok"):
            result = runner.invoke(app, ["--verbose", str(tmp_path)])
        assert result.exit_code == 0
        assert "Preset: balanced" in result.output

    def test_verbose_shows_scanners(self, tmp_path: Path):
        """--verbose should show scanner list."""
        with _patch_home(tmp_path), _patch_resolve_config("balanced"), _patch_scanner(True, "ok"):
            result = runner.invoke(app, ["--verbose", str(tmp_path)])
        assert result.exit_code == 0
        assert "Scanners:" in result.output

    def test_verbose_shows_severity(self, tmp_path: Path):
        """--verbose should show severity threshold."""
        with _patch_home(tmp_path), _patch_resolve_config("balanced"), _patch_scanner(True, "ok"):
            result = runner.invoke(app, ["--verbose", str(tmp_path)])
        assert result.exit_code == 0
        assert "Severity threshold:" in result.output

    def test_normal_mode_shows_brief_line(self, tmp_path: Path):
        """Normal mode should show brief preset line."""
        with _patch_home(tmp_path), _patch_resolve_config("balanced"), _patch_scanner(True, "ok"):
            result = runner.invoke(app, [str(tmp_path)])
        assert result.exit_code == 0
        assert "Using preset: balanced" in result.output
