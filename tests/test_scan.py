"""Tests for the scan command module (commands/scan.py).

Covers:
- Engine pipeline execution via orchestrator
- Preset selection and filtering
- Type flag filtering (--secrets, --code, --misconfig)
- Specific engine selection (--scanner)
- Pass/fail/warn verdict handling and exit codes
- Verbose config display
- JSON output
- Scan log persistence

All tests mock the orchestrator and registry to avoid actual binary
execution. Tests use the typer CLI runner.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from plsec.commands.scan import (
    SCAN_LATEST,
    SCAN_LOG_PATTERN,
    _check_scanner_prerequisites,
    _filter_registry,
    _result_to_summary_dict,
    _write_scan_log,
    app,
)
from plsec.core.health import PLSEC_EXPECTED_FILES
from plsec.engine.base import EngineResult, LayerResult, ScanResult
from plsec.engine.types import (
    AvailabilityResult,
    EngineStatus,
    Finding,
    FindingCategory,
    Layer,
    Location,
    Preset,
    Severity,
)
from plsec.engine.verdict import (
    EXIT_FAIL,
    EXIT_PASS,
    EXIT_WARN,
    Verdict,
    VerdictCounts,
    VerdictStatus,
)

runner = CliRunner()


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _make_finding(
    engine_id: str = "trivy-secrets",
    layer: Layer = Layer.STATIC,
    severity: Severity = Severity.HIGH,
    category: FindingCategory = FindingCategory.LEAKED_CREDENTIAL,
    title: str = "AWS Access Key",
    suppressed: bool = False,
) -> Finding:
    """Create a Finding for testing."""
    f = Finding(
        engine_id=engine_id,
        layer=layer,
        severity=severity,
        category=category,
        title=title,
        location=Location(file_path=Path("src/config.py"), line_start=42),
    )
    return f.with_suppressed(True) if suppressed else f


def _make_engine_result(
    engine_id: str = "trivy-secrets",
    status: EngineStatus = EngineStatus.AVAILABLE,
    findings: list[Finding] | None = None,
) -> EngineResult:
    """Create an EngineResult for testing."""
    return EngineResult(
        engine_id=engine_id,
        availability=AvailabilityResult(status=status, message="ok"),
        findings=findings or [],
    )


def _make_layer_result(
    layer: Layer = Layer.STATIC,
    engine_results: list[EngineResult] | None = None,
    findings: list[Finding] | None = None,
) -> LayerResult:
    """Create a LayerResult for testing."""
    return LayerResult(
        layer=layer,
        engine_results=engine_results or [],
        findings=findings or [],
    )


def _make_verdict(
    status: str = VerdictStatus.PASSED,
    exit_code: int = EXIT_PASS,
    rationale: str = "All clear",
    total: int = 0,
    suppressed: int = 0,
    engines_ran: int = 3,
    engines_skipped: int = 0,
) -> Verdict:
    """Create a Verdict for testing."""
    return Verdict(
        status=status,
        exit_code=exit_code,
        rationale=rationale,
        counts=VerdictCounts(
            total=total,
            suppressed=suppressed,
            engines_ran=engines_ran,
            engines_skipped=engines_skipped,
        ),
    )


def _make_scan_result(
    verdict: Verdict | None = None,
    layer_results: list[LayerResult] | None = None,
) -> ScanResult:
    """Create a ScanResult for testing."""
    result = ScanResult()
    if layer_results:
        result.layer_results = layer_results
    if verdict:
        result.verdict = verdict
    else:
        result.verdict = _make_verdict()
    return result


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
    """Patch resolve_config to return a default config with given preset."""
    from plsec.core.config import PlsecConfig

    config = PlsecConfig()
    config.preset = preset
    return patch(
        "plsec.commands.scan.resolve_config",
        return_value=(config, preset),
    )


def _patch_orchestrator(result: ScanResult | None = None):
    """Patch build_orchestrator to return a mock that produces the given result."""
    if result is None:
        result = _make_scan_result()
    mock_orch = MagicMock()
    mock_orch.scan.return_value = result
    return patch(
        "plsec.commands.scan.build_orchestrator",
        return_value=mock_orch,
    )


def _patch_registry():
    """Patch build_default_registry to return the real default registry."""
    # We use the real registry so filter tests work correctly
    return patch("plsec.commands.scan.build_default_registry")


# -----------------------------------------------------------------------
# Basic execution
# -----------------------------------------------------------------------


class TestScanExecution:
    """Contract: scan runs orchestrator, uses verdict for exit code."""

    def test_all_pass_exits_zero(self, tmp_path: Path):
        result = _make_scan_result(verdict=_make_verdict(status=VerdictStatus.PASSED))
        with _patch_home(tmp_path), _patch_resolve_config(), _patch_orchestrator(result):
            cli_result = runner.invoke(app, [str(tmp_path)])
        assert cli_result.exit_code == EXIT_PASS

    def test_fail_verdict_exits_one(self, tmp_path: Path):
        result = _make_scan_result(
            verdict=_make_verdict(
                status=VerdictStatus.FAIL,
                exit_code=EXIT_FAIL,
                rationale="HIGH findings",
                total=1,
            )
        )
        with _patch_home(tmp_path), _patch_resolve_config(), _patch_orchestrator(result):
            cli_result = runner.invoke(app, [str(tmp_path)])
        assert cli_result.exit_code == EXIT_FAIL

    def test_warn_verdict_exits_three(self, tmp_path: Path):
        result = _make_scan_result(
            verdict=_make_verdict(
                status=VerdictStatus.WARN,
                exit_code=EXIT_WARN,
                rationale="MEDIUM findings",
                total=1,
            )
        )
        with _patch_home(tmp_path), _patch_resolve_config(), _patch_orchestrator(result):
            cli_result = runner.invoke(app, [str(tmp_path)])
        assert cli_result.exit_code == EXIT_WARN

    def test_nonexistent_path_exits_one(self, tmp_path: Path):
        bad_path = tmp_path / "nonexistent"
        with _patch_home(tmp_path), _patch_resolve_config():
            cli_result = runner.invoke(app, [str(bad_path)])
        assert cli_result.exit_code == 1

    def test_orchestrator_receives_resolved_path(self, tmp_path: Path):
        result = _make_scan_result()
        mock_orch = MagicMock()
        mock_orch.scan.return_value = result
        with (
            _patch_home(tmp_path),
            _patch_resolve_config(),
            patch("plsec.commands.scan.build_orchestrator", return_value=mock_orch),
            patch("plsec.commands.scan.build_default_registry"),
        ):
            runner.invoke(app, [str(tmp_path)])
        call_args = mock_orch.scan.call_args
        assert call_args[0][0] == tmp_path.resolve()


# -----------------------------------------------------------------------
# Preset selection
# -----------------------------------------------------------------------


class TestPresetSelection:
    """Contract: --preset flag maps to Preset enum and passes to orchestrator."""

    def test_default_preset_is_balanced(self, tmp_path: Path):
        result = _make_scan_result()
        mock_orch = MagicMock()
        mock_orch.scan.return_value = result
        with (
            _patch_home(tmp_path),
            _patch_resolve_config("balanced"),
            patch("plsec.commands.scan.build_orchestrator", return_value=mock_orch),
            patch("plsec.commands.scan.build_default_registry"),
        ):
            runner.invoke(app, [str(tmp_path)])
        assert mock_orch.scan.call_args[0][1] == Preset.BALANCED

    def test_preset_shows_in_output(self, tmp_path: Path):
        result = _make_scan_result()
        with _patch_home(tmp_path), _patch_resolve_config("balanced"), _patch_orchestrator(result):
            cli_result = runner.invoke(app, ["--preset", "balanced", str(tmp_path)])
        assert "balanced" in cli_result.output


# -----------------------------------------------------------------------
# Registry filtering (--scanner, --code, --secrets, --misconfig)
# -----------------------------------------------------------------------


class TestRegistryFiltering:
    """Contract: CLI flags filter the engine registry before scanning."""

    def test_filter_by_engine_id(self):
        from plsec.engine.registry import build_default_registry

        registry = build_default_registry()
        filtered = _filter_registry(registry, engine_ids=["bandit"])
        assert len(filtered) == 1
        assert "bandit" in filtered

    def test_filter_unknown_engine_raises(self):
        from plsec.engine.registry import build_default_registry

        registry = build_default_registry()
        with pytest.raises(typer.BadParameter, match="Unknown engine"):
            _filter_registry(registry, engine_ids=["nonexistent"])

    def test_filter_by_secrets_flag(self):
        from plsec.engine.registry import build_default_registry

        registry = build_default_registry()
        filtered = _filter_registry(
            registry, type_flags={"secrets": True, "code": False, "misconfig": False}
        )
        engine_ids = {e.engine_id for e in filtered.all_engines()}
        assert "trivy-secrets" in engine_ids
        assert "bandit" not in engine_ids

    def test_filter_by_code_flag(self):
        from plsec.engine.registry import build_default_registry

        registry = build_default_registry()
        filtered = _filter_registry(
            registry, type_flags={"secrets": False, "code": True, "misconfig": False}
        )
        engine_ids = {e.engine_id for e in filtered.all_engines()}
        assert "bandit" in engine_ids
        assert "semgrep" in engine_ids
        assert "trivy-secrets" not in engine_ids

    def test_filter_by_misconfig_flag(self):
        from plsec.engine.registry import build_default_registry

        registry = build_default_registry()
        filtered = _filter_registry(
            registry, type_flags={"secrets": False, "code": False, "misconfig": True}
        )
        engine_ids = {e.engine_id for e in filtered.all_engines()}
        assert "trivy-misconfig" in engine_ids
        assert "trivy-secrets" not in engine_ids
        assert "bandit" not in engine_ids

    def test_no_flags_returns_full_registry(self):
        from plsec.engine.registry import build_default_registry

        registry = build_default_registry()
        filtered = _filter_registry(registry)
        assert len(filtered) == len(registry)

    def test_no_active_flags_returns_full_registry(self):
        from plsec.engine.registry import build_default_registry

        registry = build_default_registry()
        filtered = _filter_registry(
            registry, type_flags={"secrets": False, "code": False, "misconfig": False}
        )
        assert len(filtered) == len(registry)


# -----------------------------------------------------------------------
# CLI integration with scanner/type flags
# -----------------------------------------------------------------------


class TestScannerFlagCLI:
    """Contract: --scanner flag selects specific engines."""

    def test_scanner_flag_runs_only_named(self, tmp_path: Path):
        result = _make_scan_result()
        mock_orch = MagicMock()
        mock_orch.scan.return_value = result
        with (
            _patch_home(tmp_path),
            _patch_resolve_config(),
            patch("plsec.commands.scan.build_orchestrator", return_value=mock_orch),
        ):
            cli_result = runner.invoke(app, ["--scanner", "bandit", str(tmp_path)])
        assert cli_result.exit_code == EXIT_PASS

    def test_scanner_unknown_exits_one(self, tmp_path: Path):
        with _patch_home(tmp_path), _patch_resolve_config():
            cli_result = runner.invoke(app, ["--scanner", "nonexistent", str(tmp_path)])
        assert cli_result.exit_code == 1


# -----------------------------------------------------------------------
# Pre-flight prerequisite check
# -----------------------------------------------------------------------


class TestScannerPrerequisites:
    """Contract: _check_scanner_prerequisites raises typer.Exit(1)
    when required scanner configs are missing."""

    def test_passes_when_all_present(self, tmp_path: Path):
        plsec_home = _setup_plsec_home(tmp_path)
        _check_scanner_prerequisites(plsec_home)

    def test_fails_when_all_missing(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        plsec_home.mkdir(parents=True)
        with pytest.raises(typer.Exit) as exc_info:
            _check_scanner_prerequisites(plsec_home)
        assert exc_info.value.exit_code == 1

    def test_fails_when_partially_missing(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        first_rel, _first_desc = PLSEC_EXPECTED_FILES[0]
        first_path = plsec_home / first_rel
        first_path.parent.mkdir(parents=True, exist_ok=True)
        first_path.write_text("placeholder\n")
        with pytest.raises(typer.Exit) as exc_info:
            _check_scanner_prerequisites(plsec_home)
        assert exc_info.value.exit_code == 1

    def test_cli_exits_1_when_configs_missing(self, tmp_path: Path):
        empty_home = tmp_path / "empty_plsec_home"
        empty_home.mkdir(parents=True)
        with (
            _patch_resolve_config(),
            patch("plsec.commands.scan.get_plsec_home", return_value=empty_home),
        ):
            cli_result = runner.invoke(app, [str(tmp_path)])
        assert cli_result.exit_code == 1
        assert "plsec install" in cli_result.output


# -----------------------------------------------------------------------
# _result_to_summary_dict
# -----------------------------------------------------------------------


class TestResultToSummaryDict:
    """Contract: _result_to_summary_dict produces a JSON-serializable dict
    with overall_passed for plsec-status compatibility."""

    def test_overall_passed_true(self):
        result = _make_scan_result(verdict=_make_verdict(status=VerdictStatus.PASSED))
        d = _result_to_summary_dict(result, "/home/user/proj")
        assert d["overall_passed"] is True

    def test_overall_passed_false(self):
        result = _make_scan_result(
            verdict=_make_verdict(status=VerdictStatus.FAIL, exit_code=EXIT_FAIL, total=1)
        )
        d = _result_to_summary_dict(result, "/home/user/proj")
        assert d["overall_passed"] is False

    def test_has_required_fields(self):
        result = _make_scan_result()
        d = _result_to_summary_dict(result, "/home/user/proj")
        assert "ts" in d
        assert "target" in d
        assert "overall_passed" in d
        assert "verdict" in d
        assert "counts" in d

    def test_target_preserved(self):
        result = _make_scan_result()
        d = _result_to_summary_dict(result, "/var/project")
        assert d["target"] == "/var/project"

    def test_engines_list(self):
        er = _make_engine_result("bandit")
        lr = _make_layer_result(Layer.STATIC, [er], [])
        result = _make_scan_result(layer_results=[lr])
        d = _result_to_summary_dict(result, "/proj")
        assert len(d["engines"]) == 1
        assert d["engines"][0]["engine"] == "bandit"

    def test_ts_is_iso_format(self):
        result = _make_scan_result()
        d = _result_to_summary_dict(result, "/proj")
        assert "T" in d["ts"]


# -----------------------------------------------------------------------
# _write_scan_log
# -----------------------------------------------------------------------


class TestWriteScanLog:
    """Contract: _write_scan_log writes scan-latest.json and daily JSONL."""

    def test_returns_none_when_logs_dir_missing(self, tmp_path: Path):
        plsec_home = tmp_path / "plsec"
        plsec_home.mkdir()
        result = _make_scan_result()
        log_path = _write_scan_log(plsec_home, result, "/proj")
        assert log_path is None

    def test_creates_daily_jsonl(self, tmp_path: Path):
        plsec_home = tmp_path / "plsec"
        (plsec_home / "logs").mkdir(parents=True)
        result = _make_scan_result()
        log_path = _write_scan_log(plsec_home, result, "/proj")
        assert log_path is not None
        assert log_path.suffix == ".jsonl"
        assert log_path.name.startswith("scan-")

        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert "overall_passed" in data

    def test_creates_scan_latest_json(self, tmp_path: Path):
        plsec_home = tmp_path / "plsec"
        (plsec_home / "logs").mkdir(parents=True)
        result = _make_scan_result()
        _write_scan_log(plsec_home, result, "/proj")
        latest = plsec_home / "logs" / SCAN_LATEST
        assert latest.exists()
        data = json.loads(latest.read_text())
        assert "overall_passed" in data

    def test_overall_passed_in_latest(self, tmp_path: Path):
        plsec_home = tmp_path / "plsec"
        (plsec_home / "logs").mkdir(parents=True)
        result = _make_scan_result(verdict=_make_verdict(status=VerdictStatus.PASSED))
        _write_scan_log(plsec_home, result, "/proj")
        latest = plsec_home / "logs" / SCAN_LATEST
        data = json.loads(latest.read_text())
        assert data["overall_passed"] is True

    def test_appends_to_existing_log(self, tmp_path: Path):
        plsec_home = tmp_path / "plsec"
        (plsec_home / "logs").mkdir(parents=True)
        r1 = _make_scan_result()
        r2 = _make_scan_result()
        p1 = _write_scan_log(plsec_home, r1, "/a")
        p2 = _write_scan_log(plsec_home, r2, "/b")
        assert p1 is not None
        assert p1 == p2  # same day -> same file
        lines = p1.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_log_pattern_uses_date(self, tmp_path: Path):
        from datetime import UTC, datetime

        plsec_home = tmp_path / "plsec"
        (plsec_home / "logs").mkdir(parents=True)
        result = _make_scan_result()
        log_path = _write_scan_log(plsec_home, result, "/proj")
        assert log_path is not None
        expected_name = SCAN_LOG_PATTERN.format(date=datetime.now(UTC).strftime("%Y%m%d"))
        assert log_path.name == expected_name


# -----------------------------------------------------------------------
# JSON output
# -----------------------------------------------------------------------


class TestJsonFlag:
    """Contract: --json flag outputs scan results as JSON."""

    def test_json_flag_outputs_valid_json(self, tmp_path: Path):
        result = _make_scan_result()
        with _patch_home(tmp_path), _patch_resolve_config(), _patch_orchestrator(result):
            cli_result = runner.invoke(app, ["--json", str(tmp_path)])
        assert cli_result.exit_code == EXIT_PASS
        output = cli_result.output
        json_start = output.find("{")
        assert json_start >= 0
        data = None
        for end in range(len(output), json_start, -1):
            try:
                data = json.loads(output[json_start:end])
                break
            except json.JSONDecodeError:
                continue
        assert data is not None
        assert "overall_passed" in data
        assert "verdict" in data

    def test_json_flag_exit_1_on_failure(self, tmp_path: Path):
        result = _make_scan_result(
            verdict=_make_verdict(status=VerdictStatus.FAIL, exit_code=EXIT_FAIL, total=1)
        )
        with _patch_home(tmp_path), _patch_resolve_config(), _patch_orchestrator(result):
            cli_result = runner.invoke(app, ["--json", str(tmp_path)])
        assert cli_result.exit_code == EXIT_FAIL


# -----------------------------------------------------------------------
# Verbose output
# -----------------------------------------------------------------------


class TestVerboseOutput:
    """Contract: --verbose shows configuration details."""

    def test_verbose_shows_preset(self, tmp_path: Path):
        result = _make_scan_result()
        with _patch_home(tmp_path), _patch_resolve_config("balanced"), _patch_orchestrator(result):
            cli_result = runner.invoke(app, ["--verbose", str(tmp_path)])
        assert cli_result.exit_code == EXIT_PASS
        assert "Preset: balanced" in cli_result.output

    def test_verbose_shows_engines(self, tmp_path: Path):
        result = _make_scan_result()
        with _patch_home(tmp_path), _patch_resolve_config("balanced"), _patch_orchestrator(result):
            cli_result = runner.invoke(app, ["--verbose", str(tmp_path)])
        assert "Engines:" in cli_result.output

    def test_normal_mode_shows_brief_line(self, tmp_path: Path):
        result = _make_scan_result()
        with _patch_home(tmp_path), _patch_resolve_config("balanced"), _patch_orchestrator(result):
            cli_result = runner.invoke(app, [str(tmp_path)])
        assert "Using preset: balanced" in cli_result.output


# -----------------------------------------------------------------------
# Finding display
# -----------------------------------------------------------------------


class TestFindingDisplay:
    """Contract: findings are displayed grouped by layer with severity."""

    def test_pass_shows_no_issues(self, tmp_path: Path):
        lr = _make_layer_result(Layer.STATIC, [_make_engine_result()], [])
        result = _make_scan_result(layer_results=[lr])
        with _patch_home(tmp_path), _patch_resolve_config(), _patch_orchestrator(result):
            cli_result = runner.invoke(app, [str(tmp_path)])
        assert cli_result.exit_code == EXIT_PASS

    def test_fail_shows_critical_message(self, tmp_path: Path):
        finding = _make_finding(severity=Severity.HIGH)
        er = _make_engine_result("trivy-secrets", findings=[finding])
        lr = _make_layer_result(Layer.STATIC, [er], [finding])
        result = _make_scan_result(
            layer_results=[lr],
            verdict=_make_verdict(
                status=VerdictStatus.FAIL,
                exit_code=EXIT_FAIL,
                total=1,
            ),
        )
        with _patch_home(tmp_path), _patch_resolve_config(), _patch_orchestrator(result):
            cli_result = runner.invoke(app, [str(tmp_path)])
        assert cli_result.exit_code == EXIT_FAIL
        assert "Critical issues found" in cli_result.output


# -----------------------------------------------------------------------
# Verdict exit code mapping
# -----------------------------------------------------------------------


class TestVerdictExitCodes:
    """Contract: CLI exit code comes from verdict.exit_code."""

    def test_pass_exits_zero(self, tmp_path: Path):
        result = _make_scan_result(
            verdict=_make_verdict(status=VerdictStatus.PASSED, exit_code=EXIT_PASS)
        )
        with _patch_home(tmp_path), _patch_resolve_config(), _patch_orchestrator(result):
            cli_result = runner.invoke(app, [str(tmp_path)])
        assert cli_result.exit_code == EXIT_PASS

    def test_fail_exits_one(self, tmp_path: Path):
        result = _make_scan_result(
            verdict=_make_verdict(status=VerdictStatus.FAIL, exit_code=EXIT_FAIL, total=1)
        )
        with _patch_home(tmp_path), _patch_resolve_config(), _patch_orchestrator(result):
            cli_result = runner.invoke(app, [str(tmp_path)])
        assert cli_result.exit_code == EXIT_FAIL

    def test_warn_exits_three(self, tmp_path: Path):
        result = _make_scan_result(
            verdict=_make_verdict(status=VerdictStatus.WARN, exit_code=EXIT_WARN, total=1)
        )
        with _patch_home(tmp_path), _patch_resolve_config(), _patch_orchestrator(result):
            cli_result = runner.invoke(app, [str(tmp_path)])
        assert cli_result.exit_code == EXIT_WARN
