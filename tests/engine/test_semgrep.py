"""Tests for plsec.engine.semgrep -- Semgrep security scanning engine."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from plsec.engine.semgrep import (
    _SEVERITY_MAP,
    DEFAULT_TIMEOUT,
    SemgrepEngine,
)
from plsec.engine.types import (
    EngineStatus,
    EnvironmentInfo,
    FindingCategory,
    Layer,
    Preset,
    ScanContext,
    Severity,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SENTINEL: frozenset[str] = frozenset({"__sentinel__"})


def _make_ctx(
    available_tools: frozenset[str] | None = _SENTINEL,
    engine_configs: dict | None = None,
    target: str = "/var/project",
) -> ScanContext:
    tools = (
        frozenset({"semgrep"}) if available_tools is _SENTINEL else (available_tools or frozenset())
    )
    return ScanContext(
        target_path=Path(target),
        preset=Preset.BALANCED,
        environment=EnvironmentInfo(
            os_name="darwin",
            os_version="23.0.0",
            python_version="3.12.0",
            available_tools=tools,
        ),
        engine_configs=engine_configs or {},
    )


def _semgrep_json_output(results: list[dict] | None = None) -> str:
    return json.dumps(
        {
            "version": "1.0.0",
            "results": results or [],
            "errors": [],
            "paths": {"scanned": ["src/app.py"]},
        }
    )


def _make_result(
    check_id: str = "python.lang.security.audit.subprocess-shell-true",
    path: str = "src/app.py",
    start_line: int = 10,
    end_line: int = 10,
    message: str = "subprocess call with shell=True",
    sev: str = "WARNING",
    lines: str = "subprocess.run(cmd, shell=True)",
    cwe: list[str] | None = None,
) -> dict:
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": start_line, "col": 1},
        "end": {"line": end_line, "col": 45},
        "extra": {
            "message": message,
            "severity": sev,
            "metadata": {
                "cwe": cwe or ["CWE-78"],
                "confidence": "HIGH",
            },
            "lines": lines,
        },
    }


# ---------------------------------------------------------------------------
# Engine identity
# ---------------------------------------------------------------------------


class TestEngineIdentity:
    def test_engine_id(self) -> None:
        assert SemgrepEngine().engine_id == "semgrep"

    def test_layer(self) -> None:
        assert SemgrepEngine().layer == Layer.STATIC

    def test_display_name(self) -> None:
        assert SemgrepEngine().display_name == "Semgrep"

    def test_presets_all(self) -> None:
        assert SemgrepEngine().presets == frozenset(Preset)

    def test_dependencies(self) -> None:
        assert SemgrepEngine().dependencies == ["semgrep"]


# ---------------------------------------------------------------------------
# Availability checks
# ---------------------------------------------------------------------------


class TestCheckAvailable:
    def test_available(self) -> None:
        ctx = _make_ctx(available_tools=frozenset({"semgrep"}))
        result = SemgrepEngine().check_available(ctx)
        assert result.status == EngineStatus.AVAILABLE

    def test_unavailable(self) -> None:
        ctx = _make_ctx(available_tools=frozenset())
        result = SemgrepEngine().check_available(ctx)
        assert result.status == EngineStatus.UNAVAILABLE
        assert "semgrep" in result.message

    def test_unavailable_with_other_tools(self) -> None:
        ctx = _make_ctx(available_tools=frozenset({"bandit", "trivy"}))
        result = SemgrepEngine().check_available(ctx)
        assert result.status == EngineStatus.UNAVAILABLE


# ---------------------------------------------------------------------------
# Execute -- happy path
# ---------------------------------------------------------------------------


class TestExecuteHappyPath:
    @patch("plsec.engine.semgrep.subprocess.run")
    def test_single_finding(self, mock_run) -> None:
        result_item = _make_result()
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=_semgrep_json_output([result_item]), stderr=""
        )
        findings = SemgrepEngine().execute(_make_ctx())

        assert len(findings) == 1
        f = findings[0]
        assert f.engine_id == "semgrep"
        assert f.layer == Layer.STATIC
        assert f.severity == Severity.MEDIUM
        assert f.category == FindingCategory.CODE_ISSUE
        assert f.title == "subprocess call with shell=True"
        assert f.location is not None
        assert f.location.file_path == Path("src/app.py")
        assert f.location.line_start == 10
        assert f.location.line_end == 10

    @patch("plsec.engine.semgrep.subprocess.run")
    def test_multiple_findings(self, mock_run) -> None:
        results = [
            _make_result(message="Finding 1", sev="ERROR", start_line=5),
            _make_result(message="Finding 2", sev="WARNING", start_line=15),
        ]
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=_semgrep_json_output(results), stderr=""
        )
        findings = SemgrepEngine().execute(_make_ctx())
        assert len(findings) == 2
        assert findings[0].severity == Severity.HIGH
        assert findings[1].severity == Severity.MEDIUM

    @patch("plsec.engine.semgrep.subprocess.run")
    def test_clean_scan(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_semgrep_json_output([]), stderr=""
        )
        findings = SemgrepEngine().execute(_make_ctx())
        assert findings == []

    @patch("plsec.engine.semgrep.subprocess.run")
    def test_empty_stdout(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        findings = SemgrepEngine().execute(_make_ctx())
        assert findings == []


# ---------------------------------------------------------------------------
# Execute -- error handling
# ---------------------------------------------------------------------------


class TestExecuteErrors:
    @patch("plsec.engine.semgrep.subprocess.run")
    def test_timeout_produces_finding(self, mock_run) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="semgrep", timeout=600)
        findings = SemgrepEngine().execute(_make_ctx())
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.MISSING_CONTROL
        assert "timed out" in findings[0].description

    @patch("plsec.engine.semgrep.subprocess.run")
    def test_file_not_found(self, mock_run) -> None:
        mock_run.side_effect = FileNotFoundError("semgrep")
        findings = SemgrepEngine().execute(_make_ctx())
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.MISSING_CONTROL

    @patch("plsec.engine.semgrep.subprocess.run")
    def test_os_error(self, mock_run) -> None:
        mock_run.side_effect = OSError("Permission denied")
        findings = SemgrepEngine().execute(_make_ctx())
        assert len(findings) == 1
        assert "Permission denied" in findings[0].description

    @patch("plsec.engine.semgrep.subprocess.run")
    def test_invalid_json(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="not json", stderr=""
        )
        findings = SemgrepEngine().execute(_make_ctx())
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.MISSING_CONTROL

    @patch("plsec.engine.semgrep.subprocess.run")
    def test_prefixed_stdout_recovered(self, mock_run) -> None:
        """Non-JSON prefix before valid JSON is stripped by extract_json."""
        result_item = _make_result(message="Found via noisy output")
        prefixed = "Scanning... 42 rules loaded\n" + _semgrep_json_output([result_item])
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=prefixed, stderr=""
        )
        findings = SemgrepEngine().execute(_make_ctx())
        assert len(findings) == 1
        assert findings[0].title == "Found via noisy output"


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------


class TestCommandConstruction:
    @patch("plsec.engine.semgrep.subprocess.run")
    def test_basic_command(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_semgrep_json_output(), stderr=""
        )
        SemgrepEngine().execute(_make_ctx(target="/var/my-project"))
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "semgrep"
        assert "--config" in cmd
        assert "auto" in cmd
        assert "--json" in cmd
        assert "--quiet" in cmd
        assert str(Path("/var/my-project")) in cmd

    @patch("plsec.engine.semgrep.subprocess.run")
    def test_custom_config(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_semgrep_json_output(), stderr=""
        )
        ctx = _make_ctx(engine_configs={"semgrep": {"config": "p/python"}})
        SemgrepEngine().execute(ctx)
        cmd = mock_run.call_args[0][0]
        config_idx = cmd.index("--config")
        assert cmd[config_idx + 1] == "p/python"

    @patch("plsec.engine.semgrep.subprocess.run")
    def test_default_timeout(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_semgrep_json_output(), stderr=""
        )
        SemgrepEngine().execute(_make_ctx())
        assert mock_run.call_args[1]["timeout"] == DEFAULT_TIMEOUT

    @patch("plsec.engine.semgrep.subprocess.run")
    def test_custom_timeout(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_semgrep_json_output(), stderr=""
        )
        ctx = _make_ctx(engine_configs={"semgrep": {"timeout": 120}})
        SemgrepEngine().execute(ctx)
        assert mock_run.call_args[1]["timeout"] == 120


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    def test_error_maps_to_high(self) -> None:
        assert _SEVERITY_MAP["ERROR"] == Severity.HIGH

    def test_warning_maps_to_medium(self) -> None:
        assert _SEVERITY_MAP["WARNING"] == Severity.MEDIUM

    def test_info_maps_to_low(self) -> None:
        assert _SEVERITY_MAP["INFO"] == Severity.LOW

    @patch("plsec.engine.semgrep.subprocess.run")
    def test_unmapped_defaults_to_info(self, mock_run) -> None:
        result_item = _make_result(sev="WHATEVER")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=_semgrep_json_output([result_item]), stderr=""
        )
        findings = SemgrepEngine().execute(_make_ctx())
        assert findings[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# Finding details
# ---------------------------------------------------------------------------


class TestFindingDetails:
    @patch("plsec.engine.semgrep.subprocess.run")
    def test_evidence_contains_check_id(self, mock_run) -> None:
        result_item = _make_result(check_id="python.lang.foo.bar")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=_semgrep_json_output([result_item]), stderr=""
        )
        findings = SemgrepEngine().execute(_make_ctx())
        assert findings[0].evidence["check_id"] == "python.lang.foo.bar"

    @patch("plsec.engine.semgrep.subprocess.run")
    def test_evidence_contains_cwe(self, mock_run) -> None:
        result_item = _make_result(cwe=["CWE-78", "CWE-89"])
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=_semgrep_json_output([result_item]), stderr=""
        )
        findings = SemgrepEngine().execute(_make_ctx())
        assert findings[0].evidence["cwe"] == ["CWE-78", "CWE-89"]

    @patch("plsec.engine.semgrep.subprocess.run")
    def test_remediation_contains_rule_link(self, mock_run) -> None:
        result_item = _make_result(check_id="python.lang.foo")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=_semgrep_json_output([result_item]), stderr=""
        )
        findings = SemgrepEngine().execute(_make_ctx())
        assert "python.lang.foo" in findings[0].remediation

    @patch("plsec.engine.semgrep.subprocess.run")
    def test_description_is_matched_lines(self, mock_run) -> None:
        result_item = _make_result(lines="bad_code()")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=_semgrep_json_output([result_item]), stderr=""
        )
        findings = SemgrepEngine().execute(_make_ctx())
        assert findings[0].description == "bad_code()"

    @patch("plsec.engine.semgrep.subprocess.run")
    def test_finding_id_deterministic(self, mock_run) -> None:
        result_item = _make_result()
        output = _semgrep_json_output([result_item])
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=output, stderr=""
        )
        f1 = SemgrepEngine().execute(_make_ctx())
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=output, stderr=""
        )
        f2 = SemgrepEngine().execute(_make_ctx())
        assert f1[0].id == f2[0].id


# ---------------------------------------------------------------------------
# Tool failure finding
# ---------------------------------------------------------------------------


class TestToolFailure:
    def test_failure_category(self) -> None:
        f = SemgrepEngine()._tool_failure("broke")
        assert f.category == FindingCategory.MISSING_CONTROL

    def test_failure_severity(self) -> None:
        f = SemgrepEngine()._tool_failure("broke")
        assert f.severity == Severity.MEDIUM

    def test_failure_engine_id(self) -> None:
        f = SemgrepEngine()._tool_failure("broke")
        assert f.engine_id == "semgrep"

    def test_failure_layer(self) -> None:
        f = SemgrepEngine()._tool_failure("broke")
        assert f.layer == Layer.STATIC
