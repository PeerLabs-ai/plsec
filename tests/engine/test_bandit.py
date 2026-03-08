"""Tests for plsec.engine.bandit -- Bandit Python security scanning engine."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from plsec.engine.bandit import (
    _SEVERITY_MAP,
    DEFAULT_TIMEOUT,
    BanditEngine,
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
        frozenset({"bandit"}) if available_tools is _SENTINEL else (available_tools or frozenset())
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


def _bandit_json_output(results: list[dict] | None = None) -> str:
    return json.dumps(
        {
            "errors": [],
            "generated_at": "2026-01-01T00:00:00Z",
            "metrics": {},
            "results": results or [],
        }
    )


def _make_result(
    filename: str = "src/app.py",
    issue_severity: str = "HIGH",
    issue_text: str = "Possible SQL injection",
    line_number: int = 42,
    test_id: str = "B608",
    test_name: str = "hardcoded_sql_expressions",
    issue_confidence: str = "HIGH",
    issue_cwe: dict | None = None,
) -> dict:
    return {
        "filename": filename,
        "issue_severity": issue_severity,
        "issue_text": issue_text,
        "line_number": line_number,
        "line_range": [line_number],
        "test_id": test_id,
        "test_name": test_name,
        "issue_confidence": issue_confidence,
        "issue_cwe": issue_cwe
        or {"id": 89, "link": "https://cwe.mitre.org/data/definitions/89.html"},
        "more_info": f"https://bandit.readthedocs.io/en/latest/plugins/{test_id.lower()}.html",
        "code": f"{line_number} vulnerable_code()\n",
        "col_offset": 0,
        "end_col_offset": 20,
    }


# ---------------------------------------------------------------------------
# Engine identity
# ---------------------------------------------------------------------------


class TestEngineIdentity:
    def test_engine_id(self) -> None:
        assert BanditEngine().engine_id == "bandit"

    def test_layer(self) -> None:
        assert BanditEngine().layer == Layer.STATIC

    def test_display_name(self) -> None:
        assert BanditEngine().display_name == "Bandit"

    def test_presets_all(self) -> None:
        assert BanditEngine().presets == frozenset(Preset)

    def test_dependencies(self) -> None:
        assert BanditEngine().dependencies == ["bandit"]


# ---------------------------------------------------------------------------
# Availability checks
# ---------------------------------------------------------------------------


class TestCheckAvailable:
    def test_available_when_bandit_present(self) -> None:
        ctx = _make_ctx(available_tools=frozenset({"bandit"}))
        result = BanditEngine().check_available(ctx)
        assert result.status == EngineStatus.AVAILABLE

    def test_unavailable_when_bandit_missing(self) -> None:
        ctx = _make_ctx(available_tools=frozenset())
        result = BanditEngine().check_available(ctx)
        assert result.status == EngineStatus.UNAVAILABLE
        assert "bandit" in result.message

    def test_unavailable_with_other_tools(self) -> None:
        ctx = _make_ctx(available_tools=frozenset({"trivy", "semgrep"}))
        result = BanditEngine().check_available(ctx)
        assert result.status == EngineStatus.UNAVAILABLE


# ---------------------------------------------------------------------------
# Execute -- happy path
# ---------------------------------------------------------------------------


class TestExecuteHappyPath:
    @patch("plsec.engine.bandit.subprocess.run")
    def test_single_finding(self, mock_run) -> None:
        result_item = _make_result()
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=_bandit_json_output([result_item]), stderr=""
        )
        findings = BanditEngine().execute(_make_ctx())

        assert len(findings) == 1
        f = findings[0]
        assert f.engine_id == "bandit"
        assert f.layer == Layer.STATIC
        assert f.severity == Severity.HIGH
        assert f.category == FindingCategory.CODE_ISSUE
        assert f.title == "Possible SQL injection"
        assert f.location is not None
        assert f.location.file_path == Path("src/app.py")
        assert f.location.line_start == 42

    @patch("plsec.engine.bandit.subprocess.run")
    def test_multiple_findings(self, mock_run) -> None:
        results = [
            _make_result(issue_text="SQL injection", issue_severity="HIGH", line_number=10),
            _make_result(issue_text="Hardcoded password", issue_severity="MEDIUM", line_number=20),
        ]
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=_bandit_json_output(results), stderr=""
        )
        findings = BanditEngine().execute(_make_ctx())
        assert len(findings) == 2
        assert findings[0].title == "SQL injection"
        assert findings[1].severity == Severity.MEDIUM

    @patch("plsec.engine.bandit.subprocess.run")
    def test_clean_scan_exit_0(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_bandit_json_output([]), stderr=""
        )
        findings = BanditEngine().execute(_make_ctx())
        assert findings == []

    @patch("plsec.engine.bandit.subprocess.run")
    def test_clean_scan_empty_results(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_bandit_json_output(), stderr=""
        )
        findings = BanditEngine().execute(_make_ctx())
        assert findings == []

    @patch("plsec.engine.bandit.subprocess.run")
    def test_no_python_files_skips(self, mock_run) -> None:
        """When target has no .py files, bandit should skip gracefully."""
        ctx = _make_ctx(engine_configs={"bandit": {"has_python_files": False}})
        findings = BanditEngine().execute(ctx)
        # Should not invoke subprocess at all
        mock_run.assert_not_called()
        assert findings == []


# ---------------------------------------------------------------------------
# Execute -- error handling
# ---------------------------------------------------------------------------


class TestExecuteErrors:
    @patch("plsec.engine.bandit.subprocess.run")
    def test_timeout_produces_finding(self, mock_run) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="bandit", timeout=300)
        findings = BanditEngine().execute(_make_ctx())
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.MISSING_CONTROL
        assert "timed out" in findings[0].description

    @patch("plsec.engine.bandit.subprocess.run")
    def test_file_not_found_produces_finding(self, mock_run) -> None:
        mock_run.side_effect = FileNotFoundError("bandit")
        findings = BanditEngine().execute(_make_ctx())
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.MISSING_CONTROL

    @patch("plsec.engine.bandit.subprocess.run")
    def test_os_error_produces_finding(self, mock_run) -> None:
        mock_run.side_effect = OSError("Permission denied")
        findings = BanditEngine().execute(_make_ctx())
        assert len(findings) == 1
        assert "Permission denied" in findings[0].description

    @patch("plsec.engine.bandit.subprocess.run")
    def test_invalid_json_produces_finding(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="not valid json", stderr=""
        )
        findings = BanditEngine().execute(_make_ctx())
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.MISSING_CONTROL

    @patch("plsec.engine.bandit.subprocess.run")
    def test_empty_stdout_returns_empty(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        findings = BanditEngine().execute(_make_ctx())
        assert findings == []


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------


class TestCommandConstruction:
    @patch("plsec.engine.bandit.subprocess.run")
    def test_basic_command(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_bandit_json_output(), stderr=""
        )
        BanditEngine().execute(_make_ctx(target="/var/my-project"))
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "bandit"
        assert "-r" in cmd
        assert "--format" in cmd
        assert "json" in cmd
        assert str(Path("/var/my-project")) in cmd

    @patch("plsec.engine.bandit.subprocess.run")
    def test_severity_filter(self, mock_run) -> None:
        """Bandit should use -ll for medium+ severity."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_bandit_json_output(), stderr=""
        )
        BanditEngine().execute(_make_ctx())
        cmd = mock_run.call_args[0][0]
        assert "-ll" in cmd

    @patch("plsec.engine.bandit.subprocess.run")
    def test_exclude_dirs(self, mock_run) -> None:
        """Default exclude dirs should be passed."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_bandit_json_output(), stderr=""
        )
        BanditEngine().execute(_make_ctx(target="/var/project"))
        cmd = mock_run.call_args[0][0]
        assert "--exclude" in cmd
        exclude_idx = cmd.index("--exclude")
        exclude_val = cmd[exclude_idx + 1]
        assert ".venv" in exclude_val
        assert ".tox" in exclude_val

    @patch("plsec.engine.bandit.subprocess.run")
    def test_custom_skip_dirs(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_bandit_json_output(), stderr=""
        )
        ctx = _make_ctx(engine_configs={"bandit": {"skip_dirs": ["vendor", "third_party"]}})
        BanditEngine().execute(ctx)
        cmd = mock_run.call_args[0][0]
        exclude_idx = cmd.index("--exclude")
        exclude_val = cmd[exclude_idx + 1]
        assert "vendor" in exclude_val
        assert "third_party" in exclude_val

    @patch("plsec.engine.bandit.subprocess.run")
    def test_default_timeout(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_bandit_json_output(), stderr=""
        )
        BanditEngine().execute(_make_ctx())
        assert mock_run.call_args[1]["timeout"] == DEFAULT_TIMEOUT

    @patch("plsec.engine.bandit.subprocess.run")
    def test_custom_timeout(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_bandit_json_output(), stderr=""
        )
        ctx = _make_ctx(engine_configs={"bandit": {"timeout": 60}})
        BanditEngine().execute(ctx)
        assert mock_run.call_args[1]["timeout"] == 60


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    def test_high(self) -> None:
        assert _SEVERITY_MAP["HIGH"] == Severity.HIGH

    def test_medium(self) -> None:
        assert _SEVERITY_MAP["MEDIUM"] == Severity.MEDIUM

    def test_low(self) -> None:
        assert _SEVERITY_MAP["LOW"] == Severity.LOW

    @patch("plsec.engine.bandit.subprocess.run")
    def test_unmapped_defaults_to_info(self, mock_run) -> None:
        result_item = _make_result(issue_severity="WHATEVER")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=_bandit_json_output([result_item]), stderr=""
        )
        findings = BanditEngine().execute(_make_ctx())
        assert findings[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# Finding details
# ---------------------------------------------------------------------------


class TestFindingDetails:
    @patch("plsec.engine.bandit.subprocess.run")
    def test_evidence_contains_test_id(self, mock_run) -> None:
        result_item = _make_result(test_id="B608", test_name="hardcoded_sql")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=_bandit_json_output([result_item]), stderr=""
        )
        findings = BanditEngine().execute(_make_ctx())
        assert findings[0].evidence["test_id"] == "B608"
        assert findings[0].evidence["test_name"] == "hardcoded_sql"

    @patch("plsec.engine.bandit.subprocess.run")
    def test_evidence_contains_cwe(self, mock_run) -> None:
        result_item = _make_result(
            issue_cwe={"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"}
        )
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=_bandit_json_output([result_item]), stderr=""
        )
        findings = BanditEngine().execute(_make_ctx())
        assert findings[0].evidence["cwe_id"] == 78

    @patch("plsec.engine.bandit.subprocess.run")
    def test_remediation_present(self, mock_run) -> None:
        result_item = _make_result()
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=_bandit_json_output([result_item]), stderr=""
        )
        findings = BanditEngine().execute(_make_ctx())
        assert findings[0].remediation is not None

    @patch("plsec.engine.bandit.subprocess.run")
    def test_finding_id_deterministic(self, mock_run) -> None:
        result_item = _make_result()
        output = _bandit_json_output([result_item])
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=output, stderr=""
        )
        f1 = BanditEngine().execute(_make_ctx())
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=output, stderr=""
        )
        f2 = BanditEngine().execute(_make_ctx())
        assert f1[0].id == f2[0].id


# ---------------------------------------------------------------------------
# Tool failure finding
# ---------------------------------------------------------------------------


class TestToolFailure:
    def test_failure_finding_category(self) -> None:
        f = BanditEngine()._tool_failure("something broke")
        assert f.category == FindingCategory.MISSING_CONTROL

    def test_failure_finding_severity(self) -> None:
        f = BanditEngine()._tool_failure("something broke")
        assert f.severity == Severity.MEDIUM

    def test_failure_finding_engine_id(self) -> None:
        f = BanditEngine()._tool_failure("something broke")
        assert f.engine_id == "bandit"

    def test_failure_finding_layer(self) -> None:
        f = BanditEngine()._tool_failure("something broke")
        assert f.layer == Layer.STATIC
