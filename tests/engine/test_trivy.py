"""Tests for plsec.engine.trivy_secrets — Trivy secret scanning engine."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from plsec.engine.trivy_secrets import (
    _SEVERITY_MAP,
    DEFAULT_TIMEOUT,
    TrivySecretEngine,
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
# Fixtures
# ---------------------------------------------------------------------------


_SENTINEL: frozenset[str] = frozenset({"__sentinel__"})


def _make_ctx(
    available_tools: frozenset[str] | None = _SENTINEL,
    engine_configs: dict | None = None,
    target: str = "/var/project",
) -> ScanContext:
    """Build a ScanContext with sensible defaults for testing."""
    tools = (
        frozenset({"trivy"}) if available_tools is _SENTINEL else (available_tools or frozenset())
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


def _trivy_json_output(secrets: list[dict] | None = None, target: str = "src/config.py") -> str:
    """Build a trivy JSON output string."""
    results = []
    if secrets:
        results.append({"Target": target, "Secrets": secrets})
    return json.dumps({"Results": results})


def _make_secret(
    title: str = "AWS Access Key",
    severity: str = "HIGH",
    start_line: int = 42,
    end_line: int = 42,
    rule_id: str = "aws-access-key-id",
    category: str = "AWS",
    match: str = "AKIA***REDACTED***",
) -> dict:
    """Build a trivy secret dict."""
    return {
        "RuleID": rule_id,
        "Category": category,
        "Title": title,
        "Severity": severity,
        "StartLine": start_line,
        "EndLine": end_line,
        "Match": match,
    }


# ---------------------------------------------------------------------------
# Engine identity
# ---------------------------------------------------------------------------


class TestEngineIdentity:
    def test_engine_id(self) -> None:
        assert TrivySecretEngine().engine_id == "trivy-secrets"

    def test_layer(self) -> None:
        assert TrivySecretEngine().layer == Layer.STATIC

    def test_display_name(self) -> None:
        assert TrivySecretEngine().display_name == "Trivy Secret Scanner"

    def test_presets_all(self) -> None:
        """Secrets are checked at every preset level."""
        assert TrivySecretEngine().presets == frozenset(Preset)

    def test_dependencies(self) -> None:
        assert TrivySecretEngine().dependencies == ["trivy"]


# ---------------------------------------------------------------------------
# Availability checks
# ---------------------------------------------------------------------------


class TestCheckAvailable:
    def test_available_when_trivy_present(self) -> None:
        ctx = _make_ctx(available_tools=frozenset({"trivy"}))
        result = TrivySecretEngine().check_available(ctx)
        assert result.status == EngineStatus.AVAILABLE

    def test_unavailable_when_trivy_missing(self) -> None:
        ctx = _make_ctx(available_tools=frozenset())
        result = TrivySecretEngine().check_available(ctx)
        assert result.status == EngineStatus.UNAVAILABLE
        assert "trivy" in result.message

    def test_unavailable_with_other_tools(self) -> None:
        ctx = _make_ctx(available_tools=frozenset({"bandit", "semgrep"}))
        result = TrivySecretEngine().check_available(ctx)
        assert result.status == EngineStatus.UNAVAILABLE


# ---------------------------------------------------------------------------
# Execute — subprocess mocking
# ---------------------------------------------------------------------------


class TestExecuteHappyPath:
    @patch("plsec.engine.trivy_secrets.subprocess.run")
    def test_single_secret(self, mock_run) -> None:
        secret = _make_secret()
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_json_output([secret]), stderr=""
        )

        ctx = _make_ctx()
        findings = TrivySecretEngine().execute(ctx)

        assert len(findings) == 1
        f = findings[0]
        assert f.engine_id == "trivy-secrets"
        assert f.layer == Layer.STATIC
        assert f.severity == Severity.HIGH
        assert f.category == FindingCategory.LEAKED_CREDENTIAL
        assert f.title == "AWS Access Key"
        assert f.location is not None
        assert f.location.file_path == Path("src/config.py")
        assert f.location.line_start == 42
        assert f.location.line_end == 42

    @patch("plsec.engine.trivy_secrets.subprocess.run")
    def test_multiple_secrets(self, mock_run) -> None:
        secrets = [
            _make_secret(title="AWS Key", severity="HIGH", start_line=10),
            _make_secret(title="GitHub Token", severity="CRITICAL", start_line=20),
        ]
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_json_output(secrets), stderr=""
        )

        findings = TrivySecretEngine().execute(_make_ctx())
        assert len(findings) == 2
        assert findings[0].title == "AWS Key"
        assert findings[1].title == "GitHub Token"
        assert findings[1].severity == Severity.CRITICAL

    @patch("plsec.engine.trivy_secrets.subprocess.run")
    def test_clean_scan_empty_stdout(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        findings = TrivySecretEngine().execute(_make_ctx())
        assert findings == []

    @patch("plsec.engine.trivy_secrets.subprocess.run")
    def test_clean_scan_no_results(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"Results": []}', stderr=""
        )
        findings = TrivySecretEngine().execute(_make_ctx())
        assert findings == []

    @patch("plsec.engine.trivy_secrets.subprocess.run")
    def test_clean_scan_no_secrets_key(self, mock_run) -> None:
        """A result block with no Secrets key should produce no findings."""
        data = json.dumps({"Results": [{"Target": "foo.py"}]})
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=data, stderr=""
        )
        findings = TrivySecretEngine().execute(_make_ctx())
        assert findings == []


# ---------------------------------------------------------------------------
# Execute — error handling
# ---------------------------------------------------------------------------


class TestExecuteErrors:
    @patch("plsec.engine.trivy_secrets.subprocess.run")
    def test_timeout_produces_finding(self, mock_run) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="trivy", timeout=300)
        findings = TrivySecretEngine().execute(_make_ctx())

        assert len(findings) == 1
        f = findings[0]
        assert f.category == FindingCategory.MISSING_CONTROL
        assert "timed out" in f.description
        assert "300" in f.description

    @patch("plsec.engine.trivy_secrets.subprocess.run")
    def test_file_not_found_produces_finding(self, mock_run) -> None:
        mock_run.side_effect = FileNotFoundError("trivy")
        findings = TrivySecretEngine().execute(_make_ctx())

        assert len(findings) == 1
        assert findings[0].category == FindingCategory.MISSING_CONTROL
        assert "not found" in findings[0].description

    @patch("plsec.engine.trivy_secrets.subprocess.run")
    def test_os_error_produces_finding(self, mock_run) -> None:
        mock_run.side_effect = OSError("Permission denied")
        findings = TrivySecretEngine().execute(_make_ctx())

        assert len(findings) == 1
        assert findings[0].category == FindingCategory.MISSING_CONTROL
        assert "Permission denied" in findings[0].description

    @patch("plsec.engine.trivy_secrets.subprocess.run")
    def test_invalid_json_produces_finding(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="not valid json", stderr=""
        )
        findings = TrivySecretEngine().execute(_make_ctx())

        assert len(findings) == 1
        assert findings[0].category == FindingCategory.MISSING_CONTROL
        assert "parse" in findings[0].description.lower()


# ---------------------------------------------------------------------------
# Execute — command construction
# ---------------------------------------------------------------------------


class TestCommandConstruction:
    @patch("plsec.engine.trivy_secrets.subprocess.run")
    def test_basic_command(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        ctx = _make_ctx(target="/var/my-project")
        TrivySecretEngine().execute(ctx)

        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert cmd[0] == "trivy"
        assert "fs" in cmd
        assert "--scanners" in cmd
        assert "secret" in cmd
        assert "--format" in cmd
        assert "json" in cmd
        assert "--quiet" in cmd
        assert str(Path("/var/my-project")) in cmd

    @patch("plsec.engine.trivy_secrets.subprocess.run")
    def test_secret_config_passed(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        ctx = _make_ctx(engine_configs={"trivy-secrets": {"secret_config": "/etc/trivy.yaml"}})
        TrivySecretEngine().execute(ctx)

        cmd = mock_run.call_args[0][0]
        assert "--secret-config" in cmd
        assert "/etc/trivy.yaml" in cmd

    @patch("plsec.engine.trivy_secrets.subprocess.run")
    def test_no_secret_config_by_default(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        TrivySecretEngine().execute(_make_ctx())

        cmd = mock_run.call_args[0][0]
        assert "--secret-config" not in cmd

    @patch("plsec.engine.trivy_secrets.subprocess.run")
    def test_custom_timeout(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        ctx = _make_ctx(engine_configs={"trivy-secrets": {"timeout": 60}})
        TrivySecretEngine().execute(ctx)

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["timeout"] == 60

    @patch("plsec.engine.trivy_secrets.subprocess.run")
    def test_default_timeout(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        TrivySecretEngine().execute(_make_ctx())

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["timeout"] == DEFAULT_TIMEOUT


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    def test_critical(self) -> None:
        assert _SEVERITY_MAP["CRITICAL"] == Severity.CRITICAL

    def test_high(self) -> None:
        assert _SEVERITY_MAP["HIGH"] == Severity.HIGH

    def test_medium(self) -> None:
        assert _SEVERITY_MAP["MEDIUM"] == Severity.MEDIUM

    def test_low(self) -> None:
        assert _SEVERITY_MAP["LOW"] == Severity.LOW

    def test_unknown(self) -> None:
        assert _SEVERITY_MAP["UNKNOWN"] == Severity.INFO

    @patch("plsec.engine.trivy_secrets.subprocess.run")
    def test_unmapped_severity_defaults_to_info(self, mock_run) -> None:
        """An unrecognized severity string should default to INFO."""
        secret = _make_secret(severity="WHATEVER")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_json_output([secret]), stderr=""
        )
        findings = TrivySecretEngine().execute(_make_ctx())
        assert findings[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# Finding details
# ---------------------------------------------------------------------------


class TestFindingDetails:
    @patch("plsec.engine.trivy_secrets.subprocess.run")
    def test_evidence_contains_rule_id(self, mock_run) -> None:
        secret = _make_secret(rule_id="aws-access-key-id", category="AWS")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_json_output([secret]), stderr=""
        )
        findings = TrivySecretEngine().execute(_make_ctx())
        assert findings[0].evidence["rule_id"] == "aws-access-key-id"
        assert findings[0].evidence["trivy_category"] == "AWS"

    @patch("plsec.engine.trivy_secrets.subprocess.run")
    def test_remediation_present(self, mock_run) -> None:
        secret = _make_secret()
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_json_output([secret]), stderr=""
        )
        findings = TrivySecretEngine().execute(_make_ctx())
        assert findings[0].remediation is not None
        assert (
            "secret" in findings[0].remediation.lower()
            or "credential" in findings[0].remediation.lower()
        )

    @patch("plsec.engine.trivy_secrets.subprocess.run")
    def test_description_is_match(self, mock_run) -> None:
        secret = _make_secret(match="AKIA***HIDDEN***")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_json_output([secret]), stderr=""
        )
        findings = TrivySecretEngine().execute(_make_ctx())
        assert findings[0].description == "AKIA***HIDDEN***"

    @patch("plsec.engine.trivy_secrets.subprocess.run")
    def test_finding_id_deterministic(self, mock_run) -> None:
        """Same secret should produce same finding ID."""
        secret = _make_secret()
        output = _trivy_json_output([secret])
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=output, stderr=""
        )

        f1 = TrivySecretEngine().execute(_make_ctx())
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=output, stderr=""
        )
        f2 = TrivySecretEngine().execute(_make_ctx())

        assert f1[0].id == f2[0].id


# ---------------------------------------------------------------------------
# Tool failure finding
# ---------------------------------------------------------------------------


class TestToolFailure:
    def test_failure_finding_category(self) -> None:
        engine = TrivySecretEngine()
        f = engine._tool_failure("something broke")
        assert f.category == FindingCategory.MISSING_CONTROL

    def test_failure_finding_severity(self) -> None:
        engine = TrivySecretEngine()
        f = engine._tool_failure("something broke")
        assert f.severity == Severity.MEDIUM

    def test_failure_finding_engine_id(self) -> None:
        engine = TrivySecretEngine()
        f = engine._tool_failure("something broke")
        assert f.engine_id == "trivy-secrets"

    def test_failure_finding_layer(self) -> None:
        engine = TrivySecretEngine()
        f = engine._tool_failure("something broke")
        assert f.layer == Layer.STATIC

    def test_failure_finding_description(self) -> None:
        engine = TrivySecretEngine()
        f = engine._tool_failure("disk full")
        assert "disk full" in f.description

    def test_failure_finding_has_remediation(self) -> None:
        engine = TrivySecretEngine()
        f = engine._tool_failure("not installed")
        assert f.remediation is not None
