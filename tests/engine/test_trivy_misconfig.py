"""Tests for plsec.engine.trivy_misconfig -- Trivy misconfiguration scanning engine."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from plsec.engine.trivy_misconfig import (
    _SEVERITY_MAP,
    DEFAULT_TIMEOUT,
    TrivyMisconfigEngine,
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


def _trivy_config_json(misconfigs: list[dict] | None = None, target: str = "Dockerfile") -> str:
    """Build a trivy config JSON output string."""
    results = []
    if misconfigs:
        results.append({"Target": target, "Misconfigurations": misconfigs})
    return json.dumps({"Results": results})


def _make_misconfig(
    misconfig_id: str = "DS002",
    title: str = "Image user should not be root",
    description: str = "Running as root is a security risk.",
    severity: str = "HIGH",
    message: str = "Specify at least 1 USER command in Dockerfile",
    resolution: str = "Add a USER instruction to the Dockerfile",
) -> dict:
    """Build a trivy misconfiguration dict."""
    return {
        "ID": misconfig_id,
        "Title": title,
        "Description": description,
        "Severity": severity,
        "Message": message,
        "Resolution": resolution,
    }


# ---------------------------------------------------------------------------
# Engine identity
# ---------------------------------------------------------------------------


class TestEngineIdentity:
    def test_engine_id(self) -> None:
        assert TrivyMisconfigEngine().engine_id == "trivy-misconfig"

    def test_layer(self) -> None:
        assert TrivyMisconfigEngine().layer == Layer.CONFIG

    def test_display_name(self) -> None:
        assert TrivyMisconfigEngine().display_name == "Trivy Misconfiguration Scanner"

    def test_presets_excludes_minimal(self) -> None:
        """Misconfig scanning is NOT enabled at minimal preset."""
        presets = TrivyMisconfigEngine().presets
        assert Preset.MINIMAL not in presets
        assert Preset.BALANCED in presets
        assert Preset.STRICT in presets
        assert Preset.PARANOID in presets

    def test_dependencies(self) -> None:
        assert TrivyMisconfigEngine().dependencies == ["trivy"]


# ---------------------------------------------------------------------------
# Availability checks
# ---------------------------------------------------------------------------


class TestCheckAvailable:
    def test_available(self) -> None:
        ctx = _make_ctx(available_tools=frozenset({"trivy"}))
        result = TrivyMisconfigEngine().check_available(ctx)
        assert result.status == EngineStatus.AVAILABLE

    def test_unavailable(self) -> None:
        ctx = _make_ctx(available_tools=frozenset())
        result = TrivyMisconfigEngine().check_available(ctx)
        assert result.status == EngineStatus.UNAVAILABLE
        assert "trivy" in result.message

    def test_unavailable_with_other_tools(self) -> None:
        ctx = _make_ctx(available_tools=frozenset({"bandit", "semgrep"}))
        result = TrivyMisconfigEngine().check_available(ctx)
        assert result.status == EngineStatus.UNAVAILABLE


# ---------------------------------------------------------------------------
# Execute -- happy path
# ---------------------------------------------------------------------------


class TestExecuteHappyPath:
    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_single_misconfig(self, mock_run) -> None:
        misconfig = _make_misconfig()
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_config_json([misconfig]), stderr=""
        )
        findings = TrivyMisconfigEngine().execute(_make_ctx())

        assert len(findings) == 1
        f = findings[0]
        assert f.engine_id == "trivy-misconfig"
        assert f.layer == Layer.CONFIG
        assert f.severity == Severity.HIGH
        assert f.category == FindingCategory.MISCONFIG
        assert f.title == "Image user should not be root"
        assert f.location is not None
        assert f.location.file_path == Path("Dockerfile")

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_multiple_misconfigs(self, mock_run) -> None:
        misconfigs = [
            _make_misconfig(title="Root user", severity="HIGH"),
            _make_misconfig(
                misconfig_id="DS001",
                title="No healthcheck",
                severity="MEDIUM",
            ),
        ]
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_config_json(misconfigs), stderr=""
        )
        findings = TrivyMisconfigEngine().execute(_make_ctx())
        assert len(findings) == 2
        assert findings[0].severity == Severity.HIGH
        assert findings[1].severity == Severity.MEDIUM

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_multiple_result_blocks(self, mock_run) -> None:
        """Multiple targets in Results, each with misconfigs."""
        data = {
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [_make_misconfig(title="Finding A")],
                },
                {
                    "Target": "docker-compose.yml",
                    "Misconfigurations": [_make_misconfig(title="Finding B")],
                },
            ]
        }
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(data), stderr=""
        )
        findings = TrivyMisconfigEngine().execute(_make_ctx())
        assert len(findings) == 2
        assert findings[0].location.file_path == Path("Dockerfile")
        assert findings[1].location.file_path == Path("docker-compose.yml")

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_clean_scan(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_config_json([]), stderr=""
        )
        findings = TrivyMisconfigEngine().execute(_make_ctx())
        assert findings == []

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_empty_stdout(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        findings = TrivyMisconfigEngine().execute(_make_ctx())
        assert findings == []

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_no_misconfigurations_key(self, mock_run) -> None:
        """A result block with no Misconfigurations key should produce no findings."""
        data = json.dumps({"Results": [{"Target": "Dockerfile"}]})
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=data, stderr=""
        )
        findings = TrivyMisconfigEngine().execute(_make_ctx())
        assert findings == []


# ---------------------------------------------------------------------------
# Execute -- error handling
# ---------------------------------------------------------------------------


class TestExecuteErrors:
    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_timeout_produces_finding(self, mock_run) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="trivy", timeout=300)
        findings = TrivyMisconfigEngine().execute(_make_ctx())
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.MISSING_CONTROL
        assert "timed out" in findings[0].description

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_file_not_found(self, mock_run) -> None:
        mock_run.side_effect = FileNotFoundError("trivy")
        findings = TrivyMisconfigEngine().execute(_make_ctx())
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.MISSING_CONTROL

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_os_error(self, mock_run) -> None:
        mock_run.side_effect = OSError("Permission denied")
        findings = TrivyMisconfigEngine().execute(_make_ctx())
        assert len(findings) == 1
        assert "Permission denied" in findings[0].description

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_invalid_json(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="not json", stderr=""
        )
        findings = TrivyMisconfigEngine().execute(_make_ctx())
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.MISSING_CONTROL

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_prefixed_stdout_recovered(self, mock_run) -> None:
        """Non-JSON prefix before valid JSON is stripped by extract_json."""
        misconfig = _make_misconfig(title="Found via noisy output")
        prefixed = "Loading checks... done\n" + _trivy_config_json([misconfig])
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=prefixed, stderr=""
        )
        findings = TrivyMisconfigEngine().execute(_make_ctx())
        assert len(findings) == 1
        assert findings[0].title == "Found via noisy output"


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------


class TestCommandConstruction:
    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_basic_command(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_config_json(), stderr=""
        )
        TrivyMisconfigEngine().execute(_make_ctx(target="/var/my-project"))
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "trivy"
        assert "config" in cmd
        assert "--format" in cmd
        assert "json" in cmd
        assert "--quiet" in cmd
        assert str(Path("/var/my-project")) in cmd

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_no_fs_subcommand(self, mock_run) -> None:
        """trivy-misconfig uses 'trivy config', NOT 'trivy fs'."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_config_json(), stderr=""
        )
        TrivyMisconfigEngine().execute(_make_ctx())
        cmd = mock_run.call_args[0][0]
        assert "fs" not in cmd

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_default_timeout(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_config_json(), stderr=""
        )
        TrivyMisconfigEngine().execute(_make_ctx())
        assert mock_run.call_args[1]["timeout"] == DEFAULT_TIMEOUT

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_custom_timeout(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_config_json(), stderr=""
        )
        ctx = _make_ctx(engine_configs={"trivy-misconfig": {"timeout": 120}})
        TrivyMisconfigEngine().execute(ctx)
        assert mock_run.call_args[1]["timeout"] == 120

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_ignorefile_passed_when_present(self, mock_run, tmp_path) -> None:
        """--ignorefile is added when .trivyignore.yaml exists in target."""
        (tmp_path / ".trivyignore.yaml").write_text("misconfigurations: []\n")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_config_json(), stderr=""
        )
        TrivyMisconfigEngine().execute(_make_ctx(target=str(tmp_path)))

        cmd = mock_run.call_args[0][0]
        assert "--ignorefile" in cmd
        ignorefile_idx = cmd.index("--ignorefile")
        assert cmd[ignorefile_idx + 1] == str(tmp_path / ".trivyignore.yaml")

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_no_ignorefile_when_absent(self, mock_run) -> None:
        """--ignorefile is not added when .trivyignore.yaml does not exist."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_config_json(), stderr=""
        )
        TrivyMisconfigEngine().execute(_make_ctx())

        cmd = mock_run.call_args[0][0]
        assert "--ignorefile" not in cmd


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

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_unmapped_defaults_to_info(self, mock_run) -> None:
        misconfig = _make_misconfig(severity="WHATEVER")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_config_json([misconfig]), stderr=""
        )
        findings = TrivyMisconfigEngine().execute(_make_ctx())
        assert findings[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# Finding details
# ---------------------------------------------------------------------------


class TestFindingDetails:
    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_evidence_contains_misconfig_id(self, mock_run) -> None:
        misconfig = _make_misconfig(misconfig_id="DS002")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_config_json([misconfig]), stderr=""
        )
        findings = TrivyMisconfigEngine().execute(_make_ctx())
        assert findings[0].evidence["misconfig_id"] == "DS002"

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_description_is_trivy_description(self, mock_run) -> None:
        misconfig = _make_misconfig(description="Running as root is dangerous.")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_config_json([misconfig]), stderr=""
        )
        findings = TrivyMisconfigEngine().execute(_make_ctx())
        assert findings[0].description == "Running as root is dangerous."

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_remediation_is_resolution(self, mock_run) -> None:
        misconfig = _make_misconfig(resolution="Add USER instruction")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_config_json([misconfig]), stderr=""
        )
        findings = TrivyMisconfigEngine().execute(_make_ctx())
        assert findings[0].remediation == "Add USER instruction"

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_evidence_contains_message(self, mock_run) -> None:
        misconfig = _make_misconfig(message="Specify at least 1 USER command")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=_trivy_config_json([misconfig]), stderr=""
        )
        findings = TrivyMisconfigEngine().execute(_make_ctx())
        assert findings[0].evidence["message"] == "Specify at least 1 USER command"

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_finding_id_deterministic(self, mock_run) -> None:
        misconfig = _make_misconfig()
        output = _trivy_config_json([misconfig])
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=output, stderr=""
        )
        f1 = TrivyMisconfigEngine().execute(_make_ctx())
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=output, stderr=""
        )
        f2 = TrivyMisconfigEngine().execute(_make_ctx())
        assert f1[0].id == f2[0].id

    @patch("plsec.engine.trivy_misconfig.subprocess.run")
    def test_title_fallback(self, mock_run) -> None:
        """When Title is missing, fall back to ID."""
        misconfig = {"ID": "DS999", "Severity": "LOW", "Description": "desc", "Message": "msg"}
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=_trivy_config_json([misconfig]),
            stderr="",
        )
        findings = TrivyMisconfigEngine().execute(_make_ctx())
        assert findings[0].title == "DS999"


# ---------------------------------------------------------------------------
# Tool failure finding
# ---------------------------------------------------------------------------


class TestToolFailure:
    def test_failure_category(self) -> None:
        f = TrivyMisconfigEngine()._tool_failure("broke")
        assert f.category == FindingCategory.MISSING_CONTROL

    def test_failure_severity(self) -> None:
        f = TrivyMisconfigEngine()._tool_failure("broke")
        assert f.severity == Severity.MEDIUM

    def test_failure_engine_id(self) -> None:
        f = TrivyMisconfigEngine()._tool_failure("broke")
        assert f.engine_id == "trivy-misconfig"

    def test_failure_layer(self) -> None:
        f = TrivyMisconfigEngine()._tool_failure("broke")
        assert f.layer == Layer.CONFIG

    def test_failure_description(self) -> None:
        f = TrivyMisconfigEngine()._tool_failure("disk full")
        assert "disk full" in f.description

    def test_failure_has_remediation(self) -> None:
        f = TrivyMisconfigEngine()._tool_failure("not installed")
        assert f.remediation is not None
