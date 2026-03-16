"""Tests for TrivyDependencyEngine."""

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from plsec.engine.base import Engine
from plsec.engine.dependency import DependencyEngine
from plsec.engine.trivy_dependency import TrivyDependencyEngine
from plsec.engine.types import (
    EngineStatus,
    EnvironmentInfo,
    FindingCategory,
    Layer,
    Preset,
    ScanContext,
    Severity,
)


@pytest.fixture()
def engine():
    return TrivyDependencyEngine()


@pytest.fixture()
def ctx(tmp_path: Path):
    return ScanContext(
        target_path=tmp_path,
        preset=Preset.BALANCED,
        environment=EnvironmentInfo(
            os_name="darwin",
            os_version="23.0.0",
            python_version="3.12.0",
            available_tools=frozenset({"trivy"}),
        ),
    )


def _make_completed(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["trivy"], returncode=returncode, stdout=stdout, stderr=""
    )


def _make_trivy_vuln_json(vulns: list[dict], target: str = "requirements.txt") -> str:
    """Build a minimal Trivy vulnerability JSON output."""
    return json.dumps(
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": target,
                    "Class": "lang-pkgs",
                    "Type": "pip",
                    "Vulnerabilities": vulns,
                }
            ],
        }
    )


def _make_vuln(
    vuln_id: str = "CVE-2024-1234",
    pkg: str = "requests",
    installed: str = "2.28.0",
    fixed: str = "2.31.0",
    severity: str = "HIGH",
    title: str = "Remote code execution via crafted URL",
) -> dict:
    return {
        "VulnerabilityID": vuln_id,
        "PkgName": pkg,
        "InstalledVersion": installed,
        "FixedVersion": fixed,
        "Severity": severity,
        "Title": title,
    }


# ---------------------------------------------------------------------------
# Engine identity
# ---------------------------------------------------------------------------


class TestEngineIdentity:
    def test_engine_id(self, engine):
        assert engine.engine_id == "trivy-vuln"

    def test_is_engine_subclass(self, engine):
        assert isinstance(engine, Engine)

    def test_is_dependency_engine_subclass(self, engine):
        assert isinstance(engine, DependencyEngine)

    def test_layer(self, engine):
        assert engine.layer == Layer.STATIC

    def test_display_name(self, engine):
        assert engine.display_name == "Trivy Dependency Scanner"

    def test_presets_excludes_minimal(self, engine):
        assert Preset.MINIMAL not in engine.presets

    def test_presets_includes_balanced(self, engine):
        assert Preset.BALANCED in engine.presets

    def test_presets_includes_strict(self, engine):
        assert Preset.STRICT in engine.presets

    def test_presets_includes_paranoid(self, engine):
        assert Preset.PARANOID in engine.presets

    def test_dependencies(self, engine):
        assert engine.dependencies == ["trivy"]


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------


class TestCheckAvailable:
    def test_available_when_trivy_present(self, engine, ctx):
        result = engine.check_available(ctx)
        assert result.status == EngineStatus.AVAILABLE

    def test_unavailable_when_trivy_missing(self, engine, tmp_path):
        ctx = ScanContext(
            target_path=tmp_path,
            preset=Preset.BALANCED,
            environment=EnvironmentInfo(
                os_name="darwin",
                os_version="23.0.0",
                python_version="3.12.0",
                available_tools=frozenset(),
            ),
        )
        result = engine.check_available(ctx)
        assert result.status == EngineStatus.UNAVAILABLE

    def test_unavailable_with_other_tools(self, engine, tmp_path):
        ctx = ScanContext(
            target_path=tmp_path,
            preset=Preset.BALANCED,
            environment=EnvironmentInfo(
                os_name="darwin",
                os_version="23.0.0",
                python_version="3.12.0",
                available_tools=frozenset({"bandit", "semgrep"}),
            ),
        )
        result = engine.check_available(ctx)
        assert result.status == EngineStatus.UNAVAILABLE


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestExecuteHappyPath:
    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_single_vulnerability(self, mock_run, engine, ctx):
        stdout = _make_trivy_vuln_json([_make_vuln()])
        mock_run.return_value = _make_completed(stdout)

        findings = engine.execute(ctx)

        assert len(findings) == 1
        assert findings[0].category == FindingCategory.DEPENDENCY_VULNERABILITY
        assert findings[0].severity == Severity.HIGH
        assert "CVE-2024-1234" in findings[0].title
        assert "requests" in findings[0].title

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_multiple_vulnerabilities(self, mock_run, engine, ctx):
        vulns = [
            _make_vuln("CVE-2024-1234", "requests", severity="HIGH"),
            _make_vuln("CVE-2024-5678", "flask", severity="CRITICAL"),
        ]
        stdout = _make_trivy_vuln_json(vulns)
        mock_run.return_value = _make_completed(stdout)

        findings = engine.execute(ctx)

        assert len(findings) == 2
        severities = {f.severity for f in findings}
        assert severities == {Severity.HIGH, Severity.CRITICAL}

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_multiple_result_blocks(self, mock_run, engine, ctx):
        stdout = json.dumps(
            {
                "SchemaVersion": 2,
                "Results": [
                    {
                        "Target": "requirements.txt",
                        "Vulnerabilities": [_make_vuln("CVE-2024-1111")],
                    },
                    {
                        "Target": "package.json",
                        "Vulnerabilities": [_make_vuln("CVE-2024-2222", "lodash")],
                    },
                ],
            }
        )
        mock_run.return_value = _make_completed(stdout)

        findings = engine.execute(ctx)

        assert len(findings) == 2
        titles = {f.title for f in findings}
        assert any("CVE-2024-1111" in t for t in titles)
        assert any("CVE-2024-2222" in t for t in titles)

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_clean_scan_no_vulns(self, mock_run, engine, ctx):
        stdout = _make_trivy_vuln_json([])
        mock_run.return_value = _make_completed(stdout)

        findings = engine.execute(ctx)

        assert findings == []

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_clean_scan_no_results_key(self, mock_run, engine, ctx):
        stdout = json.dumps({"SchemaVersion": 2})
        mock_run.return_value = _make_completed(stdout)

        findings = engine.execute(ctx)

        assert findings == []

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_clean_scan_empty_stdout(self, mock_run, engine, ctx):
        mock_run.return_value = _make_completed("")

        findings = engine.execute(ctx)

        assert findings == []

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_no_vulnerabilities_key_in_result(self, mock_run, engine, ctx):
        stdout = json.dumps(
            {
                "SchemaVersion": 2,
                "Results": [{"Target": "go.sum", "Class": "lang-pkgs"}],
            }
        )
        mock_run.return_value = _make_completed(stdout)

        findings = engine.execute(ctx)

        assert findings == []


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestExecuteErrors:
    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_timeout_produces_finding(self, mock_run, engine, ctx):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="trivy", timeout=300)

        findings = engine.execute(ctx)

        assert len(findings) == 1
        assert findings[0].category == FindingCategory.MISSING_CONTROL
        assert findings[0].severity == Severity.HIGH

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_file_not_found_produces_finding(self, mock_run, engine, ctx):
        mock_run.side_effect = FileNotFoundError("trivy not found")

        findings = engine.execute(ctx)

        assert len(findings) == 1
        assert findings[0].category == FindingCategory.MISSING_CONTROL

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_os_error_produces_finding(self, mock_run, engine, ctx):
        mock_run.side_effect = OSError("permission denied")

        findings = engine.execute(ctx)

        assert len(findings) == 1
        assert findings[0].category == FindingCategory.MISSING_CONTROL

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_invalid_json_produces_finding(self, mock_run, engine, ctx):
        mock_run.return_value = _make_completed("not json", returncode=1)

        findings = engine.execute(ctx)

        assert len(findings) == 1
        assert findings[0].category == FindingCategory.MISSING_CONTROL

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_invalid_json_exit_0_treated_as_clean(self, mock_run, engine, ctx):
        mock_run.return_value = _make_completed("not json", returncode=0)

        findings = engine.execute(ctx)

        assert findings == []

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_prefixed_stdout_recovered(self, mock_run, engine, ctx):
        vuln_json = _make_trivy_vuln_json([_make_vuln()])
        stdout = f"2024-03-15T10:00:00 INFO some progress message\n{vuln_json}"
        mock_run.return_value = _make_completed(stdout)

        findings = engine.execute(ctx)

        assert len(findings) == 1
        assert findings[0].category == FindingCategory.DEPENDENCY_VULNERABILITY


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------


class TestCommandConstruction:
    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_basic_command(self, mock_run, engine, ctx):
        mock_run.return_value = _make_completed("")

        engine.execute(ctx)

        cmd = mock_run.call_args[0][0]
        assert cmd[:2] == ["trivy", "fs"]
        assert "--scanners" in cmd
        idx = cmd.index("--scanners")
        assert cmd[idx + 1] == "vuln"
        assert "--format" in cmd
        assert "json" in cmd
        assert "--quiet" in cmd
        assert str(ctx.target_path) in cmd

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_default_timeout(self, mock_run, engine, ctx):
        mock_run.return_value = _make_completed("")

        engine.execute(ctx)

        assert mock_run.call_args[1]["timeout"] == 300

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_custom_timeout(self, mock_run, engine, tmp_path):
        ctx = ScanContext(
            target_path=tmp_path,
            preset=Preset.BALANCED,
            environment=EnvironmentInfo(
                os_name="darwin",
                os_version="23.0.0",
                python_version="3.12.0",
                available_tools=frozenset({"trivy"}),
            ),
            engine_configs={"trivy-vuln": {"timeout": 600}},
        )
        mock_run.return_value = _make_completed("")

        engine.execute(ctx)

        assert mock_run.call_args[1]["timeout"] == 600

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_ignorefile_passed_when_present(self, mock_run, engine, tmp_path):
        (tmp_path / ".trivyignore.yaml").write_text("# ignore")
        ctx = ScanContext(
            target_path=tmp_path,
            preset=Preset.BALANCED,
            environment=EnvironmentInfo(
                os_name="darwin",
                os_version="23.0.0",
                python_version="3.12.0",
                available_tools=frozenset({"trivy"}),
            ),
        )
        mock_run.return_value = _make_completed("")

        engine.execute(ctx)

        cmd = mock_run.call_args[0][0]
        assert "--ignorefile" in cmd

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_no_ignorefile_when_absent(self, mock_run, engine, ctx):
        mock_run.return_value = _make_completed("")

        engine.execute(ctx)

        cmd = mock_run.call_args[0][0]
        assert "--ignorefile" not in cmd


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_critical(self, mock_run, engine, ctx):
        stdout = _make_trivy_vuln_json([_make_vuln(severity="CRITICAL")])
        mock_run.return_value = _make_completed(stdout)

        findings = engine.execute(ctx)
        assert findings[0].severity == Severity.CRITICAL

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_high(self, mock_run, engine, ctx):
        stdout = _make_trivy_vuln_json([_make_vuln(severity="HIGH")])
        mock_run.return_value = _make_completed(stdout)

        findings = engine.execute(ctx)
        assert findings[0].severity == Severity.HIGH

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_medium(self, mock_run, engine, ctx):
        stdout = _make_trivy_vuln_json([_make_vuln(severity="MEDIUM")])
        mock_run.return_value = _make_completed(stdout)

        findings = engine.execute(ctx)
        assert findings[0].severity == Severity.MEDIUM

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_low(self, mock_run, engine, ctx):
        stdout = _make_trivy_vuln_json([_make_vuln(severity="LOW")])
        mock_run.return_value = _make_completed(stdout)

        findings = engine.execute(ctx)
        assert findings[0].severity == Severity.LOW

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_unknown(self, mock_run, engine, ctx):
        stdout = _make_trivy_vuln_json([_make_vuln(severity="UNKNOWN")])
        mock_run.return_value = _make_completed(stdout)

        findings = engine.execute(ctx)
        assert findings[0].severity == Severity.INFO

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_unmapped_defaults_to_info(self, mock_run, engine, ctx):
        stdout = _make_trivy_vuln_json([_make_vuln(severity="WEIRD")])
        mock_run.return_value = _make_completed(stdout)

        findings = engine.execute(ctx)
        assert findings[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# Finding details
# ---------------------------------------------------------------------------


class TestFindingDetails:
    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_title_contains_vuln_id_and_package(self, mock_run, engine, ctx):
        stdout = _make_trivy_vuln_json([_make_vuln("CVE-2024-9999", "urllib3")])
        mock_run.return_value = _make_completed(stdout)

        findings = engine.execute(ctx)
        assert "CVE-2024-9999" in findings[0].title
        assert "urllib3" in findings[0].title

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_evidence_contains_versions(self, mock_run, engine, ctx):
        stdout = _make_trivy_vuln_json([_make_vuln(installed="1.0.0", fixed="1.2.0")])
        mock_run.return_value = _make_completed(stdout)

        findings = engine.execute(ctx)
        assert findings[0].evidence["installed_version"] == "1.0.0"
        assert findings[0].evidence["fixed_version"] == "1.2.0"

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_remediation_with_fixed_version(self, mock_run, engine, ctx):
        stdout = _make_trivy_vuln_json([_make_vuln(fixed="2.31.0")])
        mock_run.return_value = _make_completed(stdout)

        findings = engine.execute(ctx)
        assert "2.31.0" in findings[0].remediation

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_remediation_without_fixed_version(self, mock_run, engine, ctx):
        vuln = _make_vuln()
        vuln["FixedVersion"] = ""
        stdout = _make_trivy_vuln_json([vuln])
        mock_run.return_value = _make_completed(stdout)

        findings = engine.execute(ctx)
        assert findings[0].remediation  # should still have something
        assert "no fix" in findings[0].remediation.lower()

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_location_contains_target(self, mock_run, engine, ctx):
        stdout = _make_trivy_vuln_json([_make_vuln()], target="go.sum")
        mock_run.return_value = _make_completed(stdout)

        findings = engine.execute(ctx)
        assert findings[0].location is not None
        assert findings[0].location.file_path == Path("go.sum")

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_finding_id_deterministic(self, mock_run, engine, ctx):
        stdout = _make_trivy_vuln_json([_make_vuln()])
        mock_run.return_value = _make_completed(stdout)

        f1 = engine.execute(ctx)
        f2 = engine.execute(ctx)

        assert f1[0].id == f2[0].id

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_description_is_vuln_title(self, mock_run, engine, ctx):
        stdout = _make_trivy_vuln_json([_make_vuln(title="SQL injection in query parser")])
        mock_run.return_value = _make_completed(stdout)

        findings = engine.execute(ctx)
        assert findings[0].description == "SQL injection in query parser"


# ---------------------------------------------------------------------------
# Tool failure finding
# ---------------------------------------------------------------------------


class TestToolFailure:
    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_failure_finding_category(self, mock_run, engine, ctx):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="trivy", timeout=300)

        findings = engine.execute(ctx)
        assert findings[0].category == FindingCategory.MISSING_CONTROL

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_failure_finding_severity(self, mock_run, engine, ctx):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="trivy", timeout=300)

        findings = engine.execute(ctx)
        assert findings[0].severity == Severity.HIGH

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_failure_finding_engine_id(self, mock_run, engine, ctx):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="trivy", timeout=300)

        findings = engine.execute(ctx)
        assert findings[0].engine_id == "trivy-vuln"

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_failure_finding_layer(self, mock_run, engine, ctx):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="trivy", timeout=300)

        findings = engine.execute(ctx)
        assert findings[0].layer == Layer.STATIC

    @patch("plsec.engine.trivy_dependency.subprocess.run")
    def test_failure_finding_has_remediation(self, mock_run, engine, ctx):
        mock_run.side_effect = FileNotFoundError("trivy not found")

        findings = engine.execute(ctx)
        assert findings[0].remediation
