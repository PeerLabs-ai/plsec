"""Tests for the scanner registry module (core/scanners.py).

Covers:
- ScannerSpec dataclass and SCANNERS registry integrity
- Command builder functions (_build_*_cmd) produce correct argv
- Result parser functions (_parse_*_result) classify outcomes correctly
- _has_python_files file filter
- run_scanner() with mocked subprocess and shutil.which

Private functions are tested directly because they are the core logic
of the scanner system. Each builder/parser is a pure function with a
well-defined contract: builders take (Path, Path|None) and return
list[str]; parsers take (int, str) and return (bool, str).

If a private function is renamed, update the import in this file.
"""

import subprocess
from pathlib import Path
from unittest.mock import patch

from plsec.core.scanners import (
    _BANDIT_EXCLUDE_DIRS,
    _TRIVY_IGNOREFILE,
    _TRIVY_SKIP_DIRS,
    _TRIVY_SKIP_FILES,
    SCANNERS,
    ScannerSpec,
    _build_bandit_cmd,
    _build_semgrep_cmd,
    _build_trivy_misconfig_cmd,
    _build_trivy_secrets_cmd,
    _has_python_files,
    _parse_returncode_result,
    _parse_trivy_misconfig_result,
    _parse_trivy_secrets_result,
    run_scanner,
)
from plsec.core.tools import Tool

# -----------------------------------------------------------------------
# ScannerSpec and SCANNERS registry
# -----------------------------------------------------------------------


class TestScannerSpec:
    """Contract: ScannerSpec holds all metadata needed to run a scanner.
    The SCANNERS dict maps scanner IDs to complete specs."""

    def test_registry_has_expected_scanners(self):
        """Registry must contain all 4 scanners."""
        expected = {"trivy-secrets", "trivy-misconfig", "bandit", "semgrep"}
        assert set(SCANNERS.keys()) == expected

    def test_registry_keys_match_spec_ids(self):
        """Registry keys must match the spec's id field."""
        for key, spec in SCANNERS.items():
            assert key == spec.id

    def test_all_specs_have_display_name(self):
        for spec in SCANNERS.values():
            assert spec.display_name, f"Scanner {spec.id!r} missing display_name"

    def test_all_specs_have_scan_type(self):
        for spec in SCANNERS.values():
            assert spec.scan_type in ("secrets", "code", "misconfig")

    def test_all_specs_have_tool(self):
        for spec in SCANNERS.values():
            assert isinstance(spec.tool, Tool)

    def test_all_specs_have_build_command(self):
        for spec in SCANNERS.values():
            assert callable(spec.build_command)

    def test_all_specs_have_parse_result(self):
        for spec in SCANNERS.values():
            assert callable(spec.parse_result)

    def test_timeout_defaults(self):
        """Default timeout is 300s; semgrep overrides to 600s."""
        assert SCANNERS["trivy-secrets"].timeout == 300
        assert SCANNERS["semgrep"].timeout == 600

    def test_trivy_scanners_are_not_skippable(self):
        """Trivy scanners should fail when missing, not skip."""
        assert SCANNERS["trivy-secrets"].skip_when_missing is False
        assert SCANNERS["trivy-misconfig"].skip_when_missing is False

    def test_optional_scanners_are_skippable(self):
        """Bandit and semgrep should skip when missing."""
        assert SCANNERS["bandit"].skip_when_missing is True
        assert SCANNERS["semgrep"].skip_when_missing is True

    def test_bandit_has_python_file_filter(self):
        """Bandit should only run when Python files exist."""
        assert SCANNERS["bandit"].file_filter is not None

    def test_semgrep_has_no_file_filter(self):
        """Semgrep runs on any project."""
        assert SCANNERS["semgrep"].file_filter is None


# -----------------------------------------------------------------------
# Command builders
# -----------------------------------------------------------------------


class TestBuildCommands:
    """Contract: command builders take (target, config_path|None) and return
    a list of strings suitable for subprocess.run. The target path appears
    in the command. Config path is used only if provided and exists."""

    def test_trivy_secrets_basic(self, tmp_path: Path):
        cmd = _build_trivy_secrets_cmd(tmp_path, None)
        assert cmd[0] == "trivy"
        assert "secret" in cmd
        assert str(tmp_path) in cmd

    def test_trivy_secrets_with_config(self, tmp_path: Path):
        """Config path should be included when it exists."""
        config = tmp_path / "secret-config.yaml"
        config.write_text("rules: []\n")
        cmd = _build_trivy_secrets_cmd(tmp_path, config)
        assert "--secret-config" in cmd
        assert str(config) in cmd

    def test_trivy_secrets_without_existing_config(self, tmp_path: Path):
        """Config path should NOT be included when it doesn't exist."""
        config = tmp_path / "nonexistent.yaml"
        cmd = _build_trivy_secrets_cmd(tmp_path, config)
        assert "--secret-config" not in cmd

    def test_trivy_secrets_skips_venv(self, tmp_path: Path):
        """Trivy scan must skip .venv and other third-party dirs."""
        cmd = _build_trivy_secrets_cmd(tmp_path, None)
        for skip_dir in _TRIVY_SKIP_DIRS:
            idx = cmd.index("--skip-dirs")
            assert skip_dir in cmd[idx + 1 :]

    def test_trivy_secrets_skips_pyc(self, tmp_path: Path):
        """Trivy scan must skip compiled bytecode files."""
        cmd = _build_trivy_secrets_cmd(tmp_path, None)
        for skip_file in _TRIVY_SKIP_FILES:
            idx = cmd.index("--skip-files")
            assert skip_file in cmd[idx + 1 :]

    def test_trivy_secrets_with_ignorefile(self, tmp_path: Path):
        """Trivy secret scan should pass --ignorefile when .trivyignore.yaml exists."""
        ignorefile = tmp_path / _TRIVY_IGNOREFILE
        ignorefile.write_text("secrets: []\n")
        cmd = _build_trivy_secrets_cmd(tmp_path, None)
        assert "--ignorefile" in cmd
        assert str(ignorefile) in cmd

    def test_trivy_secrets_without_ignorefile(self, tmp_path: Path):
        """Trivy secret scan should NOT pass --ignorefile when file is absent."""
        cmd = _build_trivy_secrets_cmd(tmp_path, None)
        assert "--ignorefile" not in cmd

    def test_trivy_misconfig(self, tmp_path: Path):
        cmd = _build_trivy_misconfig_cmd(tmp_path, None)
        assert cmd[0] == "trivy"
        assert "config" in cmd
        assert str(tmp_path) in cmd

    def test_trivy_misconfig_skips_venv(self, tmp_path: Path):
        """Trivy misconfig must skip .venv and other third-party dirs."""
        cmd = _build_trivy_misconfig_cmd(tmp_path, None)
        for skip_dir in _TRIVY_SKIP_DIRS:
            idx = cmd.index("--skip-dirs")
            assert skip_dir in cmd[idx + 1 :]

    def test_trivy_misconfig_skips_pyc(self, tmp_path: Path):
        """Trivy misconfig must skip compiled bytecode files."""
        cmd = _build_trivy_misconfig_cmd(tmp_path, None)
        for skip_file in _TRIVY_SKIP_FILES:
            idx = cmd.index("--skip-files")
            assert skip_file in cmd[idx + 1 :]

    def test_trivy_misconfig_with_ignorefile(self, tmp_path: Path):
        """Trivy misconfig scan should pass --ignorefile when .trivyignore.yaml exists."""
        ignorefile = tmp_path / _TRIVY_IGNOREFILE
        ignorefile.write_text("misconfigurations: []\n")
        cmd = _build_trivy_misconfig_cmd(tmp_path, None)
        assert "--ignorefile" in cmd
        assert str(ignorefile) in cmd

    def test_trivy_misconfig_without_ignorefile(self, tmp_path: Path):
        """Trivy misconfig scan should NOT pass --ignorefile when file is absent."""
        cmd = _build_trivy_misconfig_cmd(tmp_path, None)
        assert "--ignorefile" not in cmd

    def test_bandit(self, tmp_path: Path):
        cmd = _build_bandit_cmd(tmp_path, None)
        assert cmd[0] == "bandit"
        assert "-r" in cmd
        assert "--exclude" in cmd
        exclude_idx = cmd.index("--exclude")
        excludes = cmd[exclude_idx + 1]
        # Exclude paths must be resolved relative to target
        for dirname in _BANDIT_EXCLUDE_DIRS:
            assert str(tmp_path / dirname) in excludes
        assert str(tmp_path) == cmd[-1]

    def test_semgrep(self, tmp_path: Path):
        cmd = _build_semgrep_cmd(tmp_path, None)
        assert cmd[0] == "semgrep"
        assert "--config" in cmd
        assert str(tmp_path) in cmd


# -----------------------------------------------------------------------
# Result parsers
# -----------------------------------------------------------------------


class TestParseTrivySecretsResult:
    """Contract: _parse_trivy_secrets_result returns (True, msg) when no
    secrets found, (False, output) when secrets are detected."""

    def test_pass_on_zero_returncode(self):
        ok, msg = _parse_trivy_secrets_result(0, "")
        assert ok is True

    def test_pass_on_no_secret_detected_text(self):
        ok, msg = _parse_trivy_secrets_result(1, "No secret detected in the scan")
        assert ok is True

    def test_fail_on_nonzero_with_findings(self):
        ok, msg = _parse_trivy_secrets_result(1, "Found AWS key in config.py")
        assert ok is False
        assert "AWS" in msg


class TestParseTrivyMisconfigResult:
    """Contract: _parse_trivy_misconfig_result returns (True, msg) when no
    misconfigs found, (False, output) when issues are detected."""

    def test_pass_on_zero_returncode(self):
        ok, msg = _parse_trivy_misconfig_result(0, "")
        assert ok is True

    def test_pass_when_no_detected_keyword(self):
        ok, msg = _parse_trivy_misconfig_result(1, "No issues in output")
        assert ok is True

    def test_fail_when_detected_in_output(self):
        ok, msg = _parse_trivy_misconfig_result(1, "Detected: CRITICAL misconfiguration")
        assert ok is False


class TestParseReturncodeResult:
    """Contract: generic parser passes on returncode 0, fails otherwise."""

    def test_pass_on_zero(self):
        ok, msg = _parse_returncode_result(0, "all good")
        assert ok is True

    def test_fail_on_nonzero(self):
        ok, msg = _parse_returncode_result(1, "error details")
        assert ok is False
        assert msg == "error details"

    def test_fail_on_other_codes(self):
        ok, msg = _parse_returncode_result(2, "critical")
        assert ok is False


# -----------------------------------------------------------------------
# File filter
# -----------------------------------------------------------------------


class TestHasPythonFiles:
    """Contract: _has_python_files(target) returns True if any *.py files
    exist under target, False otherwise."""

    def test_no_python_files(self, tmp_path: Path):
        (tmp_path / "readme.md").write_text("hello")
        assert _has_python_files(tmp_path) is False

    def test_has_python_file(self, tmp_path: Path):
        (tmp_path / "main.py").write_text("print('hi')")
        assert _has_python_files(tmp_path) is True

    def test_nested_python_file(self, tmp_path: Path):
        subdir = tmp_path / "src" / "pkg"
        subdir.mkdir(parents=True)
        (subdir / "module.py").write_text("")
        assert _has_python_files(tmp_path) is True

    def test_empty_directory(self, tmp_path: Path):
        assert _has_python_files(tmp_path) is False


# -----------------------------------------------------------------------
# run_scanner (mocked subprocess)
# -----------------------------------------------------------------------


def _make_scanner_spec(
    *,
    skip_when_missing: bool = True,
    file_filter: None = None,
    config_file: str | None = None,
    timeout: int = 10,
) -> ScannerSpec:
    """Create a minimal ScannerSpec for testing run_scanner."""
    return ScannerSpec(
        id="test-scanner",
        display_name="Test Scanner",
        scan_type="test",
        tool=Tool(name="test-tool", command="test-tool", version_flag="--version"),
        build_command=lambda target, config: ["test-tool", "scan", str(target)],
        parse_result=_parse_returncode_result,
        config_file=config_file,
        timeout=timeout,
        skip_when_missing=skip_when_missing,
        file_filter=file_filter,
    )


class TestRunScanner:
    """Contract: run_scanner(spec, target, plsec_home) handles binary
    availability, file filtering, subprocess execution, timeout, and result
    parsing. Returns (passed, message).

    These tests mock shutil.which and subprocess.run to avoid actual
    binary execution."""

    def test_skip_when_binary_missing_and_skippable(self, tmp_path: Path):
        """Missing binary with skip_when_missing=True should pass."""
        spec = _make_scanner_spec(skip_when_missing=True)
        with patch("plsec.core.scanners.shutil.which", return_value=None):
            ok, msg = run_scanner(spec, tmp_path, tmp_path)
        assert ok is True
        assert "skipped" in msg.lower()

    def test_fail_when_binary_missing_and_required(self, tmp_path: Path):
        """Missing binary with skip_when_missing=False should fail."""
        spec = _make_scanner_spec(skip_when_missing=False)
        with patch("plsec.core.scanners.shutil.which", return_value=None):
            ok, msg = run_scanner(spec, tmp_path, tmp_path)
        assert ok is False
        assert "not found" in msg.lower()

    def test_skip_when_file_filter_fails(self, tmp_path: Path):
        """Scanner with file_filter that returns False should skip."""
        spec = _make_scanner_spec()
        spec.file_filter = lambda _: False
        with patch("plsec.core.scanners.shutil.which", return_value="/usr/bin/test-tool"):
            ok, msg = run_scanner(spec, tmp_path, tmp_path)
        assert ok is True
        assert "no applicable files" in msg.lower()

    def test_successful_scan(self, tmp_path: Path):
        """Successful scan (returncode 0) should pass."""
        spec = _make_scanner_spec()
        mock_result = type("Result", (), {"returncode": 0, "stdout": "ok", "stderr": ""})()
        with (
            patch("plsec.core.scanners.shutil.which", return_value="/usr/bin/test-tool"),
            patch("plsec.core.scanners.subprocess.run", return_value=mock_result),
        ):
            ok, msg = run_scanner(spec, tmp_path, tmp_path)
        assert ok is True

    def test_failed_scan(self, tmp_path: Path):
        """Failed scan (nonzero returncode) should fail."""
        spec = _make_scanner_spec()
        mock_result = type("Result", (), {"returncode": 1, "stdout": "", "stderr": "error"})()
        with (
            patch("plsec.core.scanners.shutil.which", return_value="/usr/bin/test-tool"),
            patch("plsec.core.scanners.subprocess.run", return_value=mock_result),
        ):
            ok, msg = run_scanner(spec, tmp_path, tmp_path)
        assert ok is False

    def test_timeout_returns_failure(self, tmp_path: Path):
        """Subprocess timeout should return failure."""
        spec = _make_scanner_spec(timeout=1)
        with (
            patch("plsec.core.scanners.shutil.which", return_value="/usr/bin/test-tool"),
            patch(
                "plsec.core.scanners.subprocess.run",
                side_effect=subprocess.TimeoutExpired("test-tool", 1),
            ),
        ):
            ok, msg = run_scanner(spec, tmp_path, tmp_path)
        assert ok is False
        assert "timed out" in msg.lower()

    def test_file_not_found_skippable(self, tmp_path: Path):
        """FileNotFoundError with skip_when_missing=True should pass."""
        spec = _make_scanner_spec(skip_when_missing=True)
        with (
            patch("plsec.core.scanners.shutil.which", return_value="/usr/bin/test-tool"),
            patch(
                "plsec.core.scanners.subprocess.run",
                side_effect=FileNotFoundError("test-tool"),
            ),
        ):
            ok, msg = run_scanner(spec, tmp_path, tmp_path)
        assert ok is True
        assert "skipped" in msg.lower()

    def test_file_not_found_required(self, tmp_path: Path):
        """FileNotFoundError with skip_when_missing=False should fail."""
        spec = _make_scanner_spec(skip_when_missing=False)
        with (
            patch("plsec.core.scanners.shutil.which", return_value="/usr/bin/test-tool"),
            patch(
                "plsec.core.scanners.subprocess.run",
                side_effect=FileNotFoundError("test-tool"),
            ),
        ):
            ok, msg = run_scanner(spec, tmp_path, tmp_path)
        assert ok is False

    def test_config_file_resolved(self, tmp_path: Path):
        """Config file path should be resolved from plsec_home."""
        spec = _make_scanner_spec(config_file="configs/scan.yaml")
        captured_cmd = []

        def capture_build(target, config):
            captured_cmd.append(config)
            return ["test-tool", str(target)]

        spec.build_command = capture_build
        mock_result = type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        with (
            patch("plsec.core.scanners.shutil.which", return_value="/usr/bin/test-tool"),
            patch("plsec.core.scanners.subprocess.run", return_value=mock_result),
        ):
            run_scanner(spec, tmp_path, tmp_path)
        assert captured_cmd[0] == tmp_path / "configs" / "scan.yaml"
