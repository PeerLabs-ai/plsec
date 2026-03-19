"""Tests for the health check module (core/health.py).

Covers:
- CheckResult dataclass defaults
- count_verdicts() verdict counting
- exit_code_for() exit code determination
- check_directory_structure() with and without fix mode
- check_agent_configs() with present and missing configs
- check_config_file() with present, missing, and None paths
- check_tools() status-to-verdict mapping for all ToolStatus values
- check_runtime() Python version check
- check_project_configs() project-level agent config checks
- PLSEC_SUBDIRS constant

All check functions take explicit arguments (paths, registries), so tests
use tmp_path fixtures with no mocking needed for most functions.
"""

from pathlib import Path
from unittest.mock import patch

from plsec.core.adapters import CompatResult, VersionProbe
from plsec.core.agents import AGENTS, AgentSpec
from plsec.core.health import (
    PLSEC_EXPECTED_FILES,
    PLSEC_EXPECTED_PRESETS,
    PLSEC_EXPECTED_SCRIPTS,
    PLSEC_SUBDIRS,
    CheckResult,
    check_agent_compatibility,
    check_agent_configs,
    check_config_file,
    check_directory_structure,
    check_preset_files,
    check_project_configs,
    check_runtime,
    check_scanner_configs,
    check_tools,
    check_wrapper_scripts,
    count_verdicts,
    exit_code_for,
)
from plsec.core.tools import Tool, ToolStatus

# -----------------------------------------------------------------------
# CheckResult
# -----------------------------------------------------------------------


class TestCheckResult:
    """Contract: CheckResult holds check metadata with sensible defaults."""

    def test_required_fields(self):
        r = CheckResult(id="I-1", name="test", category="installation", verdict="ok")
        assert r.id == "I-1"
        assert r.name == "test"
        assert r.category == "installation"
        assert r.verdict == "ok"

    def test_default_detail(self):
        r = CheckResult(id="I-1", name="test", category="installation", verdict="ok")
        assert r.detail == ""

    def test_default_fix_hint(self):
        r = CheckResult(id="I-1", name="test", category="installation", verdict="ok")
        assert r.fix_hint == ""

    def test_custom_detail_and_hint(self):
        r = CheckResult(
            id="C-1",
            name="config",
            category="configuration",
            verdict="fail",
            detail="/path/to/file",
            fix_hint="Run plsec init",
        )
        assert r.detail == "/path/to/file"
        assert r.fix_hint == "Run plsec init"


# -----------------------------------------------------------------------
# PLSEC_SUBDIRS
# -----------------------------------------------------------------------


class TestPlsecSubdirs:
    """Contract: PLSEC_SUBDIRS lists expected subdirectories under plsec home."""

    def test_is_non_empty_list(self):
        assert isinstance(PLSEC_SUBDIRS, list)
        assert len(PLSEC_SUBDIRS) > 0

    def test_contains_expected_dirs(self):
        assert "configs" in PLSEC_SUBDIRS
        assert "logs" in PLSEC_SUBDIRS
        assert "manifests" in PLSEC_SUBDIRS


# -----------------------------------------------------------------------
# count_verdicts
# -----------------------------------------------------------------------


class TestCountVerdicts:
    """Contract: count_verdicts(results) returns a dict with counts for
    each verdict type: ok, warn, fail, skip."""

    def test_empty_list(self):
        counts = count_verdicts([])
        assert counts == {"ok": 0, "warn": 0, "fail": 0, "skip": 0}

    def test_all_ok(self):
        results = [
            CheckResult(id="1", name="a", category="installation", verdict="ok"),
            CheckResult(id="2", name="b", category="installation", verdict="ok"),
        ]
        counts = count_verdicts(results)
        assert counts["ok"] == 2
        assert counts["fail"] == 0

    def test_mixed_verdicts(self):
        results = [
            CheckResult(id="1", name="a", category="installation", verdict="ok"),
            CheckResult(id="2", name="b", category="installation", verdict="warn"),
            CheckResult(id="3", name="c", category="installation", verdict="fail"),
            CheckResult(id="4", name="d", category="installation", verdict="skip"),
        ]
        counts = count_verdicts(results)
        assert counts == {"ok": 1, "warn": 1, "fail": 1, "skip": 1}

    def test_multiple_fails(self):
        results = [
            CheckResult(id="1", name="a", category="installation", verdict="fail"),
            CheckResult(id="2", name="b", category="installation", verdict="fail"),
            CheckResult(id="3", name="c", category="installation", verdict="ok"),
        ]
        counts = count_verdicts(results)
        assert counts["fail"] == 2


# -----------------------------------------------------------------------
# exit_code_for
# -----------------------------------------------------------------------


class TestExitCodeFor:
    """Contract: exit_code_for(results) returns 0 if no failures, 1 if
    any failures. Warnings are acceptable (exit 0)."""

    def test_all_ok(self):
        results = [
            CheckResult(id="1", name="a", category="installation", verdict="ok"),
        ]
        assert exit_code_for(results) == 0

    def test_warnings_are_acceptable(self):
        results = [
            CheckResult(id="1", name="a", category="installation", verdict="warn"),
        ]
        assert exit_code_for(results) == 0

    def test_any_fail_returns_1(self):
        results = [
            CheckResult(id="1", name="a", category="installation", verdict="ok"),
            CheckResult(id="2", name="b", category="installation", verdict="fail"),
        ]
        assert exit_code_for(results) == 1

    def test_empty_list_returns_0(self):
        assert exit_code_for([]) == 0

    def test_skip_is_acceptable(self):
        results = [
            CheckResult(id="1", name="a", category="installation", verdict="skip"),
        ]
        assert exit_code_for(results) == 0


# -----------------------------------------------------------------------
# check_directory_structure
# -----------------------------------------------------------------------


class TestCheckDirectoryStructure:
    """Contract: check_directory_structure(plsec_home, fix=False) checks
    that the home directory and subdirectories exist. Returns CheckResults
    with appropriate verdicts. fix=True creates missing directories."""

    def test_all_present(self, tmp_path: Path):
        """All directories exist -- all results should be ok."""
        home = tmp_path / "plsec"
        home.mkdir()
        for subdir in PLSEC_SUBDIRS:
            (home / subdir).mkdir(parents=True, exist_ok=True)
        results = check_directory_structure(home)
        assert all(r.verdict == "ok" for r in results)
        # 1 home check + N subdirectory checks
        assert len(results) == 1 + len(PLSEC_SUBDIRS)

    def test_home_missing(self, tmp_path: Path):
        """Missing home directory should fail and return early."""
        home = tmp_path / "nonexistent"
        results = check_directory_structure(home)
        assert len(results) == 1
        assert results[0].verdict == "fail"
        assert results[0].id == "I-1"

    def test_subdirs_missing_without_fix(self, tmp_path: Path):
        """Missing subdirectories without fix should warn."""
        home = tmp_path / "plsec"
        home.mkdir()
        results = check_directory_structure(home, fix=False)
        # Home is ok, subdirs are warn
        assert results[0].verdict == "ok"
        subdir_results = results[1:]
        assert all(r.verdict == "warn" for r in subdir_results)

    def test_subdirs_missing_with_fix(self, tmp_path: Path):
        """fix=True should create missing subdirectories and report ok."""
        home = tmp_path / "plsec"
        home.mkdir()
        results = check_directory_structure(home, fix=True)
        assert all(r.verdict == "ok" for r in results)
        # Verify directories were actually created
        for subdir in PLSEC_SUBDIRS:
            assert (home / subdir).exists()

    def test_partial_subdirs(self, tmp_path: Path):
        """Some subdirs present, some missing -- mixed results."""
        home = tmp_path / "plsec"
        home.mkdir()
        (home / "configs").mkdir()
        (home / "logs").mkdir()
        results = check_directory_structure(home)
        verdicts = [r.verdict for r in results]
        assert "ok" in verdicts
        assert "warn" in verdicts


# -----------------------------------------------------------------------
# check_agent_configs
# -----------------------------------------------------------------------


class TestCheckAgentConfigs:
    """Contract: check_agent_configs(plsec_home, agents) checks for
    agent config files in plsec_home/configs/. One check per agent."""

    def test_all_configs_present(self, tmp_path: Path):
        """All agent configs exist -- all results should be ok."""
        configs_dir = tmp_path / "configs"
        configs_dir.mkdir()
        for spec in AGENTS.values():
            (configs_dir / spec.config_filename).write_text("test")
        results = check_agent_configs(tmp_path, AGENTS)
        assert len(results) == len(AGENTS)
        assert all(r.verdict == "ok" for r in results)

    def test_no_configs_present(self, tmp_path: Path):
        """No agent configs exist -- all results should be warn."""
        (tmp_path / "configs").mkdir()
        results = check_agent_configs(tmp_path, AGENTS)
        assert len(results) == len(AGENTS)
        assert all(r.verdict == "warn" for r in results)

    def test_check_ids_are_sequential(self, tmp_path: Path):
        """Check IDs should be I-2, I-3, etc."""
        (tmp_path / "configs").mkdir()
        results = check_agent_configs(tmp_path, AGENTS)
        ids = [r.id for r in results]
        expected = [f"I-{i}" for i in range(2, 2 + len(AGENTS))]
        assert ids == expected

    def test_custom_agent_registry(self, tmp_path: Path):
        """Works with arbitrary agent specs, not just the global AGENTS."""
        (tmp_path / "configs").mkdir()
        custom_agents = {
            "test": AgentSpec(
                id="test",
                display_name="Test Agent",
                config_filename="test.yaml",
                templates={"strict": "s", "balanced": "b"},
                config_type="test",
            ),
        }
        results = check_agent_configs(tmp_path, custom_agents)
        assert len(results) == 1
        assert results[0].verdict == "warn"
        assert "test.yaml" in results[0].name


# -----------------------------------------------------------------------
# check_config_file
# -----------------------------------------------------------------------


class TestCheckConfigFile:
    """Contract: check_config_file(config_path) checks if plsec.yaml exists.
    Takes the result of find_config_file() -- Path or None."""

    def test_config_exists(self, tmp_path: Path):
        config = tmp_path / "plsec.yaml"
        config.write_text("preset: balanced\n")
        results = check_config_file(config)
        assert len(results) == 1
        assert results[0].verdict == "ok"
        assert results[0].id == "C-1"

    def test_config_none(self):
        """None (no config found) should return skip."""
        results = check_config_file(None)
        assert len(results) == 1
        assert results[0].verdict == "skip"

    def test_config_path_in_detail(self, tmp_path: Path):
        config = tmp_path / "plsec.yaml"
        config.write_text("preset: balanced\n")
        results = check_config_file(config)
        assert str(config) in results[0].detail


# -----------------------------------------------------------------------
# check_tools
# -----------------------------------------------------------------------


class TestCheckTools:
    """Contract: check_tools(tools) converts ToolStatus to CheckResult
    verdicts. OK->ok, MISSING->fail (required) or warn (optional),
    OUTDATED->warn, ERROR->fail."""

    def _make_tool(
        self,
        *,
        status: ToolStatus = ToolStatus.OK,
        required: bool = True,
        version: str | None = "1.0.0",
        min_version: str | None = None,
        error: str | None = None,
    ) -> Tool:
        t = Tool(name="test-tool", command="test", version_flag="--version")
        t.status = status
        t.required = required
        t.version = version
        t.min_version = min_version
        t.error = error
        return t

    def test_ok_tool(self):
        tool = self._make_tool(status=ToolStatus.OK, version="2.0.0")
        results = check_tools([tool])
        assert len(results) == 1
        assert results[0].verdict == "ok"
        assert "2.0.0" in results[0].name

    def test_missing_required_tool(self):
        tool = self._make_tool(status=ToolStatus.MISSING, required=True)
        results = check_tools([tool])
        assert results[0].verdict == "fail"

    def test_missing_optional_tool(self):
        tool = self._make_tool(status=ToolStatus.MISSING, required=False)
        results = check_tools([tool])
        assert results[0].verdict == "warn"
        assert "optional" in results[0].name.lower()

    def test_outdated_tool(self):
        tool = self._make_tool(status=ToolStatus.OUTDATED, version="1.0.0", min_version="2.0.0")
        results = check_tools([tool])
        assert results[0].verdict == "warn"
        assert "outdated" in results[0].name.lower()

    def test_error_tool(self):
        tool = self._make_tool(status=ToolStatus.ERROR, error="segfault")
        results = check_tools([tool])
        assert results[0].verdict == "fail"
        assert "segfault" in results[0].detail

    def test_multiple_tools(self):
        tools = [
            self._make_tool(status=ToolStatus.OK),
            self._make_tool(status=ToolStatus.MISSING, required=False),
            self._make_tool(status=ToolStatus.ERROR, error="broken"),
        ]
        results = check_tools(tools)
        assert len(results) == 3

    def test_ok_tool_without_version(self):
        tool = self._make_tool(status=ToolStatus.OK, version=None)
        results = check_tools([tool])
        assert results[0].verdict == "ok"


# -----------------------------------------------------------------------
# check_runtime
# -----------------------------------------------------------------------


class TestCheckRuntime:
    """Contract: check_runtime() checks Python >= 3.12. Since tests run
    on 3.12+, we test the current runtime and mock for < 3.12."""

    def test_current_runtime_passes(self):
        """Current runtime (3.12+) should pass."""
        results = check_runtime()
        assert len(results) == 1
        assert results[0].verdict == "ok"
        assert results[0].id == "I-runtime"
        assert "Python" in results[0].name

    def test_old_runtime_fails(self):
        """Mocked Python 3.11 should fail."""
        mock_version = type(
            "version_info",
            (),
            {
                "major": 3,
                "minor": 11,
                "micro": 0,
                "__ge__": lambda self, other: (self.major, self.minor) >= other[:2],
            },
        )()
        with patch("plsec.core.health.sys") as mock_sys:
            mock_sys.version_info = mock_version
            results = check_runtime()
        assert len(results) == 1
        assert results[0].verdict == "fail"
        assert "3.12" in results[0].detail


# -----------------------------------------------------------------------
# check_project_configs
# -----------------------------------------------------------------------


class TestCheckProjectConfigs:
    """Contract: check_project_configs(project_path, agents) checks for
    each agent's config file in the project root."""

    def test_all_configs_present(self, tmp_path: Path):
        """All agent config files exist in project root."""
        for spec in AGENTS.values():
            (tmp_path / spec.config_filename).write_text("test")
        results = check_project_configs(tmp_path, AGENTS)
        assert len(results) == len(AGENTS)
        assert all(r.verdict == "ok" for r in results)
        assert all(r.category == "configuration" for r in results)

    def test_no_configs_present(self, tmp_path: Path):
        """No agent config files exist in project root."""
        results = check_project_configs(tmp_path, AGENTS)
        assert len(results) == len(AGENTS)
        assert all(r.verdict == "warn" for r in results)

    def test_check_ids_start_at_c4(self, tmp_path: Path):
        """Check IDs should be C-4, C-5, etc."""
        results = check_project_configs(tmp_path, AGENTS)
        ids = [r.id for r in results]
        expected = [f"C-{i}" for i in range(4, 4 + len(AGENTS))]
        assert ids == expected

    def test_partial_configs(self, tmp_path: Path):
        """Some agent configs present, some missing."""
        # Create only the first agent's config
        first_spec = next(iter(AGENTS.values()))
        (tmp_path / first_spec.config_filename).write_text("test")
        results = check_project_configs(tmp_path, AGENTS)
        verdicts = [r.verdict for r in results]
        assert "ok" in verdicts
        assert "warn" in verdicts

    def test_custom_agent_registry(self, tmp_path: Path):
        """Works with custom agent specs."""
        custom_agents = {
            "custom": AgentSpec(
                id="custom",
                display_name="Custom Agent",
                config_filename="custom.toml",
                templates={"strict": "s", "balanced": "b"},
                config_type="custom",
            ),
        }
        results = check_project_configs(tmp_path, custom_agents)
        assert len(results) == 1
        assert results[0].verdict == "warn"
        assert "custom.toml" in results[0].name


# -----------------------------------------------------------------------
# check_scanner_configs
# -----------------------------------------------------------------------


class TestCheckScannerConfigs:
    """Contract: check_scanner_configs verifies that trivy-secret.yaml,
    trivy.yaml, and pre-commit hook exist under plsec_home."""

    def test_all_present(self, tmp_path: Path):
        """All expected files exist -- all results should be ok."""
        home = tmp_path / "plsec"
        for rel_path, _ in PLSEC_EXPECTED_FILES:
            full = home / rel_path
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text("content\n")
        results = check_scanner_configs(home)
        assert len(results) == len(PLSEC_EXPECTED_FILES)
        assert all(r.verdict == "ok" for r in results)

    def test_all_missing(self, tmp_path: Path):
        """No expected files -- all results should be warn."""
        home = tmp_path / "plsec"
        home.mkdir()
        results = check_scanner_configs(home)
        assert len(results) == len(PLSEC_EXPECTED_FILES)
        assert all(r.verdict == "warn" for r in results)

    def test_fix_hint_references_install(self, tmp_path: Path):
        """Fix hints should direct to plsec install --force."""
        home = tmp_path / "plsec"
        home.mkdir()
        results = check_scanner_configs(home)
        for r in results:
            assert "plsec install" in r.fix_hint

    def test_check_ids_start_at_i5(self, tmp_path: Path):
        """Check IDs should start at I-5 per plsec-status design doc."""
        home = tmp_path / "plsec"
        home.mkdir()
        results = check_scanner_configs(home)
        assert results[0].id == "I-5"

    def test_partial_files(self, tmp_path: Path):
        """Some files present, others missing -- mixed verdicts."""
        home = tmp_path / "plsec"
        trivy_dir = home / "trivy"
        trivy_dir.mkdir(parents=True)
        (trivy_dir / "trivy-secret.yaml").write_text("rules:\n")
        results = check_scanner_configs(home)
        verdicts = [r.verdict for r in results]
        assert "ok" in verdicts
        assert "warn" in verdicts


# -----------------------------------------------------------------------
# check_wrapper_scripts
# -----------------------------------------------------------------------


class TestCheckWrapperScripts:
    """Contract: check_wrapper_scripts checks that wrapper scripts
    exist and are executable under plsec_home.

    Why tested directly: This function implements health checks I-8
    through I-10 for wrapper scripts.  It verifies both presence and
    executable permission.  Fix by updating the corresponding
    PLSEC_EXPECTED_SCRIPTS list in health.py.
    """

    def test_all_present_and_executable(self, tmp_path: Path):
        """All scripts present and executable -- all ok."""
        home = tmp_path / "plsec"
        home.mkdir()
        for rel_path, _ in PLSEC_EXPECTED_SCRIPTS:
            script = home / rel_path
            script.write_text("#!/bin/bash\n")
            script.chmod(0o755)
        results = check_wrapper_scripts(home)
        assert len(results) == len(PLSEC_EXPECTED_SCRIPTS)
        assert all(r.verdict == "ok" for r in results)

    def test_all_missing(self, tmp_path: Path):
        """No scripts present -- all results should be warn."""
        home = tmp_path / "plsec"
        home.mkdir()
        results = check_wrapper_scripts(home)
        assert len(results) == len(PLSEC_EXPECTED_SCRIPTS)
        assert all(r.verdict == "warn" for r in results)

    def test_present_but_not_executable(self, tmp_path: Path):
        """Scripts present but not executable -- warn."""
        home = tmp_path / "plsec"
        home.mkdir()
        for rel_path, _ in PLSEC_EXPECTED_SCRIPTS:
            script = home / rel_path
            script.write_text("#!/bin/bash\n")
            script.chmod(0o644)
        results = check_wrapper_scripts(home)
        assert all(r.verdict == "warn" for r in results)
        assert all("not executable" in r.detail for r in results)

    def test_check_ids_start_at_i8(self, tmp_path: Path):
        """Check IDs should start at I-8 per plsec-status design doc."""
        home = tmp_path / "plsec"
        home.mkdir()
        results = check_wrapper_scripts(home)
        assert results[0].id == "I-8"

    def test_fix_hint_references_install(self, tmp_path: Path):
        """Fix hints should direct to plsec install."""
        home = tmp_path / "plsec"
        home.mkdir()
        results = check_wrapper_scripts(home)
        for r in results:
            assert "plsec install" in r.fix_hint

    def test_partial_scripts(self, tmp_path: Path):
        """Some scripts present, others missing -- mixed verdicts."""
        home = tmp_path / "plsec"
        home.mkdir()
        # Only create the first expected script
        first_path, _ = PLSEC_EXPECTED_SCRIPTS[0]
        script = home / first_path
        script.write_text("#!/bin/bash\n")
        script.chmod(0o755)
        results = check_wrapper_scripts(home)
        verdicts = [r.verdict for r in results]
        assert "ok" in verdicts
        assert "warn" in verdicts

    def test_expected_scripts_constant(self):
        """PLSEC_EXPECTED_SCRIPTS should contain all three scripts."""
        names = [name for name, _ in PLSEC_EXPECTED_SCRIPTS]
        assert "claude-wrapper.sh" in names
        assert "opencode-wrapper.sh" in names
        assert "plsec-audit.sh" in names


# -----------------------------------------------------------------------
# check_preset_files
# -----------------------------------------------------------------------


class TestCheckPresetFiles:
    """Contract: check_preset_files verifies that the 4 built-in preset
    TOML files exist under config/presets/ in plsec_home.

    Why tested directly: This function implements health checks I-12
    through I-15 for preset configuration files. Fix by updating the
    corresponding PLSEC_EXPECTED_PRESETS list in health.py.
    """

    def test_all_present(self, tmp_path: Path):
        """All preset files exist -- all results should be ok."""
        home = tmp_path / "plsec"
        for rel_path, _ in PLSEC_EXPECTED_PRESETS:
            full = home / rel_path
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text("[layers.static]\nenabled = true\n")
        results = check_preset_files(home)
        assert len(results) == len(PLSEC_EXPECTED_PRESETS)
        assert all(r.verdict == "ok" for r in results)

    def test_all_missing(self, tmp_path: Path):
        """No preset files -- all results should be warn."""
        home = tmp_path / "plsec"
        home.mkdir()
        results = check_preset_files(home)
        assert len(results) == len(PLSEC_EXPECTED_PRESETS)
        assert all(r.verdict == "warn" for r in results)

    def test_fix_hint_references_install(self, tmp_path: Path):
        """Fix hints should direct to plsec install --force."""
        home = tmp_path / "plsec"
        home.mkdir()
        results = check_preset_files(home)
        for r in results:
            assert "plsec install" in r.fix_hint

    def test_check_ids_start_at_i12(self, tmp_path: Path):
        """Check IDs should start at I-12."""
        home = tmp_path / "plsec"
        home.mkdir()
        results = check_preset_files(home)
        assert results[0].id == "I-12"

    def test_partial_files(self, tmp_path: Path):
        """Some presets present, others missing -- mixed verdicts."""
        home = tmp_path / "plsec"
        preset_dir = home / "configs" / "presets"
        preset_dir.mkdir(parents=True)
        (preset_dir / "balanced.toml").write_text("[layers.static]\nenabled = true\n")
        results = check_preset_files(home)
        verdicts = [r.verdict for r in results]
        assert "ok" in verdicts
        assert "warn" in verdicts

    def test_expected_presets_constant(self):
        """PLSEC_EXPECTED_PRESETS should contain all four preset files."""
        names = [name for name, _ in PLSEC_EXPECTED_PRESETS]
        assert "configs/presets/minimal.toml" in names
        assert "configs/presets/balanced.toml" in names
        assert "configs/presets/strict.toml" in names
        assert "configs/presets/paranoid.toml" in names


# -----------------------------------------------------------------------
# check_agent_compatibility
# -----------------------------------------------------------------------


def _make_compat_result(
    agent_id: str = "test-agent",
    verdict: str = "ok",
    detail: str = "all good",
    *,
    binary_version: str | None = None,
    data_version: str | None = None,
) -> CompatResult:
    """Build a CompatResult for testing."""
    return CompatResult(
        agent_id=agent_id,
        probe=VersionProbe(
            agent_id=agent_id,
            binary_version=binary_version,
            data_version=data_version,
            data_dir_exists=data_version is not None,
            binary_found=binary_version is not None,
        ),
        verdict=verdict,
        detail=detail,
        effective_version=data_version or binary_version,
    )


class TestCheckAgentCompatibility:
    """Contract: check_agent_compatibility translates CompatResult objects
    into CheckResult objects for doctor display.

    Why tested directly: This function implements doctor checks D-1, D-2,
    and D-drift.  It bridges the compatibility module and the doctor
    rendering pipeline.  Fix by updating the mapping in health.py.
    """

    def test_ok_verdict_maps_to_ok(self):
        """CompatResult with ok verdict -> CheckResult with ok verdict."""
        cr = _make_compat_result(verdict="ok", detail="1.2.15 (validated 2026-03-01)")
        results = check_agent_compatibility([cr])
        assert len(results) == 1
        assert results[0].verdict == "ok"
        assert results[0].id == "D-1"
        assert "compatibility" in results[0].name

    def test_warn_verdict_maps_to_warn(self):
        cr = _make_compat_result(verdict="warn", detail="1.3.0 untested")
        results = check_agent_compatibility([cr])
        assert len(results) == 1
        assert results[0].verdict == "warn"
        assert results[0].fix_hint  # should have a fix hint

    def test_fail_verdict_maps_to_fail(self):
        cr = _make_compat_result(verdict="fail", detail="0.9.0 below minimum 1.0.0")
        results = check_agent_compatibility([cr])
        assert len(results) == 1
        assert results[0].verdict == "fail"
        assert results[0].fix_hint  # should have a fix hint

    def test_skip_verdict_maps_to_skip(self):
        cr = _make_compat_result(verdict="skip", detail="not installed")
        results = check_agent_compatibility([cr])
        assert len(results) == 1
        assert results[0].verdict == "skip"

    def test_sequential_check_ids(self):
        """Multiple agents should get sequential D-1, D-2 IDs."""
        crs = [
            _make_compat_result(agent_id="opencode", verdict="ok"),
            _make_compat_result(agent_id="claude-code", verdict="ok"),
        ]
        results = check_agent_compatibility(crs)
        # Filter out drift results
        d_results = [r for r in results if r.id.startswith("D-") and r.id != "D-drift"]
        assert d_results[0].id == "D-1"
        assert d_results[1].id == "D-2"

    def test_drift_produces_extra_result(self):
        """Binary != data version should produce a D-drift warning."""
        cr = _make_compat_result(
            verdict="ok",
            detail="1.2.15 (validated)",
            binary_version="1.2.10",
            data_version="1.2.15",
        )
        results = check_agent_compatibility([cr])
        drift_results = [r for r in results if r.id == "D-drift"]
        assert len(drift_results) == 1
        assert drift_results[0].verdict == "warn"
        assert "1.2.10" in drift_results[0].detail
        assert "1.2.15" in drift_results[0].detail

    def test_no_drift_when_versions_match(self):
        """Same binary and data version should not produce D-drift."""
        cr = _make_compat_result(
            verdict="ok",
            binary_version="1.2.15",
            data_version="1.2.15",
        )
        results = check_agent_compatibility([cr])
        drift_results = [r for r in results if r.id == "D-drift"]
        assert len(drift_results) == 0

    def test_no_drift_when_no_binary(self):
        """No binary version -> no drift check."""
        cr = _make_compat_result(
            verdict="ok",
            data_version="1.2.15",
        )
        results = check_agent_compatibility([cr])
        drift_results = [r for r in results if r.id == "D-drift"]
        assert len(drift_results) == 0

    def test_no_drift_when_no_data_version(self):
        """No data version -> no drift check."""
        cr = _make_compat_result(
            verdict="warn",
            binary_version="1.2.15",
        )
        results = check_agent_compatibility([cr])
        drift_results = [r for r in results if r.id == "D-drift"]
        assert len(drift_results) == 0

    def test_empty_input(self):
        """Empty compat results -> empty check results."""
        results = check_agent_compatibility([])
        assert results == []

    def test_agent_id_in_check_name(self):
        """Agent ID should appear in the check name."""
        cr = _make_compat_result(agent_id="opencode", verdict="ok")
        results = check_agent_compatibility([cr])
        assert "opencode" in results[0].name

    def test_detail_preserved(self):
        """Detail from CompatResult should be preserved in CheckResult."""
        detail = "1.2.15 (validated 2026-03-01)"
        cr = _make_compat_result(verdict="ok", detail=detail)
        results = check_agent_compatibility([cr])
        assert results[0].detail == detail

    def test_category_is_installation(self):
        """All results should be in the installation category."""
        crs = [
            _make_compat_result(verdict="ok"),
            _make_compat_result(verdict="warn"),
            _make_compat_result(verdict="fail"),
            _make_compat_result(verdict="skip"),
        ]
        results = check_agent_compatibility(crs)
        assert all(r.category == "installation" for r in results)
