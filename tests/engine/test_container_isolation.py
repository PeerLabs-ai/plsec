"""Tests for plsec.engine.container_isolation -- container isolation check.

Covers the ContainerIsolationEngine: identity properties, availability
check, execute() logic for missing runtime / unresponsive runtime /
missing container config, and the _runtime_accessible helper.

Contract: This engine checks whether a security *control* is in place.
It doesn't scan artifacts for vulnerabilities. "No findings" means
the control is present. A finding of category MISSING_CONTROL means
the control is absent.
"""

from pathlib import Path
from unittest.mock import patch

from plsec.engine.base import Engine
from plsec.engine.container_isolation import ContainerIsolationEngine
from plsec.engine.types import (
    AvailabilityResult,
    EngineStatus,
    EnvironmentInfo,
    FindingCategory,
    Layer,
    Preset,
    ScanContext,
    Severity,
)

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _make_env(
    container_runtime: str | None = "podman",
    available_tools: frozenset[str] | None = None,
) -> EnvironmentInfo:
    return EnvironmentInfo(
        os_name="darwin",
        os_version="24.0.0",
        python_version="3.12.0",
        container_runtime=container_runtime,
        available_tools=available_tools or frozenset(),
    )


def _make_ctx(
    container_runtime: str | None = "podman",
    target_path: Path | None = None,
    preset: Preset = Preset.STRICT,
    container_files: list[str] | None = None,
) -> ScanContext:
    """Create a ScanContext.

    If container_files is provided, creates a tmp_path-like directory
    with those files. Otherwise uses the provided target_path.
    """
    tp = target_path or Path("/fake/project")
    return ScanContext(
        target_path=tp,
        preset=preset,
        environment=_make_env(container_runtime=container_runtime),
    )


# -----------------------------------------------------------------------
# Identity properties
# -----------------------------------------------------------------------


class TestContainerIsolationEngineIdentity:
    """Contract: Engine identity properties are correct."""

    def test_is_engine_subclass(self):
        assert issubclass(ContainerIsolationEngine, Engine)

    def test_engine_id(self):
        e = ContainerIsolationEngine()
        assert e.engine_id == "container-isolation"

    def test_layer(self):
        e = ContainerIsolationEngine()
        assert e.layer == Layer.ISOLATION

    def test_display_name(self):
        e = ContainerIsolationEngine()
        assert e.display_name == "Container Isolation Check"

    def test_presets(self):
        e = ContainerIsolationEngine()
        assert e.presets == frozenset({Preset.STRICT, Preset.PARANOID})

    def test_not_in_minimal_preset(self):
        e = ContainerIsolationEngine()
        assert Preset.MINIMAL not in e.presets

    def test_not_in_balanced_preset(self):
        e = ContainerIsolationEngine()
        assert Preset.BALANCED not in e.presets

    def test_dependencies_empty(self):
        """No hard dependencies -- the engine reports gaps, doesn't require tools."""
        e = ContainerIsolationEngine()
        assert e.dependencies == []

    def test_repr(self):
        e = ContainerIsolationEngine()
        r = repr(e)
        assert "ContainerIsolationEngine" in r
        assert "container-isolation" in r


# -----------------------------------------------------------------------
# check_available
# -----------------------------------------------------------------------


class TestContainerIsolationCheckAvailable:
    """Contract: This engine is always available -- it checks for controls,
    it doesn't require external tools."""

    def test_always_available(self):
        e = ContainerIsolationEngine()
        ctx = _make_ctx()
        result = e.check_available(ctx)
        assert isinstance(result, AvailabilityResult)
        assert result.status == EngineStatus.AVAILABLE

    def test_available_even_without_runtime(self):
        e = ContainerIsolationEngine()
        ctx = _make_ctx(container_runtime=None)
        result = e.check_available(ctx)
        assert result.status == EngineStatus.AVAILABLE


# -----------------------------------------------------------------------
# execute — no container runtime
# -----------------------------------------------------------------------


class TestContainerIsolationNoRuntime:
    """Contract: When no container runtime is detected, the engine
    produces a HIGH MISSING_CONTROL finding and returns immediately."""

    def test_no_runtime_produces_finding(self):
        e = ContainerIsolationEngine()
        ctx = _make_ctx(container_runtime=None)
        findings = e.execute(ctx)
        assert len(findings) == 1

    def test_no_runtime_finding_properties(self):
        e = ContainerIsolationEngine()
        ctx = _make_ctx(container_runtime=None)
        f = e.execute(ctx)[0]
        assert f.engine_id == "container-isolation"
        assert f.layer == Layer.ISOLATION
        assert f.severity == Severity.HIGH
        assert f.category == FindingCategory.MISSING_CONTROL
        assert "no container runtime" in f.title.lower()
        assert f.remediation is not None

    def test_no_runtime_returns_early(self):
        """When no runtime, only the missing-runtime finding is returned.
        No accessibility or config checks run."""
        e = ContainerIsolationEngine()
        ctx = _make_ctx(container_runtime=None)
        findings = e.execute(ctx)
        # Only 1 finding (the missing runtime), not 2+ (missing runtime + missing config)
        assert len(findings) == 1


# -----------------------------------------------------------------------
# execute — runtime not accessible
# -----------------------------------------------------------------------


class TestContainerIsolationRuntimeNotAccessible:
    """Contract: When a runtime is installed but not responsive,
    the engine produces a MEDIUM MISSING_CONTROL finding."""

    @patch.object(ContainerIsolationEngine, "_runtime_accessible", return_value=False)
    def test_unresponsive_runtime_produces_finding(self, _mock):
        e = ContainerIsolationEngine()
        ctx = _make_ctx(container_runtime="podman")
        findings = e.execute(ctx)
        unresponsive = [f for f in findings if "not responsive" in f.title]
        assert len(unresponsive) == 1

    @patch.object(ContainerIsolationEngine, "_runtime_accessible", return_value=False)
    def test_unresponsive_runtime_finding_properties(self, _mock):
        e = ContainerIsolationEngine()
        ctx = _make_ctx(container_runtime="podman")
        f = [f for f in e.execute(ctx) if "not responsive" in f.title][0]
        assert f.severity == Severity.MEDIUM
        assert f.category == FindingCategory.MISSING_CONTROL
        assert "podman" in f.title.lower()
        assert f.remediation is not None
        assert "podman" in f.remediation

    @patch.object(ContainerIsolationEngine, "_runtime_accessible", return_value=False)
    def test_unresponsive_docker_runtime(self, _mock):
        e = ContainerIsolationEngine()
        ctx = _make_ctx(container_runtime="docker")
        f = [f for f in e.execute(ctx) if "not responsive" in f.title][0]
        assert "docker" in f.title.lower()
        assert "docker" in f.remediation


# -----------------------------------------------------------------------
# execute — runtime accessible, no container config
# -----------------------------------------------------------------------


class TestContainerIsolationNoConfig:
    """Contract: When a runtime is accessible but the project has no
    container configuration files, the engine produces a LOW MISCONFIG
    finding."""

    @patch.object(ContainerIsolationEngine, "_runtime_accessible", return_value=True)
    def test_no_config_produces_finding(self, _mock, tmp_path):
        e = ContainerIsolationEngine()
        ctx = _make_ctx(container_runtime="podman", target_path=tmp_path)
        findings = e.execute(ctx)
        assert len(findings) == 1

    @patch.object(ContainerIsolationEngine, "_runtime_accessible", return_value=True)
    def test_no_config_finding_properties(self, _mock, tmp_path):
        e = ContainerIsolationEngine()
        ctx = _make_ctx(container_runtime="podman", target_path=tmp_path)
        f = e.execute(ctx)[0]
        assert f.severity == Severity.LOW
        assert f.category == FindingCategory.MISCONFIG
        assert "no container configuration" in f.title.lower()

    @patch.object(ContainerIsolationEngine, "_runtime_accessible", return_value=True)
    def test_dockerfile_present(self, _mock, tmp_path):
        (tmp_path / "Dockerfile").touch()
        e = ContainerIsolationEngine()
        ctx = _make_ctx(container_runtime="podman", target_path=tmp_path)
        findings = e.execute(ctx)
        assert len(findings) == 0

    @patch.object(ContainerIsolationEngine, "_runtime_accessible", return_value=True)
    def test_containerfile_present(self, _mock, tmp_path):
        (tmp_path / "Containerfile").touch()
        e = ContainerIsolationEngine()
        ctx = _make_ctx(container_runtime="podman", target_path=tmp_path)
        findings = e.execute(ctx)
        assert len(findings) == 0

    @patch.object(ContainerIsolationEngine, "_runtime_accessible", return_value=True)
    def test_compose_yaml_present(self, _mock, tmp_path):
        (tmp_path / "compose.yaml").touch()
        e = ContainerIsolationEngine()
        ctx = _make_ctx(container_runtime="podman", target_path=tmp_path)
        findings = e.execute(ctx)
        assert len(findings) == 0

    @patch.object(ContainerIsolationEngine, "_runtime_accessible", return_value=True)
    def test_compose_yml_present(self, _mock, tmp_path):
        (tmp_path / "compose.yml").touch()
        e = ContainerIsolationEngine()
        ctx = _make_ctx(container_runtime="podman", target_path=tmp_path)
        findings = e.execute(ctx)
        assert len(findings) == 0

    @patch.object(ContainerIsolationEngine, "_runtime_accessible", return_value=True)
    def test_docker_compose_yaml_present(self, _mock, tmp_path):
        (tmp_path / "docker-compose.yaml").touch()
        e = ContainerIsolationEngine()
        ctx = _make_ctx(container_runtime="podman", target_path=tmp_path)
        findings = e.execute(ctx)
        assert len(findings) == 0

    @patch.object(ContainerIsolationEngine, "_runtime_accessible", return_value=True)
    def test_docker_compose_yml_present(self, _mock, tmp_path):
        (tmp_path / "docker-compose.yml").touch()
        e = ContainerIsolationEngine()
        ctx = _make_ctx(container_runtime="podman", target_path=tmp_path)
        findings = e.execute(ctx)
        assert len(findings) == 0


# -----------------------------------------------------------------------
# execute — fully configured (clean result)
# -----------------------------------------------------------------------


class TestContainerIsolationClean:
    """Contract: When runtime is accessible and config exists, no findings."""

    @patch.object(ContainerIsolationEngine, "_runtime_accessible", return_value=True)
    def test_clean_result(self, _mock, tmp_path):
        (tmp_path / "Containerfile").touch()
        e = ContainerIsolationEngine()
        ctx = _make_ctx(container_runtime="podman", target_path=tmp_path)
        findings = e.execute(ctx)
        assert findings == []


# -----------------------------------------------------------------------
# execute — unresponsive runtime + no config (compound)
# -----------------------------------------------------------------------


class TestContainerIsolationCompound:
    """Contract: Multiple issues can be reported simultaneously."""

    @patch.object(ContainerIsolationEngine, "_runtime_accessible", return_value=False)
    def test_unresponsive_and_no_config(self, _mock, tmp_path):
        """Both unresponsive runtime and missing config produce findings."""
        e = ContainerIsolationEngine()
        ctx = _make_ctx(container_runtime="podman", target_path=tmp_path)
        findings = e.execute(ctx)
        assert len(findings) == 2
        categories = {f.category for f in findings}
        assert FindingCategory.MISSING_CONTROL in categories
        assert FindingCategory.MISCONFIG in categories


# -----------------------------------------------------------------------
# _runtime_accessible
# -----------------------------------------------------------------------


class TestRuntimeAccessible:
    """Contract: _runtime_accessible returns True if the runtime
    responds to 'info' command, False otherwise."""

    @patch("plsec.engine.container_isolation.subprocess.run")
    def test_accessible_returns_true(self, mock_run):
        mock_run.return_value.returncode = 0
        assert ContainerIsolationEngine._runtime_accessible("podman") is True
        mock_run.assert_called_once_with(
            ["podman", "info"],
            capture_output=True,
            timeout=10,
        )

    @patch("plsec.engine.container_isolation.subprocess.run")
    def test_nonzero_exit_returns_false(self, mock_run):
        mock_run.return_value.returncode = 1
        assert ContainerIsolationEngine._runtime_accessible("docker") is False

    @patch("plsec.engine.container_isolation.subprocess.run")
    def test_timeout_returns_false(self, mock_run):
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker info", timeout=10)
        assert ContainerIsolationEngine._runtime_accessible("docker") is False

    @patch("plsec.engine.container_isolation.subprocess.run")
    def test_os_error_returns_false(self, mock_run):
        mock_run.side_effect = OSError("No such file")
        assert ContainerIsolationEngine._runtime_accessible("podman") is False

    @patch("plsec.engine.container_isolation.subprocess.run")
    def test_docker_runtime(self, mock_run):
        """Verifies the correct runtime name is used in the command."""
        mock_run.return_value.returncode = 0
        ContainerIsolationEngine._runtime_accessible("docker")
        mock_run.assert_called_once_with(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
