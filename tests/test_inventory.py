"""Tests for plsec.core.inventory -- artifact discovery model."""

from pathlib import Path

from plsec.core.agents import AgentSpec
from plsec.core.inventory import (
    Artifact,
    Inventory,
    _file_size,
    _matches_plsec_template,
    discover_all,
    discover_external_artifacts,
    discover_global_artifacts,
    discover_project_artifacts,
    format_size,
)

# ---------------------------------------------------------------------------
# Artifact dataclass
# ---------------------------------------------------------------------------


class TestArtifact:
    """Verify Artifact dataclass defaults and construction."""

    def test_required_fields(self, tmp_path: Path):
        a = Artifact(path=tmp_path, category="global_config", description="test")
        assert a.path == tmp_path
        assert a.category == "global_config"
        assert a.description == "test"

    def test_defaults(self, tmp_path: Path):
        a = Artifact(path=tmp_path, category="global_config", description="test")
        assert a.size_bytes == 0
        assert a.removable is True
        assert a.matches_template is True

    def test_custom_values(self, tmp_path: Path):
        a = Artifact(
            path=tmp_path,
            category="project_config",
            description="custom",
            size_bytes=1024,
            removable=False,
            matches_template=False,
        )
        assert a.size_bytes == 1024
        assert a.removable is False
        assert a.matches_template is False


# ---------------------------------------------------------------------------
# Inventory dataclass
# ---------------------------------------------------------------------------


class TestInventory:
    """Verify Inventory properties and filtering."""

    def _make_artifact(self, tmp_path: Path, category: str, size: int = 100) -> Artifact:
        return Artifact(
            path=tmp_path / category,
            category=category,  # type: ignore[arg-type]
            description=category,
            size_bytes=size,
        )

    def test_empty_inventory(self):
        inv = Inventory()
        assert inv.artifacts == []
        assert inv.global_artifacts == []
        assert inv.project_artifacts == []
        assert inv.total_size == 0

    def test_global_artifacts_filter(self, tmp_path: Path):
        inv = Inventory(
            artifacts=[
                self._make_artifact(tmp_path, "global_config"),
                self._make_artifact(tmp_path, "global_log"),
                self._make_artifact(tmp_path, "global_runtime"),
                self._make_artifact(tmp_path, "global_directory"),
                self._make_artifact(tmp_path, "external_config"),
                self._make_artifact(tmp_path, "project_config"),
            ]
        )
        global_cats = {a.category for a in inv.global_artifacts}
        assert "global_config" in global_cats
        assert "global_log" in global_cats
        assert "global_runtime" in global_cats
        assert "global_directory" in global_cats
        assert "external_config" in global_cats
        assert "project_config" not in global_cats

    def test_project_artifacts_filter(self, tmp_path: Path):
        inv = Inventory(
            artifacts=[
                self._make_artifact(tmp_path, "global_config"),
                self._make_artifact(tmp_path, "project_config"),
                self._make_artifact(tmp_path, "project_manifest"),
            ]
        )
        project_cats = {a.category for a in inv.project_artifacts}
        assert "project_config" in project_cats
        assert "project_manifest" in project_cats
        assert "global_config" not in project_cats

    def test_total_size(self, tmp_path: Path):
        inv = Inventory(
            artifacts=[
                self._make_artifact(tmp_path, "global_config", 100),
                self._make_artifact(tmp_path, "project_config", 200),
            ]
        )
        assert inv.total_size == 300

    def test_global_size(self, tmp_path: Path):
        inv = Inventory(
            artifacts=[
                self._make_artifact(tmp_path, "global_config", 100),
                self._make_artifact(tmp_path, "external_config", 50),
                self._make_artifact(tmp_path, "project_config", 200),
            ]
        )
        assert inv.global_size == 150

    def test_project_size(self, tmp_path: Path):
        inv = Inventory(
            artifacts=[
                self._make_artifact(tmp_path, "global_config", 100),
                self._make_artifact(tmp_path, "project_config", 200),
                self._make_artifact(tmp_path, "project_manifest", 50),
            ]
        )
        assert inv.project_size == 250


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestFormatSize:
    """Verify human-readable size formatting."""

    def test_zero_bytes(self):
        assert format_size(0) == "0 B"

    def test_small_bytes(self):
        assert format_size(512) == "512 B"

    def test_one_kb(self):
        assert format_size(1024) == "1.0 KB"

    def test_fractional_kb(self):
        assert format_size(1536) == "1.5 KB"

    def test_one_mb(self):
        assert format_size(1024 * 1024) == "1.0 MB"

    def test_fractional_mb(self):
        assert format_size(int(2.5 * 1024 * 1024)) == "2.5 MB"

    def test_boundary_below_kb(self):
        assert format_size(1023) == "1023 B"

    def test_boundary_below_mb(self):
        result = format_size(1024 * 1024 - 1)
        assert "KB" in result


class TestFileSize:
    """Verify _file_size helper."""

    def test_existing_file(self, tmp_path: Path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        assert _file_size(f) == 5

    def test_missing_file(self, tmp_path: Path):
        assert _file_size(tmp_path / "nonexistent") == 0

    def test_directory(self, tmp_path: Path):
        assert _file_size(tmp_path) == 0


class TestMatchesPlsecTemplate:
    """Verify template matching heuristic."""

    def test_matches_plsec_marker(self, tmp_path: Path):
        f = tmp_path / "CLAUDE.md"
        f.write_text("# Security constraints\n## plsec generated\nNEVER do bad things")
        assert _matches_plsec_template(f) is True

    def test_no_match(self, tmp_path: Path):
        f = tmp_path / "CLAUDE.md"
        f.write_text("# My custom instructions\nDo whatever you want")
        assert _matches_plsec_template(f) is False

    def test_missing_file(self, tmp_path: Path):
        assert _matches_plsec_template(tmp_path / "nonexistent") is False

    def test_case_insensitive(self, tmp_path: Path):
        f = tmp_path / "config.md"
        f.write_text("PLSEC configuration")
        assert _matches_plsec_template(f) is True


# ---------------------------------------------------------------------------
# Discovery functions
# ---------------------------------------------------------------------------


class TestDiscoverGlobalArtifacts:
    """Verify global artifact discovery under plsec home."""

    def test_empty_when_missing(self, tmp_path: Path):
        result = discover_global_artifacts(tmp_path / "nonexistent")
        assert result == []

    def test_discovers_config_files(self, tmp_path: Path):
        configs = tmp_path / "configs"
        configs.mkdir()
        (configs / "CLAUDE.md").write_text("test")
        (configs / "opencode.json").write_text("{}")

        result = discover_global_artifacts(tmp_path)
        paths = {a.path for a in result}
        assert configs / "CLAUDE.md" in paths
        assert configs / "opencode.json" in paths

    def test_classifies_log_files(self, tmp_path: Path):
        logs = tmp_path / "logs"
        logs.mkdir()
        (logs / "pipelock.log").write_text("log data")

        result = discover_global_artifacts(tmp_path)
        log_artifacts = [a for a in result if a.category == "global_log"]
        assert len(log_artifacts) == 1
        assert log_artifacts[0].description == "logs/pipelock.log"

    def test_classifies_pid_files(self, tmp_path: Path):
        (tmp_path / "pipelock.pid").write_text("12345")

        result = discover_global_artifacts(tmp_path)
        runtime = [a for a in result if a.category == "global_runtime"]
        assert any(a.description == "pipelock.pid" for a in runtime)

    def test_classifies_directories(self, tmp_path: Path):
        (tmp_path / "trivy").mkdir()

        result = discover_global_artifacts(tmp_path)
        dirs = [a for a in result if a.category == "global_directory"]
        assert len(dirs) == 1
        assert dirs[0].description == "trivy/"

    def test_measures_file_size(self, tmp_path: Path):
        content = "x" * 256
        (tmp_path / "test.yaml").write_text(content)

        result = discover_global_artifacts(tmp_path)
        file_artifacts = [a for a in result if a.path.name == "test.yaml"]
        assert file_artifacts[0].size_bytes == 256

    def test_classifies_installed_json(self, tmp_path: Path):
        (tmp_path / ".installed.json").write_text("{}")

        result = discover_global_artifacts(tmp_path)
        runtime = [a for a in result if a.category == "global_runtime"]
        assert any(a.description == ".installed.json" for a in runtime)


class TestDiscoverExternalArtifacts:
    """Verify discovery of agent configs in native locations."""

    def test_finds_existing_config(self, tmp_path: Path):
        config_dir = tmp_path / ".config" / "testagent"
        config_dir.mkdir(parents=True)
        (config_dir / "agent.json").write_text('{"plsec": true}')

        agents = {
            "test": AgentSpec(
                id="test",
                display_name="Test Agent",
                config_filename="agent.json",
                templates={"balanced": "{}"},
                config_type="test",
                global_config_dir=config_dir,
            )
        }
        result = discover_external_artifacts(agents)
        assert len(result) == 1
        assert result[0].category == "external_config"

    def test_skips_missing_config(self, tmp_path: Path):
        agents = {
            "test": AgentSpec(
                id="test",
                display_name="Test Agent",
                config_filename="agent.json",
                templates={"balanced": "{}"},
                config_type="test",
                global_config_dir=tmp_path / "nonexistent",
            )
        }
        result = discover_external_artifacts(agents)
        assert result == []

    def test_skips_agents_without_global_dir(self):
        agents = {
            "test": AgentSpec(
                id="test",
                display_name="Test Agent",
                config_filename="agent.json",
                templates={"balanced": "{}"},
                config_type="test",
                global_config_dir=None,
            )
        }
        result = discover_external_artifacts(agents)
        assert result == []

    def test_checks_template_match(self, tmp_path: Path):
        config_dir = tmp_path / ".config" / "testagent"
        config_dir.mkdir(parents=True)
        (config_dir / "agent.json").write_text("custom content, user wrote this")

        agents = {
            "test": AgentSpec(
                id="test",
                display_name="Test Agent",
                config_filename="agent.json",
                templates={"balanced": "{}"},
                config_type="test",
                global_config_dir=config_dir,
            )
        }
        result = discover_external_artifacts(agents)
        assert result[0].matches_template is False


class TestDiscoverProjectArtifacts:
    """Verify discovery of plsec files in a project directory."""

    def test_finds_agent_configs(self, tmp_path: Path):
        (tmp_path / "CLAUDE.md").write_text("# plsec security\nNEVER")
        (tmp_path / "opencode.json").write_text('{"$schema": "plsec"}')

        result = discover_project_artifacts(tmp_path)
        filenames = {a.path.name for a in result}
        assert "CLAUDE.md" in filenames
        assert "opencode.json" in filenames

    def test_finds_plsec_yaml(self, tmp_path: Path):
        (tmp_path / "plsec.yaml").write_text("project:\n  name: test")

        result = discover_project_artifacts(tmp_path)
        assert any(a.path.name == "plsec.yaml" for a in result)

    def test_finds_manifest(self, tmp_path: Path):
        (tmp_path / ".plsec-manifest.json").write_text("{}")

        result = discover_project_artifacts(tmp_path)
        manifests = [a for a in result if a.category == "project_manifest"]
        assert len(manifests) == 1

    def test_empty_project(self, tmp_path: Path):
        result = discover_project_artifacts(tmp_path)
        assert result == []

    def test_template_matching_on_agent_configs(self, tmp_path: Path):
        (tmp_path / "CLAUDE.md").write_text("custom content, user wrote this")

        result = discover_project_artifacts(tmp_path)
        claude = [a for a in result if a.path.name == "CLAUDE.md"]
        assert claude[0].matches_template is False


class TestDiscoverAll:
    """Verify full inventory discovery."""

    def test_combines_all_sources(self, tmp_path: Path):
        plsec_home = tmp_path / "home"
        project_dir = tmp_path / "project"
        plsec_home.mkdir()
        project_dir.mkdir()

        (plsec_home / "configs").mkdir()
        (plsec_home / "configs" / "CLAUDE.md").write_text("plsec test")
        (project_dir / "plsec.yaml").write_text("project:\n  name: test")

        agents = {
            "test": AgentSpec(
                id="test",
                display_name="Test Agent",
                config_filename="CLAUDE.md",
                templates={"balanced": "plsec test"},
                config_type="test",
                global_config_dir=None,
            )
        }
        inv = discover_all(plsec_home, project_dir, agents)
        assert len(inv.artifacts) > 0
        assert len(inv.global_artifacts) > 0
        assert len(inv.project_artifacts) > 0

    def test_empty_system(self, tmp_path: Path):
        inv = discover_all(
            tmp_path / "nonexistent_home",
            tmp_path / "nonexistent_project",
            {},
        )
        assert inv.artifacts == []
        assert inv.total_size == 0
