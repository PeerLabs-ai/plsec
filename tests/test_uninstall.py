"""Tests for plsec uninstall command (commands/uninstall.py).

Covers:
- Artifact removal logic (_remove_artifacts, _remove_global_root)
- Scope selection (--global, --project, --all, interactive)
- Dry-run mode (no changes)
- Cancellation (exit code 2)
- Nothing-to-remove scenario
- Customised file warnings

All tests use tmp_path for isolation and mock get_plsec_home() and
Path.cwd() to avoid side effects.
"""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from plsec.commands.install import deploy_global_configs
from plsec.commands.uninstall import (
    _remove_artifacts,
    _remove_global_root,
    app,
)
from plsec.core.agents import AGENTS, AgentSpec
from plsec.core.inventory import Artifact

runner = CliRunner()

# Fake agents with no global_config_dir to avoid discovering real files
# on the developer's system during tests.
_TEST_AGENTS: dict[str, AgentSpec] = {
    aid: AgentSpec(
        id=spec.id,
        display_name=spec.display_name,
        config_filename=spec.config_filename,
        templates=spec.templates,
        config_type=spec.config_type,
        validate=spec.validate,
        global_config_dir=None,  # Override to avoid real filesystem
        wrapper_template=spec.wrapper_template,
    )
    for aid, spec in AGENTS.items()
}


# -----------------------------------------------------------------------
# _remove_artifacts
# -----------------------------------------------------------------------


class TestRemoveArtifacts:
    """Contract: _remove_artifacts deletes files and directories,
    returning (removed_count, error_count)."""

    def test_removes_files(self, tmp_path: Path):
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_text("aaa")
        f2.write_text("bbb")
        artifacts = [
            Artifact(path=f1, category="global_config", description="a"),
            Artifact(path=f2, category="global_config", description="b"),
        ]
        removed, errors = _remove_artifacts(artifacts)
        assert removed == 2
        assert errors == 0
        assert not f1.exists()
        assert not f2.exists()

    def test_removes_directories(self, tmp_path: Path):
        d = tmp_path / "subdir"
        d.mkdir()
        (d / "file.txt").write_text("content")
        artifacts = [
            Artifact(path=d, category="global_directory", description="subdir/"),
        ]
        removed, errors = _remove_artifacts(artifacts)
        assert removed == 1
        assert not d.exists()

    def test_handles_missing_gracefully(self, tmp_path: Path):
        gone = tmp_path / "gone.txt"
        artifacts = [
            Artifact(path=gone, category="global_config", description="gone"),
        ]
        removed, errors = _remove_artifacts(artifacts)
        # Missing files should not count as removed or errors
        assert removed == 0
        assert errors == 0

    def test_returns_zero_for_empty_list(self):
        removed, errors = _remove_artifacts([])
        assert removed == 0
        assert errors == 0


# -----------------------------------------------------------------------
# _remove_global_root
# -----------------------------------------------------------------------


class TestRemoveGlobalRoot:
    """Contract: _remove_global_root removes plsec_home and its parent
    if both are empty after artifact removal."""

    def test_removes_empty_root(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        plsec_home.mkdir(parents=True)
        _remove_global_root(plsec_home)
        assert not plsec_home.exists()
        # .peerlabs should also be removed since it's empty
        assert not plsec_home.parent.exists()

    def test_preserves_nonempty_root(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        plsec_home.mkdir(parents=True)
        (plsec_home / "leftover.txt").write_text("x")
        _remove_global_root(plsec_home)
        # Should NOT be removed because it has contents
        assert plsec_home.exists()

    def test_preserves_nonempty_parent(self, tmp_path: Path):
        peerlabs = tmp_path / ".peerlabs"
        plsec_home = peerlabs / "plsec"
        plsec_home.mkdir(parents=True)
        (peerlabs / "other_tool").mkdir()
        _remove_global_root(plsec_home)
        # plsec_home removed, but .peerlabs kept because other_tool exists
        assert not plsec_home.exists()
        assert peerlabs.exists()

    def test_noop_for_nonexistent(self, tmp_path: Path):
        plsec_home = tmp_path / "does_not_exist"
        _remove_global_root(plsec_home)  # should not raise


# -----------------------------------------------------------------------
# plsec uninstall CLI command
# -----------------------------------------------------------------------


def _setup_full_install(tmp_path: Path) -> tuple[Path, Path]:
    """Deploy a full install and create project-local files.

    Returns (plsec_home, project_dir).
    Uses _TEST_AGENTS to avoid touching real global_config_dir paths.
    """
    plsec_home = tmp_path / ".peerlabs" / "plsec"
    deploy_global_configs(plsec_home, agents=_TEST_AGENTS)

    project_dir = tmp_path / "myproject"
    project_dir.mkdir()
    # Create project-local files that look like plsec templates
    (project_dir / "CLAUDE.md").write_text("# plsec security config\n## NEVER\n## ALWAYS\n")
    (project_dir / "plsec.yaml").write_text("# plsec configuration\nproject:\n  name: test\n")

    return plsec_home, project_dir


def _patch_agents():
    """Patch AGENTS in the uninstall module to use test agents."""
    return patch("plsec.commands.uninstall.AGENTS", _TEST_AGENTS)


class TestUninstallCLI:
    """Contract: plsec uninstall discovers and removes artifacts
    based on scope flags and user confirmation."""

    def test_nothing_to_remove(self, tmp_path: Path):
        empty_home = tmp_path / "empty"
        empty_home.mkdir()
        project_dir = tmp_path / "proj"
        project_dir.mkdir()
        with (
            patch("plsec.commands.uninstall.get_plsec_home", return_value=empty_home),
            patch("plsec.commands.uninstall.Path.cwd", return_value=project_dir),
            _patch_agents(),
        ):
            result = runner.invoke(app, [])
        assert result.exit_code == 0
        assert "Nothing to remove" in result.output or "none found" in result.output.lower()

    def test_global_flag_removes_global(self, tmp_path: Path):
        plsec_home, project_dir = _setup_full_install(tmp_path)
        with (
            patch("plsec.commands.uninstall.get_plsec_home", return_value=plsec_home),
            patch("plsec.commands.uninstall.Path.cwd", return_value=project_dir),
            _patch_agents(),
        ):
            result = runner.invoke(app, ["--global", "--yes"])
        assert result.exit_code == 0
        # Global configs should be gone
        assert not (plsec_home / "trivy" / "trivy.yaml").exists()
        # Project files should still exist
        assert (project_dir / "CLAUDE.md").exists()
        assert (project_dir / "plsec.yaml").exists()

    def test_project_flag_removes_project(self, tmp_path: Path):
        plsec_home, project_dir = _setup_full_install(tmp_path)
        with (
            patch("plsec.commands.uninstall.get_plsec_home", return_value=plsec_home),
            patch("plsec.commands.uninstall.Path.cwd", return_value=project_dir),
            _patch_agents(),
        ):
            result = runner.invoke(app, ["--project", "--yes"])
        assert result.exit_code == 0
        # Project files should be gone
        assert not (project_dir / "CLAUDE.md").exists()
        assert not (project_dir / "plsec.yaml").exists()
        # Global configs should still exist
        assert (plsec_home / "trivy" / "trivy.yaml").exists()

    def test_all_flag_removes_everything(self, tmp_path: Path):
        plsec_home, project_dir = _setup_full_install(tmp_path)
        with (
            patch("plsec.commands.uninstall.get_plsec_home", return_value=plsec_home),
            patch("plsec.commands.uninstall.Path.cwd", return_value=project_dir),
            _patch_agents(),
        ):
            result = runner.invoke(app, ["--all", "--yes"])
        assert result.exit_code == 0
        assert not (plsec_home / "trivy" / "trivy.yaml").exists()
        assert not (project_dir / "CLAUDE.md").exists()

    def test_dry_run_no_changes(self, tmp_path: Path):
        plsec_home, project_dir = _setup_full_install(tmp_path)
        before = {str(p) for p in plsec_home.rglob("*")}

        with (
            patch("plsec.commands.uninstall.get_plsec_home", return_value=plsec_home),
            patch("plsec.commands.uninstall.Path.cwd", return_value=project_dir),
            _patch_agents(),
        ):
            result = runner.invoke(app, ["--dry-run"])
        assert result.exit_code == 0
        assert "Dry run" in result.output

        after = {str(p) for p in plsec_home.rglob("*")}
        assert before == after

    def test_cancel_exits_2(self, tmp_path: Path):
        plsec_home, project_dir = _setup_full_install(tmp_path)
        with (
            patch("plsec.commands.uninstall.get_plsec_home", return_value=plsec_home),
            patch("plsec.commands.uninstall.Path.cwd", return_value=project_dir),
            _patch_agents(),
        ):
            # Answer "n" to the first prompt (remove global?) and "n" to project
            result = runner.invoke(app, [], input="n\nn\n")
        assert result.exit_code == 2

    def test_interactive_remove_global_only(self, tmp_path: Path):
        plsec_home, project_dir = _setup_full_install(tmp_path)
        with (
            patch("plsec.commands.uninstall.get_plsec_home", return_value=plsec_home),
            patch("plsec.commands.uninstall.Path.cwd", return_value=project_dir),
            _patch_agents(),
        ):
            # "y" for global, "n" for project, "y" for final confirm
            result = runner.invoke(app, [], input="y\nn\ny\n")
        assert result.exit_code == 0
        # Global gone, project still there
        assert not (plsec_home / "trivy" / "trivy.yaml").exists()
        assert (project_dir / "CLAUDE.md").exists()

    def test_yes_flag_skips_prompts(self, tmp_path: Path):
        plsec_home, project_dir = _setup_full_install(tmp_path)
        with (
            patch("plsec.commands.uninstall.get_plsec_home", return_value=plsec_home),
            patch("plsec.commands.uninstall.Path.cwd", return_value=project_dir),
            _patch_agents(),
        ):
            result = runner.invoke(app, ["--yes"])
        assert result.exit_code == 0
        # With --yes and no scope flag, interactive mode selects global+external+project
        assert not (plsec_home / "trivy" / "trivy.yaml").exists()
        assert not (project_dir / "CLAUDE.md").exists()

    def test_shows_remainder_report(self, tmp_path: Path):
        plsec_home, project_dir = _setup_full_install(tmp_path)
        with (
            patch("plsec.commands.uninstall.get_plsec_home", return_value=plsec_home),
            patch("plsec.commands.uninstall.Path.cwd", return_value=project_dir),
            _patch_agents(),
        ):
            result = runner.invoke(app, ["--all", "--yes"])
        assert result.exit_code == 0
        assert "pipx uninstall plsec" in result.output

    def test_customised_file_warning(self, tmp_path: Path):
        plsec_home, project_dir = _setup_full_install(tmp_path)
        # Write a file that does NOT contain the plsec marker
        (project_dir / "CLAUDE.md").write_text("# My Custom Config\n## NEVER\n## ALWAYS\n")
        with (
            patch("plsec.commands.uninstall.get_plsec_home", return_value=plsec_home),
            patch("plsec.commands.uninstall.Path.cwd", return_value=project_dir),
            _patch_agents(),
        ):
            result = runner.invoke(app, ["--project", "--yes"])
        assert result.exit_code == 0
        assert "customised" in result.output.lower()
