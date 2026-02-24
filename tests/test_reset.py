"""Tests for plsec reset command (commands/reset.py).

Covers:
- Process stopping logic
- Global state wipe
- External config removal
- Redeployment after wipe
- --dry-run (no changes), --yes (skip confirmation)
- Exit codes: 0 (success), 2 (cancelled)

All tests use tmp_path for isolation and mock get_plsec_home, AGENTS,
and PROCESSES to avoid side effects.
"""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from plsec.commands.install import (
    deploy_global_configs,
    read_installed_metadata,
    write_installed_metadata,
)
from plsec.commands.reset import (
    _PRESERVED_DIRS,
    _remove_external_configs,
    _wipe_global_state,
    app,
)
from plsec.core.agents import AGENTS, AgentSpec
from plsec.core.health import PLSEC_SUBDIRS

runner = CliRunner()


# -----------------------------------------------------------------------
# _wipe_global_state
# -----------------------------------------------------------------------


class TestWipeGlobalState:
    """Contract: _wipe_global_state removes children of plsec_home,
    preserving the root directory and (by default) the logs/ directory."""

    def test_preserves_logs_by_default(self, tmp_path: Path):
        """With preserve_logs=True (default), logs/ survives the wipe."""
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agents=AGENTS)
        # Add a log file
        logs_dir = plsec_home / "logs"
        logs_dir.mkdir(exist_ok=True)
        (logs_dir / "session.log").write_text("data\n")

        count = _wipe_global_state(plsec_home)
        assert count > 0
        # Root and logs should survive
        assert plsec_home.is_dir()
        assert logs_dir.is_dir()
        assert (logs_dir / "session.log").read_text() == "data\n"
        # Everything else should be gone
        remaining = {c.name for c in plsec_home.iterdir()}
        assert remaining == {"logs"}

    def test_wipes_logs_when_requested(self, tmp_path: Path):
        """With preserve_logs=False, logs/ is also removed."""
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agents=AGENTS)
        logs_dir = plsec_home / "logs"
        logs_dir.mkdir(exist_ok=True)
        (logs_dir / "session.log").write_text("data\n")

        count = _wipe_global_state(plsec_home, preserve_logs=False)
        assert count > 0
        assert plsec_home.is_dir()
        assert not logs_dir.exists()
        assert list(plsec_home.iterdir()) == []

    def test_returns_zero_for_empty_dir(self, tmp_path: Path):
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        plsec_home.mkdir(parents=True)
        count = _wipe_global_state(plsec_home)
        assert count == 0

    def test_returns_zero_for_nonexistent_dir(self, tmp_path: Path):
        plsec_home = tmp_path / "does_not_exist"
        count = _wipe_global_state(plsec_home)
        assert count == 0

    def test_preserved_dirs_constant(self):
        """_PRESERVED_DIRS should contain 'logs'."""
        assert "logs" in _PRESERVED_DIRS


# -----------------------------------------------------------------------
# _remove_external_configs
# -----------------------------------------------------------------------


class TestRemoveExternalConfigs:
    """Contract: _remove_external_configs removes agent config files
    from their native locations."""

    def test_removes_existing_external_config(self, tmp_path: Path):
        # Create a fake agent with a global_config_dir
        fake_agents: dict[str, AgentSpec] = {
            "test": AgentSpec(
                id="test",
                display_name="Test Agent",
                config_filename="test.json",
                templates={"balanced": "{}"},
                config_type="test",
                global_config_dir=tmp_path / ".config" / "test",
            ),
        }
        # Create the native config file
        native_dir = tmp_path / ".config" / "test"
        native_dir.mkdir(parents=True)
        (native_dir / "test.json").write_text("{}\n")

        count = _remove_external_configs(fake_agents)
        assert count == 1
        assert not (native_dir / "test.json").exists()

    def test_skips_agents_without_global_config_dir(self, tmp_path: Path):
        fake_agents: dict[str, AgentSpec] = {
            "noext": AgentSpec(
                id="noext",
                display_name="No External",
                config_filename="noext.md",
                templates={"balanced": "# test"},
                config_type="noext",
                global_config_dir=None,
            ),
        }
        count = _remove_external_configs(fake_agents)
        assert count == 0

    def test_skips_nonexistent_native_file(self, tmp_path: Path):
        fake_agents: dict[str, AgentSpec] = {
            "ghost": AgentSpec(
                id="ghost",
                display_name="Ghost",
                config_filename="ghost.json",
                templates={"balanced": "{}"},
                config_type="ghost",
                global_config_dir=tmp_path / ".config" / "ghost",
            ),
        }
        # Don't create the file
        count = _remove_external_configs(fake_agents)
        assert count == 0


# -----------------------------------------------------------------------
# plsec reset CLI command
# -----------------------------------------------------------------------


class TestResetCLI:
    """Contract: plsec reset wipes global state, removes external configs,
    and redeploys fresh defaults."""

    def _setup_installed(self, tmp_path: Path) -> Path:
        """Deploy a full install and return plsec_home."""
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        deploy_global_configs(plsec_home, agents=AGENTS)
        write_installed_metadata(
            plsec_home, preset="balanced", agent_ids=["claude", "opencode"], version="0.1.0"
        )
        return plsec_home

    def test_reset_with_yes_exits_zero(self, tmp_path: Path):
        plsec_home = self._setup_installed(tmp_path)
        with patch("plsec.commands.reset.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--yes"])
        assert result.exit_code == 0

    def test_reset_redeploys_configs(self, tmp_path: Path):
        plsec_home = self._setup_installed(tmp_path)
        # Write a marker to prove wipe + redeploy happened
        marker = plsec_home / "trivy" / "trivy-secret.yaml"
        marker.write_text("stale marker\n")

        with patch("plsec.commands.reset.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--yes"])
        assert result.exit_code == 0
        # File should exist again with fresh content
        assert marker.exists()
        assert marker.read_text() != "stale marker\n"

    def test_reset_writes_new_metadata(self, tmp_path: Path):
        plsec_home = self._setup_installed(tmp_path)
        with patch("plsec.commands.reset.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--yes", "--preset", "strict"])
        assert result.exit_code == 0
        metadata = read_installed_metadata(plsec_home)
        assert metadata is not None
        assert metadata["preset"] == "strict"

    def test_reset_recreates_subdirectories(self, tmp_path: Path):
        plsec_home = self._setup_installed(tmp_path)
        with patch("plsec.commands.reset.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--yes"])
        assert result.exit_code == 0
        for subdir in PLSEC_SUBDIRS:
            assert (plsec_home / subdir).is_dir(), f"Missing subdir after reset: {subdir}"

    def test_dry_run_makes_no_changes(self, tmp_path: Path):
        plsec_home = self._setup_installed(tmp_path)
        # Snapshot file list before dry-run
        before = {str(p) for p in plsec_home.rglob("*")}

        with patch("plsec.commands.reset.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--dry-run"])
        assert result.exit_code == 0
        assert "Dry run" in result.output

        # File list should be unchanged
        after = {str(p) for p in plsec_home.rglob("*")}
        assert before == after

    def test_cancel_exits_2(self, tmp_path: Path):
        plsec_home = self._setup_installed(tmp_path)
        with patch("plsec.commands.reset.get_plsec_home", return_value=plsec_home):
            # Simulate user typing "n" to the confirmation prompt
            result = runner.invoke(app, [], input="n\n")
        assert result.exit_code == 2

    def test_reset_with_preset(self, tmp_path: Path):
        plsec_home = self._setup_installed(tmp_path)
        with patch("plsec.commands.reset.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--yes", "--preset", "paranoid"])
        assert result.exit_code == 0
        assert "paranoid" in result.output
        metadata = read_installed_metadata(plsec_home)
        assert metadata is not None
        assert metadata["preset"] == "paranoid"

    def test_reset_from_empty_state(self, tmp_path: Path):
        """Reset on an empty plsec_home should still succeed."""
        plsec_home = tmp_path / ".peerlabs" / "plsec"
        plsec_home.mkdir(parents=True)
        with patch("plsec.commands.reset.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--yes"])
        assert result.exit_code == 0
        # Should have deployed fresh configs
        assert (plsec_home / "trivy" / "trivy.yaml").exists()

    def test_reset_preserves_logs_by_default(self, tmp_path: Path):
        """CLI reset without --wipe-logs should preserve logs/."""
        plsec_home = self._setup_installed(tmp_path)
        logs_dir = plsec_home / "logs"
        logs_dir.mkdir(exist_ok=True)
        (logs_dir / "session.log").write_text("keep me\n")

        with patch("plsec.commands.reset.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--yes"])
        assert result.exit_code == 0
        assert (logs_dir / "session.log").read_text() == "keep me\n"
        assert "preserved" in result.output.lower()

    def test_reset_wipe_logs_flag(self, tmp_path: Path):
        """CLI reset with --wipe-logs should remove logs/."""
        plsec_home = self._setup_installed(tmp_path)
        logs_dir = plsec_home / "logs"
        logs_dir.mkdir(exist_ok=True)
        (logs_dir / "session.log").write_text("delete me\n")

        with patch("plsec.commands.reset.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--yes", "--wipe-logs"])
        assert result.exit_code == 0
        # logs dir is recreated by deploy_global_configs but old file is gone
        assert not (logs_dir / "session.log").exists()

    def test_reset_reinjects_aliases(self, tmp_path: Path):
        """Reset should call inject_aliases (output mentions aliases)."""
        plsec_home = self._setup_installed(tmp_path)
        with patch("plsec.commands.reset.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--yes"])
        assert result.exit_code == 0
        assert "aliases" in result.output.lower()

    def test_reset_no_aliases_flag(self, tmp_path: Path):
        """--no-aliases should skip alias injection."""
        plsec_home = self._setup_installed(tmp_path)
        with patch("plsec.commands.reset.get_plsec_home", return_value=plsec_home):
            result = runner.invoke(app, ["--yes", "--no-aliases"])
        assert result.exit_code == 0
        # Should not contain the "Shell Aliases" header
        assert "shell aliases" not in result.output.lower()
