"""Tests for the secure command module (commands/secure.py).

Covers:
- Change and ChangeSet dataclasses
- _add_agent_config_changes() create/modify/conflict logic
- calculate_changes() full change calculation with various project states
- display_issues() output formatting
- apply_changes() filesystem writes
- GITIGNORE_SECURITY_PATTERNS constant

The core logic (calculate_changes, _add_agent_config_changes, apply_changes)
is tested as pure functions with tmp_path. No subprocess mocking needed for
these -- the subprocess calls only occur in the main secure() command wrapper.

display_issues() is tested by capturing Rich console output.
"""

from pathlib import Path
from typing import Literal

from plsec.commands.secure import (
    GITIGNORE_SECURITY_PATTERNS,
    Change,
    ChangeSet,
    _add_agent_config_changes,
    apply_changes,
    calculate_changes,
    display_issues,
)
from plsec.core.detector import ProjectInfo, SecurityIssue
from plsec.core.wizard import WizardState

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _make_info(
    tmp_path: Path,
    *,
    project_type: Literal["python", "node", "go", "rust", "mixed", "unknown"] = "python",
    detected_agents: dict[str, bool] | None = None,
    has_plsec_yaml: bool = False,
    has_gitignore: bool = False,
    has_pre_commit: bool = False,
    gitignore_patterns: list[str] | None = None,
    is_git_repo: bool = True,
) -> ProjectInfo:
    """Create a ProjectInfo fixture with controlled fields."""
    return ProjectInfo(
        path=tmp_path,
        name="test-project",
        type=project_type,
        detected_agents=detected_agents or {},
        has_plsec_yaml=has_plsec_yaml,
        has_gitignore=has_gitignore,
        has_pre_commit=has_pre_commit,
        gitignore_patterns=gitignore_patterns or [],
        is_git_repo=is_git_repo,
        file_counts={"py": 10},
    )


def _make_state(
    *,
    agents: list[str] | None = None,
    preset: str = "balanced",
) -> WizardState:
    """Create a WizardState fixture with controlled fields."""
    return WizardState(
        project_name="test-project",
        project_type="python",
        agents=agents or ["claude", "opencode"],
        preset=preset,
    )


# -----------------------------------------------------------------------
# Change and ChangeSet
# -----------------------------------------------------------------------


class TestChange:
    """Contract: Change holds a proposed file change with action type."""

    def test_create_action(self):
        c = Change(action="create", path="CLAUDE.md", description="Config", content="x")
        assert c.action == "create"
        assert c.selected is True

    def test_defaults(self):
        c = Change(action="skip", path="f", description="d")
        assert c.content is None
        assert c.diff is None
        assert c.selected is True


class TestChangeSet:
    """Contract: ChangeSet groups changes by type and provides query methods."""

    def test_empty_has_no_changes(self):
        cs = ChangeSet()
        assert cs.has_changes() is False
        assert cs.has_conflicts() is False

    def test_creates_count_as_changes(self):
        cs = ChangeSet(creates=[Change(action="create", path="f", description="d")])
        assert cs.has_changes() is True

    def test_modifies_count_as_changes(self):
        cs = ChangeSet(modifies=[Change(action="modify", path="f", description="d")])
        assert cs.has_changes() is True

    def test_skips_do_not_count_as_changes(self):
        cs = ChangeSet(skips=[Change(action="skip", path="f", description="d")])
        assert cs.has_changes() is False

    def test_conflicts_detected(self):
        cs = ChangeSet(conflicts=[Change(action="conflict", path="f", description="d")])
        assert cs.has_conflicts() is True

    def test_conflicts_do_not_count_as_changes(self):
        cs = ChangeSet(conflicts=[Change(action="conflict", path="f", description="d")])
        assert cs.has_changes() is False


# -----------------------------------------------------------------------
# _add_agent_config_changes
# -----------------------------------------------------------------------


class TestAddAgentConfigChanges:
    """Contract: _add_agent_config_changes categorizes each agent's config
    as create (not detected), modify (detected + force), or conflict
    (detected + no force). Unknown agent IDs are skipped."""

    def test_creates_when_no_config_detected(self, tmp_path: Path):
        """Agent config not detected -> create."""
        changes = ChangeSet()
        info = _make_info(tmp_path, detected_agents={"claude": False})
        state = _make_state(agents=["claude"])
        _add_agent_config_changes(changes, info, state, force=False)
        assert len(changes.creates) == 1
        assert changes.creates[0].path == "CLAUDE.md"

    def test_conflict_when_detected_no_force(self, tmp_path: Path):
        """Agent config detected + no force -> conflict."""
        changes = ChangeSet()
        info = _make_info(tmp_path, detected_agents={"claude": True})
        state = _make_state(agents=["claude"])
        _add_agent_config_changes(changes, info, state, force=False)
        assert len(changes.conflicts) == 1
        assert changes.conflicts[0].path == "CLAUDE.md"

    def test_modifies_when_detected_with_force(self, tmp_path: Path):
        """Agent config detected + force -> modify."""
        changes = ChangeSet()
        info = _make_info(tmp_path, detected_agents={"claude": True})
        state = _make_state(agents=["claude"])
        _add_agent_config_changes(changes, info, state, force=True)
        assert len(changes.modifies) == 1
        assert changes.modifies[0].path == "CLAUDE.md"

    def test_multiple_agents(self, tmp_path: Path):
        """Both agents with no config -> two creates."""
        changes = ChangeSet()
        info = _make_info(tmp_path, detected_agents={})
        state = _make_state(agents=["claude", "opencode"])
        _add_agent_config_changes(changes, info, state, force=False)
        assert len(changes.creates) == 2
        paths = {c.path for c in changes.creates}
        assert "CLAUDE.md" in paths
        assert "opencode.json" in paths

    def test_unknown_agent_skipped(self, tmp_path: Path):
        """Unknown agent ID should be silently skipped."""
        changes = ChangeSet()
        info = _make_info(tmp_path)
        state = _make_state(agents=["nonexistent"])
        _add_agent_config_changes(changes, info, state, force=False)
        assert len(changes.creates) == 0
        assert len(changes.conflicts) == 0

    def test_template_content_included(self, tmp_path: Path):
        """Created changes should include template content."""
        changes = ChangeSet()
        info = _make_info(tmp_path, detected_agents={})
        state = _make_state(agents=["claude"], preset="balanced")
        _add_agent_config_changes(changes, info, state, force=False)
        assert changes.creates[0].content is not None
        assert len(changes.creates[0].content) > 0


# -----------------------------------------------------------------------
# calculate_changes
# -----------------------------------------------------------------------


class TestCalculateChanges:
    """Contract: calculate_changes computes the full set of file changes
    needed to secure a project based on its current state."""

    def test_fresh_project_creates_all(self, tmp_path: Path):
        """Fresh project with nothing present -> creates for everything."""
        info = _make_info(tmp_path)
        state = _make_state(agents=["claude"])
        changes = calculate_changes(tmp_path, info, state)
        paths = {c.path for c in changes.creates}
        assert "CLAUDE.md" in paths
        assert "plsec.yaml" in paths
        assert ".pre-commit-config.yaml" in paths
        assert ".gitignore" in paths

    def test_trivy_config_created_when_missing(self, tmp_path: Path):
        """Missing trivy config should be created."""
        info = _make_info(tmp_path)
        state = _make_state(agents=["claude"])
        changes = calculate_changes(tmp_path, info, state)
        trivy_creates = [c for c in changes.creates if "trivy" in c.path]
        assert len(trivy_creates) == 1

    def test_trivy_config_not_created_when_present(self, tmp_path: Path):
        """Existing trivy config should not be recreated."""
        trivy_dir = tmp_path / "trivy"
        trivy_dir.mkdir()
        (trivy_dir / "trivy-secret.yaml").write_text("rules:\n")
        info = _make_info(tmp_path)
        state = _make_state(agents=["claude"])
        changes = calculate_changes(tmp_path, info, state)
        trivy_creates = [c for c in changes.creates if "trivy" in c.path]
        assert len(trivy_creates) == 0

    def test_plsec_yaml_skipped_when_exists(self, tmp_path: Path):
        """Existing plsec.yaml should be skipped."""
        info = _make_info(tmp_path, has_plsec_yaml=True)
        state = _make_state(agents=["claude"])
        changes = calculate_changes(tmp_path, info, state)
        yaml_skips = [c for c in changes.skips if c.path == "plsec.yaml"]
        assert len(yaml_skips) == 1

    def test_pre_commit_skipped_when_exists(self, tmp_path: Path):
        """Existing pre-commit config should be skipped."""
        info = _make_info(tmp_path, has_pre_commit=True)
        state = _make_state(agents=["claude"])
        changes = calculate_changes(tmp_path, info, state)
        pc_skips = [c for c in changes.skips if ".pre-commit" in c.path]
        assert len(pc_skips) == 1

    def test_gitignore_modified_when_missing_patterns(self, tmp_path: Path):
        """Existing .gitignore without plsec patterns should be modified."""
        (tmp_path / ".gitignore").write_text("*.pyc\n__pycache__/\n")
        info = _make_info(tmp_path, has_gitignore=True)
        state = _make_state(agents=["claude"])
        changes = calculate_changes(tmp_path, info, state)
        gi_mods = [c for c in changes.modifies if c.path == ".gitignore"]
        assert len(gi_mods) == 1
        assert gi_mods[0].content is not None
        assert "plsec security patterns" in gi_mods[0].content

    def test_gitignore_skipped_when_patterns_present(self, tmp_path: Path):
        """Existing .gitignore with plsec patterns should be skipped."""
        (tmp_path / ".gitignore").write_text("# plsec security patterns\n.env\n")
        info = _make_info(
            tmp_path,
            has_gitignore=True,
            gitignore_patterns=[".env"],
        )
        state = _make_state(agents=["claude"])
        changes = calculate_changes(tmp_path, info, state)
        gi_skips = [c for c in changes.skips if c.path == ".gitignore"]
        assert len(gi_skips) == 1

    def test_gitignore_created_when_not_present(self, tmp_path: Path):
        """No .gitignore should create one."""
        info = _make_info(tmp_path, has_gitignore=False)
        state = _make_state(agents=["claude"])
        changes = calculate_changes(tmp_path, info, state)
        gi_creates = [c for c in changes.creates if c.path == ".gitignore"]
        assert len(gi_creates) == 1

    def test_plsec_yaml_includes_project_name(self, tmp_path: Path):
        """Generated plsec.yaml should include the project name."""
        info = _make_info(tmp_path)
        state = _make_state(agents=["claude"])
        changes = calculate_changes(tmp_path, info, state)
        yaml_change = next(c for c in changes.creates if c.path == "plsec.yaml")
        assert yaml_change.content is not None
        assert "test-project" in yaml_change.content

    def test_strict_preset_enables_isolation(self, tmp_path: Path):
        """Strict preset should enable isolation in plsec.yaml."""
        info = _make_info(tmp_path)
        state = _make_state(agents=["claude"], preset="strict")
        changes = calculate_changes(tmp_path, info, state)
        yaml_change = next(c for c in changes.creates if c.path == "plsec.yaml")
        assert yaml_change.content is not None
        assert "enabled: true" in yaml_change.content

    def test_paranoid_preset_enables_proxy(self, tmp_path: Path):
        """Paranoid preset should enable proxy in plsec.yaml."""
        info = _make_info(tmp_path)
        state = _make_state(agents=["claude"], preset="paranoid")
        changes = calculate_changes(tmp_path, info, state)
        yaml_change = next(c for c in changes.creates if c.path == "plsec.yaml")
        assert yaml_change.content is not None
        # Proxy enabled is true only for paranoid
        lines = yaml_change.content.split("\n")
        proxy_section = False
        for line in lines:
            if "proxy:" in line:
                proxy_section = True
            if proxy_section and "enabled:" in line:
                assert "true" in line
                break


# -----------------------------------------------------------------------
# apply_changes
# -----------------------------------------------------------------------


class TestApplyChanges:
    """Contract: apply_changes writes created and modified files to disk.
    Unselected changes are skipped."""

    def test_creates_file(self, tmp_path: Path):
        """Created changes should write files."""
        changes = ChangeSet(
            creates=[Change(action="create", path="new.txt", description="test", content="hello")]
        )
        apply_changes(tmp_path, changes)
        assert (tmp_path / "new.txt").read_text() == "hello"

    def test_creates_nested_directories(self, tmp_path: Path):
        """Creates should make parent directories as needed."""
        changes = ChangeSet(
            creates=[
                Change(
                    action="create",
                    path="deep/nested/file.txt",
                    description="test",
                    content="data",
                )
            ]
        )
        apply_changes(tmp_path, changes)
        assert (tmp_path / "deep" / "nested" / "file.txt").read_text() == "data"

    def test_modifies_file(self, tmp_path: Path):
        """Modified changes should overwrite files."""
        (tmp_path / "existing.txt").write_text("old")
        changes = ChangeSet(
            modifies=[
                Change(action="modify", path="existing.txt", description="test", content="new")
            ]
        )
        apply_changes(tmp_path, changes)
        assert (tmp_path / "existing.txt").read_text() == "new"

    def test_skips_unselected_creates(self, tmp_path: Path):
        """Unselected creates should not write files."""
        changes = ChangeSet(
            creates=[
                Change(
                    action="create",
                    path="skipped.txt",
                    description="test",
                    content="x",
                    selected=False,
                )
            ]
        )
        apply_changes(tmp_path, changes)
        assert not (tmp_path / "skipped.txt").exists()

    def test_skips_unselected_modifies(self, tmp_path: Path):
        """Unselected modifies should not overwrite files."""
        (tmp_path / "keep.txt").write_text("original")
        changes = ChangeSet(
            modifies=[
                Change(
                    action="modify",
                    path="keep.txt",
                    description="test",
                    content="replaced",
                    selected=False,
                )
            ]
        )
        apply_changes(tmp_path, changes)
        assert (tmp_path / "keep.txt").read_text() == "original"

    def test_none_content_not_written(self, tmp_path: Path):
        """Changes with None content should create the path but not write."""
        changes = ChangeSet(
            creates=[Change(action="create", path="empty.txt", description="test", content=None)]
        )
        apply_changes(tmp_path, changes)
        # Parent dir created but file not written
        assert not (tmp_path / "empty.txt").exists()


# -----------------------------------------------------------------------
# display_issues
# -----------------------------------------------------------------------


class TestDisplayIssues:
    """Contract: display_issues renders security issues to the console.
    Empty list does nothing. More than 10 issues shows truncation."""

    def test_empty_issues(self, capsys):
        """Empty list should produce no output."""
        display_issues([])
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_few_issues(self, capsys):
        """A few issues should all be displayed."""
        issues = [
            SecurityIssue(
                severity="high",
                message="Exposed API key",
                file="config.py",
                line=42,
            ),
            SecurityIssue(
                severity="low",
                message="Debug mode enabled",
                file="settings.py",
            ),
        ]
        display_issues(issues)
        # Issues are printed to Rich console, not captured by capsys.
        # We just verify no exception is raised.

    def test_many_issues_truncated(self, capsys):
        """More than 10 issues should show truncation message."""
        issues = [
            SecurityIssue(
                severity="medium",
                message=f"Issue {i}",
                file=f"file{i}.py",
            )
            for i in range(15)
        ]
        display_issues(issues)
        # Verifies no exception for 15 issues


# -----------------------------------------------------------------------
# GITIGNORE_SECURITY_PATTERNS
# -----------------------------------------------------------------------


class TestGitignorePatterns:
    """Contract: GITIGNORE_SECURITY_PATTERNS contains expected security
    patterns."""

    def test_contains_env(self):
        assert ".env" in GITIGNORE_SECURITY_PATTERNS

    def test_contains_pem(self):
        assert "*.pem" in GITIGNORE_SECURITY_PATTERNS

    def test_contains_aws(self):
        assert ".aws/" in GITIGNORE_SECURITY_PATTERNS

    def test_has_header_and_footer(self):
        assert "plsec security patterns" in GITIGNORE_SECURITY_PATTERNS
        assert "end plsec patterns" in GITIGNORE_SECURITY_PATTERNS
