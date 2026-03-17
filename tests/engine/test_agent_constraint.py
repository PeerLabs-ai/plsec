"""Tests for plsec.engine.agent_constraint -- agent constraint validation.

Covers the AgentConstraintEngine: identity properties, availability
check, execute() logic for missing config files, invalid structure,
and preset-mode mismatch.

Contract: This engine validates that agent configuration files
(CLAUDE.md, opencode.json) are deployed and match the active preset.
- "No findings" means all configs are present and correct.
- MISSING_CONTROL means the config file does not exist.
- POLICY_VIOLATION means the config exists but lacks required sections.
- MISCONFIG means the config exists but doesn't match the preset mode.
"""

import json
from pathlib import Path

from plsec.engine.agent_constraint import AgentConstraintEngine
from plsec.engine.base import Engine
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


def _make_env() -> EnvironmentInfo:
    return EnvironmentInfo(
        os_name="darwin",
        os_version="24.0.0",
        python_version="3.12.0",
    )


def _make_ctx(
    target_path: Path | None = None,
    preset: Preset = Preset.BALANCED,
) -> ScanContext:
    tp = target_path or Path("/fake/project")
    return ScanContext(
        target_path=tp,
        preset=preset,
        environment=_make_env(),
    )


def _write_balanced_claude_md(project: Path) -> None:
    """Write a valid balanced CLAUDE.md."""
    (project / "CLAUDE.md").write_text(
        "# CLAUDE.md - Balanced Security Configuration\n"
        "### NEVER (Hard Blocks)\n"
        "- NEVER access files outside the project\n"
        "### ASK FIRST (Soft Blocks)\n"
        "- Creating files outside src/\n"
        "### ALWAYS\n"
        "- Show commands before execution\n"
        "### Allowed Operations\n"
        "- Git operations (add, commit, status, diff)\n"
    )


def _write_strict_claude_md(project: Path) -> None:
    """Write a valid strict CLAUDE.md."""
    (project / "CLAUDE.md").write_text(
        "# CLAUDE.md - Strict Security Configuration\n"
        "### NEVER (Hard Blocks)\n"
        "- NEVER read, write, or access files outside the project\n"
        "### ASK FIRST (Soft Blocks)\n"
        "- Git write operations\n"
        "### ALWAYS (Required Actions)\n"
        "- ALWAYS confirm destructive operations\n"
        "### Project Boundaries\n"
        "- Working directory: Current directory only\n"
        "### Allowed Operations\n"
        "- Git read-only (status, diff, log)\n"
    )


def _write_balanced_opencode_json(project: Path) -> None:
    """Write a valid balanced opencode.json."""
    (project / "opencode.json").write_text(
        json.dumps(
            {
                "$schema": "https://opencode.ai/config.json",
                "permission": {
                    "*": "ask",
                    "bash": {"*": "ask", "git status": "allow"},
                    "external_directory": "ask",
                },
            }
        )
    )


def _write_strict_opencode_json(project: Path) -> None:
    """Write a valid strict opencode.json."""
    (project / "opencode.json").write_text(
        json.dumps(
            {
                "$schema": "https://opencode.ai/config.json",
                "permission": {
                    "*": "deny",
                    "bash": {"*": "deny", "git status": "allow"},
                    "external_directory": "deny",
                },
            }
        )
    )


# -----------------------------------------------------------------------
# Identity properties
# -----------------------------------------------------------------------


class TestAgentConstraintEngineIdentity:
    """Contract: Engine identity properties are correct."""

    def test_is_engine_subclass(self):
        assert issubclass(AgentConstraintEngine, Engine)

    def test_engine_id(self):
        e = AgentConstraintEngine()
        assert e.engine_id == "agent-constraint"

    def test_layer(self):
        e = AgentConstraintEngine()
        assert e.layer == Layer.CONFIG

    def test_display_name(self):
        e = AgentConstraintEngine()
        assert e.display_name == "Agent Constraint Validator"

    def test_presets(self):
        e = AgentConstraintEngine()
        assert e.presets == frozenset(
            {
                Preset.BALANCED,
                Preset.STRICT,
                Preset.PARANOID,
            }
        )

    def test_not_in_minimal_preset(self):
        e = AgentConstraintEngine()
        assert Preset.MINIMAL not in e.presets

    def test_dependencies_empty(self):
        """No external tool dependencies -- pure Python file analysis."""
        e = AgentConstraintEngine()
        assert e.dependencies == []

    def test_repr(self):
        e = AgentConstraintEngine()
        r = repr(e)
        assert "AgentConstraintEngine" in r
        assert "agent-constraint" in r


# -----------------------------------------------------------------------
# check_available
# -----------------------------------------------------------------------


class TestAgentConstraintCheckAvailable:
    """Contract: This engine is always available -- no external tools needed."""

    def test_always_available(self):
        e = AgentConstraintEngine()
        ctx = _make_ctx()
        result = e.check_available(ctx)
        assert isinstance(result, AvailabilityResult)
        assert result.status == EngineStatus.AVAILABLE


# -----------------------------------------------------------------------
# execute -- no config files at all
# -----------------------------------------------------------------------


class TestAgentConstraintMissingFiles:
    """Contract: When config files are missing, produce MISSING_CONTROL findings."""

    def test_missing_claude_md(self, tmp_path):
        """Missing CLAUDE.md produces a MISSING_CONTROL finding."""
        _write_balanced_opencode_json(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path)
        findings = e.execute(ctx)
        claude_findings = [f for f in findings if "CLAUDE.md" in f.title]
        assert len(claude_findings) == 1
        f = claude_findings[0]
        assert f.category == FindingCategory.MISSING_CONTROL
        assert f.severity == Severity.HIGH
        assert f.engine_id == "agent-constraint"
        assert f.layer == Layer.CONFIG
        assert f.remediation is not None

    def test_missing_opencode_json(self, tmp_path):
        """Missing opencode.json produces a MISSING_CONTROL finding."""
        _write_balanced_claude_md(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path)
        findings = e.execute(ctx)
        oc_findings = [f for f in findings if "opencode.json" in f.title]
        assert len(oc_findings) == 1
        f = oc_findings[0]
        assert f.category == FindingCategory.MISSING_CONTROL
        assert f.severity == Severity.HIGH

    def test_both_missing(self, tmp_path):
        """Both files missing produces two MISSING_CONTROL findings."""
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path)
        findings = e.execute(ctx)
        missing = [f for f in findings if f.category == FindingCategory.MISSING_CONTROL]
        assert len(missing) == 2

    def test_missing_file_location(self, tmp_path):
        """MISSING_CONTROL findings include the expected file path."""
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path)
        findings = e.execute(ctx)
        for f in findings:
            if f.category == FindingCategory.MISSING_CONTROL:
                assert f.location is not None
                assert f.location.file_path is not None


# -----------------------------------------------------------------------
# execute -- files exist but have invalid structure
# -----------------------------------------------------------------------


class TestAgentConstraintInvalidStructure:
    """Contract: Files that exist but lack required sections produce
    POLICY_VIOLATION findings."""

    def test_claude_md_missing_never(self, tmp_path):
        """CLAUDE.md without NEVER section produces POLICY_VIOLATION."""
        (tmp_path / "CLAUDE.md").write_text("# CLAUDE.md\n### ALWAYS\n- Show commands\n")
        _write_balanced_opencode_json(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path)
        findings = e.execute(ctx)
        violations = [
            f
            for f in findings
            if f.category == FindingCategory.POLICY_VIOLATION and "CLAUDE.md" in f.title
        ]
        assert len(violations) >= 1
        assert any("NEVER" in f.description for f in violations)

    def test_claude_md_missing_always(self, tmp_path):
        """CLAUDE.md without ALWAYS section produces POLICY_VIOLATION."""
        (tmp_path / "CLAUDE.md").write_text(
            "# CLAUDE.md\n### NEVER (Hard Blocks)\n- NEVER access files outside\n"
        )
        _write_balanced_opencode_json(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path)
        findings = e.execute(ctx)
        violations = [
            f
            for f in findings
            if f.category == FindingCategory.POLICY_VIOLATION and "CLAUDE.md" in f.title
        ]
        assert len(violations) >= 1
        assert any("ALWAYS" in f.description for f in violations)

    def test_opencode_json_invalid_json(self, tmp_path):
        """opencode.json with invalid JSON produces POLICY_VIOLATION."""
        (tmp_path / "opencode.json").write_text("{ not valid json")
        _write_balanced_claude_md(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path)
        findings = e.execute(ctx)
        violations = [
            f
            for f in findings
            if f.category == FindingCategory.POLICY_VIOLATION and "opencode.json" in f.title
        ]
        assert len(violations) >= 1

    def test_opencode_json_missing_permission(self, tmp_path):
        """opencode.json without permission section produces POLICY_VIOLATION."""
        (tmp_path / "opencode.json").write_text(
            json.dumps(
                {
                    "$schema": "https://opencode.ai/config.json",
                }
            )
        )
        _write_balanced_claude_md(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path)
        findings = e.execute(ctx)
        violations = [
            f
            for f in findings
            if f.category == FindingCategory.POLICY_VIOLATION and "opencode.json" in f.title
        ]
        assert len(violations) >= 1
        assert any("permission" in f.description.lower() for f in violations)

    def test_opencode_json_missing_bash_rules(self, tmp_path):
        """opencode.json without bash rules produces POLICY_VIOLATION."""
        (tmp_path / "opencode.json").write_text(
            json.dumps(
                {
                    "$schema": "https://opencode.ai/config.json",
                    "permission": {"*": "ask"},
                }
            )
        )
        _write_balanced_claude_md(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path)
        findings = e.execute(ctx)
        violations = [
            f
            for f in findings
            if f.category == FindingCategory.POLICY_VIOLATION and "opencode.json" in f.title
        ]
        assert len(violations) >= 1
        assert any("bash" in f.description.lower() for f in violations)

    def test_invalid_structure_severity(self, tmp_path):
        """Structure violations are MEDIUM severity."""
        (tmp_path / "CLAUDE.md").write_text("# Empty config\n")
        _write_balanced_opencode_json(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path)
        findings = e.execute(ctx)
        violations = [f for f in findings if f.category == FindingCategory.POLICY_VIOLATION]
        assert all(f.severity == Severity.MEDIUM for f in violations)


# -----------------------------------------------------------------------
# execute -- files valid but wrong preset mode
# -----------------------------------------------------------------------


class TestAgentConstraintPresetMismatch:
    """Contract: When files are structurally valid but don't match the
    active preset's security mode, produce MISCONFIG findings."""

    def test_balanced_config_at_strict_preset(self, tmp_path):
        """Balanced CLAUDE.md at strict preset is a MISCONFIG."""
        _write_balanced_claude_md(tmp_path)
        _write_strict_opencode_json(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path, preset=Preset.STRICT)
        findings = e.execute(ctx)
        misconfigs = [
            f
            for f in findings
            if f.category == FindingCategory.MISCONFIG and "CLAUDE.md" in f.title
        ]
        assert len(misconfigs) >= 1

    def test_balanced_opencode_at_strict_preset(self, tmp_path):
        """Balanced opencode.json at strict preset is a MISCONFIG."""
        _write_strict_claude_md(tmp_path)
        _write_balanced_opencode_json(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path, preset=Preset.STRICT)
        findings = e.execute(ctx)
        misconfigs = [
            f
            for f in findings
            if f.category == FindingCategory.MISCONFIG and "opencode.json" in f.title
        ]
        assert len(misconfigs) >= 1

    def test_strict_config_at_balanced_preset_is_ok(self, tmp_path):
        """Strict config at balanced preset is acceptable (stricter is fine)."""
        _write_strict_claude_md(tmp_path)
        _write_strict_opencode_json(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path, preset=Preset.BALANCED)
        findings = e.execute(ctx)
        misconfigs = [f for f in findings if f.category == FindingCategory.MISCONFIG]
        assert len(misconfigs) == 0

    def test_paranoid_uses_strict_mode(self, tmp_path):
        """Paranoid preset expects strict-mode configs."""
        _write_balanced_claude_md(tmp_path)
        _write_balanced_opencode_json(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path, preset=Preset.PARANOID)
        findings = e.execute(ctx)
        misconfigs = [f for f in findings if f.category == FindingCategory.MISCONFIG]
        assert len(misconfigs) >= 1

    def test_preset_mismatch_severity(self, tmp_path):
        """Preset mismatches are MEDIUM severity."""
        _write_balanced_claude_md(tmp_path)
        _write_balanced_opencode_json(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path, preset=Preset.STRICT)
        findings = e.execute(ctx)
        misconfigs = [f for f in findings if f.category == FindingCategory.MISCONFIG]
        assert all(f.severity == Severity.MEDIUM for f in misconfigs)

    def test_preset_mismatch_has_remediation(self, tmp_path):
        """Preset mismatch findings include remediation advice."""
        _write_balanced_claude_md(tmp_path)
        _write_balanced_opencode_json(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path, preset=Preset.STRICT)
        findings = e.execute(ctx)
        misconfigs = [f for f in findings if f.category == FindingCategory.MISCONFIG]
        assert all(f.remediation is not None for f in misconfigs)


# -----------------------------------------------------------------------
# execute -- clean results (everything correct)
# -----------------------------------------------------------------------


class TestAgentConstraintClean:
    """Contract: When all configs are present and match preset, no findings."""

    def test_balanced_preset_clean(self, tmp_path):
        """Balanced configs at balanced preset produce no findings."""
        _write_balanced_claude_md(tmp_path)
        _write_balanced_opencode_json(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path, preset=Preset.BALANCED)
        findings = e.execute(ctx)
        assert findings == []

    def test_strict_preset_clean(self, tmp_path):
        """Strict configs at strict preset produce no findings."""
        _write_strict_claude_md(tmp_path)
        _write_strict_opencode_json(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path, preset=Preset.STRICT)
        findings = e.execute(ctx)
        assert findings == []

    def test_paranoid_preset_with_strict_configs(self, tmp_path):
        """Strict configs at paranoid preset produce no findings."""
        _write_strict_claude_md(tmp_path)
        _write_strict_opencode_json(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path, preset=Preset.PARANOID)
        findings = e.execute(ctx)
        assert findings == []


# -----------------------------------------------------------------------
# execute -- compound scenarios
# -----------------------------------------------------------------------


class TestAgentConstraintCompound:
    """Contract: Multiple issues across files are all reported."""

    def test_one_missing_one_invalid(self, tmp_path):
        """Missing CLAUDE.md + invalid opencode.json = findings for both."""
        (tmp_path / "opencode.json").write_text("{ broken }")
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path)
        findings = e.execute(ctx)
        categories = {f.category for f in findings}
        assert FindingCategory.MISSING_CONTROL in categories
        assert FindingCategory.POLICY_VIOLATION in categories

    def test_both_wrong_preset(self, tmp_path):
        """Both files present but wrong preset = MISCONFIG for both."""
        _write_balanced_claude_md(tmp_path)
        _write_balanced_opencode_json(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path, preset=Preset.STRICT)
        findings = e.execute(ctx)
        misconfigs = [f for f in findings if f.category == FindingCategory.MISCONFIG]
        filenames = {f.title for f in misconfigs}
        assert any("CLAUDE.md" in t for t in filenames)
        assert any("opencode.json" in t for t in filenames)

    def test_all_findings_have_engine_id(self, tmp_path):
        """Every finding produced has the correct engine_id."""
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path)
        findings = e.execute(ctx)
        assert all(f.engine_id == "agent-constraint" for f in findings)

    def test_all_findings_have_config_layer(self, tmp_path):
        """Every finding produced has CONFIG layer."""
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path)
        findings = e.execute(ctx)
        assert all(f.layer == Layer.CONFIG for f in findings)


# -----------------------------------------------------------------------
# execute -- defensive edge cases
# -----------------------------------------------------------------------


class TestAgentConstraintEdgeCases:
    """Contract: Defensive guards handle edge cases gracefully."""

    def test_claude_md_unreadable_during_mode_check(self, tmp_path):
        """If CLAUDE.md becomes unreadable during mode check, no crash."""
        from unittest.mock import patch

        _write_balanced_claude_md(tmp_path)
        _write_strict_opencode_json(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path, preset=Preset.STRICT)
        # The validator reads the file first (structure check).
        # We need that to succeed, then fail on the mode check read.
        # Patch _check_claude_md_mode's internal read_text to fail.
        real_method = e._check_claude_md_mode

        def fail_mode_check(spec, config_path, location, findings):
            with patch.object(
                type(config_path),
                "read_text",
                side_effect=OSError("Permission denied"),
            ):
                real_method(spec, config_path, location, findings)

        with patch.object(e, "_check_claude_md_mode", fail_mode_check):
            findings = e.execute(ctx)
            assert isinstance(findings, list)

    def test_opencode_json_unreadable_during_mode_check(self, tmp_path):
        """If opencode.json becomes unreadable during mode check, no crash."""
        from unittest.mock import patch

        _write_strict_claude_md(tmp_path)
        _write_balanced_opencode_json(tmp_path)
        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path, preset=Preset.STRICT)

        real_read = Path.read_text

        def fail_oc_read(self, *a, **kw):
            if self.name == "opencode.json":
                raise OSError("Permission denied")
            return real_read(self, *a, **kw)

        with patch.object(Path, "read_text", fail_oc_read):
            findings = e.execute(ctx)
            assert isinstance(findings, list)

    def test_agent_without_validator(self, tmp_path):
        """Agents with no validate function skip structural checks."""
        from unittest.mock import patch

        from plsec.core.agents import AGENTS, AgentSpec

        _write_balanced_claude_md(tmp_path)
        _write_balanced_opencode_json(tmp_path)

        # Create a mock agent with no validator
        mock_agents = {
            **AGENTS,
            "test-agent": AgentSpec(
                id="test-agent",
                display_name="Test Agent",
                config_filename="CLAUDE.md",
                templates={"balanced": "", "strict": ""},
                config_type="test",
                validate=None,
            ),
        }

        e = AgentConstraintEngine()
        ctx = _make_ctx(target_path=tmp_path, preset=Preset.BALANCED)
        with patch("plsec.engine.agent_constraint.AGENTS", mock_agents):
            findings = e.execute(ctx)
            # test-agent has no validator, so structural check is skipped
            # It should still run without error
            assert isinstance(findings, list)
