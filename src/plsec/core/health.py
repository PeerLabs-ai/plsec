"""Health check model -- reusable check functions for doctor and status.

Each check function takes explicit arguments (paths, registries) rather
than calling get_plsec_home() internally, making them testable with
tmp_path and no mocking.

Check IDs (I-1, C-3, etc.) align with the plsec-status design doc
(docs/plsec-status-design.md).
"""

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from plsec.core.agents import AgentSpec
from plsec.core.tools import Tool, ToolStatus

# Expected subdirectories under ~/.peerlabs/plsec/
PLSEC_SUBDIRS: list[str] = [
    "config",
    "config/presets",
    "configs",
    "logs",
    "manifests",
    "trivy",
    "trivy/policies",
]

# Expected files under ~/.peerlabs/plsec/ (beyond agent configs).
# Each tuple is (relative_path, human_description).
PLSEC_EXPECTED_FILES: list[tuple[str, str]] = [
    ("trivy/trivy-secret.yaml", "Trivy secret scanning rules"),
    ("trivy/trivy.yaml", "Trivy configuration"),
    ("configs/pre-commit", "Pre-commit hook template"),
]

# Expected preset TOML files deployed by plsec install.
# Each tuple is (relative_path, human_description).
PLSEC_EXPECTED_PRESETS: list[tuple[str, str]] = [
    ("config/presets/minimal.toml", "Minimal security preset"),
    ("config/presets/balanced.toml", "Balanced security preset"),
    ("config/presets/strict.toml", "Strict security preset"),
    ("config/presets/paranoid.toml", "Paranoid security preset"),
]

# Expected executable scripts deployed by plsec install.
# Each tuple is (relative_path, human_description).
PLSEC_EXPECTED_SCRIPTS: list[tuple[str, str]] = [
    ("claude-wrapper.sh", "Claude Code wrapper script"),
    ("opencode-wrapper.sh", "OpenCode wrapper script"),
    ("plsec-audit.sh", "Audit logging script"),
    ("plsec-status.sh", "Health status script"),
]


@dataclass
class CheckResult:
    """Result of a single health check."""

    # Check identifier matching plsec-status design doc (e.g., "I-1", "C-3")
    id: str
    # Human-readable check name (e.g., "plsec directory")
    name: str
    # Check category per the health model
    category: Literal["installation", "configuration", "activity", "findings"]
    # Check outcome
    verdict: Literal["ok", "warn", "fail", "skip"]
    # Additional detail for display (e.g., file path, version string)
    detail: str = ""
    # Suggested remediation (e.g., "Run 'plsec init' to create")
    fix_hint: str = ""


# ---------------------------------------------------------------------------
# Verdict helpers
# ---------------------------------------------------------------------------


def count_verdicts(results: list[CheckResult]) -> dict[str, int]:
    """Count results by verdict type.

    Returns dict with keys "ok", "warn", "fail", "skip" and integer counts.
    """
    counts = {"ok": 0, "warn": 0, "fail": 0, "skip": 0}
    for r in results:
        counts[r.verdict] += 1
    return counts


def exit_code_for(results: list[CheckResult]) -> int:
    """Determine exit code from check results.

    0 = all ok (warnings are acceptable).
    1 = any failures present.
    """
    return 1 if any(r.verdict == "fail" for r in results) else 0


# ---------------------------------------------------------------------------
# Installation checks
# ---------------------------------------------------------------------------


def check_directory_structure(
    plsec_home: Path,
    *,
    fix: bool = False,
) -> list[CheckResult]:
    """Check plsec home directory and expected subdirectories exist.

    If fix=True, create missing directories and report them as OK.
    Produces check I-1 (home) plus one check per expected subdirectory.
    """
    results: list[CheckResult] = []

    # I-1: plsec home directory
    if plsec_home.exists():
        results.append(
            CheckResult(
                id="I-1",
                name="plsec directory",
                category="installation",
                verdict="ok",
                detail=str(plsec_home),
            )
        )
    else:
        results.append(
            CheckResult(
                id="I-1",
                name="plsec directory",
                category="installation",
                verdict="fail",
                detail=str(plsec_home),
                fix_hint="Run 'plsec install' to create",
            )
        )
        # If home doesn't exist, subdirectory checks are meaningless
        return results

    # Subdirectories
    for subdir in PLSEC_SUBDIRS:
        path = plsec_home / subdir
        if path.exists():
            results.append(
                CheckResult(
                    id="I-1",
                    name=f"  {subdir}/",
                    category="installation",
                    verdict="ok",
                    detail=str(path),
                )
            )
        elif fix:
            path.mkdir(parents=True, exist_ok=True)
            results.append(
                CheckResult(
                    id="I-1",
                    name=f"  {subdir}/ (created)",
                    category="installation",
                    verdict="ok",
                    detail=str(path),
                )
            )
        else:
            results.append(
                CheckResult(
                    id="I-1",
                    name=f"  {subdir}/ missing",
                    category="installation",
                    verdict="warn",
                    fix_hint="Run with --fix to create",
                )
            )

    return results


def check_agent_configs(
    plsec_home: Path,
    agents: dict[str, AgentSpec],
) -> list[CheckResult]:
    """Check that expected agent config files exist in plsec_home/configs/.

    Iterates the agent registry.  Produces one check per agent.
    Check IDs correspond to I-2, I-3, etc. from the status design doc.
    """
    results: list[CheckResult] = []

    for i, (_agent_id, spec) in enumerate(agents.items(), start=2):
        check_id = f"I-{i}"
        config_path = plsec_home / "configs" / spec.config_filename

        if config_path.exists():
            results.append(
                CheckResult(
                    id=check_id,
                    name=f"{spec.config_filename} config",
                    category="installation",
                    verdict="ok",
                    detail=str(config_path),
                )
            )
        else:
            results.append(
                CheckResult(
                    id=check_id,
                    name=f"{spec.config_filename} config",
                    category="installation",
                    verdict="warn",
                    detail=f"{spec.display_name} template missing",
                    fix_hint="Run 'plsec install' to create",
                )
            )

    return results


def check_scanner_configs(plsec_home: Path) -> list[CheckResult]:
    """Check that scanner and tool config files exist in plsec_home.

    Verifies trivy-secret.yaml, trivy.yaml, and pre-commit hook template.
    These files are deployed by plsec install and are required for plsec scan
    and pre-commit integration to function correctly.

    Check IDs start at I-5 per the plsec-status design doc.
    """
    results: list[CheckResult] = []

    for i, (rel_path, description) in enumerate(PLSEC_EXPECTED_FILES, start=5):
        check_id = f"I-{i}"
        full_path = plsec_home / rel_path

        if full_path.exists():
            results.append(
                CheckResult(
                    id=check_id,
                    name=description,
                    category="installation",
                    verdict="ok",
                    detail=str(full_path),
                )
            )
        else:
            results.append(
                CheckResult(
                    id=check_id,
                    name=description,
                    category="installation",
                    verdict="warn",
                    detail=f"{rel_path} missing",
                    fix_hint="Run 'plsec install --force' to deploy",
                )
            )

    return results


def check_preset_files(plsec_home: Path) -> list[CheckResult]:
    """Check that preset TOML files are deployed in plsec_home.

    Verifies minimal.toml, balanced.toml, strict.toml, and paranoid.toml
    exist under config/presets/. These files are deployed by plsec install
    and provide the base security configurations for plsec scan.

    Check IDs use I-12 through I-15 (continuing after wrapper scripts).
    """
    results: list[CheckResult] = []

    for i, (rel_path, description) in enumerate(PLSEC_EXPECTED_PRESETS, start=12):
        check_id = f"I-{i}"
        full_path = plsec_home / rel_path

        if full_path.exists():
            results.append(
                CheckResult(
                    id=check_id,
                    name=description,
                    category="installation",
                    verdict="ok",
                    detail=str(full_path),
                )
            )
        else:
            results.append(
                CheckResult(
                    id=check_id,
                    name=description,
                    category="installation",
                    verdict="warn",
                    detail=f"{rel_path} missing",
                    fix_hint="Run 'plsec install --force' to deploy",
                )
            )

    return results


def check_wrapper_scripts(plsec_home: Path) -> list[CheckResult]:
    """Check that wrapper scripts exist and are executable.

    Verifies claude-wrapper.sh, opencode-wrapper.sh, and plsec-audit.sh.
    These scripts are deployed by plsec install and are required for
    session logging and audit functionality.

    Check IDs start at I-8 per the plsec-status design doc.
    """
    results: list[CheckResult] = []

    for i, (rel_path, description) in enumerate(PLSEC_EXPECTED_SCRIPTS, start=8):
        check_id = f"I-{i}"
        full_path = plsec_home / rel_path

        if full_path.exists():
            import os

            if os.access(full_path, os.X_OK):
                results.append(
                    CheckResult(
                        id=check_id,
                        name=description,
                        category="installation",
                        verdict="ok",
                        detail=str(full_path),
                    )
                )
            else:
                results.append(
                    CheckResult(
                        id=check_id,
                        name=description,
                        category="installation",
                        verdict="warn",
                        detail=f"{rel_path} not executable",
                        fix_hint="Run 'plsec install --force' to fix permissions",
                    )
                )
        else:
            results.append(
                CheckResult(
                    id=check_id,
                    name=description,
                    category="installation",
                    verdict="warn",
                    detail=f"{rel_path} missing",
                    fix_hint="Run 'plsec install' to deploy wrapper scripts",
                )
            )

    return results


def check_config_file(config_path: Path | None) -> list[CheckResult]:
    """Check for the existence of a plsec.yaml configuration file.

    Takes the result of find_config_file() (None if not found).
    """
    if config_path:
        return [
            CheckResult(
                id="C-1",
                name="Config file",
                category="configuration",
                verdict="ok",
                detail=str(config_path),
            )
        ]
    return [
        CheckResult(
            id="C-1",
            name="Config file",
            category="configuration",
            verdict="skip",
            detail="No plsec.yaml found",
            fix_hint="Run 'plsec init' to create one",
        )
    ]


def check_tools(tools: list[Tool]) -> list[CheckResult]:
    """Convert checked Tool statuses to CheckResults.

    Expects tools to have been checked already via ToolChecker.check_all().
    Produces one check per tool.
    """
    results: list[CheckResult] = []

    for tool in tools:
        if tool.status == ToolStatus.OK:
            version_info = f"v{tool.version}" if tool.version else ""
            results.append(
                CheckResult(
                    id="I-tool",
                    name=f"{tool.name} {version_info}".strip(),
                    category="installation",
                    verdict="ok",
                    detail=tool.path or "",
                )
            )
        elif tool.status == ToolStatus.MISSING:
            verdict = "fail" if tool.required else "warn"
            suffix = "" if tool.required else " (optional)"
            results.append(
                CheckResult(
                    id="I-tool",
                    name=f"{tool.name} not found{suffix}",
                    category="installation",
                    verdict=verdict,
                    fix_hint=tool.install_hint,
                )
            )
        elif tool.status == ToolStatus.OUTDATED:
            results.append(
                CheckResult(
                    id="I-tool",
                    name=f"{tool.name} v{tool.version} (outdated)",
                    category="installation",
                    verdict="warn",
                    detail=f"Minimum: v{tool.min_version}",
                )
            )
        else:
            results.append(
                CheckResult(
                    id="I-tool",
                    name=tool.name,
                    category="installation",
                    verdict="fail",
                    detail=tool.error or "Unknown error",
                )
            )

    return results


def check_runtime() -> list[CheckResult]:
    """Check Python version meets minimum (3.12+)."""
    v = sys.version_info
    version_str = f"Python {v.major}.{v.minor}.{v.micro}"

    if v >= (3, 12):
        return [
            CheckResult(
                id="I-runtime",
                name=version_str,
                category="installation",
                verdict="ok",
            )
        ]
    return [
        CheckResult(
            id="I-runtime",
            name=version_str,
            category="installation",
            verdict="fail",
            detail="Requires Python 3.12+",
        )
    ]


# ---------------------------------------------------------------------------
# Configuration checks (project-level)
# ---------------------------------------------------------------------------


def check_project_configs(
    project_path: Path,
    agents: dict[str, AgentSpec],
) -> list[CheckResult]:
    """Check project-level agent configs exist.

    Iterates the agent registry and checks for each agent's config file
    in the project root.  Checks C-4, C-5, etc. from the status design doc.
    """
    results: list[CheckResult] = []

    for i, (_agent_id, spec) in enumerate(agents.items(), start=4):
        check_id = f"C-{i}"
        config_path = project_path / spec.config_filename

        if config_path.exists():
            results.append(
                CheckResult(
                    id=check_id,
                    name=f"{spec.config_filename} (project)",
                    category="configuration",
                    verdict="ok",
                    detail=str(config_path),
                )
            )
        else:
            results.append(
                CheckResult(
                    id=check_id,
                    name=f"{spec.config_filename} (project)",
                    category="configuration",
                    verdict="warn",
                    detail="Not found in project root",
                    fix_hint="Run 'plsec init' or 'plsec secure' to create",
                )
            )

    return results
