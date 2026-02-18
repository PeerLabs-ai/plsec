"""
plsec secure - Add security to an existing project.

Analyzes project, identifies gaps, and applies security configuration.
"""

__version__ = "0.1.0"

import shutil
import subprocess
from pathlib import Path
from typing import Literal
from dataclasses import dataclass, field

import typer

from plsec.core.config import get_plsec_home
from plsec.core.output import console, print_ok, print_error, print_warning, print_info
from plsec.core.detector import ProjectDetector, ProjectInfo, SecurityIssue
from plsec.core.wizard import (
    Wizard,
    WizardState,
    AGENT_CHOICES,
    PRESET_CHOICES,
)
from plsec.configs.templates import (
    CLAUDE_MD_STRICT,
    CLAUDE_MD_BALANCED,
    OPENCODE_JSON_STRICT,
    OPENCODE_JSON_BALANCED,
)

app = typer.Typer(
    help="Secure an existing project.",
    no_args_is_help=False,
)


Preset = Literal["minimal", "balanced", "strict", "paranoid"]
AgentType = Literal["claude", "opencode", "both"]


@dataclass
class Change:
    """A proposed change to the project."""

    action: Literal["create", "modify", "skip", "conflict"]
    path: str
    description: str
    content: str | None = None
    diff: str | None = None  # For modify actions
    selected: bool = True  # For selective application


@dataclass
class ChangeSet:
    """Collection of proposed changes."""

    creates: list[Change] = field(default_factory=list)
    modifies: list[Change] = field(default_factory=list)
    skips: list[Change] = field(default_factory=list)
    conflicts: list[Change] = field(default_factory=list)

    def has_changes(self) -> bool:
        """Check if there are any changes to apply."""
        return bool(self.creates or self.modifies)

    def has_conflicts(self) -> bool:
        """Check if there are conflicts."""
        return bool(self.conflicts)


# Security patterns to add to .gitignore
GITIGNORE_SECURITY_PATTERNS = """
# === plsec security patterns (added by plsec secure) ===
# Secrets and credentials
.env
.env.*
!.env.example
*.pem
*.key
*.p12
*.pfx
**/secrets/
**/credentials/

# Cloud provider configs
.aws/
.azure/
.gcp/

# IDE secrets
.idea/dataSources/
.vscode/*.json

# plsec
.plsec-manifest.json
# === end plsec patterns ===
"""


def display_issues(issues: list[SecurityIssue]) -> None:
    """Display detected security issues."""
    if not issues:
        return

    console.print()
    console.print(f"[yellow][!] Found {len(issues)} potential issues:[/yellow]")

    for issue in issues[:10]:  # Limit display
        severity_color = {
            "critical": "red",
            "high": "red",
            "medium": "yellow",
            "low": "dim",
        }
        color = severity_color.get(issue.severity, "dim")
        location = f"{issue.file}:{issue.line}" if issue.line else issue.file
        console.print(f"    [{color}]{issue.severity.upper()}[/{color}]: {issue.message}")
        console.print(f"          {location}")

    if len(issues) > 10:
        console.print(f"    ... and {len(issues) - 10} more")


def calculate_changes(
    project_path: Path,
    info: ProjectInfo,
    state: WizardState,
    force: bool = False,
) -> ChangeSet:
    """Calculate what changes need to be made."""
    changes = ChangeSet()
    is_strict = state.preset in ("strict", "paranoid")

    # CLAUDE.md
    claude_content = CLAUDE_MD_STRICT if is_strict else CLAUDE_MD_BALANCED
    if "claude" in state.agents:
        if not info.has_claude_md:
            changes.creates.append(
                Change(
                    action="create",
                    path="CLAUDE.md",
                    description="AI assistant constraints",
                    content=claude_content,
                )
            )
        elif force:
            changes.modifies.append(
                Change(
                    action="modify",
                    path="CLAUDE.md",
                    description="Replace with template",
                    content=claude_content,
                )
            )
        else:
            changes.conflicts.append(
                Change(
                    action="conflict",
                    path="CLAUDE.md",
                    description="Exists but differs from template",
                )
            )

    # opencode.json
    opencode_content = OPENCODE_JSON_STRICT if is_strict else OPENCODE_JSON_BALANCED
    if "opencode" in state.agents:
        if not info.has_opencode_json:
            changes.creates.append(
                Change(
                    action="create",
                    path="opencode.json",
                    description="OpenCode configuration",
                    content=opencode_content,
                )
            )
        elif force:
            changes.modifies.append(
                Change(
                    action="modify",
                    path="opencode.json",
                    description="Replace with template",
                    content=opencode_content,
                )
            )
        else:
            changes.skips.append(
                Change(
                    action="skip",
                    path="opencode.json",
                    description="Already exists",
                )
            )

    # plsec.yaml
    plsec_yaml = f"""version: 1

project:
  name: {info.name}
  type: {info.type}

agent:
  type: {"claude-code" if "claude" in state.agents else "opencode"}
  config_path: ./CLAUDE.md

layers:
  static:
    enabled: true
    scanners:
      - trivy-secrets
      - trivy-misconfig
      {"- bandit" if info.type == "python" else ""}
      - semgrep

  isolation:
    enabled: {str(is_strict).lower()}
    runtime: podman

  proxy:
    enabled: {str(state.preset == "paranoid").lower()}
    mode: {"strict" if state.preset == "paranoid" else "balanced"}

  audit:
    enabled: true
    log_dir: ~/.peerlabs/plsec/logs
    integrity: {str(state.preset in ("strict", "paranoid")).lower()}
"""

    if not info.has_plsec_yaml:
        changes.creates.append(
            Change(
                action="create",
                path="plsec.yaml",
                description="plsec configuration",
                content=plsec_yaml,
            )
        )
    else:
        changes.skips.append(
            Change(
                action="skip",
                path="plsec.yaml",
                description="Already exists",
            )
        )

    # trivy config
    trivy_path = project_path / "trivy" / "trivy-secret.yaml"
    if not trivy_path.exists():
        changes.creates.append(
            Change(
                action="create",
                path="trivy/trivy-secret.yaml",
                description="Secret scanning rules",
                content="# Trivy secret scanning config\n",
            )
        )

    # .pre-commit-config.yaml
    if not info.has_pre_commit:
        pre_commit_content = """repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']

  - repo: local
    hooks:
      - id: trivy-secrets
        name: Trivy Secret Scan
        entry: trivy fs --scanners secret --exit-code 1
        language: system
        pass_filenames: false
"""
        changes.creates.append(
            Change(
                action="create",
                path=".pre-commit-config.yaml",
                description="Pre-commit hooks",
                content=pre_commit_content,
            )
        )
    else:
        changes.skips.append(
            Change(
                action="skip",
                path=".pre-commit-config.yaml",
                description="Already exists",
            )
        )

    # .gitignore (modify)
    if info.has_gitignore:
        # Check if security patterns already present
        gitignore_content = (project_path / ".gitignore").read_text()
        if "plsec security patterns" not in gitignore_content:
            # Count new patterns
            new_patterns = len(
                [
                    p
                    for p in GITIGNORE_SECURITY_PATTERNS.strip().split("\n")
                    if p and not p.startswith("#")
                ]
            )
            changes.modifies.append(
                Change(
                    action="modify",
                    path=".gitignore",
                    description=f"Add {new_patterns} security patterns",
                    content=gitignore_content + GITIGNORE_SECURITY_PATTERNS,
                )
            )
        else:
            changes.skips.append(
                Change(
                    action="skip",
                    path=".gitignore",
                    description="Security patterns already present",
                )
            )
    else:
        changes.creates.append(
            Change(
                action="create",
                path=".gitignore",
                description="Security-enhanced gitignore",
                content=GITIGNORE_SECURITY_PATTERNS,
            )
        )

    return changes


def display_changes(changes: ChangeSet) -> None:
    """Display proposed changes."""
    console.print()
    console.print("[bold]Proposed Changes[/bold]")
    console.print("-" * 40)

    if changes.creates:
        console.print()
        console.print("[green]CREATE:[/green]")
        for change in changes.creates:
            console.print(f"  + {change.path:<35} ({change.description})")

    if changes.modifies:
        console.print()
        console.print("[yellow]MODIFY:[/yellow]")
        for change in changes.modifies:
            console.print(f"  ~ {change.path:<35} ({change.description})")

    if changes.skips:
        console.print()
        console.print("[dim]SKIP (already exists):[/dim]")
        for change in changes.skips:
            console.print(f"  - {change.path:<35} ({change.description})")

    if changes.conflicts:
        console.print()
        console.print("[red]CONFLICTS:[/red]")
        for change in changes.conflicts:
            console.print(f"  ! {change.path:<35} ({change.description})")


def apply_changes(project_path: Path, changes: ChangeSet) -> None:
    """Apply the calculated changes."""
    console.print()
    console.print("Applying changes...")

    for change in changes.creates:
        if not change.selected:
            continue

        file_path = project_path / change.path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        if change.content:
            file_path.write_text(change.content)
        print_ok(f"Created {change.path}")

    for change in changes.modifies:
        if not change.selected:
            continue

        file_path = project_path / change.path
        if change.content:
            file_path.write_text(change.content)
        print_ok(f"Updated {change.path}")


def run_analysis_wizard(info: ProjectInfo) -> WizardState:
    """Run the wizard for an analyzed project."""
    wizard = Wizard("plsec secure - Secure Existing Project")
    wizard.header(total_steps=4)

    # Step 1: AI assistants
    wizard.step_header("AI Assistants")
    agents = wizard.multi_select(
        "Which AI coding assistants do you use with this project?",
        choices=AGENT_CHOICES,
    )
    wizard.state.agents = agents

    # Step 2: Security posture
    wizard.step_header("Security Posture")
    preset = wizard.select(
        "How strict should security controls be?",
        choices=PRESET_CHOICES,
        default="balanced",
    )
    wizard.state.preset = preset

    # Step 3: Review detected settings
    wizard.step_header("Review Detected Settings")
    console.print("    We detected the following. Adjust if needed:")
    console.print()
    console.print(f"    Project type:     {info.type}")
    if info.package_manager:
        console.print(f"    Package manager:  {info.package_manager}")
    if info.test_framework:
        console.print(f"    Test framework:   {info.test_framework}")
    if info.cloud_providers:
        console.print(f"    Cloud providers:  {', '.join(info.cloud_providers)}")
    console.print()

    if not wizard.confirm("Is this correct?", default=True):
        # Could add editing here, for now just proceed
        wizard.info("Proceeding with detected settings")

    wizard.state.project_type = info.type
    wizard.state.cloud_providers = info.cloud_providers

    return wizard.state


@app.callback(invoke_without_command=True)
def secure(
    path: Path = typer.Argument(
        Path("."),
        help="Project path (default: current directory)",
    ),
    preset: Preset = typer.Option(
        "balanced",
        "--preset",
        "-p",
        help="Security preset: minimal, balanced, strict, paranoid",
    ),
    agent: AgentType = typer.Option(
        "both",
        "--agent",
        "-a",
        help="AI agent: claude, opencode, both",
    ),
    no_wizard: bool = typer.Option(
        False,
        "--no-wizard",
        help="Skip wizard, use detected/default values",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show what would change without applying",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing config files",
    ),
    no_scan: bool = typer.Option(
        False,
        "--no-scan",
        help="Skip security scan after setup",
    ),
) -> None:
    """
    Add security configuration to an existing project.

    Analyzes the project, identifies security gaps, and applies
    configuration with user confirmation.
    """
    project_path = path.resolve()

    # Check if directory exists
    if not project_path.is_dir():
        print_error(f"Not a directory: {project_path}")
        raise typer.Exit(1)

    console.print("[bold]plsec secure[/bold] - Secure Existing Project\n")
    console.print("Analyzing project...")
    console.print()

    # Analyze project
    detector = ProjectDetector(project_path)
    info = detector.analyze()

    # Display detection results
    print_ok(f"Detected: {info.type.title()} project")
    if info.is_git_repo:
        print_ok("Detected: Git repository")
    else:
        print_warning("Not a git repository")

    # Count files
    total_files = sum(info.file_counts.values())
    print_ok(f"Detected: {total_files} files")

    # Check existing security
    if not info.has_claude_md:
        print_warning("No CLAUDE.md found")
    if not info.has_opencode_json:
        print_warning("No opencode.json found")
    if not info.has_pre_commit:
        print_warning("No pre-commit hooks installed")
    if info.has_gitignore:
        # Check for missing patterns
        missing_patterns = []
        for pattern in [".env", "*.pem", "*.key", ".aws/"]:
            if pattern not in info.gitignore_patterns:
                missing_patterns.append(pattern)
        if missing_patterns:
            print_warning(f".gitignore missing: {', '.join(missing_patterns[:3])}...")

    # Quick security scan
    console.print()
    console.print("Running quick security scan...")
    issues = detector.quick_scan(info)
    display_issues(issues)

    # Run wizard or use CLI options
    if no_wizard:
        state = WizardState(
            project_name=info.name,
            project_type=info.type,
            agents=["claude", "opencode"] if agent == "both" else [agent],
            preset=preset,
            cloud_providers=info.cloud_providers,
        )
    else:
        state = run_analysis_wizard(info)

    # Calculate changes
    changes = calculate_changes(project_path, info, state, force=force)

    # Display changes
    display_changes(changes)

    if not changes.has_changes():
        console.print()
        console.print("[green]Project is already configured![/green]")
        raise typer.Exit(0)

    if changes.has_conflicts() and not force:
        console.print()
        console.print("[yellow]Conflicts detected. Use --force to overwrite.[/yellow]")

    # Dry run exit
    if dry_run:
        console.print()
        console.print("[dim]Dry run - no changes applied[/dim]")
        console.print("Run without --dry-run to apply changes.")
        raise typer.Exit(0)

    # Confirm changes
    console.print()
    apply = typer.confirm("Apply changes?", default=True)

    if not apply:
        console.print("Aborted.")
        raise typer.Exit(0)

    # Apply changes
    apply_changes(project_path, changes)

    # Install pre-commit hooks if git repo
    if info.is_git_repo and shutil.which("pre-commit"):
        try:
            subprocess.run(
                ["pre-commit", "install"],
                cwd=project_path,
                capture_output=True,
                check=True,
            )
            print_ok("Installed pre-commit hooks")
        except subprocess.CalledProcessError:
            print_warning("Failed to install pre-commit hooks")

    # Run security scan
    if not no_scan and shutil.which("trivy"):
        console.print()
        console.print("Running security scan...")
        try:
            result = subprocess.run(
                ["trivy", "fs", "--scanners", "secret", "--quiet", str(project_path)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                print_ok("No new issues found")
            else:
                print_warning("Issues found - review output above")
        except Exception:
            print_warning("Scan failed")

    # Display remaining issues
    if issues:
        console.print()
        console.print(f"[yellow][!] {len(issues)} pre-existing issues remain[/yellow]")

    # Done
    console.print()
    console.print("[green]Security configuration applied![/green]")
    console.print()
    console.print("Next steps:")
    if issues:
        console.print("  1. Review and fix the issues found above")
        console.print("  2. Review generated CLAUDE.md constraints")
        console.print("  3. Commit security configuration:")
    else:
        console.print("  1. Review generated CLAUDE.md constraints")
        console.print("  2. Commit security configuration:")
    console.print('     git add -A && git commit -m "Add plsec security configuration"')

    raise typer.Exit(0)
