"""
plsec create - Create a new secure project.

Scaffolds a new project with security built-in from day one.
"""

import subprocess
import shutil
from pathlib import Path
from typing import Literal

import typer

from plsec.core.config import PlsecConfig, save_config, get_plsec_home
from plsec.core.output import console, print_ok, print_error, print_warning, print_info
from plsec.core.wizard import (
    Wizard,
    WizardState,
    PROJECT_TYPE_CHOICES,
    AGENT_CHOICES,
    PRESET_CHOICES,
    SENSITIVE_DATA_CHOICES,
    CLOUD_PROVIDER_CHOICES,
)
from plsec.configs.templates import (
    CLAUDE_MD_STRICT,
    CLAUDE_MD_BALANCED,
    OPENCODE_JSON_STRICT,
    OPENCODE_JSON_BALANCED,
)

app = typer.Typer(
    help="Create a new secure project.",
    no_args_is_help=True,
)


ProjectType = Literal["python", "node", "go", "rust", "mixed", "other"]
Preset = Literal["minimal", "balanced", "strict", "paranoid"]
AgentType = Literal["claude", "opencode", "both"]


def create_python_template(project_path: Path, name: str) -> None:
    """Create Python project structure."""
    # Convert name to valid Python package name
    pkg_name = name.replace("-", "_").replace(" ", "_").lower()

    # Create directories
    (project_path / "src" / pkg_name).mkdir(parents=True)
    (project_path / "tests").mkdir(parents=True)

    # Create __init__.py
    (project_path / "src" / pkg_name / "__init__.py").write_text(
        f'"""{name} package."""\n\n__version__ = "0.1.0"\n'
    )
    (project_path / "tests" / "__init__.py").write_text('"""Tests for the package."""\n')

    # Create pyproject.toml
    pyproject = f'''[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "{name}"
version = "0.1.0"
description = ""
readme = "README.md"
requires-python = ">=3.12"
dependencies = []

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "ruff>=0.4",
]

[tool.hatch.build.targets.wheel]
packages = ["src/{pkg_name}"]

[tool.ruff]
target-version = "py312"
line-length = 100

[tool.pytest.ini_options]
testpaths = ["tests"]
'''
    (project_path / "pyproject.toml").write_text(pyproject)


def create_node_template(project_path: Path, name: str) -> None:
    """Create Node.js project structure."""
    (project_path / "src").mkdir(parents=True)

    # Create package.json
    package_json = f'''{{
  "name": "{name}",
  "version": "0.1.0",
  "description": "",
  "main": "src/index.js",
  "scripts": {{
    "start": "node src/index.js",
    "test": "echo \\"No tests yet\\""
  }},
  "keywords": [],
  "license": "ISC"
}}
'''
    (project_path / "package.json").write_text(package_json)

    # Create index.js
    (project_path / "src" / "index.js").write_text('// Entry point\nconsole.log("Hello");\n')


def create_go_template(project_path: Path, name: str) -> None:
    """Create Go project structure."""
    # Create go.mod
    go_mod = f"""module {name}

go 1.22
"""
    (project_path / "go.mod").write_text(go_mod)

    # Create main.go
    main_go = """package main

import "fmt"

func main() {
	fmt.Println("Hello")
}
"""
    (project_path / "main.go").write_text(main_go)


def create_gitignore(project_path: Path, project_type: str, providers: list[str]) -> None:
    """Create security-enhanced .gitignore."""
    common = """# === plsec security patterns ===
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

    python_patterns = """# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
.venv/
venv/
.eggs/
*.egg-info/
dist/
build/
.pytest_cache/
.mypy_cache/
.ruff_cache/
"""

    node_patterns = """# Node.js
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*
.npm
.yarn/
dist/
build/
"""

    go_patterns = """# Go
*.exe
*.exe~
*.dll
*.so
*.dylib
*.test
*.out
vendor/
"""

    content = common

    if project_type == "python":
        content += python_patterns
    elif project_type == "node":
        content += node_patterns
    elif project_type == "go":
        content += go_patterns
    elif project_type == "mixed":
        content += python_patterns + node_patterns + go_patterns

    (project_path / ".gitignore").write_text(content)


def create_pre_commit_config(project_path: Path, project_type: str) -> None:
    """Create .pre-commit-config.yaml."""
    config = """repos:
  # Security: Secret scanning
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
        exclude: package-lock.json|yarn.lock

  # Security: Trivy
  - repo: local
    hooks:
      - id: trivy-secrets
        name: Trivy Secret Scan
        entry: trivy fs --scanners secret --exit-code 1
        language: system
        pass_filenames: false

"""

    if project_type == "python":
        config += """  # Python: Linting
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.4.0
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format

  # Python: Security
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.8
    hooks:
      - id: bandit
        args: ['-ll', '-r', 'src/']
"""

    (project_path / ".pre-commit-config.yaml").write_text(config)


def create_readme(project_path: Path, name: str, project_type: str) -> None:
    """Create README.md."""
    readme = f"""# {name}

## Development

### Setup

```bash
# Clone and install
git clone <repository-url>
cd {name}
"""

    if project_type == "python":
        readme += """
# Using uv (recommended)
uv pip install -e ".[dev]"

# Or using pip
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
```
"""
    elif project_type == "node":
        readme += """
npm install
```

### Running

```bash
npm start
```
"""
    elif project_type == "go":
        readme += """
go mod download
```

### Running

```bash
go run .
```
"""

    readme += """
## Security

This project uses [plsec](https://github.com/peerlabs/plsec) for security.

```bash
# Check security status
plsec doctor

# Run security scan
plsec scan

# Validate configuration
plsec validate
```

See `CLAUDE.md` for AI assistant security constraints.
"""

    (project_path / "README.md").write_text(readme)


def run_wizard() -> WizardState:
    """Run the interactive wizard."""
    wizard = Wizard("plsec create - New Secure Project")
    wizard.header(total_steps=5)

    # Step 1: Project type
    wizard.step_header("Project Type")
    project_type = wizard.select(
        "What kind of project are you building?",
        choices=PROJECT_TYPE_CHOICES,
        default="python",
    )
    wizard.state.project_type = project_type

    # Step 2: AI assistants
    wizard.step_header("AI Assistants")
    agents = wizard.multi_select(
        "Which AI coding assistants will you use?",
        choices=AGENT_CHOICES,
    )
    wizard.state.agents = agents

    # Step 3: Security posture
    wizard.step_header("Security Posture")
    preset = wizard.select(
        "How strict should security controls be?",
        choices=PRESET_CHOICES,
        default="balanced",
    )
    wizard.info("You can always adjust this later in plsec.yaml")
    wizard.state.preset = preset

    # Step 4: Sensitive data
    wizard.step_header("Sensitive Data")
    sensitive = wizard.multi_select(
        "What sensitive data will this project handle?",
        choices=SENSITIVE_DATA_CHOICES,
    )
    wizard.state.sensitive_data = sensitive

    # Step 5: Cloud providers
    wizard.step_header("Cloud Providers")
    providers = wizard.multi_select(
        "Which cloud providers will you use?",
        choices=CLOUD_PROVIDER_CHOICES,
    )
    wizard.state.cloud_providers = providers

    return wizard.state


@app.callback(invoke_without_command=True)
def create(
    name: str = typer.Argument(..., help="Project name (creates directory)"),
    template: ProjectType = typer.Option(
        "python",
        "--template",
        "-t",
        help="Project template: python, node, go, rust, mixed, other",
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
        help="Skip wizard, use defaults/flags only",
    ),
    no_git: bool = typer.Option(
        False,
        "--no-git",
        help="Don't initialize git repository",
    ),
    output: Path = typer.Option(
        Path("."),
        "--output",
        "-o",
        help="Parent directory for the project",
    ),
) -> None:
    """
    Create a new project with security built-in.

    Scaffolds directory structure, security configuration, and tooling.
    """
    # Determine project path
    project_path = output.resolve() / name

    # Check if directory exists
    if project_path.exists():
        print_error(f"Directory already exists: {project_path}")
        console.print("\nUse 'plsec secure' to add security to an existing project.")
        raise typer.Exit(1)

    # Run wizard or use CLI options
    if no_wizard:
        state = WizardState(
            project_name=name,
            project_type=template,
            agents=["claude", "opencode"] if agent == "both" else [agent],
            preset=preset,
        )
    else:
        state = run_wizard()
        state.project_name = name
        # Override with CLI options if provided
        if template != "python":  # non-default means user specified
            state.project_type = template

        # Show summary
        console.print("\n[bold]Summary[/bold]")
        console.print("-" * 40)
        console.print(f"  Project:     {name}")
        console.print(f"  Type:        {state.project_type}")
        console.print(f"  Agents:      {', '.join(state.agents)}")
        console.print(f"  Posture:     {state.preset}")
        if state.sensitive_data:
            console.print(f"  Data:        {', '.join(state.sensitive_data)}")
        if state.cloud_providers:
            console.print(f"  Providers:   {', '.join(state.cloud_providers)}")
        console.print()

        if not typer.confirm("Create project?", default=True):
            console.print("Aborted.")
            raise typer.Exit(0)

    # Create project
    console.print(f"\nCreating {project_path}/")

    # Create directory
    project_path.mkdir(parents=True)
    print_ok("Created directory structure")

    # Create language-specific template
    if state.project_type == "python":
        create_python_template(project_path, name)
        print_ok("Created Python project structure")
    elif state.project_type == "node":
        create_node_template(project_path, name)
        print_ok("Created Node.js project structure")
    elif state.project_type == "go":
        create_go_template(project_path, name)
        print_ok("Created Go project structure")

    # Determine if strict mode
    is_strict = state.preset in ("strict", "paranoid")

    # Create CLAUDE.md
    if "claude" in state.agents or "both" in state.agents:
        claude_content = CLAUDE_MD_STRICT if is_strict else CLAUDE_MD_BALANCED
        (project_path / "CLAUDE.md").write_text(claude_content)
        print_ok("Created CLAUDE.md")

    # Create opencode.json
    if "opencode" in state.agents or "both" in state.agents:
        opencode_content = OPENCODE_JSON_STRICT if is_strict else OPENCODE_JSON_BALANCED
        (project_path / "opencode.json").write_text(opencode_content)
        print_ok("Created opencode.json")

    # Create plsec.yaml
    # (simplified - would use config builder in full implementation)
    plsec_yaml = f"""version: 1

project:
  name: {name}
  type: {state.project_type}

agent:
  type: {"claude-code" if "claude" in state.agents else "opencode"}
  config_path: ./CLAUDE.md

layers:
  static:
    enabled: true
    scanners:
      - trivy-secrets
      - trivy-misconfig
      {"- bandit" if state.project_type == "python" else ""}
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
    (project_path / "plsec.yaml").write_text(plsec_yaml)
    print_ok("Created plsec.yaml")

    # Create .gitignore
    create_gitignore(project_path, state.project_type, state.cloud_providers)
    print_ok("Created .gitignore (security-enhanced)")

    # Create pre-commit config
    create_pre_commit_config(project_path, state.project_type)
    print_ok("Created .pre-commit-config.yaml")

    # Create trivy config
    trivy_dir = project_path / "trivy"
    trivy_dir.mkdir()
    plsec_home = get_plsec_home()
    trivy_secret = plsec_home / "trivy" / "trivy-secret.yaml"
    if trivy_secret.exists():
        shutil.copy(trivy_secret, trivy_dir / "trivy-secret.yaml")
    else:
        # Create minimal config
        (trivy_dir / "trivy-secret.yaml").write_text("# Trivy secret scanning config\n")
    print_ok("Created trivy/trivy-secret.yaml")

    # Create README
    create_readme(project_path, name, state.project_type)
    print_ok("Created README.md")

    # Initialize git
    if not no_git:
        if shutil.which("git"):
            try:
                subprocess.run(
                    ["git", "init"],
                    cwd=project_path,
                    capture_output=True,
                    check=True,
                )
                print_ok("Initialized git repository")

                # Install pre-commit hooks
                if shutil.which("pre-commit"):
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
                else:
                    print_warning("pre-commit not found, skipping hook installation")

            except subprocess.CalledProcessError:
                print_warning("Failed to initialize git repository")
        else:
            print_warning("git not found, skipping repository initialization")

    # Done
    console.print()
    console.print("[green]Project created successfully![/green]")
    console.print()
    console.print("Next steps:")
    console.print(f"  cd {name}")
    console.print("  plsec doctor          # Verify dependencies")
    console.print("  plsec scan            # Run initial security scan")

    raise typer.Exit(0)
