# plsec - Security Tooling for AI Coding Assistants

A defense-in-depth security framework for Claude Code, Opencode, and other AI coding assistants.

## Installation

### Using uv (Recommended)

```bash
# Install globally with uv
uv tool install plsec

# Or run without installing
uvx plsec doctor

# Development install
uv pip install -e ".[dev]"
```

### Using pipx

```bash
# Install in isolated environment
pipx install plsec
```

### Using pip

```bash
# Install globally (not recommended)
pip install plsec

# Install in virtual environment
python -m venv .venv
source .venv/bin/activate
pip install plsec
```

### Using Homebrew (macOS)

```bash
# Add the tap
brew tap peerlabs/tap

# Install plsec with dependencies
brew install plsec

# Or install with optional tools
brew install plsec pipelock podman
```

### From Source

```bash
# Clone and install with uv
git clone https://github.com/peerlabs/plsec
cd plsec
uv pip install -e ".[dev]"

# Or with pip
pip install -e ".[dev]"
```

## Quick Start

```bash
# Check system dependencies
plsec doctor

# Create a new secure project
plsec create my-api

# Or secure an existing project
plsec secure

# Run security scans
plsec scan

# Validate configuration
plsec validate
```

## Commands

| Command           | Description                                    |
|-------------------|------------------------------------------------|
| `plsec create`    | Create a new project with security built-in    |
| `plsec secure`    | Add security to an existing project            |
| `plsec doctor`    | Check system dependencies and configuration    |
| `plsec init`      | Initialize security configuration (low-level)  |
| `plsec scan`      | Run security scanners (Trivy, Bandit, Semgrep) |
| `plsec validate`  | Validate configuration files                   |
| `plsec proxy`     | Manage Pipelock runtime proxy                  |
| `plsec integrity` | Workspace integrity monitoring                 |

## Security Layers

plsec implements a 5-layer security model:

```
Layer 1: STATIC      - Trivy, Bandit, Semgrep, detect-secrets
Layer 2: CONFIG      - CLAUDE.md, opencode.json, deny patterns
Layer 3: ISOLATION   - Podman/Docker containers, macOS sandbox
Layer 4: RUNTIME     - Pipelock egress proxy, DLP, response scanning
Layer 5: AUDIT       - Structured logging, integrity monitoring
```

## Presets

| Preset     | Description                                |
|------------|--------------------------------------------|
| `minimal`  | Secret scanning only                       |
| `balanced` | Full static analysis, audit logging        |
| `strict`   | Add container isolation and Pipelock proxy |
| `paranoid` | Strict mode with network isolation         |

## Configuration

### plsec.yaml

```yaml
version: 1

project:
  name: my-project
  type: python

agent:
  type: claude-code
  config_path: ./CLAUDE.md

layers:
  static:
    enabled: true
    scanners:
      - trivy-secrets
      - trivy-misconfig
      - bandit
      - semgrep

  isolation:
    enabled: false
    runtime: podman

  proxy:
    enabled: false
    binary: pipelock
    mode: balanced

  audit:
    enabled: true
    log_dir: ~/.plsec/logs
    integrity: true
```

## Requirements

### Required
- Python 3.12+
- Trivy

### Optional
- Bandit (Python code analysis)
- Semgrep (multi-language analysis)
- Pipelock (runtime proxy)
- Podman or Docker (container isolation)

## Development

### Using uv (Recommended)

```bash
# Install dev dependencies
uv pip install -e ".[dev]"

# Run tests
uv run pytest

# Run linter
uv run ruff check .

# Run type checker
uv run mypy src/

# Run single command without install
uvx --from . plsec doctor
```

### Using pip

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check .

# Run type checker
mypy src/
```

### Project Scripts

```bash
# These work with both uv and pip once installed
plsec doctor --all      # Full dependency check
plsec init --preset strict
plsec scan --secrets
plsec validate
```

## License

Apache-2.0

## References

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Pipelock](https://github.com/luckyPipewrench/pipelock)
- [Anthropic Claude Code Sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing)
