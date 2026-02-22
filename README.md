# plsec - Security Tooling for AI Coding Assistants

A defense-in-depth security framework for AI coding assistants
(Claude Code, OpenCode, Gemini CLI, and others).

plsec wraps Trivy, Bandit, Semgrep, and other scanners into a unified
CLI with progressive security presets, agent-specific configuration
management, and runtime monitoring via Pipelock.  Agents and scanners
are declared in registries so new tools can be added in one place
without modifying command logic.

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
    log_dir: ~/.peerlabs/plsec/logs
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

Make is the unified entry point for all build, test, and lint operations.

```bash
# Setup
uv pip install -e ".[dev]"    # or: pip install -e ".[dev]"

# Full CI pipeline (lint + type check + build + all tests)
make ci

# Individual targets
make lint                      # ruff check + ruff format --check
make check                     # ty type checker
make test-python               # pytest (426 tests)
make test-unit                 # BATS unit tests (34 tests)
make test-integration          # BATS integration tests (53 tests)
make test                      # All BATS tests
make build                     # Assemble bootstrap.sh from templates
make verify                    # Ensure build matches promoted reference
```

### Testing

The test suite has two layers:

- **pytest** (426 tests, 69% coverage) -- Python CLI across 3 tiers:
  pure logic (config, tools, templates, integrity, validation),
  filesystem with `tmp_path` (detector, init, create, output),
  and subprocess mocking (scan, doctor, proxy, secure). Includes
  registry module tests for agents, scanners, processes, and health.
- **BATS** (87 tests) -- Bootstrap shell script: directory structure
  creation, agent config generation, wrapper script assembly, dry-run
  mode, idempotency, and template escaping.

```bash
# Run Python tests with coverage
uv run pytest --cov=plsec --cov-report=html

# Run a single test file
uv run pytest tests/test_config.py -v

# Run BATS tests
make test-unit
make test-integration
```

### Quality Tools

| Tool | Purpose | Command |
|------|---------|---------|
| ruff | Lint + format | `uv run ruff check .` / `uv run ruff format .` |
| ty | Type checking | `uv run ty check src/` |
| pytest | Python tests | `uv run pytest tests/ -v` |
| BATS | Shell tests | `make test-unit` / `make test-integration` |

## License

MIT License. See [LICENSE](LICENSE) for details.

## References

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Pipelock](https://github.com/luckyPipewrench/pipelock)
- [Anthropic Claude Code Sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing)
