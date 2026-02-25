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
# 1. Install global configuration, wrapper scripts, and shell aliases
plsec install

# 2. Source your shell to activate aliases (or restart terminal)
source ~/.zshrc

# 3. Check system dependencies
plsec doctor

# 4. Initialize a project
plsec create my-api        # new project
plsec secure               # existing project

# 5. Run security scans
plsec scan

# 6. Launch agents with session logging and audit
claude-safe                # wrapper around claude with logging
opencode-safe              # wrapper around opencode with logging
```

## Commands

| Command             | Description                                        |
|---------------------|----------------------------------------------------|
| `plsec install`     | Deploy global configs, wrapper scripts, and aliases |
| `plsec create`      | Create a new project with security built-in        |
| `plsec secure`      | Add security to an existing project                |
| `plsec doctor`      | Check system dependencies and configuration        |
| `plsec init`        | Initialize project security configuration          |
| `plsec scan`        | Run security scanners (Trivy, Bandit, Semgrep). See [Scanner Limitations](docs/scanner-limitations.md) |
| `plsec validate`    | Validate configuration files                       |
| `plsec proxy`       | Manage Pipelock runtime proxy                      |
| `plsec integrity`   | Workspace integrity monitoring                     |
| `plsec reset`       | Reset to factory defaults (preserves logs)          |
| `plsec uninstall`   | Remove all plsec artifacts from the system         |

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

## Wrapper Scripts and Aliases

`plsec install` deploys wrapper scripts that add session logging and
audit capabilities when running AI coding agents:

```bash
# Deploy wrappers, configs, and shell aliases
plsec install

# Or deploy without modifying your shell RC file
plsec install --no-aliases
```

**What gets deployed to `~/.peerlabs/plsec/`:**

| File                  | Purpose                                                                   |
|-----------------------|---------------------------------------------------------------------------|
| `claude-wrapper.sh`   | Session logging, config auto-deploy, audit via `CLAUDE_CODE_SHELL_PREFIX` |
| `opencode-wrapper.sh` | Session logging, config auto-deploy                                       |
| `plsec-audit.sh`      | Per-command audit logging (every shell command Claude executes)           |

**Shell aliases added to `~/.zshrc` (or `~/.bashrc`):**

| Alias           | Target                                  |
|-----------------|-----------------------------------------|
| `claude-safe`   | `~/.peerlabs/plsec/claude-wrapper.sh`   |
| `opencode-safe` | `~/.peerlabs/plsec/opencode-wrapper.sh` |
| `plsec-logs`    | `tail -f ~/.peerlabs/plsec/logs/*.log`  |
| `plsec-status`  | `~/.peerlabs/plsec/plsec-status.sh`     |

The wrappers provide two tiers of logging:

- **Tier 1** (both agents): Git branch/SHA, agent version, preset,
  session duration, auto-deploy of agent configs to project
- **Tier 2** (Claude only): `CLAUDE_CODE_SHELL_PREFIX` audit logging --
  every shell command the LLM executes is logged to a separate daily
  audit file

Use `plsec uninstall` to remove wrappers and aliases cleanly.

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
make setup                     # or: uv sync --dev

# Common workflows
make dev-check                 # Quick local loop (lint + types + tests + build)
make ci                        # Full CI pipeline (lint + types + all tests + golden)
make all                       # Alias for make ci

# Individual targets
make lint                      # All linting (Python + templates + bootstrap)
make check                     # ty type checker
make test                      # All tests (pytest + BATS)
make test-python               # pytest only
make build                     # Assemble bootstrap.sh from templates
make verify                    # Ensure build matches promoted reference
make scan                      # Run plsec scan on own codebase

# Lifecycle (modifies ~/.peerlabs/plsec)
make install                   # Deploy global configs
make deploy                    # Force redeploy global configs
make reset                     # Factory reset (preserves logs)
```

### Testing

The test suite has two layers:

- **pytest** (666 tests, 77% coverage) -- Python CLI across 3 tiers:
  pure logic (config, tools, templates, integrity, validation),
  filesystem with `tmp_path` (detector, init, create, output, install,
  reset, uninstall, inventory), and subprocess mocking (scan, doctor,
  proxy, secure). Includes registry module tests for agents, scanners,
  processes, and health. Wrapper deployment and shell alias
  injection/removal are tested with full filesystem isolation.
- **BATS** (172 tests) -- Bootstrap shell script: 75 unit tests
  (directory structure, agent configs, wrapper scripts, logging fields),
  53 integration tests (idempotency, agent switching, dry-run), and
  44 assembler escaping tests.

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

| Tool   | Purpose       | Command                                        |
|--------|---------------|------------------------------------------------|
| ruff   | Lint + format | `uv run ruff check .` / `uv run ruff format .` |
| ty     | Type checking | `uv run ty check src/`                         |
| pytest | Python tests  | `uv run pytest tests/ -v`                      |
| BATS   | Shell tests   | `make test-unit` / `make test-integration`     |

## Documentation

Comprehensive guides and references:

- [Scanner Limitations](docs/scanner-limitations.md) - Detection tradeoffs and false positive/negative rates
- [CI/CD Integration](docs/ci-cd-integration.md) - Integrating plsec-status into your pipeline
- [Troubleshooting](docs/troubleshooting.md) - Common issues and solutions
- [plsec-status Command](docs/commands/plsec-status.md) - Health check reference

For command-specific help:
```bash
plsec --help
plsec scan --help
plsec-status --help
```

## License

MIT License. See [LICENSE](LICENSE) for details.

## References

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Pipelock](https://github.com/luckyPipewrench/pipelock)
- [Anthropic Claude Code Sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing)
