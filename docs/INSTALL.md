# Installation Guide

## Quick Start (Bootstrap)

The fastest way to get plsec protection on a project. Zero dependencies
beyond bash and curl.

```bash
curl -fsSL https://raw.githubusercontent.com/peerlabs/plsec/main/bin/bootstrap.default.sh | bash
```

This creates the `~/.peerlabs/plsec/` directory structure, deploys agent
configs, wrapper scripts, shell aliases, and Trivy secret-scanning rules.
Suitable for CI environments and quick onboarding.

## Python CLI

The full-featured CLI provides scanning, validation, integrity monitoring,
proxy management, and (in v0.2.0) managed agent execution.

### uv (Recommended)

[uv](https://docs.astral.sh/uv/) is the recommended installer. It
handles Python version management and creates isolated tool environments
automatically.

```bash
# Install as a global tool
uv tool install plsec

# Or run without installing (ephemeral)
uvx plsec doctor

# Verify
plsec --version
plsec doctor
```

### pipx

[pipx](https://pipx.pypa.io/) also installs into isolated environments:

```bash
pipx install plsec
```

### pip

Direct pip install works but pollutes the global Python environment.
Prefer uv or pipx.

```bash
# In a virtual environment (recommended over global)
python -m venv .venv
source .venv/bin/activate
pip install plsec
```

### Homebrew (macOS)

A Homebrew formula exists but is not yet published to a public tap.
SHA256 values are placeholders. To test locally:

```bash
brew install --build-from-source ./homebrew/plsec.rb
```

Once the tap is published:

```bash
brew tap peerlabs/tap
brew install plsec
```

Homebrew installs Trivy automatically as a dependency. Optional tools:

```bash
brew install pipelock podman bandit
```

## Development Install

For contributing or running from source:

```bash
git clone https://github.com/peerlabs/plsec
cd plsec

# Install with dev dependencies
uv pip install -e ".[dev]"

# Or with pip
pip install -e ".[dev]"

# Verify
make test-python     # 426+ pytest tests
make lint            # ruff + template validation
make check           # ty type checking
make ci              # Full pipeline
```

### Build and Test Distribution

```bash
# Build sdist and wheel
make build-dist

# Test a clean install from the built wheel
make install-test
```

## Required and Optional Tools

plsec orchestrates external security tools. Run `plsec doctor` to check
which are installed.

### Required

| Tool   | Purpose                | Install                         |
|--------|------------------------|---------------------------------|
| trivy  | Secret + misconfig scan | `brew install trivy` / [GitHub](https://github.com/aquasecurity/trivy) |

### Optional

| Tool      | Purpose                 | Install                            |
|-----------|-------------------------|------------------------------------|
| bandit    | Python security scanner | `pip install bandit`               |
| semgrep   | Multi-language scanner  | `pip install semgrep`              |
| pipelock  | Runtime egress proxy    | `brew install pipelock` (if available) |
| podman    | Container isolation     | `brew install podman` / [podman.io](https://podman.io) |

## Post-Install

After installing, run through the basic setup:

```bash
# Check dependencies
plsec doctor

# Initialize plsec for a project
cd your-project
plsec init

# Or create a new project with security baked in
plsec create my-api

# Run a security scan
plsec scan .
```

## Uninstall

```bash
# uv
uv tool uninstall plsec

# pipx
pipx uninstall plsec

# pip
pip uninstall plsec

# Homebrew
brew uninstall plsec

# Remove plsec data (optional)
rm -rf ~/.peerlabs/plsec
```
