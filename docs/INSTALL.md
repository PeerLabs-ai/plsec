# Installation Guide

## Bootstrap (zero dependencies, quick start)

The fastest way to get plsec protection. Requires only Bash and curl.

```bash
curl -fsSL https://raw.githubusercontent.com/PeerLabs-ai/plsec/main/build/bootstrap.sh | bash
```

This creates `~/.peerlabs/plsec/`, deploys agent configs, wrapper scripts,
shell aliases, and Trivy secret-scanning rules. Suitable for CI
environments and quick onboarding.

After bootstrap:
```bash
source ~/.zshrc         # activate aliases (or restart terminal)
claude-safe             # run Claude Code with session logging
opencode-safe           # run OpenCode with session logging
plsec-status            # check health
```

## From Source (contributor path)

For contributing or running the full Python CLI:

```bash
git clone https://github.com/PeerLabs-ai/plsec
cd plsec
make setup              # installs dev dependencies via uv
make ci                 # lint + types + build + all tests + golden
```

This gives you the `plsec` CLI plus the full development toolchain.

```bash
# Deploy global configs, wrappers, and shell aliases
uv run plsec install

# Verify
uv run plsec doctor
uv run plsec scan .
```

## PyPI / Homebrew

Coming soon. Not yet published.

## Required and Optional Tools

plsec orchestrates external security tools. Run `plsec doctor` to check
which are installed.

### Required

| Tool  | Purpose                 | Install                                                                |
|-------|-------------------------|------------------------------------------------------------------------|
| trivy | Secret + misconfig scan | `brew install trivy` / [GitHub](https://github.com/aquasecurity/trivy) |

### Optional

| Tool     | Purpose                 | Install                                                |
|----------|-------------------------|--------------------------------------------------------|
| bandit   | Python security scanner | `pip install bandit`                                   |
| semgrep  | Multi-language scanner  | `pip install semgrep`                                  |
| pipelock | Runtime egress proxy    | `brew install pipelock` (if available)                 |
| podman   | Container isolation     | `brew install podman` / [podman.io](https://podman.io) |

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
# CLI (if installed from source)
uv pip uninstall plsec

# Remove plsec data (optional -- preserves nothing)
rm -rf ~/.peerlabs/plsec

# Or use the built-in uninstall (removes wrappers, aliases, configs)
plsec uninstall
```
