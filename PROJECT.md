# PROJECT.md - plsec Project Overview

## What is plsec?

A defense-in-depth security framework for AI coding assistants (Claude Code, Opencode, Codex, etc.).

## Problem Statement

AI coding agents have broad filesystem and network access. Without guardrails, they can:
- Leak secrets to external services
- Execute malicious code from compromised dependencies
- Modify sensitive configuration files
- Exfiltrate data via network calls

## 5-Layer Security Model

| Layer | Name | Tools/Techniques |
|-------|------|------------------|
| 1 | STATIC | Trivy, Bandit, Semgrep, detect-secrets |
| 2 | CONFIG | CLAUDE.md constraints, opencode.json permissions, deny patterns |
| 3 | ISOLATION | Podman/Docker containers, macOS sandbox |
| 4 | RUNTIME | Pipelock egress proxy, DLP, response scanning |
| 5 | AUDIT | Structured logging, integrity monitoring |

## Architecture

### Two Components

1. **Python CLI (`plsec`)** - User-facing tool for setup, scanning, validation
2. **Bootstrap shell script (`bootstrap.sh`)** - Standalone installer/configurator, assembled from templates, tested with BATS

### Security Presets

| Preset | Description |
|--------|-------------|
| `minimal` | Secret scanning only |
| `balanced` | Full static analysis, audit logging |
| `strict` | Add container isolation and Pipelock proxy |
| `paranoid` | Strict mode with network isolation |

### Design Principles

- **Layered architecture**: Each security layer is independent and composable
- **Preset-driven**: Progressive security levels from minimal to paranoid
- **Configuration-first**: `plsec.yaml` drives behavior, integrates with agent configs
- **Deep modules**: Core logic in `core/` (config, tools, output), thin command wrappers in `commands/`
- **Template-based bootstrap**: Shell script assembled from modular templates for maintainability
- **Dual test strategy**: pytest for Python, BATS for shell scripts

## TODOs

### High Priority

- [ ] Build pytest test cases for Python CLI component
- [ ] Verify ty type checker integration works correctly

### Medium Priority

- [ ] Document bootstrap.sh component and template system
- [ ] Add integration tests for plsec commands

### Low Priority

- [ ] Add CSS/HTML guidelines back to AGENTS.md if web components are added

## Outstanding Items

_(Items requiring decisions or external input)_

- Bootstrap.sh component coverage - to be discussed

## References

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Pipelock](https://github.com/luckyPipewrench/pipelock)
- [Anthropic Claude Code Sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing)
- [John Ousterhout - A Philosophy of Software Design](https://web.stanford.edu/~ouster/cgi-bin/book.php)
