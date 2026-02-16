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

| Layer | Name      | Tools/Techniques                                                |
|-------|-----------|-----------------------------------------------------------------|
| 1     | STATIC    | Trivy, Bandit, Semgrep, detect-secrets                          |
| 2     | CONFIG    | CLAUDE.md constraints, opencode.json permissions, deny patterns |
| 3     | ISOLATION | Podman/Docker containers, macOS sandbox                         |
| 4     | RUNTIME   | Pipelock egress proxy, DLP, response scanning                   |
| 5     | AUDIT     | Structured logging, integrity monitoring                        |

## Architecture

### Two Components

1. **Python CLI (`plsec`)** - User-facing tool for setup, scanning, validation
2. **Bootstrap shell script (`bootstrap.sh`)** - Standalone
   installer/configurator, assembled from templates, tested with BATS

### Security Presets

| Preset     | Description                                |
|------------|--------------------------------------------|
| `minimal`  | Secret scanning only                       |
| `balanced` | Full static analysis, audit logging        |
| `strict`   | Add container isolation and Pipelock proxy |
| `paranoid` | Strict mode with network isolation         |

### Design Principles

- **Layered architecture**: Each security layer is independent and composable
- **Preset-driven**: Progressive security levels from minimal to paranoid
- **Configuration-first**: `plsec.yaml` drives behavior, integrates with agent configs
- **Deep modules**: Core logic in `core/` (config, tools, output), thin command
  wrappers in `commands/`
- **Template-based bootstrap**: Shell script assembled from modular templates
  for maintainability
- **Dual test strategy**: pytest for Python, BATS for shell scripts

## TODOs

### High Priority

- [ ] **Path migration**: Unify Python CLI to use `~/.peerlabs/plsec` (see below)
- [ ] Build pytest test cases for Python CLI component (see TESTING.md)
- [ ] Verify ty type checker integration works correctly
- [ ] **Unify build system through Make** (see below)

### Medium Priority

- [ ] **mkdocs setup**: Wire up documentation site (see below)
- [ ] Document bootstrap.sh component and template system
- [ ] Add integration tests for plsec commands

### Low Priority

- [ ] Add CSS/HTML guidelines back to AGENTS.md if web components are added

## Path Migration: `~/.plsec` to `~/.peerlabs/plsec`

The bootstrap shell scripts already use `~/.peerlabs/plsec` consistently.
The Python CLI still uses the old `~/.plsec` path. These must be unified.

### Root cause

`get_plsec_home()` in `src/plsec/core/config.py:187` returns
`Path.home() / ".plsec"`. All callers resolve through this function.

### Files requiring changes

**Python code (functional changes):**

| File                             | Lines                 | What                                                                                          |
|----------------------------------|-----------------------|-----------------------------------------------------------------------------------------------|
| `src/plsec/core/config.py`       | 49, 97, 113, 127, 187 | `get_plsec_home()`, `PlsecSettings`, `AuditLayerConfig` default, `find_config_file` docstring |
| `src/plsec/configs/templates.py` | 86, 226, 298          | Hardcoded strings in CLAUDE_MD_BALANCED, PLSEC_YAML_TEMPLATE, PRE_COMMIT_HOOK                 |
| `src/plsec/commands/init.py`     | 120, 132, 151         | Help text and display strings                                                                 |
| `src/plsec/commands/create.py`   | 532                   | Generated YAML content                                                                        |
| `src/plsec/commands/secure.py`   | 224                   | Generated YAML content                                                                        |
| `src/plsec/commands/validate.py` | 202                   | User-facing hint message                                                                      |

**Documentation and packaging:**

| File                | What                | Lines |
|---------------------|---------------------|-------|
| `homebrew/plsec.rb` | Caveats text        | 81    |
| `HANDOFF.md`        | Config search docs  | 199   |
| `README.md`         | Example YAML config | 152   |

**Already correct** (no changes needed):
- All bootstrap templates, shell scripts, BATS tests use `~/.peerlabs/plsec`
- `CLAUDE.md` already uses `~/.peerlabs/plsec`
- `.plsec-manifest.json` is a per-workspace filename, not a home directory path

## Makefile Unification

Currently there are two entry points: Make (bootstrap side) and pytest/uv
(Python side). Unify everything under Make so `make all` works end-to-end.

### Proposed target map

| Target                  | What                                     | Side      |
|-------------------------|------------------------------------------|-----------|
| `make all`              | lint + check + test + build + verify     | Both      |
| `make ci`               | Full CI pipeline (non-interactive)       | Both      |
| `make setup`            | `uv pip install -e ".[dev]"`             | Python    |
| `make lint`             | All linting (Python + templates)         | Both      |
| `make lint-python`      | `ruff check .` + `ruff format . --check` | Python    |
| `make lint-templates`   | JSON/YAML/shell template validation      | Bootstrap |
| `make check`            | `ty check src/`                          | Python    |
| `make format`           | `ruff format .` (mutating, not in CI)    | Python    |
| `make test`             | All tests (Python + BATS)                | Both      |
| `make test-python`      | `pytest tests/ --ignore=tests/bats`      | Python    |
| `make test-unit`        | BATS unit tests                          | Bootstrap |
| `make test-integration` | BATS integration tests                   | Bootstrap |
| `make build`            | Assemble bootstrap.sh                    | Bootstrap |
| `make verify`           | Build matches promoted reference         | Bootstrap |
| `make promote`          | Copy build to bin/                       | Bootstrap |
| `make golden`           | Regenerate golden fixtures               | Bootstrap |
| `make clean`            | Remove all artifacts + venvs             | Both      |
| `make docs`             | `mkdocs serve` (local preview)           | Docs      |
| `make docs-build`       | `mkdocs build` (static site)             | Docs      |

### Design notes

- `make format` is mutating (changes files) so excluded from CI; `make lint`
  is read-only (includes `ruff format . --check`)
- `make test-python` uses plain `pytest` (assumes `make setup` has been run)
- `make ci` is the full non-interactive pipeline including `make check` (ty)
  and `make lint-python`

## mkdocs Setup

No mkdocs configuration exists yet. The `docs/` directory contains internal
design/handoff docs but no user-facing documentation or `mkdocs.yml`.

### What's needed

1. `mkdocs.yml` at project root
2. `mkdocs-material` + optional `mkdocstrings[python]` in pyproject.toml
   as a `docs` optional dependency group
3. `docs/index.md` as landing page (derive from README.md)
4. Reorganize `docs/` into user docs vs contributor/internal docs

### Proposed docs structure

```
docs/
├── index.md                     # Home (from README.md)
├── getting-started.md           # Installation + quick start
├── commands/                    # Per-command reference
│   ├── create.md
│   ├── secure.md
│   ├── doctor.md
│   ├── init.md
│   ├── scan.md
│   ├── validate.md
│   ├── proxy.md
│   └── integrity.md
├── configuration.md             # plsec.yaml, presets, layers
├── security-model.md            # 5-layer model explanation
├── development/                 # Contributor docs
│   ├── testing.md               # From TESTING.md
│   ├── bootstrap.md             # From HANDOFF-bootstrap.md
│   ├── build-process.md         # From build-process-design.md
│   └── design-create-secure.md  # From DESIGN-CREATE-SECURE.md
├── roadmap.md                   # Feature roadmap
└── reference/                   # API reference (optional, via mkdocstrings)
```

### Approach

Start with skeleton: `mkdocs.yml`, `docs/index.md`, wire existing docs into
nav. User-facing command docs added incrementally as CLI stabilizes.

## Outstanding Items

_(Items requiring decisions or external input)_

- Bootstrap.sh component coverage - to be discussed
- User selection of equivalent tools (linters, type checkers, etc.) should be
  considered for a future release. Currently plsec ships opinionated defaults
  (ruff for linting/formatting, ty for type checking).

## References

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Pipelock](https://github.com/luckyPipewrench/pipelock)
- [Anthropic Claude Code Sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing)
- [John Ousterhout - A Philosophy of Software Design](https://web.stanford.edu/~ouster/cgi-bin/book.php)
