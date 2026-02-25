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

1. **Python CLI (`plsec`)** - Full-featured security tool for setup,
   scanning, validation, integrity monitoring, proxy management, and
   managed agent execution (`plsec run`, v0.2.0).

2. **Bootstrap shell script (`bootstrap.sh`)** - Zero-dependency
   standalone installer. Creates directory structure, agent configs,
   wrapper scripts, shell aliases, and Trivy configuration. Designed
   for `curl | bash` quick-start.

### How They Relate

Bootstrap is the **quick-start runtime layer**: it installs wrapper
scripts that provide session logging and auto-deploy agent configs.
The Python CLI is the **full-featured analysis and control layer**.

| Capability                | Bootstrap   | CLI         | Status                          |
|---------------------------|-------------|-------------|---------------------------------|
| Directory structure       | Yes         | Yes         | Overlap (same paths)            |
| Agent config templates    | Yes         | Yes         | Overlap (same content)          |
| Wrapper scripts + logging | Yes         | **Planned** | Gap -- `plsec init` to generate |
| Shell aliases             | Yes         | **Planned** | Gap -- `plsec init` to generate |
| Managed agent execution   | No          | **Planned** | `plsec run` command (v0.2.0)    |
| Container isolation       | No          | **Planned** | `plsec run --container`         |
| Structured scanning       | Basic       | Yes         | CLI superior                    |
| Validation, integrity     | No          | Yes         | CLI only                        |
| Health status             | **Planned** | No          | `plsec-status` (bash, Phase 1)  |

Users should run bootstrap for immediate protection, then install the
CLI for full functionality. Future goal: the CLI subsumes all bootstrap
capabilities, making bootstrap optional for fresh installs. Both should
ultimately be generated from the same registry metadata (single source
of truth).

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

- [x] **Path migration**: Unify Python CLI to use `~/.peerlabs/plsec` (see below)
- [ ] Build pytest test cases for Python CLI component (see TESTING.md)
- [x] Verify ty type checker integration works correctly
- [x] **Unify build system through Make** (see below). All targets
  implemented except `make docs` / `make docs-build`, which depend on
  mkdocs setup (separate TODO).
- [x] **Registry refactoring**: Extract agent, scanner, and process registries
  from command files into `core/agents.py`, `core/scanners.py`,
  `core/processes.py`. Decompose `doctor.py` into reusable health check
  functions in `core/health.py`. Phases A-C complete, zero `except Exception`
  remaining.
  (see [docs/DESIGN-PLSEC-REFACTOR.md](docs/DESIGN-PLSEC-REFACTOR.md))
- [x] **Fix scan bugs**: Trivy `trivy-secret.yaml` rewritten to use
  RE2-compatible regex (removed `(?!...)` lookahead). Bandit `--exclude`
  added for `.venv,.tox,node_modules,build,dist,.eggs`.
- [x] **Add `make scan` target**: Run `plsec scan .` against own codebase
  as integration/dogfood test for scanner configuration.
- [x] **Get `make scan` clean**: Added `--skip-dirs` (7 dirs) and
  `--skip-files` (`**/*.pyc`) to trivy commands and `trivy.yaml`.
  Created `.trivyignore.yaml` with per-path suppression for 21 files.
  `plsec init` now deploys trivy configs. `plsec doctor` checks I-5/I-6/I-7.
- [x] **`plsec install` / `plsec reset`**: Lifecycle management commands.
  `plsec install` deploys global configs (replaces `plsec init --global`).
  `plsec reset` wipes and redeploys. Includes artifact inventory model in
  `core/inventory.py`, `plsec scan` pre-flight check, `.installed.json`
  metadata, and `make clean-install` / `make reset` / `make install-global`
  targets. Phases 1-4 complete (inventory, install, scan pre-flight, reset).
  (see [docs/DESIGN-INSTALL-RESET-UNINSTALL.md](docs/DESIGN-INSTALL-RESET-UNINSTALL.md))
- [x] **`plsec uninstall`**: Clean removal of all plsec artifacts. Interactive
  mode with scope selection (`--global`, `--project`, `--all`), template
  matching for project-local files, customised file warnings, remainder
  report (external tools, how to remove plsec itself). Phase 5 complete.
  (see [docs/DESIGN-INSTALL-RESET-UNINSTALL.md](docs/DESIGN-INSTALL-RESET-UNINSTALL.md))
- [x] **Enhanced wrapper logging**: Upgrade wrapper templates from 3-line
  session bookends to full audit. Tier 1: git info, duration, preset,
  agent version. Tier 2: `CLAUDE_CODE_SHELL_PREFIX` for Claude Code
  command auditing via `plsec-audit.sh`. Tier 3 (future): OTEL
  integration. 41 BATS tests in `test_wrapper_logging.bats`.
- [x] **Bridge CLI/bootstrap gap**: `plsec install` now deploys wrapper
  scripts (`claude-wrapper.sh`, `opencode-wrapper.sh`, `plsec-audit.sh`)
  with `@@PLSEC_DIR@@` substitution and executable permissions. Shell
  aliases (`claude-safe`, `opencode-safe`, `plsec-logs`) injected into
  RC file with start/end markers, removable by `plsec uninstall`.
  `--no-aliases` flag to opt out. Health checks I-8/I-9/I-10 verify
  wrapper scripts. `AgentSpec.wrapper_template` now consumed by install.
- [x] **Scan result persistence**: `plsec scan` writes structured results
  to `~/.peerlabs/plsec/logs/` via `ScanResult`/`ScanSummary` dataclasses.
  Daily JSONL log (`scan-YYYYMMDD.jsonl`) + `scan-latest.json` summary.
  `--json` CLI flag for machine-readable output. 661 tests, 77% coverage.
- [x] **Installation testing**: Added `make install-test` (clean install
  in isolated venv) and `make build-dist` (sdist + wheel) targets.
  Created `docs/INSTALL.md` covering all installation paths (pipx, uv,
  homebrew, bootstrap).
- [x] **`plsec-status` Phase 1**: Bash status script in bootstrap,
  Python integration via health.py + templates.py, CI/CD + user docs.
  83 BATS tests (58 unit + 25 integration). Bootstrap-only deployment
  per Option A. The status design doc (`docs/plsec-status-design.md`)
  is APPROVED v0.2.
  (see [docs/plsec-status-design.md](docs/plsec-status-design.md))

### Medium Priority

- [ ] **mkdocs setup**: Wire up documentation site (see below)
- [ ] Document bootstrap.sh component and template system
- [ ] Add integration tests for plsec commands
- [ ] **Multi-project support**: Add a PROJECTS registry
  (`~/.peerlabs/plsec/projects.yaml`), per-project log directories,
  `plsec project list/remove` commands. Enabled by the registry
  refactoring. (see "Future Directions" in
  [docs/DESIGN-PLSEC-REFACTOR.md](docs/DESIGN-PLSEC-REFACTOR.md))
- [ ] **Agent support**: Gemini CLI
- [ ] **Agent support**: Codex (OpenAI)
- [ ] **Agent support**: CoPilot (GitHub)
- [ ] **Agent support**: ollama (local models)
- [ ] Determine what other AI coding tools to support
- [ ] **Agent data monitoring**: Read and monitor agent operational data
  (sessions, tool calls, token usage, errors). Per-agent adapters with
  version-pinned compatibility registry. `plsec doctor` checks for adapter
  health, `plsec status` for activity, `plsec monitor` for detailed views.
  Supports OpenCode (SQLite) and Claude Code (JSONL) at launch; other
  agents to follow.
  (see [docs/DESIGN-AGENT-MONITORING.md](docs/DESIGN-AGENT-MONITORING.md))
- [ ] **`plsec run` command** (v0.2.0): Managed agent execution with
  full security wrapping. Container isolation (Podman default, Docker
  fallback, macOS sandbox -- user-configurable). `CLAUDE_CODE_SHELL_PREFIX`
  audit logging. Pre/post-flight checks. Replaces bootstrap `*-safe`
  aliases. See `plsec run` Command section below.
- [ ] **MCP server harness** (near-term): `plsec create` generates a
  sample MCP server project with plsec security baked in (logging,
  scanning, permission enforcement at each security level). Reference
  implementation and template.
- [ ] **Local server security parameters**: Rich set of controls for
  securing local development servers (ports, bindings, TLS, auth).
- [ ] **PyPI publishing**: Publish to TestPyPI, verify `pipx install
  plsec`, then publish to PyPI. Prerequisite for Homebrew tap and mise.
- [ ] **Homebrew tap**: Test formula locally (`brew install
  --build-from-source`), create `peerlabs/homebrew-tap` repo, update
  SHA256s, make first real release.

### Low Priority

- [ ] Add CSS/HTML guidelines back to AGENTS.md if web components are added

### Future

- [ ] **Agent monitoring for additional agents**: Extend data adapters
  to Gemini CLI, Codex, CoPilot, ollama as their data formats are
  analyzed. Community-maintainable `compatibility.yaml` version registry.
  (see [docs/DESIGN-AGENT-MONITORING.md](docs/DESIGN-AGENT-MONITORING.md))
- [ ] **MCP server securing**: Monitor, audit, and enforce security
  policies on third-party MCP servers that agents connect to.
- [ ] **ACP support**: Agent Communication Protocol integration for
  cross-agent security coordination. Protocol still in infancy.
- [ ] **Signature database**: Ship with modified sqlite/duckdb instance
  for pattern storage, secret signatures, etc.
- [ ] **Single metadata source**: Converge bootstrap and CLI wrapper
  generation to use same registry metadata. Aspiration -- plan for it
  now, implement when the CLI subsumes bootstrap functionality.
- [ ] **apt packaging**: Debian/Ubuntu package for server environments.

## Path Migration: `~/.plsec` to `~/.peerlabs/plsec` (COMPLETE)

All Python source code, templates, and bootstrap scripts now use
`~/.peerlabs/plsec` consistently.  `get_plsec_home()` returns
`Path.home() / ".peerlabs" / "plsec"`.  The `.plsec-manifest.json`
filename is a per-workspace artifact, not a home directory path.

## Versioning

**Decision**: 2-level versioning with `VERSION` file as single source of truth.

- **Top-level**: `VERSION` file at project root (plain text, e.g., `0.1.0`).
  All consumers read from this: pyproject.toml (hatchling dynamic version),
  `__init__.py` (`importlib.metadata`), Makefile (`cat VERSION`).
- **Bootstrap**: Stamped at build time with `+bootstrap` suffix per semver
  build metadata convention (e.g., `0.1.0+bootstrap`).
- **Per-command versioning**: Deferred. Each command module has a `__version__`
  attribute for future use but it is not yet exposed in CLI output.
- **Component-level VERSIONS.toml**: Deferred. One unified version is
  sufficient until components release independently.

### Version sources

| Consumer          | Source                                           | Value             |
|-------------------|--------------------------------------------------|-------------------|
| PyPI / pip        | `pyproject.toml` dynamic from `VERSION`          | `0.1.0`           |
| `plsec --version` | `importlib.metadata.version("plsec")`            | `0.1.0`           |
| Bootstrap script  | Makefile passes `VERSION+bootstrap` to assembler | `0.1.0+bootstrap` |
| Uninstalled dev   | Fallback in `__init__.py`                        | `0.0.0-dev`       |

## Makefile Reference

Make is the unified entry point. See `docs/build-process.md` for
developer workflows and the full target reference.

### Target map

| Target                  | What                                        | Side      |
|-------------------------|---------------------------------------------|-----------|
| `make all`              | Full pipeline (alias for `make ci`)         | Both      |
| `make ci`               | lint + check + build + assembler + test + verify + golden | Both |
| `make dev-check`        | lint + check + test + build + verify (quick)| Both      |
| `make setup`            | `uv sync --dev`                             | Python    |
| `make lint`             | All linting (Python + templates + bootstrap)| Both      |
| `make lint-python`      | `ruff check .` + `ruff format . --check`    | Python    |
| `make check`            | `ty check src/`                             | Python    |
| `make format`           | `ruff format .` (mutating, not in CI)       | Python    |
| `make scan`             | `plsec scan .` (dogfood own codebase)       | Python    |
| `make install`          | Deploy global configs (alias for install-global) | Lifecycle |
| `make install-global`   | `plsec install --check`                     | Lifecycle |
| `make deploy`           | `plsec install --force --check`             | Lifecycle |
| `make reset`            | `plsec reset --yes` (preserves logs)        | Lifecycle |
| `make clean-install`    | Reset + install from clean slate            | Lifecycle |
| `make build-dist`       | Build sdist + wheel via `uv build`          | Packaging |
| `make install-test`     | Clean install test in isolated venv         | Packaging |
| `make test`             | All tests (pytest + BATS unit + integration)| Both      |
| `make test-python`      | `pytest tests/ --ignore=tests/bats`         | Python    |
| `make test-unit`        | BATS unit tests                             | Bootstrap |
| `make test-integration` | BATS integration tests                      | Bootstrap |
| `make test-assembler`   | Template assembler escaping tests           | Bootstrap |
| `make build`            | Assemble bootstrap.sh                       | Bootstrap |
| `make verify`           | Build matches promoted reference            | Bootstrap |
| `make promote`          | Copy build to bin/ (skips if unchanged)     | Bootstrap |
| `make golden`           | Regenerate golden fixtures                  | Bootstrap |
| `make golden-check`     | Verify golden files match templates         | Bootstrap |
| `make clean`            | Remove build artifacts and caches           | Both      |

### Design notes

- `make all` is an alias for `make ci` -- use `make dev-check` for the
  faster local development loop (skips assembler tests and golden checks)
- `make format` is mutating (changes files) so excluded from CI; `make lint`
  is read-only (includes `ruff format . --check`)
- `make test-python` uses plain `pytest` (assumes `make setup` has been run)
- Lifecycle targets (`install`, `deploy`, `reset`) modify `~/.peerlabs/plsec/`
- `make reset` preserves logs by default; use `plsec reset --wipe-logs` to
  remove them
- `make promote` is a no-op when build matches the reference (no git noise)

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

## Roadmap

See [docs/roadmap.md](docs/roadmap.md) for future milestones:

- **v0.1.x** - Scan fixes, wrapper logging, CLI/bootstrap bridge,
  `plsec-status` Phases 1-2
- **v0.2.0** - `plsec run` command: managed agent execution, container
  isolation (Podman default), MCP server harness
- **v0.3** - JS/TS ecosystem support (multiple package managers,
  postinstall script risks, npm audit integration)
- **v0.4** - TUI dashboard (`plsec-status` Phase 3): project dashboard,
  log viewer, container status, proxy monitoring

## Outstanding Items

_(Items requiring decisions or external input)_

- Bootstrap.sh component coverage - to be discussed
- User selection of equivalent tools (linters, type checkers, etc.) should be
  considered for a future release. Currently plsec ships opinionated defaults
  (ruff for linting/formatting, ty for type checking).
- Container runtime default: Podman out-of-the-box, user-configurable via
  `plsec.yaml`. Need to prominently communicate Podman requirement to users.
- Single metadata source timeline: when does the CLI fully subsume bootstrap?
- Signature database architecture: sqlite vs duckdb, embedded vs external,
  update mechanism for pattern distribution.

## Scan Bugs (resolved)

### Bug 1: Trivy regex uses RE2-incompatible syntax (FIXED)

`templates/bootstrap/trivy-secret.yaml` line 52 used `(?!...)` negative
lookahead in the `openai-legacy` rule. Trivy uses Go's regexp package
(RE2-based) which does not support Perl extensions.

**Resolution**: Rewrote regex to `\bsk-[A-Za-z0-9]{40,64}\b`. Legacy
keys are pure alphanumeric after `sk-` (no hyphens). Modern formats
(`sk-proj-`, `sk-ant-`) contain hyphens and are caught by their own
rules. No negative lookahead needed.

### Bug 2: Bandit scans `.venv/` (FIXED)

`_build_bandit_cmd()` in `src/plsec/core/scanners.py` passed the target
directory without exclusions.

**Resolution**: Added `--exclude .venv,.tox,node_modules,build,dist,.eggs`
to the bandit command builder.

### Bug 3: Trivy scans `.venv/` and `__pycache__/` (FIXED)

Trivy's `generic-secret` rule walked into `.venv/lib/python3.12/site-packages/`
producing hundreds of false positives from third-party packages (pygments,
markdown_it, rich, yaml, etc.). Also scanned compiled `.pyc` bytecode.

**Resolution (3 layers):**
1. `trivy.yaml` config: added `skip-dirs` (7 dirs) and `skip-files` (`**/*.pyc`)
2. CLI command builders: `--skip-dirs` and `--skip-files` flags via
   `_add_trivy_common_flags()` (belt and suspenders)
3. `.trivyignore.yaml`: per-path suppression for 21 source files where
   trivy's `generic-secret` rule matches the word "secret" in config
   paths, detection regex patterns, test fixtures, and documentation

### Bug 4: Trivy false positives from own source code (FIXED)

Trivy's `generic-secret` rule matches any occurrence of "secret" in code.
A security tool scanning itself produces guaranteed false positives from
`--secret-config` flags, `trivy-secret.yaml` path references, detection
regex patterns, and test fixtures with dummy credentials.

**Resolution**: Created `.trivyignore.yaml` using trivy's YAML ignore
format (requires `--ignorefile` flag, experimental in v0.69.1). Supports
per-path suppression: 4 rule IDs (`generic-secret`, `generic-api-key`,
`stripe-secret-token`) across 21 files + 1 misconfig (`DS-0026`) for
the test Containerfile.

## `plsec run` Command (v0.2.0)

A managed execution command that wraps AI coding agents with full plsec
security, replacing the bootstrap `*-safe` aliases with richer CLI
control.

### Usage

    plsec run claude [-- <args>]
    plsec run opencode [-- <args>]
    plsec run --container claude [-- <args>]

### What it does

1. **Pre-flight checks**: Verify plsec is configured, agent configs are
   deployed, security mode is set
2. **Environment setup**: Set `CLAUDE_CODE_SHELL_PREFIX` for audit
   logging, deploy agent configs to project if missing, configure
   OTEL exporters if enabled
3. **Container mode** (optional): Start a Podman/Docker container with
   the project mounted, network policies applied, and the agent running
   inside. This enables Layer 3 (isolation) and Layer 4 (runtime proxy).
   **Default container runtime: Podman.** User-configurable via
   `plsec.yaml`. Docker and macOS sandbox as fallback options.
4. **Execute agent**: Run the agent with all plsec security wrappers
5. **Post-flight**: Log session summary, scan results, duration

### Relationship to bootstrap wrappers

The bootstrap `*-safe` aliases (e.g., `claude-safe`) provide minimal
session logging. `plsec run` provides the same functionality plus:
- Container isolation (Podman/Docker/macOS sandbox)
- `CLAUDE_CODE_SHELL_PREFIX` audit logging (every command the LLM runs)
- Pre/post scan integration
- Structured telemetry (OTEL)
- Managed agent config deployment

Bootstrap wrappers remain available for environments without the Python
CLI installed.

### Implementation notes

- New file: `src/plsec/commands/run.py`
- Uses `AgentSpec` from agent registry
- Uses `ProcessSpec` patterns from process registry
- Container support via `PROCESSES` registry (add Podman/Docker specs)

## MCP Integration

### Near-term: plsec MCP server harness

`plsec create --mcp-server` generates a sample MCP server project with
plsec security baked in at every level:
- Logging of all tool invocations
- Secret scanning of inputs/outputs
- Permission enforcement matching the project's security preset
- Audit trail compatible with `plsec-status` reporting

This serves as a reference implementation and template for building
secure MCP servers that interoperate with plsec-managed agents.

### Future: Securing existing MCP servers

Monitor, audit, and enforce security policies on third-party MCP
servers that agents connect to. This includes:
- Permission auditing (what tools does the server expose?)
- Traffic monitoring (what data flows through the server?)
- Policy enforcement (deny/allow rules for MCP tool invocations)
- Integration with `plsec.yaml` security presets

## References

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Pipelock](https://github.com/luckyPipewrench/pipelock)
- [Anthropic Claude Code Sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing)
- [John Ousterhout - A Philosophy of Software Design](https://web.stanford.edu/~ouster/cgi-bin/book.php)
