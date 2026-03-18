# PROJECT.md - plsec Project Overview

**Version:** 0.1.0
**Status:** Engine architecture implemented, 6 of 12 engines complete, all at
100% test coverage

---

## What is plsec?

A defense-in-depth security framework for AI coding assistants (Claude Code,
OpenCode, and others). AI agents have broad filesystem and network access.
Without guardrails, they can leak secrets, execute malicious code from
compromised dependencies, modify sensitive files, or exfiltrate data. plsec
provides layered security controls: static analysis, configuration validation,
container isolation, network egress control, and audit logging.

---

## 5-Layer Security Model

Security controls are organised into 5 layers, each addressable by dedicated engines:

| Layer | Name      | Control Type           | Implemented Engines          | Planned Engines                          |
|-------|-----------|------------------------|------------------------------|------------------------------------------|
| 1     | STATIC    | Detection              | TrivySecret, Bandit, Semgrep, TrivyDependency | PipAuditEngine (Phase 2)      |
| 2     | CONFIG    | Detection + Validation | TrivyMisconfig               | AgentConstraintEngine, DenyPatternEngine |
| 3     | ISOLATION | Control Validation     | ContainerIsolationEngine     | SandboxEngine (macOS sandbox)            |
| 4     | RUNTIME   | Control Validation     | —                            | EgressProxyEngine, DLPEngine             |
| 5     | AUDIT     | Control Validation     | —                            | AuditLogEngine, IntegrityEngine          |

**Detection engines** (Layers 1-2) scan code and configuration for
vulnerabilities, secrets, and misconfigurations. They produce findings of
category `SECRET`, `VULNERABILITY`, `MISCONFIG`.

**Control validation engines** (Layers 3-5) verify that security controls are in
place. They produce `MISSING_CONTROL` findings when infrastructure is absent. At
strict/paranoid presets, plsec *provides* these controls (e.g., container
harness, egress proxy) and the engines validate correct configuration.

---

## Architecture

### Engine Pipeline

The scan command uses a layered engine pipeline. This is the core of plsec's
security architecture.

#### Flow

```
plsec.yaml (config)
  → Orchestrator
    → Registry (layer groups)
      → Layer Pipeline (STATIC → CONFIG → ISOLATION → RUNTIME → AUDIT)
        → Correlation (cross-layer compound risk detection)
          → Policy (severity floor + suppressions)
            → Verdict (strategy-based PASS/WARN/FAIL/ERROR)
```

#### Core Abstractions

| Abstraction           | Purpose                                                                                                                                                                               | Module                   |
|-----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------|
| **Finding**           | Universal intermediate representation. Frozen dataclass, deterministic ID via content hash, `with_severity()`/`with_suppressed()` for safe copies.                                    | `engine/types.py`        |
| **Engine**            | Abstract base for detection/control engines. Stateless. Properties: `engine_id`, `layer`, `display_name`, `presets`, `dependencies`. Methods: `check_available(ctx)`, `execute(ctx)`. | `engine/base.py`         |
| **EngineGroup**       | Manages engines within a single security layer. Filters by preset, gates on availability.                                                                                             | `engine/base.py`         |
| **Orchestrator**      | Scan lifecycle coordinator. Detects environment → builds context → walks layers → correlates → applies policy → computes verdict.                                                     | `engine/orchestrator.py` |
| **Policy**            | Post-detection filter. Answers "which findings matter?" Applies severity floor and suppression rules.                                                                                 | `engine/policy.py`       |
| **Verdict**           | Outcome interpreter. Three strategies: `ThresholdVerdictStrategy` (minimal/balanced), `StrictVerdictStrategy` (strict/paranoid), `AuditVerdictStrategy` (audit mode).                 | `engine/verdict.py`      |
| **EngineRegistry**    | Central catalog. `register()`, `group_for(layer)`, `get(id)`, `build_default_registry()`.                                                                                             | `engine/registry.py`     |
| **CorrelationEngine** | Cross-layer risk detection. Runs after all layers, produces synthetic findings for compound risks (e.g., secret + no egress control = CRITICAL).                                      | `engine/correlation.py`  |

#### Implemented Engines (6)

| Engine ID             | Layer     | Category  | What It Does                                                  |
|-----------------------|-----------|-----------|---------------------------------------------------------------|
| `trivy-secrets`       | STATIC    | Detection | Trivy secret scanning (leaked credentials, API keys)          |
| `bandit`              | STATIC    | Detection | Python static analysis (B-class security issues)              |
| `semgrep`             | STATIC    | Detection | Multi-language SAST (pattern-based security rules)            |
| `trivy-vuln`          | STATIC    | Detection | Cross-language dependency vulnerability scanning              |
| `trivy-misconfig`     | CONFIG    | Detection | IaC misconfiguration scanning (Dockerfiles, Kubernetes, etc.) |
| `container-isolation` | ISOLATION | Control   | Container runtime + config check (Podman/Docker presence)     |

#### Defensive JSON Parsing

All engines that invoke external tools use the `extract_json()` pattern
documented in `docs/secure-tool-handling.md`. This three-state handler survives
contaminated stdout (progress bars, status messages), treating:
- Clean JSON → parse normally
- No JSON with exit 0 → clean scan
- No JSON with error → tool failure finding

Security principle: plsec is a security tool — never trust external tool output.

#### Findings as Universal IR

All engines produce `Finding` objects. No scanner-specific output leaks past the
engine boundary. The `Finding` dataclass is the contract between engines and the
rest of the system.

### Python CLI

The CLI is organised into thin command wrappers over deep core modules:

```
src/plsec/
├── cli.py                     # Entry point, typer app, 11 subcommands
├── commands/                  # Command modules (thin wrappers, 12 files, 3,734 lines)
├── core/                      # Business logic (15 modules, 3,574 lines)
│   ├── config.py              # Configuration management
│   ├── tools.py               # Tool checking
│   ├── agents.py              # Agent registry (Claude, OpenCode metadata)
│   ├── processes.py           # Process registry (Pipelock, container runtimes)
│   ├── health.py              # Health check model
│   ├── inventory.py           # Artifact inventory
│   ├── detector.py            # Project detection
│   ├── presets.py             # Preset configurations
│   ├── wizard.py              # Interactive wizards
│   ├── compatibility.py       # Agent data adapter version probing
│   └── adapters/              # Agent data adapters (Claude, OpenCode)
├── engine/                    # Scan pipeline (15 modules, 2,887 lines)
│   ├── types.py               # Core types (Finding, Layer, Severity, ScanContext)
│   ├── base.py                # Engine ABC, EngineGroup, extract_json
│   ├── registry.py            # Engine catalog
│   ├── orchestrator.py        # Scan lifecycle
│   ├── policy.py              # Post-detection filtering
│   ├── correlation.py         # Cross-layer risk detection
│   ├── verdict.py             # Outcome strategies
│   ├── dependency.py          # DependencyEngine ABC
│   ├── bandit.py              # Bandit engine
│   ├── semgrep.py             # Semgrep engine
│   ├── trivy_secrets.py       # Trivy secret engine
│   ├── trivy_dependency.py    # Trivy dependency vuln engine
│   ├── trivy_misconfig.py     # Trivy misconfig engine
│   └── container_isolation.py # Container isolation engine
└── configs/                   # Embedded templates (3 modules, 1,418 lines)
```

**11 CLI Commands:** `create`, `secure`, `doctor`, `init`, `install`, `reset`,
`scan`, `uninstall`, `validate`, `proxy`, `integrity`.

**47 Python modules, 12,169 lines of source code.**

### Bootstrap

`bootstrap.sh` is a zero-dependency standalone installer assembled from modular
templates in `templates/bootstrap/`. Designed for `curl | bash` quick-start.
Creates directory structure, agent configs, wrapper scripts, shell aliases, and
Trivy configuration.

#### How They Relate

Bootstrap is the **runtime layer** (session logging, auto-deploy agent configs).
The Python CLI is the **analysis and control layer** (scanning, validation,
managed execution).

| Capability                | Bootstrap | CLI     | Status                                         |
|---------------------------|-----------|---------|------------------------------------------------|
| Directory structure       | Yes       | Yes     | Overlap (same paths)                           |
| Agent config templates    | Yes       | Yes     | Overlap (same content)                         |
| Wrapper scripts + logging | Yes       | Planned | `plsec init` generates                         |
| Shell aliases             | Yes       | Planned | `plsec init` generates                         |
| Managed agent execution   | No        | Planned | `plsec run` (v0.2.0)                           |
| Container isolation       | No        | Planned | Preset-driven (v0.2.0)                         |
| Structured scanning       | Basic     | Yes     | CLI superior (engine pipeline)                 |
| Validation, integrity     | No        | Yes     | CLI only                                       |
| Health status             | Planned   | Partial | `plsec-status` (bash), `plsec doctor` (Python) |

Users run bootstrap for immediate protection, then install the CLI for full
functionality. Future goal: CLI subsumes all bootstrap capabilities.

---

## Security Presets

The preset is the single knob that determines scan scope, execution mode, and verdict strategy.

| Preset   | Engines (count)    | Execution Mode | Verdict Strategy | Fail Threshold |
|----------|--------------------|----------------|------------------|----------------|
| minimal  | 3 (static only)    | Host           | Threshold        | CRITICAL       |
| balanced | 5 (+misconfig,dep) | Host           | Threshold        | HIGH           |
| strict   | 6 (+container)     | **Container**  | Strict           | Any finding    |
| paranoid | 6 (+container)     | **Container**  | Strict           | Any finding    |

**Key architectural decision:** At strict/paranoid, the agent runs inside a
container automatically. Container isolation is not opt-in — the preset
determines the execution mode. The user sets the preset in `plsec.yaml`;
everything else follows from it.

**Preset → Engine Mapping:**

| Engine                  | Type       | minimal | balanced | strict | paranoid |
|-------------------------|------------|---------|----------|--------|----------|
| TrivySecretEngine       | detection  | x       | x        | x      | x        |
| BanditEngine            | detection  |         | x        | x      | x        |
| SemgrepEngine           | detection  |         | x        | x      | x        |
| TrivyMisconfigEngine    | detection  |         | x        | x      | x        |
| ContainerIsolationEngine| control    |         |          | x      | x        |
| TrivyDependencyEngine   | detection  |         | x        | x      | x        |
| PipAuditEngine          | detection  | —       | —        | planned| planned  |
| AgentConstraintEngine   | detection  | —       | planned  | planned| planned  |
| DenyPatternEngine       | detection  | —       | —        | planned| planned  |
| SandboxEngine           | control    | —       | —        | planned| planned  |
| EgressProxyEngine       | control    | —       | —        | planned| planned  |
| DLPEngine               | control    | —       | —        | —      | planned  |
| AuditLogEngine          | control    | —       | planned  | planned| planned  |
| IntegrityEngine         | control    | —       | —        | —      | planned  |

---

## Design Principles

- **Layered architecture**: Each security layer is independent and composable
- **Preset-driven**: Progressive security levels from minimal to paranoid. The
  preset is the single control knob — it determines scan scope, execution mode,
  and verdict interpretation.
- **Policy/mechanism separation**: Policy (what matters) is declarative.
  Mechanism (how to check) is imperative. Verdict strategies interpret findings
  into actionable outcomes.
- **Findings as universal IR**: All engines produce `Finding` objects. No
  scanner-specific output leaks past the engine boundary.
- **Configuration-first**: `plsec.yaml` drives behavior, integrates with agent
  configs
- **Deep modules**: Core logic in `core/` and `engine/`, thin command wrappers
  in `commands/`
- **Defensive coding**: plsec is a security tool — never trust external tool
  output. See `docs/secure-tool-handling.md` for the exemplar pattern.
- **Template-based bootstrap**: Shell script assembled from modular templates
  for maintainability
- **Test-first**: Tests define contracts. Write tests before fixing sketch code.
- **Dual test strategy**: pytest for Python (1,303 tests), BATS for shell
  scripts (284 tests)

---

## Current State

### Version

**0.1.0** — Single source of truth in `VERSION` file. Python package reads via
`importlib.metadata`, bootstrap stamped at build time with `+bootstrap` suffix.

### Test Coverage

| Suite            |     Count | Notes                                                   |
|------------------|----------:|---------------------------------------------------------|
| pytest           |     1,303 | Engine + template tests updated for M9 + watch mode     |
| BATS unit        |       152 | Bootstrap script unit tests                             |
| BATS integration |        88 | Bootstrap end-to-end tests                              |
| Assembler        |        44 | Template escaping edge cases                            |
| **Total**        | **1,587** | All passing                                             |

**Engine test coverage:** All 6 implemented engines at 100% coverage. 14 engine
test files, 536 tests.

### CI Status

- **`make ci`** — green (lint + types + build + all tests + golden)
- **`make scan`** — clean (exit 0, engine pipeline dogfoods own codebase)
- **GitHub Actions:**
  - `test-bootstrap.yml` — triggers on `bin/bootstrap.sh`, `tests/bats/**`,
    `templates/**` changes. Runs BATS unit + integration tests on Ubuntu and
    macOS.
  - `test-plsec.yml` — **planned** for Python code. Will trigger on `src/**`,
    `tests/**` (excluding BATS), dependency changes. Two jobs: lint (ruff + ty)
    and test (pytest with Python 3.12 + 3.14 matrix).

### What's Implemented vs. Planned

**Fully Implemented:**
- Engine architecture (types, base, verdict, registry, orchestrator, policy,
  correlation)
- 7 concrete engines (TrivySecret, Bandit, Semgrep, TrivyDependency,
  TrivyMisconfig, AgentConstraint, ContainerIsolation)
- Scan command rewritten to use engine pipeline
- Lifecycle management (install, reset, uninstall)
- Enhanced wrapper logging (Tier 1 + Tier 2 with `CLAUDE_CODE_SHELL_PREFIX`)
- Scan result persistence (JSONL logs, JSON summary)
- `plsec-status` Phase 1 (bash script, Python integration)
- `test-plsec.yml` GitHub Actions workflow (3 jobs: lint, test matrix, scan)

**In Progress / Near-term:**
- PipAuditEngine (Python-specific depth, Milestone 9 Phase 2)
- Tool class redesign (OS-aware install hints, see issue #6)

**Planned (v0.2.0):**
- `plsec run` command (managed agent execution, preset-driven container
  isolation)
- Wrapper scripts generated by CLI (subsume bootstrap capability)
- EgressProxyEngine, DLPEngine, AuditLogEngine, IntegrityEngine

---

## Module Inventory

| Subsystem   | Modules |      Lines | Description                                                                                                    |
|-------------|--------:|-----------:|----------------------------------------------------------------------------------------------------------------|
| `engine/`   |      15 |      2,887 | Scan pipeline: types, base, registry, orchestrator, 6 engines, policy, correlation, verdict                    |
| `core/`     |      15 |      3,764 | Business logic: config, tools, agents, processes, health, inventory, detector, adapters                        |
| `commands/` |      12 |      3,734 | CLI command modules: create, secure, doctor, init, install, reset, scan, uninstall, validate, proxy, integrity |
| `configs/`  |       3 |      1,717 | Embedded templates: CLAUDE.md, opencode.json, trivy configs, wrapper scripts                                   |
| **Total**   |  **47** | **12,216** | Full Python codebase (includes top-level __init__.py and cli.py: 138 lines)                                    |

---

## Versioning

**Decision**: 2-level versioning with `VERSION` file as single source of truth.

- **Top-level**: `VERSION` file at project root (plain text, e.g., `0.1.0`).
  All consumers read from this: `pyproject.toml` (hatchling dynamic version),
  `__init__.py` (`importlib.metadata`), Makefile (`cat VERSION`).
- **Bootstrap**: Stamped at build time with `+bootstrap` suffix per semver
  build metadata convention (e.g., `0.1.0+bootstrap`).

### Version sources

| Consumer          | Source                                           | Value             |
|-------------------|--------------------------------------------------|-------------------|
| PyPI / pip        | `pyproject.toml` dynamic from `VERSION`          | `0.1.0`           |
| `plsec --version` | `importlib.metadata.version("plsec")`            | `0.1.0`           |
| Bootstrap script  | Makefile passes `VERSION+bootstrap` to assembler | `0.1.0+bootstrap` |
| Uninstalled dev   | Fallback in `__init__.py`                        | `0.0.0-dev`       |

---

## Makefile Reference

Make is the unified entry point. See `docs/build-process.md` for developer workflows and full target reference.

### Target map

| Target                  | What                                                      | Side      |
|-------------------------|-----------------------------------------------------------|-----------|
| `make all`              | Full pipeline (alias for `make ci`)                       | Both      |
| `make ci`               | lint + check + build + assembler + test + verify + golden | Both      |
| `make dev-check`        | lint + check + test + build + verify (quick)              | Both      |
| `make setup`            | `uv sync --dev`                                           | Python    |
| `make lint`             | All linting (Python + templates + bootstrap)              | Both      |
| `make lint-python`      | `ruff check .` + `ruff format . --check`                  | Python    |
| `make check`            | `ty check src/`                                           | Python    |
| `make format`           | `ruff format .` (mutating, not in CI)                     | Python    |
| `make scan`             | `plsec scan .` (dogfood own codebase)                     | Python    |
| `make install`          | Deploy global configs (alias for install-global)          | Lifecycle |
| `make install-global`   | `plsec install --check`                                   | Lifecycle |
| `make deploy`           | `plsec install --force --check`                           | Lifecycle |
| `make reset`            | `plsec reset --yes` (preserves logs)                      | Lifecycle |
| `make clean-install`    | Reset + install from clean slate                          | Lifecycle |
| `make build-dist`       | Build sdist + wheel via `uv build`                        | Packaging |
| `make install-test`     | Clean install test in isolated venv                       | Packaging |
| `make test`             | All tests (pytest + BATS unit + integration)              | Both      |
| `make test-python`      | `pytest tests/ --ignore=tests/bats`                       | Python    |
| `make test-unit`        | BATS unit tests                                           | Bootstrap |
| `make test-integration` | BATS integration tests                                    | Bootstrap |
| `make test-assembler`   | Template assembler escaping tests                         | Bootstrap |
| `make build`            | Assemble bootstrap.sh                                     | Bootstrap |
| `make verify`           | Build matches promoted reference                          | Bootstrap |
| `make promote`          | Copy build to bin/ (skips if unchanged)                   | Bootstrap |
| `make golden`           | Regenerate golden fixtures                                | Bootstrap |
| `make golden-check`     | Verify golden files match templates                       | Bootstrap |
| `make clean`            | Remove build artifacts and caches                         | Both      |

---

## Known Gaps and Outstanding Items

### Engine Gaps (Priority Order)

**High Priority:**
- **PipAuditEngine** — Layer 1 STATIC. Python-specific depth engine for
  Milestone 9 Phase 2. TrivyDependencyEngine (cross-language baseline) is
  already implemented at balanced+.
- **AgentConstraintEngine** — Layer 2 CONFIG. Validates that
  CLAUDE.md/opencode.json deny patterns are deployed and match the preset.

**Medium Priority:**
- **DenyPatternEngine** — Layer 2 CONFIG. Verifies file/command deny lists match
  preset expectations.
- **EgressProxyEngine** — Layer 4 RUNTIME. Validates Pipelock network proxy is
  running (strict/paranoid only).
- **AuditLogEngine** — Layer 5 AUDIT. Verifies structured audit logging is
  active.

**Low Priority:**
- **SandboxEngine** — Layer 3 ISOLATION. macOS sandbox-exec check.
- **DLPEngine** — Layer 4 RUNTIME. Data loss prevention on agent responses
  (paranoid only).
- **IntegrityEngine** — Layer 5 AUDIT. Workspace file hashing for tampering
  detection (paranoid only).

### Technical Gaps

- **Trivy `--skip-dirs` / `--config` not wired into engines.** The old scanner
  system passed `--skip-dirs` as CLI flags. The new engines pass `--ignorefile`
  but not `--skip-dirs` or `--config`. The deployed `trivy.yaml` at
  `~/.peerlabs/plsec/trivy/trivy.yaml` contains these settings but engines don't
  point trivy at it. Low priority — only matters when scanning outside the
  project root (trivy auto-discovers `trivy.yaml` in cwd). See `HANDOFF.md` for
  details.

- **Tool class lacks OS-aware install hints (issue #6).** `Tool.install_hint`
  is a single string hardcoded to macOS (`brew install trivy`). The same
  brew-only hints are duplicated in `tools.py`, `health.py`, `doctor.py`,
  engine remediation strings, and `skeleton.bash`. Needs redesign: either
  `install_hint: str | dict[str, str]` keyed by platform, or a centralized
  tool registry with closures for install resolution. This blocks correct
  Linux support in `plsec doctor` output. See issue #6.

### Open Questions

- **Container runtime default communication.** Podman is the default. How
  prominently should we communicate this to users during install?
- **Single metadata source timeline.** When does the CLI fully subsume bootstrap
  capabilities?
- **Signature database architecture.** sqlite vs duckdb, embedded vs external,
  update mechanism for pattern distribution.
- **Python version matrix maintenance.** Currently testing min (3.12) + latest
  (3.14). How to manage ongoing updates to `pyproject.toml` `requires-python`
  and CI matrix?

---

## Roadmap

See [`docs/roadmap.md`](docs/roadmap.md) for detailed milestones and planning.

**v0.1.x (current)** — Foundation
- Scan fixes, wrapper logging, CLI/bootstrap bridge
- `plsec-status` Phases 1-2
- **Engine architecture** (complete)

**v0.2.0** — Managed Execution
- `plsec run` command: preset-driven container isolation
- Wrapper script generation by CLI
- MCP server harness (`plsec create --mcp-server`)
- Fill engine gaps (Dependency, AgentConstraint, DenyPattern)

**v0.3** — JS/TS Ecosystem
- Multiple package managers (npm, yarn, pnpm, bun)
- Postinstall script risk analysis
- npm audit integration

**v0.4** — TUI Dashboard
- `plsec-status` Phase 3: interactive dashboard
- Project status, log viewer, container status, proxy monitoring

---

## Documentation Index

### Design Documents (Status)

| Document                | Status                   | Location                                        |
|-------------------------|--------------------------|-------------------------------------------------|
| Engine Architecture     | Draft / Interface Design | `docs/design/DESIGN-PLSEC-ENGINE.md`            |
| Agent Monitoring        | PROPOSED (v0.1)          | `docs/design/DESIGN-AGENT-MONITORING.md`        |
| Install/Reset/Uninstall | IMPLEMENTED (v0.2)       | `docs/design/DESIGN-INSTALL-RESET-UNINSTALL.md` |
| Registry Refactoring    | IMPLEMENTED (v0.2)       | `docs/design/DESIGN-PLSEC-REFACTOR.md`          |
| Create & Secure         | IMPLEMENTED (v0.1.0)     | `docs/design/DESIGN-CREATE-SECURE.md`           |
| plsec-status            | APPROVED (v0.2)          | `docs/plsec-status-design.md`                   |

### Developer Guides

- **Installation:** `docs/INSTALL.md` — bootstrap, pip, uv, dev setup
- **Build Process:** `docs/build-process.md` — Make targets, assembler, template
  system
- **Testing Strategy:** `TESTING.md` — 3 tiers, test inventory
- **Writing Engines:** `docs/writing-engines.md` — Add new security engines
- **Secure Tool Handling:** `docs/secure-tool-handling.md` — Defensive
  subprocess patterns
- **CI/CD Integration:** `docs/ci-cd-integration.md` — Exit codes, GitHub
  Actions examples
- **Troubleshooting:** `docs/troubleshooting.md` — Common issues and fixes

### User-Facing Documentation

- **Commands:** `docs/commands/plsec-status.md` (more to be added as CLI
  stabilizes)
- **Scanner Limitations:** `docs/scanner-limitations.md` — Tradeoffs and
  transparency notes

### Archived

- **Previous PROJECT.md:** `docs/archive/PROJECT-20260313.md`
- **Previous HANDOFF.md:** `docs/archive/HANDOFF-20260309.md`
- **Bootstrap Handoff:** `docs/archive/HANDOFF-bootstrap.md`

---

## References

- [OWASP Top 10 for Agentic Applications
  2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Pipelock](https://github.com/luckyPipewrench/pipelock) — Network egress proxy for AI agents
- [Anthropic Claude Code
  Sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing) —
  Container isolation for AI coding assistants
- [John Ousterhout - A Philosophy of Software
  Design](https://web.stanford.edu/~ouster/cgi-bin/book.php) — Design
  principles: deep modules, push complexity down
