# plsec - HANDOFF

**Last Updated:** 2026-03-14
**Status:** `make ci` green, `make scan` clean (exit 0), 1232 pytest + 152 BATS unit + 88 BATS integration + 44 assembler tests

---

## What is plsec?

A defense-in-depth security framework for AI coding assistants. Scans
code, validates configurations, checks infrastructure controls, and
(planned) manages isolated agent execution. Supports Claude Code and
OpenCode.

## Current State

### Engine architecture (complete, tested, in production)

The scan pipeline uses a layered engine architecture. The old scanner
system (`core/scanners.py`) has been removed.

```
plsec.yaml (config) -> Orchestrator -> Registry -> Layer Pipeline -> Correlation -> Policy -> Verdict
```

**Core abstractions** (`src/plsec/engine/`):
- `types.py` -- Finding (universal IR), Location, Layer, Severity, Preset, ScanContext
- `base.py` -- Engine ABC, EngineGroup, EngineResult, LayerResult, ScanResult, `extract_json()`
- `verdict.py` -- VerdictStrategy (Threshold, Strict, Audit), Verdict, VerdictStatus
- `registry.py` -- EngineRegistry, `build_default_registry()`
- `policy.py` -- Suppression, Policy (severity floor + suppression rules)
- `correlation.py` -- CorrelationEngine, CorrelationRule, 3 built-in rules
- `orchestrator.py` -- Orchestrator, `build_orchestrator()`

**Concrete engines** (5 implemented, all at 100% test coverage):
- `trivy_secrets.py` -- TrivySecretEngine (Layer 1: STATIC)
- `bandit.py` -- BanditEngine (Layer 1: STATIC)
- `semgrep.py` -- SemgrepEngine (Layer 1: STATIC)
- `trivy_misconfig.py` -- TrivyMisconfigEngine (Layer 2: CONFIG)
- `container_isolation.py` -- ContainerIsolationEngine (Layer 3: ISOLATION)

**All engines use defensive JSON extraction** (`extract_json()` in
`base.py`) to survive contaminated stdout (progress bars, status
messages). Three-state output handling: clean JSON -> parse, no JSON
with exit 0 -> clean scan, no JSON with error -> tool failure finding.
See `docs/secure-tool-handling.md` for the exemplar pattern.

### Scan command

`plsec scan` (`commands/scan.py`) uses the engine pipeline end-to-end.
Preset determines which engines run and which verdict strategy applies:

| Preset   | Engines | Verdict strategy | Fail threshold |
|----------|---------|------------------|----------------|
| minimal  | 3 (static only) | Threshold | CRITICAL |
| balanced | 4 (+misconfig) | Threshold | HIGH |
| strict   | 5 (+container) | Strict | Any finding |
| paranoid | 5 (+container) | Strict | Any finding |

### What was completed in recent sessions

1. **Engine architecture** -- Full implementation: types, base, verdict,
   registry, policy, correlation, orchestrator. All at 100% coverage.

2. **5 concrete engines** -- TrivySecret, Bandit, Semgrep, TrivyMisconfig,
   ContainerIsolation. All at 100% coverage.

3. **Scan command rewrite** -- `commands/scan.py` rewritten to use engine
   pipeline. Old `core/scanners.py` removed.

4. **Resilient JSON parsing** -- `extract_json()` function + all engines
   hardened against contaminated stdout. Bandit `-q` flag added. Documented
   in `docs/secure-tool-handling.md`.

5. **`.trivyignore.yaml` wired into engines** -- Both trivy engines now
   pass `--ignorefile` when the file exists in the target directory.

6. **Roadmap and design doc updated** -- Container execution is
   preset-driven (not opt-in). Wrapper scripts evolve to delegate to
   `plsec run`. Open design questions captured for container harness.

7. **Old scanner system removed** -- Deleted `core/scanners.py` (443 lines)
   and `tests/test_scanners.py` (66 tests). Fixed `test_templates.py`
   cross-references (inlined expected values). Removed stale entry from
   `.trivyignore.yaml`. Updated `TESTING.md` test inventory.

8. **PROJECT.md rewritten** -- Fresh document covering engine architecture,
   preset-driven execution model, module inventory, known gaps, and
   documentation index. Old version archived at
   `docs/archive/PROJECT-20260313.md`.

9. **`test-plsec.yml` GitHub Actions workflow** -- Three-job CI for Python
   code: lint (ruff + ty), test (pytest with Python 3.12 + 3.14 matrix),
   scan (dogfood `plsec scan` with trivy, bandit, semgrep installed via
   `aquasecurity/setup-trivy@v0.2.5` and pip). Triggers on `src/**`,
   `tests/**` (excluding BATS), `pyproject.toml`, `uv.lock` changes.
   Uses `astral-sh/setup-uv@v7` with caching.

## Instructions

- **Read AGENTS.md** for coding standards, build commands, project conventions
- **Read TESTING.md** for the pytest test plan and test inventory
- **Read `docs/DESIGN-PLSEC-ENGINE.md`** for the engine architecture design
- **Read `docs/roadmap.md`** for the version roadmap and milestone plan
- **Git operations**: Do NOT touch git. The user handles all commits.
- **Never suppress lint warnings** (`# noqa`, `per-file-ignores`). Fix the code.
- **Never use `except Exception`** -- catch specific exception types.
- **Use `Annotated` typer syntax** for CLI parameters.
- **No Pydantic** -- plain dataclasses throughout.
- **Alpha phase** -- scorched earth, no backward compatibility needed.
- **Write tests first** -- tests define the contracts.
- **Scanner false positive suppressions** are acceptable (`.trivyignore.yaml`,
  `# nosemgrep`). These are different from lint suppressions.

## Key Design Decisions

- **plsec is a security tool** -- defensive coding is paramount. Never trust
  external tool output. See `docs/secure-tool-handling.md`.
- **Preset determines execution mode** -- at strict/paranoid, the agent runs
  inside a container automatically. See `docs/roadmap.md` v0.2.0.
- **Detection vs. control engines** -- Layers 1-2 detect vulnerabilities.
  Layers 3-5 validate that security controls are in place.
- **Policy/mechanism separation** -- Policy (what matters) is declarative.
  Mechanism (how to check) is imperative. The verdict strategy interprets
  findings into actionable outcomes.
- **Findings as universal IR** -- All engines produce `Finding` objects.
  No scanner-specific output leaks past the engine boundary.

## Known Gaps

### Trivy `--skip-dirs` / `--config` not wired into new engines

The old scanner system passed `--skip-dirs` (`.venv`, `node_modules`, etc.)
as CLI flags to trivy. The new engines don't. The `trivy.yaml` config file
deployed by `plsec install` to `~/.peerlabs/plsec/trivy/trivy.yaml` contains
these settings, but the engines don't pass `--config` to point trivy at it.

This hasn't caused issues because `make scan` runs from the project root
and trivy's default config path is `trivy.yaml` (auto-discovered in cwd).
But if the scan target is a different directory, skip-dirs won't apply.

**Resolution**: Either pass `--config` pointing to the deployed `trivy.yaml`,
or add `--skip-dirs` as engine config options. Low priority -- only matters
when scanning outside the project root.

### Engine gaps vs. design

The design doc (`DESIGN-PLSEC-ENGINE.md`) describes 12 engines. 5 are
implemented. Missing:

| Engine | Layer | Priority |
|--------|-------|----------|
| DependencyEngine (pip-audit) | STATIC | High -- restores `--deps` flag |
| AgentConstraintEngine | CONFIG | Medium -- validates CLAUDE.md/opencode.json |
| DenyPatternEngine | CONFIG | Medium -- verifies deny lists match preset |
| SandboxEngine | ISOLATION | Low -- macOS sandbox check |
| EgressProxyEngine | RUNTIME | Blocked on `plsec run` |
| DLPEngine | RUNTIME | Blocked on `plsec run` |
| AuditLogEngine | AUDIT | Blocked on audit infrastructure |
| IntegrityEngine | AUDIT | Blocked on audit infrastructure |

### Container harness (v0.2.0)

Open design questions documented in `docs/roadmap.md`:
- Agent binary provisioning (baked into image or mounted from host?)
- Container lifecycle (per-session or long-lived?)
- Image management (pre-built, built by `plsec init`, or pulled?)
- File access model (bind mount vs volume?)
- Network policy mechanism (Pipelock vs Podman network rules?)

## Project Structure

```
plsec/
├── VERSION                 # 0.1.0
├── src/plsec/
│   ├── cli.py              # Entry point, typer app
│   ├── commands/           # Subcommands (scan, doctor, init, install, etc.)
│   ├── core/               # Business logic (config, agents, tools, health)
│   ├── engine/             # Engine architecture (13 modules)
│   └── configs/            # Embedded templates
├── tests/
│   ├── engine/             # 12 engine test files (469 tests)
│   ├── test_*.py           # 19 other test files (763 tests)
│   └── bats/               # BATS shell script tests (240 tests)
├── docs/                   # Design docs, roadmap, guides
├── templates/bootstrap/    # Bootstrap script templates
└── build/                  # Assembled bootstrap.sh
```

## Relevant Documentation

| Document | Purpose |
|----------|---------|
| `AGENTS.md` | Coding standards, build commands, conventions |
| `TESTING.md` | Test plan, inventory, tiers |
| `PROJECT.md` | TODOs, architecture decisions, outstanding items |
| `docs/DESIGN-PLSEC-ENGINE.md` | Engine architecture design |
| `docs/roadmap.md` | Version roadmap, milestones, v0.2.0 plan |
| `docs/secure-tool-handling.md` | Defensive subprocess output handling |
| `docs/writing-engines.md` | Developer guide for custom engines |
| `docs/HANDOFF-20260309.md` | Previous handoff (sessions 1-18) |

## Build Commands

```bash
make setup          # uv sync --dev
make test           # All tests (pytest + BATS)
make dev-check      # Quick: lint + types + tests + build
make ci             # Full CI: lint + types + build + all tests + golden
make scan           # Run plsec scan on own codebase
make lint           # All linting
make build          # Assemble bootstrap.sh
```
