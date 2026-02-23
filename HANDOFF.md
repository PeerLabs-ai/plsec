# plsec - HANDOFF

**Last Updated:** 2026-02-23
**Status:** `make ci` green, `make scan` clean (all 4 scanners pass), 565 pytest + 75 BATS unit + 53 BATS integration + 44 assembler tests, 75% coverage

---

## Goal

Build **plsec**, a defense-in-depth security framework for AI coding assistants.
This project has had twelve objectives across sessions:

1. Get `make ci` passing end-to-end after previous infrastructure work (complete)
2. Remove Pydantic in favour of plain dataclasses (complete)
3. Implement Phase 1 pytest test cases - Tier 1 pure logic tests (complete)
4. Eliminate all lint suppressions - zero `# noqa`, zero `per-file-ignores` (complete)
5. Implement Phase 2 pytest test cases - Tier 2 filesystem tests with `tmp_path` (complete)
6. Registry refactoring - extract agent/scanner/process registries from command files (complete - Phases A-C)
7. Registry module tests - write test files for the 4 new core modules (complete)
8. Tier 3 command tests - subprocess-mocking tests for command modules (complete - Phase F)
9. Fix scan bugs, close CLI/bootstrap gap, get `make scan` clean (complete)
10. Lifecycle management - `plsec install`, `plsec reset`, `plsec uninstall`, scan pre-flight, artifact inventory (complete - Phases 1-6)
11. Update plsec-status-design.md - resolve open questions, add registry notes, mark APPROVED v0.2 (complete)
12. Enhanced wrapper logging - Tier 1 session enrichment + Tier 2 audit logging via `CLAUDE_CODE_SHELL_PREFIX` (complete)

Items 1-12 are complete.

## Instructions

- **Read AGENTS.md** for coding standards, build commands, and project conventions
- **Read PROJECT.md** for TODOs, architecture decisions, and outstanding items
- **Read TESTING.md** for the full pytest test plan (3 tiers, 22 test files)
- **Read `docs/DESIGN-PLSEC-REFACTOR.md`** for the registry refactoring design:
  entity-operation model, 4 new core modules, phased implementation plan
- **Read `docs/DESIGN-INSTALL-RESET-UNINSTALL.md`** for lifecycle commands design
  (IMPLEMENTED)
- **Read `docs/plsec-status-design.md`** for the status command design
  (APPROVED v0.2, registry-driven check generation)
- **Git operations**: Do NOT touch git. The user handles all commits.
- **Podman is the default container runtime** for `plsec run --container`,
  user-configurable via `plsec.yaml`
- **Version roadmap**: v0.1.x (current), v0.2.0 (`plsec run`), v0.3 (JS/TS),
  v0.4 (TUI)
- **Use uv** for all Python toolchain operations (not pip/venv directly)
- **Use Make** as the unified entry point for all build/test/lint operations
  (`make ci` is the full pipeline)
- **Follow semver** conventions - `VERSION` file is single source of truth
- The user prefers to review plans before execution - present proposals, get
  approval, then build
- Keep PROJECT.md updated with completed TODOs (mark with `[x]`)
- When testing private functions, document clearly **what contract** is being
  tested, **why** it's tested directly, and **how to fix** if it breaks
- **Never suppress lint warnings** (`# noqa`, `per-file-ignores`). Fix the
  underlying code.
- **Never use `except Exception`** - catch specific exception types (`OSError`,
  `subprocess.SubprocessError`, etc.)
- **Use `Annotated` typer syntax** for CLI parameters: `param: Annotated[Type,
  typer.Option(...)] = default`
- **Convention:** Use comments above dataclass fields (not trailing docstrings).
  Class-level docstrings remain as docstrings.
- **Pydantic policy:** Fully removed. Plain dataclasses throughout. No
  re-introduction.
- **License:** MIT. Copyright holder: Peerlabs Inc., Toronto, ON, Canada.
- **Template escaping**: `@@INCLUDE:file@@` for content templates
  (single-quoted strings, escape `'`), `@@INCLUDE_SCRIPT:file@@` for
  script templates (heredocs, escape `$` and `` ` ``, then replace
  `@@PLSEC_DIR@@` with `${PLSEC_DIR}`)
- **POSIX portability**: Don't use `grep -P` (Perl regex) in shell
  templates -- macOS default grep doesn't support it. Use `awk` or
  `sed` instead.
- **`make promote` and `make golden`** must be run after template changes
  (CI verify and golden-check steps will fail otherwise)

## Accomplished (this session)

### Milestone 8: Enhanced wrapper logging

Implemented two-tier wrapper logging upgrade and CLAUDE_CODE_SHELL_PREFIX
audit logging.

**Tier 1 (both wrappers):** Added git branch, git SHA, agent version,
preset detection, session duration to `wrapper-claude.sh` and
`wrapper-opencode.sh`. Preset detection uses `awk` to parse `plsec.yaml`,
falls back to CLAUDE.md "Strict Security" heuristic, defaults to "unknown".

**Tier 2 (Claude only):** `CLAUDE_CODE_SHELL_PREFIX` audit logging via new
`plsec-audit.sh` script. Logs `[timestamp] [pid] cwd=/path cmd=<command>`
to separate daily audit log (`claude-audit-YYYYMMDD.log`). Uses `exec "$@"`
to preserve exit codes and stdio. Fire-and-forget logging pattern ensures
command execution is never blocked by log failures.

**Files created:**
- `templates/bootstrap/plsec-audit.sh` - Audit script for shell prefix
- `tests/bats/unit/test_wrapper_logging.bats` - 41 BATS tests

**Files modified:**
- `templates/bootstrap/wrapper-claude.sh` - Tier 1 + Tier 2 wiring
- `templates/bootstrap/wrapper-opencode.sh` - Tier 1 fields
- `templates/bootstrap/skeleton.bash` - `@@INCLUDE_SCRIPT:plsec-audit.sh@@`
- `build/bootstrap.sh`, `bin/bootstrap.default.sh` - Rebuilt
- `tests/bats/golden/*` - Regenerated

### Milestone 7: Update plsec-status-design.md

Updated `docs/plsec-status-design.md` from DRAFT to APPROVED v0.2:
- Document control: DRAFT -> APPROVED, version 0.1 -> 0.2
- Resolved all 5 open questions (CWD default, fixed thresholds,
  presence-check only, single project, exit codes 0=OK/1=FAIL)
- Added "Registry-Driven Check Generation" section
- Added "Shared Data Contract: CheckResult" section
- Added "Source" column to check inventory tables
- Added "Lifecycle Commands" integration point section
- Fixed quiet mode exit code semantics inconsistency

### Lifecycle management commands (Phases 1-4)

Implemented `plsec install` and `plsec reset` commands with full test
coverage, plus `plsec scan` pre-flight check and artifact inventory model.

**Phase 1: Core inventory model** (`core/inventory.py`)
- `Artifact` and `Inventory` dataclasses for tracking plsec filesystem footprint
- `discover_global_artifacts()`, `discover_external_artifacts()`,
  `discover_project_artifacts()`, `discover_all()`, `format_size()`
- 42 tests in `tests/test_inventory.py`, 98% coverage

**Phase 2: `plsec install` command** (`commands/install.py`)
- `_deploy_file()` - write-if-missing with `--force` override
- `deploy_global_configs()` - shared deployment logic (used by both
  `plsec install` and `plsec init`)
- `write_installed_metadata()` / `read_installed_metadata()` - `.installed.json`
  with timestamp, preset, agents, version
- `check_installation()` - verify all expected files present
- CLI: `--preset`, `--agent`, `--force`, `--check` flags
- Refactored `plsec init` to delegate global deployment to `install.py`
- `plsec init --global` prints deprecation warning
- 29 tests in `tests/test_install_cmd.py`, 100% coverage of `install.py`

**Phase 3: `plsec scan` pre-flight check** (`commands/scan.py`)
- `_check_scanner_prerequisites()` verifies scanner configs exist before
  scanning, exits 1 with "Run 'plsec install'" message if missing
- 4 new tests in `tests/test_scan.py` (existing tests updated for pre-flight)

**Phase 4: `plsec reset` command** (`commands/reset.py`)
- `_stop_managed_processes()` - SIGTERM to running pipelock
- `_wipe_global_state()` - remove all children, preserve root dir
- `_remove_external_configs()` - clean agent native config locations
- Redeploys fresh defaults via `deploy_global_configs()` with `--force`
- CLI: `--preset`, `--agent`, `--yes`, `--dry-run` flags
- Exit codes: 0 (success), 2 (user cancelled)
- 14 tests in `tests/test_reset.py`, 90% coverage

**Makefile targets added:**
- `make install-global` - `plsec install --check`
- `make reset` - `plsec reset --yes`
- `make clean-install` - reset + install from clean slate
- `make deploy` updated to use `plsec install --force --check`

**Also fixed:**
- `tests/test_init.py` broken import (`_deploy_global_file` -> `_deploy_file`)
- Pre-existing ruff lint issues in `test_inventory.py` and `test_scanners.py`
- `ty` type check: removed unused `type: ignore[no-any-return]` in `install.py`
- `datetime.timezone.utc` -> `datetime.UTC` alias (UP017)

**Phase 5: `plsec uninstall` command** (`commands/uninstall.py`)
- `_remove_artifacts()` - removes files and directories by depth (children first)
- `_remove_global_root()` - removes empty plsec_home and parent
- `_print_inventory_summary()` - grouped artifact display
- `_print_remainder_report()` - shows external tools and how to remove plsec itself
- Interactive mode: sequential `typer.confirm()` for each scope
- Flag mode: `--global`, `--project`, `--all` for direct scope selection
- `--dry-run`, `--yes` support
- Customised file detection via `_matches_plsec_template()` (from inventory.py)
- Exit codes: 0 (success), 1 (error), 2 (cancelled)
- 18 tests in `tests/test_uninstall.py`, 87% coverage
- Registered in `cli.py` and `commands/__init__.py`

**Phase 6: Documentation and deprecation**
- Updated `health.py` fix_hints: `plsec init` -> `plsec install` for global
  installation checks (I-1, I-2, I-3, I-5, I-6, I-7)
- Updated `templates.py` module docstring
- Updated design doc status to IMPLEMENTED
- Updated PROJECT.md, HANDOFF.md
- Added HANDOFF.md to `.trivyignore.yaml` for trivy false positives

**107 new tests added** (458 -> 565 pytest tests), coverage 71% -> 75%.

### Previous sub-session: Get `make scan` clean -- trivy false positive elimination

Fixed trivy scanning `.venv/` (same class of bug as the Bandit fix from
last session) and eliminated all false positives from trivy scanning
plsec's own source code.

**Trivy skip-dirs + skip-files (belt and suspenders):**

- Added `_TRIVY_SKIP_DIRS` (7 dirs) and `_TRIVY_SKIP_FILES` (`**/*.pyc`)
  constants to `scanners.py`
- Both trivy command builders now pass `--skip-dirs` and `--skip-files` flags
- `trivy.yaml` template updated with matching `skip-dirs` and `skip-files`
  config keys
- `templates/bootstrap/trivy.yaml` and `TRIVY_CONFIG_YAML` in templates.py
  kept in sync

**`.trivyignore.yaml` for per-path false positive suppression:**

- Created `.trivyignore.yaml` using trivy's YAML ignore format with
  per-path suppression for 21 files across 4 rule IDs (`generic-secret`,
  `generic-api-key`, `stripe-secret-token`) + 1 misconfig (`DS-0026`)
- Added `_TRIVY_IGNOREFILE` constant and `_add_trivy_common_flags()` helper
  to `scanners.py` -- automatically passes `--ignorefile` when the file
  exists in the target directory
- Reworded comments in `.trivyignore.yaml` to avoid triggering the
  `generic-secret` rule on the ignore file itself

**Synced `plsec init` deployment + verified doctor checks:**

- `make deploy` deploys updated `trivy.yaml` with skip-dirs/skip-files
- `plsec doctor` shows I-5, I-6, I-7 scanner config checks all OK

**Result:** `make scan` now passes clean -- all 4 scanners (trivy secrets,
trivy misconfig, bandit, semgrep) report zero findings.

**32 new tests added** (426 -> 458 pytest tests):

| Test file                 | New tests | What                                                          |
|---------------------------|-----------|---------------------------------------------------------------|
| `tests/test_scanners.py`  | 10        | skip-dirs, skip-files, ignorefile present/absent (both cmds)  |
| `tests/test_templates.py` | 4         | skip-dirs, skip-files, cross-check with scanners.py constants |
| (previous session)        | 18        | init deploy, health scanner configs, template rules           |

Overall coverage increased from 69% to 71%.

### Previous sub-session: scan bugs + CLI/bootstrap bridge

- Fixed Trivy RE2 regex bug in `openai-legacy` rule
- Fixed Bandit `.venv` scanning
- Synced `TRIVY_SCAN_RULES_YAML` (Python template now has all 9 rules)
- Added `TRIVY_CONFIG_YAML` template constant
- Made `plsec init` deploy trivy configs + pre-commit hook
- Added `check_scanner_configs()` to health.py (checks I-5, I-6, I-7)
- Wired scanner config checks into doctor.py
- Added `make deploy`, `make scan`, `make build-dist`, `make install-test` targets
- Created `docs/INSTALL.md`
- 20 tests added (426 from previous 446)

## Accomplished (previous sessions)

### Session 8: Registry tests + command tests (Phases C-F)

- Fixed all remaining `except Exception` catches (3 files, narrowed to specific types)
- Registry module tests: 142 new tests across 4 test files (100% coverage of each module)
- Tier 3 command tests: 74 new tests across 4 test files (scan.py, doctor.py at 100%)
- Coverage: 52% -> 69%

### Session 7: Registry refactoring Phase B (10 steps)

All 10 consumer files rewired to use registries. `make ci` green (216 pytest +
34 BATS unit + 53 BATS integration + lint/format/typecheck/golden).

| Step    | File                   | What Changed                                                         |
|---------|------------------------|----------------------------------------------------------------------|
| **B1**  | `core/detector.py`     | `detected_agents: dict[str, bool]` replaces per-agent booleans       |
| **B2**  | `core/wizard.py`       | `AGENT_CHOICES` generated from `AGENTS.values()`                     |
| **B3**  | `core/config.py`       | `AgentType` removed, runtime validation via `_resolve_constraint()`  |
| **B4**  | `commands/init.py`     | Agent loop via `resolve_agent_ids()`, `get_template()`               |
| **B5**  | `commands/secure.py`   | `_add_agent_config_changes()` helper, registry loops                 |
| **B6**  | `commands/create.py`   | Agent loop, `get_template()`                                         |
| **B7**  | `commands/validate.py` | Validators moved into `core/agents.py`, loops `AGENTS`               |
| **B8**  | `commands/doctor.py`   | Delegates to `health.py` check functions (~80 lines from 208)        |
| **B9**  | `commands/scan.py`     | Generic loop over `SCANNERS` + `run_scanner()` (~130 lines from 277) |
| **B10** | `commands/proxy.py`    | Uses `PROCESSES["pipelock"]` spec                                    |

Also fixed during Phase B: removed 4 `except Exception` in validate.py, 2 in
proxy.py, fixed variable shadowing, fixed f-string lint. Total codebase reduced
by ~146 SLOC, coverage 43% -> 52%.

### Session 6: Registry refactoring Phase A + design

Created 4 new registry modules (`core/agents.py`, `core/scanners.py`,
`core/processes.py`, `core/health.py`) with registries and pure functions. No
consumer changes. Design doc: `docs/DESIGN-PLSEC-REFACTOR.md`.

### Sessions 1-5: Foundation

1. `make ci` green (lint, format, type check, BATS, pytest)
2. Pydantic removed, plain dataclasses throughout
3. Phase 1 tests: 6 Tier 1 pure-logic test files (122 new tests)
4. Zero lint suppressions
5. Phase 2 tests: 4 Tier 2 filesystem test files (82 new tests)

## Discoveries

1. **Rich `no_color=True` does not strip all ANSI codes** - bold (`\x1b[1m`) and
   dim sequences still appear. Strip ANSI codes from captured text with a helper
   in tests.
2. **OpenAI key regex `sk-[a-zA-Z0-9]{32,}` doesn't match `sk-proj-*` format** -
   the hyphen in `sk-proj-` breaks the match. Test keys must use pure
   alphanumeric sequences after `sk-`.
3. **The `"both"` agent pattern doesn't scale past 2 agents.**
   `resolve_agent_ids("both")` and `resolve_agent_ids("all")` both expand to all
   registered agent IDs.
4. **Agent config type mismatch:** CLI uses `"claude"` as agent ID but
   `config.py` uses `"claude-code"` as `AgentConfig.type`. Resolved via
   `AgentSpec.config_type` field.
5. **`ty` type checker catches variable shadowing** - `create.py` had a
   `template` parameter and loop variable with the same name but different
   types.
6. **`_LITERAL_CONSTRAINTS` for agent_type is now dynamic** - resolved at
   validation time via `_resolve_constraint("agent_type")` which lazily imports
   from the AGENTS registry.
7. **Validator functions moved into registry entries** - `_validate_claude_md`
   and `_validate_opencode_json` are self-contained private functions in
   `core/agents.py`, eliminating circular imports.
8. **Zero `except Exception` remaining** - all narrowed to specific exception types across 3 files.
9. **Typer CLI runner flag ordering matters** - flags like `--secrets`, `--code`
   must come BEFORE the positional path argument, or typer returns exit code 2
   (parsing error). Tests in `test_scan.py` were fixed for this.
10. **`patch.multiple` requires short attribute names** -
    `patch.multiple("module", attr1=mock1)` not full dotted paths. For full
    dotted paths, use individual `patch()` calls or an `ExitStack` pattern (as
    done in `test_doctor.py`).
11. **`ty` checks test files too** - `make ci` only runs `ty check src/`, but
    running `ty check tests/` catches real issues. Test helpers must use proper
    Literal types (not bare `str`) when constructing dataclasses with Literal
    fields. Use `assert content is not None` before operations on `str | None`
    fields.
12. **Trailing docstrings on dataclass fields are a pre-PEP 526 pattern.**
    Project convention: comments above fields, class docstrings as docstrings.
13. **Agent metadata was scattered across 35+ files.** Registry reduced adding a
    new agent to 1 `AgentSpec` entry.
14. **Scanner invocation follows an identical pattern across all 4 tools.**
    Generic `run_scanner(spec, target, home)` replaces all four `run_<tool>()`
    functions.
15. **Bootstrap/CLI gap is significant.** Wrapper scripts, shell aliases, and
    session logging only exist in bootstrap -- the Python CLI has none of these.
    `AgentSpec.wrapper_template` exists but is unused. `plsec init` needs to
    generate wrappers.
16. **`CLAUDE_CODE_SHELL_PREFIX`** is the key integration point for audit
    logging. It wraps ALL bash commands Claude Code executes. Setting it in the
    wrapper gives complete visibility into what the LLM did during a session.
17. **Trivy trivy-secret.yaml has a blocking RE2 regex bug.** The
    `openai-legacy` rule uses `(?!...)` negative lookahead which Go's regexp
    (RE2) does not support. Secret scanning is completely broken.
18. **Bandit scans `.venv/` by default.** All findings in `plsec scan` output
    are false positives from third-party packages. Need `--exclude .venv,...` in
    the command builder.
19. **`plsec run` is the convergence point.** It bridges the CLI and bootstrap
    by providing managed agent execution with container support, replacing the
    `*-safe` aliases. Warrants a v0.2.0 version bump.
20. **`log_dir` in `plsec.yaml` is aspirational.** The
    `AuditLayerConfig.log_dir` field exists but nothing in the Python CLI writes
    to it. Only bootstrap wrappers write to the logs directory.
21. **Podman as default container runtime.** User-configurable via `plsec.yaml`,
    prominently communicated.
22. **`.venv.make` is dead code.** Referenced only in `make clean` but nothing
    creates it. The only venv is `.venv/`, managed by `uv sync`. Removed.
23. **Bandit `.venv` scanning is a symptom of a broader issue.** Any
    file-walking scanner will scan `.venv/` unless excluded. Need exclusions for
    `.venv`, `.tox`, `node_modules`, `build`, `dist`.
24. **Production distribution: pipx/uvx is primary.** `pipx install plsec` or
    `uvx plsec` creates an isolated venv per tool. Homebrew formula exists but
    has placeholder SHA256s. apt is future.
25. **RE2 regex fix: character class exclusion beats lookahead.** Legacy OpenAI
    keys are `sk-` + pure alphanumeric (no hyphens). Modern keys (`sk-proj-`,
    `sk-ant-`) have hyphens. `[A-Za-z0-9]{40,64}` excludes hyphens naturally,
    making the negative lookahead unnecessary.
26. **Bandit exclusions must cover all generated/vendored paths.** `.venv`,
    `.tox`, `node_modules`, `build`, `dist`, `.eggs` -- any directory containing
    third-party or generated Python files.
27. **Three sources of trivy-secret.yaml existed independently.** Bootstrap
    template, Python CLI template (`TRIVY_SCAN_RULES_YAML`), and deployed copy
    at `~/.peerlabs/plsec/trivy/`. Python template was missing 2 rules
    (`openai-legacy`, `aws-secret-key`). Synced.
28. **`plsec init` didn't deploy trivy configs.** It created the `trivy/`
    directory but never wrote config files into it. Only bootstrap did. Fixed.
29. **`.trivyignore` (plain text) only supports global rule ID suppression.**
    `.trivyignore.yaml` (YAML format) supports per-path suppression but requires
    explicit `--ignorefile` flag (still experimental in trivy v0.69.1).
30. **Trivy `--skip-dirs __pycache__` does not reliably skip `.pyc` files at all
    depths.** Must also use `--skip-files "**/*.pyc"` to exclude compiled
    bytecode.
31. **Trivy's `generic-secret` rule matches any occurrence of the word "secret"
    in code.** Config path references (`trivy-secret.yaml`, `--secret-config`),
    detection regex patterns, docstrings -- a security tool scanning itself is a
    guaranteed false positive factory. Per-path suppression via
    `.trivyignore.yaml` is the correct solution.
32. **plsec has no lifecycle management.** No install, reset, or uninstall
    commands. Testing depends on stale state from previous runs. Users cannot
    cleanly remove plsec or reset to factory defaults. Design doc written:
    `docs/DESIGN-INSTALL-RESET-UNINSTALL.md`.
33. **`grep -oP` is not portable to macOS default grep.** The wrapper
    templates must use `awk` for YAML field extraction instead of
    Perl-compatible regex. Fixed `_detect_preset()` to use
    `awk '/^preset:/ { print $2 }'`.
34. **`CLAUDE_CODE_SHELL_PREFIX` is a prefix command, not an env var that
    wraps output.** Claude Code prepends the script path to every shell
    command it executes, so the audit script receives the original command
    as `$@` and must `exec "$@"` to preserve exit codes and stdio.
35. **Audit log must be separate from session log.** Session logs go to
    `claude-YYYYMMDD.log`, audit logs go to `claude-audit-YYYYMMDD.log`.
    Mixing them would make grep/awk parsing for `plsec-status` unreliable.
36. **The audit script must be fast and fire-and-forget.** It runs on EVERY
    shell command Claude executes. Logging failures must never prevent
    command execution. The `{...} >> "$AUDIT_LOG" 2>/dev/null` pattern
    ensures this.
37. **`make promote` and `make golden` must be run after template changes.**
    The CI pipeline has a `verify` step that diffs `build/bootstrap.sh`
    against `bin/bootstrap.default.sh`, and a `golden-check` step that
    diffs templates against golden files. Both will fail after template
    modifications until promoted/regenerated.
38. **The assembler escaping tests (`test-assembler-escaping.sh`) use
    inline template copies, not actual template files.** This is by
    design -- they test the escaping mechanism itself, not the wrapper
    content. New wrapper features are tested by BATS integration/unit
    tests against the assembled `build/bootstrap.sh`.
39. **OpenCode stores rich operational data in SQLite.** `opencode.db`
    at `~/.local/share/opencode/` contains sessions, messages, 16K+
    parts (tool calls, token usage, patches), todos, and permissions.
    Uses Drizzle ORM with schema migrations. Dual-write to JSON files
    in `storage/`. Git object stores in `snapshot/` for file snapshots.
40. **OpenCode `part` table is equivalent to `CLAUDE_CODE_SHELL_PREFIX`.**
    The `type=tool, tool=bash` parts contain every bash command with
    full input/output. No shell prefix wrapper needed for OpenCode --
    plsec can query the database directly.
41. **Claude Code stores session data as JSONL files.** Per-project at
    `~/.claude/projects/{path-hash}/{session-id}.jsonl`. Each line is a
    JSON object with role, content blocks (text, tool_use, tool_result,
    thinking), version, gitBranch, cwd. `stats-cache.json` has pre-
    aggregated daily metrics (messages, tokens, cost).
42. **Neither agent documents their data format as a stable API.**
    Formats are internal implementation details that evolve across
    versions. A compatibility registry with version pinning and
    automated schema validation is essential.
43. **OpenCode auth tokens stored in plaintext.** `auth.json` at
    `~/.local/share/opencode/auth.json` contains OAuth access/refresh
    tokens per provider. plsec should WARN about this but NEVER read
    token values.

## What Needs to Happen Next

### v0.1.x milestones (in order)

1. ~~**Fix scan bugs**~~ (DONE)
2. ~~**Add `make scan` target**~~ (DONE)
3. ~~**Get `make scan` clean**~~ (DONE -- skip-dirs, skip-files, .trivyignore.yaml)
4. ~~**`plsec init` deploys scanner configs**~~ (DONE -- trivy-secret.yaml, trivy.yaml, pre-commit)
5. ~~**`plsec doctor` checks scanner configs**~~ (DONE -- checks I-5, I-6, I-7)
6. ~~**`plsec install` / `plsec reset` / `plsec uninstall`**~~ (DONE --
   Phases 1-6: inventory, install, scan pre-flight, reset, uninstall,
   docs. 565 tests, 75% coverage)
7. ~~**Update plsec-status-design.md**~~ (DONE - APPROVED v0.2, registry-driven
   check generation, CheckResult data contract, all 5 open questions resolved)
8. ~~**Enhanced wrapper logging**~~ (DONE - Tier 1: git info, duration, preset,
   agent version in both wrappers. Tier 2: `CLAUDE_CODE_SHELL_PREFIX` audit
   logging via `plsec-audit.sh`. 41 BATS tests)
9. **Bridge CLI/bootstrap gap** - `plsec init` generates wrappers +
   shell aliases using `AgentSpec.wrapper_template`
10. **Scan result persistence** - write to logs for plsec-status
11. **`plsec-status` Phase 1** - bash health checks in bootstrap
12. **`plsec-status` Phase 2** - watch mode
13. **Agent monitoring foundation** - `data_dir` in AgentSpec,
    `compatibility.yaml`, adapter protocol, doctor checks D-1..D-4
14. **Agent data adapters** - OpenCode SQLite + Claude Code JSONL
    adapters, plsec-status activity checks

### v0.2.0 milestones

15. **`plsec monitor` command** - agent activity summary, audit view,
    token tracking, security cross-reference with wrapper logs
16. **`plsec run` command** - managed agent execution, container
    isolation (Podman default), `CLAUDE_CODE_SHELL_PREFIX` audit,
    pre/post-flight checks
17. **MCP server harness** - `plsec create --mcp-server` generates
    secured sample MCP server project

## Relevant files / directories

### Design documents
- `AGENTS.md` - Coding standards, build commands, project conventions
- `PROJECT.md` - TODOs, architecture decisions
- `TESTING.md` - Full 3-tier pytest test plan (22 files)
- `docs/DESIGN-AGENT-MONITORING.md` - Agent data monitoring + compatibility registry (PROPOSED)
- `docs/DESIGN-INSTALL-RESET-UNINSTALL.md` - Lifecycle commands (IMPLEMENTED)
- `docs/DESIGN-PLSEC-REFACTOR.md` - Registry refactoring design (IMPLEMENTED)
- `docs/DESIGN-CREATE-SECURE.md` - Create/secure commands (IMPLEMENTED)
- `docs/plsec-status-design.md` - Health check model (APPROVED v0.2)
- `docs/INSTALL.md` - Installation guide (6 paths)

### Registry and core modules
- `src/plsec/core/agents.py` - `AgentSpec`, `AGENTS`, `is_strict()`, `security_mode()`, `get_template()`, `resolve_agent_ids()`, validators
- `src/plsec/core/scanners.py` - `ScannerSpec`, `SCANNERS`, `run_scanner()`, `_TRIVY_SKIP_DIRS`, `_TRIVY_SKIP_FILES`, `_TRIVY_IGNOREFILE`, `_add_trivy_common_flags()`
- `src/plsec/core/processes.py` - `ProcessSpec`, `PROCESSES`, `find_binary()`, `is_running()`, path helpers
- `src/plsec/core/health.py` - `CheckResult`, `PLSEC_SUBDIRS`, `PLSEC_EXPECTED_FILES`, check functions including `check_scanner_configs()`, verdict helpers
- `src/plsec/core/inventory.py` - `Artifact`, `Inventory`, `discover_global_artifacts()`, `discover_external_artifacts()`, `discover_project_artifacts()`, `discover_all()`, `format_size()`

### Lifecycle command modules
- `src/plsec/commands/install.py` - `plsec install`, shared `deploy_global_configs()`, `.installed.json` metadata
- `src/plsec/commands/reset.py` - `plsec reset`, process stop, wipe, redeploy
- `src/plsec/commands/uninstall.py` - `plsec uninstall`, interactive scope selection, artifact removal, remainder report

### Bootstrap templates and wrapper scripts
- `templates/bootstrap/skeleton.bash` - Bootstrap skeleton, `@@INCLUDE*@@` markers
- `templates/bootstrap/wrapper-claude.sh` - Claude wrapper (Tier 1 + Tier 2 logging)
- `templates/bootstrap/wrapper-opencode.sh` - Opencode wrapper (Tier 1 logging)
- `templates/bootstrap/plsec-audit.sh` - Audit script for `CLAUDE_CODE_SHELL_PREFIX`
- `scripts/assemble-bootstrap.sh` - Template assembler
- `scripts/test-assembler-escaping.sh` - 44 escaping tests
- `build/bootstrap.sh` - Assembled output
- `bin/bootstrap.default.sh` - Promoted reference
- `tests/bats/unit/test_wrapper_logging.bats` - 41 BATS wrapper logging tests

### Trivy configuration (3 layers)
- `templates/bootstrap/trivy.yaml` - Bootstrap template (authoritative, includes skip-dirs + skip-files)
- `src/plsec/configs/templates.py` -> `TRIVY_CONFIG_YAML` - Python CLI copy (kept in sync)
- `.trivyignore.yaml` - Per-path false positive suppression (21 files, 4 rule IDs + 1 misconfig)

### Test files (565 pytest tests, all passing, 75% coverage)
- `tests/conftest.py` - 3 shared fixtures
- `tests/test_cli.py` - 4 tests (top-level app smoke tests)
- `tests/test_config.py` - 28 tests (config + package version)
- `tests/test_tools.py` - 21 tests
- `tests/test_templates.py` - 46 tests (skip-dirs, skip-files, rule sync)
- `tests/test_integrity.py` - 29 tests
- `tests/test_validate.py` - 18 tests
- `tests/test_output.py` - 20 tests
- `tests/test_init.py` - 19 tests (deploy file, preset configs, scanner config deployment)
- `tests/test_install_cmd.py` - 30 tests (deploy logic, idempotency, force, check, metadata, CLI)
- `tests/test_reset.py` - 15 tests (wipe, external removal, dry-run, cancel, redeploy)
- `tests/test_uninstall.py` - 19 tests (artifact removal, scope selection, dry-run, interactive, customised files)
- `tests/test_inventory.py` - 43 tests (artifact dataclass, inventory, discover functions)
- `tests/test_detector.py` - 34 tests
- `tests/test_create.py` - 20 tests
- `tests/test_agents.py` - 40 tests (registry structure + helpers)
- `tests/test_scanners.py` - 49 tests (skip-dirs, skip-files, ignorefile)
- `tests/test_processes.py` - 23 tests (spec, paths, is_running)
- `tests/test_health.py` - 47 tests (scanner config checks)
- `tests/test_secure.py` - 39 tests (Change/ChangeSet, calculate_changes, apply_changes)
- `tests/test_scan.py` - 15 tests (scan execution, flag resolution, pre-flight prerequisites)
- `tests/test_doctor.py` - 14 tests (render, orchestration, flags)
- `tests/test_proxy.py` - 14 tests (start, stop, status, logs)

### Packaging
- `pyproject.toml` - MIT license, no pydantic
- `VERSION` - Single source of truth for semver
- `Makefile` - `make ci` runs full pipeline
