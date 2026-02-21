# plsec Registry Refactoring - Design Specification

## Document Control

| Field    | Value                                     |
|----------|-------------------------------------------|
| Author   | Gylthuin (with AI Assistance from Claude) |
| Status   | DRAFT                                     |
| Version  | 0.1                                       |
| Date     | 2026-02-21                                |
| Audience | plsec contributors                        |


## Problem Statement

Testing Phase 3 (subprocess mocking) exposed structural problems in the
codebase that make testing difficult and adding new agents/tools expensive.
The root cause is **scattered metadata**: knowledge about agents, scanners,
and managed processes is duplicated across command files rather than
declared in one place and consumed generically.

### Evidence

A full codebase trace identified the following change costs:

| Scenario                          | Files to change                                  | Lines to touch |
|-----------------------------------|--------------------------------------------------|----------------|
| Add a new AI agent (e.g., Gemini) | ~35                                              | 50+            |
| Add a new scanner tool            | ~15                                              | 30+            |
| Test `doctor.py` in isolation     | Requires 5 mocks, 0 pure-logic seams             |                |
| Test `scan.py` in isolation       | 4 bespoke `run_*` functions to mock individually |                |

### Specific problems

1. **`doctor.py` is a 140-line monolith.** It mixes 5 concerns (directory
   checks, config checks, tool checks, optional tool checks, runtime
   checks) in one function with no testable seams. The `plsec-status`
   design doc (I-1 through F-2) needs the same check logic, guaranteeing
   duplication.

2. **Agent metadata is scattered across 12+ if/elif branches** in
   `init.py`, `secure.py`, `create.py`, `validate.py`, and `doctor.py`.
   Each branch hardcodes which file to create, which template to use, and
   which detector field to check. Adding a third agent requires touching
   all of them.

3. **The `"both"` agent pattern doesn't scale.** `AgentType = Literal[
   "claude", "opencode", "both"]` appears in 3 command files. When a
   third agent is added, `"both"` becomes ambiguous. The concept should
   be "all configured agents", not an enumerated variant.

4. **Scanner invocation is ad hoc.** `scan.py` has 4 separate
   `run_<tool>()` functions, each constructing a `subprocess.run` call
   with bespoke argument lists and result parsing. The pattern is
   identical across all four; only the arguments differ.

5. **`secure.py` `calculate_changes()` has per-file blocks** that
   duplicate the agent-to-template mapping already present in `init.py`.

6. **Process management is hardcoded to Pipelock.** `proxy.py` is 267
   lines of Pipelock-specific code. The pattern (PID file, log file,
   start/stop/status) is generic but the implementation is not.


## Design Principles

1. **Declare once, consume everywhere.** Metadata about agents, scanners,
   and processes lives in registry modules. Commands iterate the
   registries; they don't hardcode entity knowledge.

2. **Entities and operations are separate concerns.** Registries describe
   *what exists* (nouns). Commands describe *what to do* (verbs). The
   interface between them is iteration.

3. **New entity, one file change.** Adding a new agent should require
   adding one `AgentSpec` entry. Adding a new scanner should require
   adding one `ScannerSpec` entry. No if/elif changes in command files.

4. **Testable without mocking.** Registry data and check functions should
   be pure or near-pure (taking `Path` arguments, not calling
   `get_plsec_home()` internally). Mocking is reserved for subprocess
   calls, not for plumbing.

5. **Don't over-abstract.** We're not building a plugin system. The
   registries are plain dicts of dataclasses, not metaclass-driven
   discovery mechanisms. If it doesn't simplify testing or reduce
   duplication, it doesn't belong here.


## Architecture

### Entity-Operation Model

There are three entity types (the nouns) and four operation families (the
verbs):

```
  Entities (Registries)              Operations (Commands)
  =====================              =====================

  AGENTS                  ------>    CREATE / INIT / SECURE
  (claude, opencode, ...)            "produce config files"

  SCANNERS                ------>    SCAN
  (trivy-secrets, bandit, ...)       "run security checks"

  PROCESSES               ------>    PROXY (start/stop/status)
  (pipelock, ...)                    "manage background services"

  All three               ------>    DOCTOR / STATUS (MONITOR)
                                     "check environment health"
```

Operations iterate registries. They don't contain entity-specific
knowledge. The registry is the single source of truth.


### New Core Modules

Four new files in `src/plsec/core/`:

```
core/
├── agents.py        # Agent registry
├── scanners.py      # Scanner registry
├── processes.py     # Process registry
├── health.py        # Health check functions
├── config.py        # (existing) Configuration loading
├── detector.py      # (existing) Project analysis
├── output.py        # (existing) Rich console helpers
├── tools.py         # (existing) Tool checking
└── wizard.py        # (existing) Interactive prompts
```


## Detailed Design

### 1. Agent Registry (`core/agents.py`)

```python
@dataclass
class AgentSpec:
    """Everything plsec needs to know about an AI coding agent."""

    # Short identifier used in CLI and config (e.g., "claude", "opencode")
    id: str

    # Human-readable name (e.g., "Claude Code", "OpenCode")
    display_name: str

    # Config file this agent expects in the project root (e.g., "CLAUDE.md")
    config_filename: str

    # Map from security mode ("strict", "balanced") to template content
    templates: dict[str, str]

    # Validation function: takes file path, returns list of errors (empty = valid)
    validate: Callable[[Path], list[str]] | None

    # Additional global install location (e.g., ~/.config/opencode/), or None
    global_config_dir: Path | None

    # Bootstrap wrapper script template name (e.g., "wrapper-claude.sh"), or None
    wrapper_template: str | None
```

**Module-level registry:**

```python
AGENTS: dict[str, AgentSpec] = {
    "claude": AgentSpec(
        id="claude",
        display_name="Claude Code",
        config_filename="CLAUDE.md",
        templates={
            "strict": CLAUDE_MD_STRICT,
            "balanced": CLAUDE_MD_BALANCED,
        },
        validate=validate_claude_md,
        global_config_dir=None,
        wrapper_template="wrapper-claude.sh",
    ),
    "opencode": AgentSpec(
        id="opencode",
        display_name="OpenCode",
        config_filename="opencode.json",
        templates={
            "strict": OPENCODE_JSON_STRICT,
            "balanced": OPENCODE_JSON_BALANCED,
        },
        validate=validate_opencode_json,
        global_config_dir=Path.home() / ".config" / "opencode",
        wrapper_template="wrapper-opencode.sh",
    ),
}
```

**Helper functions:**

```python
def get_template(agent_id: str, preset: str) -> str:
    """Get template content for an agent at a given preset level.

    The preset is mapped to a security mode: "strict" and "paranoid"
    map to "strict"; "minimal" and "balanced" map to "balanced".
    """

def is_strict(preset: str) -> bool:
    """Whether a preset uses strict security mode."""
    return preset in ("strict", "paranoid")

def security_mode(preset: str) -> str:
    """Map a preset name to its security mode key."""
    return "strict" if is_strict(preset) else "balanced"

def resolve_agent_ids(agent_arg: str) -> list[str]:
    """Expand the CLI --agent argument to a list of agent IDs.

    "both" (or "all") expands to all registered agent IDs.
    A single agent ID is returned as a one-element list.
    Validates that the ID exists in the registry.
    """
```

**Impact on consumers:**

| Consumer      | Before                                                                               | After                                                                    |
|---------------|--------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| `init.py`     | `if agent in ("claude", "both"): ...` x2, `if agent in ("opencode", "both"): ...` x2 | `for agent_id in resolve_agent_ids(agent): spec = AGENTS[agent_id]; ...` |
| `secure.py`   | `if "claude" in state.agents: ...`, `if "opencode" in state.agents: ...`             | `for agent_id in state.agents: spec = AGENTS[agent_id]; ...`             |
| `create.py`   | Same pattern as init.py                                                              | Same fix as init.py                                                      |
| `validate.py` | `validate_claude_md()`, `validate_opencode_json()` hardcoded                         | `for spec in AGENTS.values(): if spec.validate: spec.validate(path)`     |
| `doctor.py`   | Hardcoded checks for CLAUDE.md and opencode.json                                     | Iterate `AGENTS` for expected config files                               |
| `detector.py` | `has_claude_md: bool`, `has_opencode_json: bool`                                     | `detected_agents: dict[str, bool]` populated by iterating `AGENTS`       |
| `wizard.py`   | `AGENT_CHOICES` hardcoded list                                                       | Generated from `AGENTS.values()`                                         |

**Adding a new agent (e.g., Gemini):**

1. Create template strings in `configs/templates.py`
   (e.g., `GEMINI_SETTINGS_STRICT`, `GEMINI_SETTINGS_BALANCED`)
2. Optionally add a `validate_gemini_settings()` function
3. Add one `AgentSpec` entry to `AGENTS` in `core/agents.py`
4. Add bootstrap template if wrapper is needed
5. No changes to any command file


### 2. Scanner Registry (`core/scanners.py`)

```python
@dataclass
class ScannerSpec:
    """Everything plsec needs to know about a security scanner."""

    # Unique identifier (e.g., "trivy-secrets", "bandit")
    id: str

    # Human-readable name (e.g., "Trivy Secret Scan", "Bandit")
    display_name: str

    # Category of scan (e.g., "secrets", "code", "misconfig")
    scan_type: str

    # Binary metadata from core/tools.py (availability checks, install hints)
    tool: Tool

    # Given (target_path, config_path), return subprocess argv
    build_command: Callable[[Path, Path | None], list[str]]

    # Given (returncode, combined_output), return (passed, message)
    parse_result: Callable[[int, str], tuple[bool, str]]

    # Relative path under plsec_home for tool config, or None
    config_file: str | None

    # Subprocess timeout in seconds
    timeout: int = 300

    # If True, missing binary is a skip (pass), not failure
    skip_when_missing: bool = True

    # Predicate to check for scannable files (e.g., *.py), or None
    file_filter: Callable[[Path], bool] | None = None
```

**Module-level registry:**

```python
SCANNERS: dict[str, ScannerSpec] = {
    "trivy-secrets": ScannerSpec(
        id="trivy-secrets",
        display_name="Trivy Secret Scan",
        scan_type="secrets",
        tool=...,  # reference to trivy Tool
        build_command=_build_trivy_secrets_cmd,
        parse_result=_parse_trivy_result,
        config_file="trivy/trivy-secret.yaml",
        skip_when_missing=False,
    ),
    "bandit": ScannerSpec(
        id="bandit",
        display_name="Bandit",
        scan_type="code",
        tool=...,
        build_command=_build_bandit_cmd,
        parse_result=_parse_returncode_result,
        config_file=None,
        skip_when_missing=True,
        file_filter=_has_python_files,
    ),
    # ... semgrep, trivy-misconfig
}
```

**Generic scan runner:**

```python
def run_scanner(
    spec: ScannerSpec,
    target: Path,
    plsec_home: Path,
) -> tuple[bool, str]:
    """Run a single scanner. Handles binary checks, file filtering,
    command construction, subprocess execution, timeout, and result
    parsing. Returns (passed, message)."""
```

**Impact on `scan.py`:**

The 4 separate `run_trivy_secrets()`, `run_trivy_misconfig()`,
`run_bandit()`, `run_semgrep()` functions are replaced by a single
generic loop:

```python
for scanner_id, spec in SCANNERS.items():
    if scan_type != "all" and spec.scan_type != scan_type:
        continue
    passed, message = run_scanner(spec, path, plsec_home)
    # ... tally results
```

**Adding a new scanner:**

1. If the binary isn't already in `REQUIRED_TOOLS`/`OPTIONAL_TOOLS`,
   add a `Tool` entry to `core/tools.py`
2. Write `_build_<tool>_cmd()` and `_parse_<tool>_result()` functions
   (or reuse generic ones like `_parse_returncode_result`)
3. Add one `ScannerSpec` entry to `SCANNERS` in `core/scanners.py`
4. No changes to `scan.py` or any other command file


### 3. Process Registry (`core/processes.py`)

```python
@dataclass
class ProcessSpec:
    """A managed background process that plsec can start/stop/monitor."""

    # Unique identifier (e.g., "pipelock")
    id: str

    # Human-readable name (e.g., "Pipelock Security Proxy")
    display_name: str

    # Command name for shutil.which() (e.g., "pipelock")
    binary: str

    # PID file path, relative to plsec_home (e.g., "pipelock.pid")
    pid_file: str

    # Log file path, relative to plsec_home (e.g., "logs/pipelock.log")
    log_file: str

    # Config file path, relative to plsec_home (e.g., "pipelock.yaml")
    config_file: str

    # How to install the binary
    install_hint: str

    # Given (binary_path, config_path, port, mode), return run argv
    build_run_cmd: Callable[[Path, Path, int, str], list[str]]

    # Given (binary_path, mode, output_path), return config-gen argv, or None
    build_config_cmd: Callable[[Path, str, Path], list[str]] | None
```

**Module-level registry:**

```python
PROCESSES: dict[str, ProcessSpec] = {
    "pipelock": ProcessSpec(
        id="pipelock",
        display_name="Pipelock Security Proxy",
        binary="pipelock",
        pid_file="pipelock.pid",
        log_file="logs/pipelock.log",
        config_file="pipelock.yaml",
        install_hint="go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest",
        build_run_cmd=_build_pipelock_run_cmd,
        build_config_cmd=_build_pipelock_config_cmd,
    ),
}
```

**Generic process management functions:**

```python
def find_binary(spec: ProcessSpec) -> Path | None:
    """Find the process binary on PATH."""

def get_pid_file_path(spec: ProcessSpec, plsec_home: Path) -> Path:
    """Get the full path to the PID file."""

def is_running(spec: ProcessSpec, plsec_home: Path) -> tuple[bool, int | None]:
    """Check if the process is running. Cleans up stale PID files."""

def get_log_path(spec: ProcessSpec, plsec_home: Path) -> Path:
    """Get the full path to the log file."""
```

**Impact on `proxy.py`:**

The hardcoded `get_pid_file()`, `is_pipelock_running()`,
`find_pipelock()` functions are replaced by generic versions that
take a `ProcessSpec`. The `start`, `stop`, `status`, `logs` commands
look up the process spec from the registry.

**Adding a new managed process:**

1. Write `_build_<process>_run_cmd()` and optionally
   `_build_<process>_config_cmd()`
2. Add one `ProcessSpec` entry to `PROCESSES`
3. No changes to `proxy.py` command logic


### 4. Health Check Model (`core/health.py`)

```python
@dataclass
class CheckResult:
    """Result of a single health check."""

    # Check identifier matching plsec-status design doc (e.g., "I-1", "C-3")
    id: str

    # Human-readable check name (e.g., "plsec directory")
    name: str

    # Check category per the health model
    category: Literal["installation", "configuration", "activity", "findings"]

    # Check outcome
    verdict: Literal["ok", "warn", "fail", "skip"]

    # Additional detail for display (e.g., file path, version string)
    detail: str = ""

    # Suggested remediation (e.g., "Run 'plsec init' to create")
    fix_hint: str = ""
```

**Check functions:**

All check functions take explicit arguments (paths, registries) rather
than calling `get_plsec_home()` internally. This makes them testable
with `tmp_path`.

```python
def check_directory_structure(
    plsec_home: Path,
    *,
    fix: bool = False,
) -> list[CheckResult]:
    """Check plsec home and expected subdirectories exist.

    If fix=True, create missing directories and report them as OK.
    Checks I-1 from the status design doc.
    """

def check_agent_configs(
    plsec_home: Path,
    agents: dict[str, AgentSpec],
) -> list[CheckResult]:
    """Check that expected agent config files exist in plsec_home/configs.

    Iterates the agent registry. Checks I-2, I-3 from the status
    design doc.
    """

def check_tools(
    tools: list[Tool],
) -> list[CheckResult]:
    """Convert checked Tool statuses to CheckResults.

    Expects tools to have been checked already via ToolChecker.
    Checks I-4 through I-11 from the status design doc.
    """

def check_runtime() -> list[CheckResult]:
    """Check Python version meets minimum (3.12+)."""

def check_project_configs(
    project_path: Path,
    agents: dict[str, AgentSpec],
) -> list[CheckResult]:
    """Check project-level agent configs exist and match templates.

    Checks C-4, C-5 from the status design doc.
    """
```

**Impact on `doctor.py`:**

```python
@app.callback(invoke_without_command=True)
def doctor(install, fix, all_tools) -> None:
    plsec_home = get_plsec_home()
    results: list[CheckResult] = []

    results.extend(check_directory_structure(plsec_home, fix=fix))
    results.extend(check_agent_configs(plsec_home, AGENTS))
    results.extend(check_config_file(find_config_file()))

    checker = ToolChecker(REQUIRED_TOOLS.copy())
    checker.check_all()
    results.extend(check_tools(checker.tools))

    if all_tools:
        opt_checker = ToolChecker(OPTIONAL_TOOLS.copy())
        opt_checker.check_all()
        results.extend(check_tools(opt_checker.tools))

    results.extend(check_runtime())

    render_results(results)
    render_summary(results)
    exit_on_verdict(results, install=install, fix=fix)
```

This is approximately 25 lines of orchestration. Each `check_*`
function is independently testable.

**Impact on `plsec-status`:**

The bash `plsec-status` script (Phase 1) implements its own checks.
When Phase 3 introduces a Python TUI, it will call the same `check_*`
functions from `core/health.py`. The check IDs (I-1 through F-2) are
shared between the bash and Python implementations, ensuring
consistency.


## Expected Directory Structure Constant

A single constant defines what subdirectories plsec expects under
`~/.peerlabs/plsec/`:

```python
# In core/health.py or a shared constants location
PLSEC_SUBDIRS: list[str] = [
    "configs",
    "logs",
    "manifests",
    "trivy",
    "trivy/policies",
]
```

This replaces the hardcoded list in `doctor.py:84` and `init.py:148`.


## Migration of Existing Code

### detector.py: Agent detection

**Before:**
```python
@dataclass
class ProjectInfo:
    has_claude_md: bool = False
    has_opencode_json: bool = False
```

**After:**
```python
@dataclass
class ProjectInfo:
    # Map from agent ID to whether its config file was found
    detected_agents: dict[str, bool] = field(default_factory=dict)
```

The `analyze()` method iterates `AGENTS` to populate this dict:

```python
for agent_id, spec in AGENTS.items():
    info.detected_agents[agent_id] = (self.path / spec.config_filename).exists()
```

Consumers that previously checked `info.has_claude_md` now check
`info.detected_agents.get("claude", False)`.


### config.py: AgentType constraint

**Before:**
```python
AgentType = Literal["claude-code", "opencode", "codex"]
```

**After:**
The Literal constraint is widened or replaced with string validation
against the agent registry at the boundary:

```python
def _validate_agent_type(value: str) -> None:
    """Validate agent type against known types."""
    # Accept registry IDs and their config-level variants
    valid = {"claude-code", "opencode", "codex"} | set(AGENTS.keys())
    if value not in valid:
        raise ValueError(f"Unknown agent type: {value!r}")
```

The mapping between CLI agent IDs ("claude") and config agent types
("claude-code") is maintained in the agent registry as a `config_type`
field if needed, or as a simple convention.


### wizard.py: Agent choices

**Before:**
```python
AGENT_CHOICES = [
    Choice("claude", "Claude Code", checked=True),
    Choice("opencode", "Opencode", checked=True),
    Choice("copilot", "GitHub Copilot"),
    ...
]
```

**After:**
```python
def get_agent_choices() -> list[Choice]:
    """Generate wizard choices from the agent registry."""
    return [
        Choice(spec.id, spec.display_name, checked=True)
        for spec in AGENTS.values()
    ]
```

Note: Non-plsec agents (Copilot, Cursor, etc.) that appear in the
wizard for informational purposes but don't have plsec config support
can remain as static entries. The registry only contains agents that
plsec actively manages config for.


### secure.py: calculate_changes()

**Before:**
```python
def calculate_changes(project_path, info, state, force=False):
    changes = ChangeSet()
    is_strict = state.preset in ("strict", "paranoid")

    # CLAUDE.md -- 15 lines of if/elif
    claude_content = CLAUDE_MD_STRICT if is_strict else CLAUDE_MD_BALANCED
    if "claude" in state.agents:
        if not info.has_claude_md:
            changes.creates.append(...)
        elif force:
            changes.modifies.append(...)
        else:
            changes.conflicts.append(...)

    # opencode.json -- 15 lines of if/elif (same pattern)
    ...
```

**After:**
```python
def calculate_changes(project_path, info, state, force=False):
    changes = ChangeSet()
    mode = security_mode(state.preset)

    for agent_id in state.agents:
        spec = AGENTS[agent_id]
        _add_agent_config_change(changes, spec, info, mode, force)

    _add_plsec_yaml_change(changes, info, state)
    _add_trivy_change(changes, project_path)
    _add_pre_commit_change(changes, info)
    _add_gitignore_change(changes, project_path, info)
    return changes


def _add_agent_config_change(
    changes: ChangeSet,
    spec: AgentSpec,
    info: ProjectInfo,
    mode: str,
    force: bool,
) -> None:
    """Add a create/modify/skip/conflict entry for one agent's config."""
    exists = info.detected_agents.get(spec.id, False)
    content = spec.templates[mode]

    if not exists:
        changes.creates.append(
            Change(action="create", path=spec.config_filename,
                   description=f"{spec.display_name} configuration",
                   content=content)
        )
    elif force:
        changes.modifies.append(
            Change(action="modify", path=spec.config_filename,
                   description="Replace with template", content=content)
        )
    else:
        changes.conflicts.append(
            Change(action="conflict", path=spec.config_filename,
                   description="Exists but differs from template")
        )
```

Each helper is independently testable.


## Remaining `except Exception` Fixes

Per project policy (never suppress, never catch broad exceptions), two
remaining instances need narrowing:

| File        | Line | Current                  | Fix                                                                           |
|-------------|------|--------------------------|-------------------------------------------------------------------------------|
| `secure.py` | 588  | `except Exception:`      | `except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):` |
| `tools.py`  | 163  | `except Exception as e:` | `except (OSError, subprocess.SubprocessError) as e:`                          |

These are addressed as part of Phase C (cleanup).


## Implementation Plan

### Phasing

The refactoring is split into phases to maintain a green test suite at
each step:

| Phase                   | Scope                                                                                                                                                          | Verify                                    |
|-------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------|
| **A: Foundation**       | Create `core/agents.py`, `core/scanners.py`, `core/processes.py`, `core/health.py` with registries and pure functions. No consumer changes.                    | `make ci` passes (new files are additive) |
| **B: Rewire consumers** | One command at a time: `init.py`, `secure.py`, `create.py`, `validate.py`, `doctor.py`, `scan.py`, `proxy.py`. Update `detector.py`, `wizard.py`, `config.py`. | Run `pytest` after each file change       |
| **C: Cleanup**          | Fix `except Exception` in `secure.py` and `tools.py`. Remove dead code.                                                                                        | `make ci` passes                          |
| **D: Full verify**      | Run full `make ci`. All 216 existing tests pass.                                                                                                               | `make ci` green                           |
| **E: Phase 3 tests**    | Write subprocess-mocking tests against the clean interfaces.                                                                                                   | `pytest` all pass                         |

### Phase B ordering

Consumer files should be rewired in dependency order:

1. `core/detector.py` -- replace `has_claude_md`/`has_opencode_json`
   with `detected_agents` dict
2. `core/wizard.py` -- generate `AGENT_CHOICES` from registry
3. `core/config.py` -- widen `AgentType`, update `LITERAL_CONSTRAINTS`
4. `commands/init.py` -- iterate agents, use `is_strict()`,
   `get_template()`
5. `commands/secure.py` -- iterate agents in `calculate_changes()`,
   extract helpers
6. `commands/create.py` -- same pattern as init
7. `commands/validate.py` -- iterate agents for validation
8. `commands/doctor.py` -- delegate to `health.py` check functions
9. `commands/scan.py` -- generic scanner loop
10. `commands/proxy.py` -- consume `PROCESSES` registry

### Risk mitigation

- Existing Phase 1+2 tests (216 tests) serve as the regression safety
  net. If any fail during Phase B, the consumer change is incorrect.
- Each consumer is changed in a single commit. If a change is too
  complex, it can be reverted independently.
- The registries are additive (Phase A), so they cannot break existing
  code. Phase B is where the risk lives.


## Future Directions

This refactoring establishes the entity-operation model. The following
items are out of scope for this effort but are enabled (or simplified)
by the registry architecture.

### Impact on `plsec-status`

The `plsec-status` design doc (`docs/plsec-status-design.md`) defines
20 health checks across 4 categories (Installation, Configuration,
Activity, Findings). That design predates the registry model and
assumes checks are hand-written per entity. With the registries in
place, the relationship changes:

- **Installation checks (I-1 through I-11)** are generated by
  iterating the agent, scanner, and process registries. Adding a new
  agent automatically adds its installation check. The `check_*`
  functions in `core/health.py` produce `CheckResult` objects with the
  same IDs (I-1, I-2, ...) used in the status design doc.

- **Configuration checks (C-1 through C-7)** use the agent registry to
  know which project-level files to inspect and which templates to
  compare against. `check_project_configs()` iterates `AGENTS` rather
  than hardcoding CLAUDE.md and opencode.json.

- **Activity checks (A-1 through A-3)** and **Findings checks (F-1,
  F-2)** depend on log parsing, which is independent of the registries.
  However, the process registry can inform which log files to inspect
  (each `ProcessSpec` declares its `log_file` path).

The `plsec-status` design doc should be updated to reflect this:

1. **Check generation should be registry-driven.** The check inventory
   tables (I-1 through I-11, C-1 through C-7) should note that checks
   are generated from registries, not enumerated statically. The bash
   Phase 1 implementation may still enumerate checks manually, but the
   Python Phase 3 TUI should iterate the registries.

2. **The `CheckResult` dataclass is the shared data contract.** Both
   `plsec doctor` and the Python `plsec-status` TUI produce
   `CheckResult` objects. The bash `plsec-status` produces equivalent
   output in its text/JSON format. The check IDs are the stable
   interface between all three.

3. **New agents/scanners automatically appear in status output.** This
   is the key benefit: adding a Gemini agent to the registry means
   `plsec doctor` and `plsec-status` both check for Gemini's config
   file without any changes to those commands.


### Multi-Project: The PROJECTS Registry

The current codebase identifies "which project" solely by the current
working directory. There is no project registry, no stored project
paths, and no cross-project awareness. The entity model makes
multi-project support a natural extension.

**Sketch of a PROJECTS registry:**

```python
@dataclass
class ProjectRecord:
    """A project that plsec is managing."""

    # Unique identifier, derived from path or user-assigned
    id: str

    # Absolute path to the project root
    path: Path

    # Path to the project's plsec.yaml
    config_path: Path

    # Agent IDs configured for this project
    agents: list[str]

    # Active security preset
    preset: str

    # Timestamp of last scan, parsed from logs
    last_scan: datetime | None = None

    # Timestamp of last agent session, parsed from logs
    last_session: datetime | None = None
```

**Where the registry would live:**

`~/.peerlabs/plsec/projects.yaml` (or `projects.json`) -- a manifest
of all projects plsec has been initialized in. Updated by `plsec init`
and `plsec secure`. Read by `plsec status --all-projects` and the
Phase 3 TUI dashboard.

**What it enables:**

- `plsec status --all-projects` -- iterate the registry, run checks
  against each project, produce a summary.
- Per-project log directories: `logs/{project.id}/` instead of a
  single flat `logs/` directory.
- Per-project manifests: `manifests/{project.id}/` for integrity
  monitoring across projects.
- `plsec project list` / `plsec project remove` -- management commands.
- The Phase 3 TUI dashboard can show all projects in a table with
  health status per project.

**Why it's deferred:**

The current single-project model works for the common case (one
terminal, one project). Multi-project adds complexity (stale entries,
moved directories, permission boundaries) that should be designed
carefully. The registry architecture makes it possible without
rearchitecting; the `plsec project` command and manifest format are
the remaining design decisions.


## What This Does Not Cover

- **Multi-project registry.** The entity model makes multi-project
  *possible* (iterate PROJECTS instead of just cwd), but the actual
  project registry data structure and `plsec project` command are
  deferred.
- **Bootstrap shell script changes.** The Python CLI registries don't
  affect `bootstrap.sh`. The shell side has its own equivalent patterns
  that may benefit from a similar refactoring, but that is a separate
  effort.
- **Plugin system.** The registries are compile-time dicts, not runtime
  discovery. If third-party agents/scanners need to be registered
  dynamically, that's a future extension.
- **Log format migration.** The `plsec-status` design doc proposes JSON
  lines for Phase 3. This refactoring does not change log formats.


## Open Questions

1. **Agent config type mapping.** The CLI uses `"claude"` as the agent
   ID, but `config.py` uses `"claude-code"` as the `AgentConfig.type`
   value. Should the registry carry both, or should we normalize to one?
   Current proposal: add a `config_type: str` field to `AgentSpec` for
   the YAML-serialized value.

2. **Scanner-to-Tool relationship.** `SCANNERS` references `Tool`
   objects from `REQUIRED_TOOLS`/`OPTIONAL_TOOLS`. Should scanners
   embed their own `Tool` or reference shared ones by ID? Shared
   references avoid duplication but create a coupling between the two
   registries. Current proposal: scanners reference shared Tool objects.

3. **`both` deprecation timeline.** The `"both"` value in `--agent`
   should become `"all"` or be removed in favor of multi-value options
   (`--agent claude --agent opencode`). This is a CLI compatibility
   concern. Current proposal: keep `"both"` as an alias for
   `resolve_agent_ids("all")` during the transition.

4. **Preset-to-mode mapping.** Currently 4 presets map to 2 modes
   (strict/balanced). Should the registry support more modes, or is the
   2-mode model sufficient? Current proposal: 2 modes is sufficient.
   Presets control layer enable/disable flags, not template content.


## References

- [TESTING.md](../TESTING.md) -- Test plan that exposed these issues
- [docs/plsec-status-design.md](plsec-status-design.md) -- Health check
  model and check IDs (I-1 through F-2)
- [docs/DESIGN-CREATE-SECURE.md](DESIGN-CREATE-SECURE.md) -- Original
  create/secure command design
- [PROJECT.md](../PROJECT.md) -- Project roadmap and architecture
