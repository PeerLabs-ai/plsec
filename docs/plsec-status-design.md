# plsec-status: Design Specification

## Document Control

| Field    | Value                                     |
|----------|-------------------------------------------|
| Author   | Gylthuin (with AI Assistance from Claude) |
| Status   | DRAFT                                     |
| Version  | 0.1                                       |
| Date     | 2026-02-15                                |
| Audience | plsec contributors, community test team   |


## Problem Statement

When plsec is working correctly, it produces no visible output. Scans pass
silently, hooks run without blocking, wrappers log to files nobody is
actively watching. From the user's perspective, "nothing happened" and
"nothing is running" are indistinguishable.

Community test team feedback (February 2026) confirms this creates a trust
gap: users need continuous evidence the system is active and functioning,
not just error reports when something fails. This is analogous to the "dark
cockpit" problem in aviation instrumentation -- an unlit panel is ambiguous
about whether everything is fine or the instruments are dead.


## Design Principles

1. **Zero additional dependencies.** The status command ships inside
   bootstrap.sh output. No Python, no pip, no npm. Pure bash, same as the
   rest of plsec.

2. **Read-only.** Status never modifies state. It inspects files, checks
   processes, reads logs. Safe to run at any time, including in CI.

3. **Composable.** Machine-readable output (JSON via `--json`) alongside
   the human-readable default. Enables future TUI, web dashboard, or
   monitoring integration without changing the data layer.

4. **Graduated disclosure.** Quick glance at the top (overall health),
   details below. `--verbose` for everything. `--watch` for continuous.

5. **Health assertions, not raw data.** Each check produces a verdict
   (green/yellow/red) with rationale. The user sees "pre-commit hook:
   active" not "file exists at .git/hooks/pre-commit."


## Scope

### Phase 1: `plsec-status` (bash, ships in bootstrap)

Single command, one-shot execution, colored terminal output. Answers:
"Is plsec installed, configured, and active in this environment?"

### Phase 2: `plsec-status --watch` (bash, minimal extension)

Continuous refresh mode. Same data, re-polled on interval. Answers: "Is
plsec still working while I use my AI agent?"

### Phase 3: TUI (separate package, Textual or similar)

Interactive dashboard with live log tailing, scan triggering, session
history. Built on the data contracts established in Phases 1-2. Out of
scope for this document; noted here for roadmap context.


## Health Model

### Check Categories

Each check belongs to one of four categories:

- **Installation** -- is the component present and reachable?
- **Configuration** -- is the component configured correctly for the active mode?
- **Activity** -- has the component been active recently?
- **Findings** -- has the component detected anything requiring attention?

### Verdicts

| Verdict | Display  | Meaning                                                                   |
|---------|----------|---------------------------------------------------------------------------|
| OK      | green    | Component is present, configured, and recently active with no findings    |
| WARN    | yellow   | Component is present but degraded, stale, or has non-blocking findings    |
| FAIL    | red      | Component is missing, misconfigured, or has blocking findings             |
| SKIP    | dim/grey | Component is not applicable (e.g., opencode checks when `--agent claude`) |

### Check Inventory

The following table defines each health check, its category, and the
thresholds for each verdict.

#### Installation Checks

Note: the installation checks are similar to the checks done in ```plsec doctor```


| ID   | Check                | OK                                                                              | WARN                                       | FAIL                        |
|------|----------------------|---------------------------------------------------------------------------------|--------------------------------------------|-----------------------------|
| I-1  | plsec directory      | `$PLSEC_DIR` exists with expected subdirectories                                | Partial structure (e.g., missing `trivy/`) | `$PLSEC_DIR` does not exist |
| I-2  | CLAUDE.md config     | `$PLSEC_DIR/configs/CLAUDE.md` exists                                           | File exists but is empty or zero-length    | File missing                |
| I-3  | opencode.json config | `$PLSEC_DIR/configs/opencode.json` exists and parses as valid JSON              | File exists but is not valid JSON          | File missing                |
| I-4  | trivy binary         | `command -v trivy` succeeds                                                     | --                                         | trivy not found on PATH     |
| I-5  | trivy config         | `$PLSEC_DIR/trivy/trivy-secret.yaml` exists                                     | --                                         | File missing                |
| I-6  | pre-commit template  | `$PLSEC_DIR/configs/pre-commit` exists and is executable                        | Exists but not executable                  | Missing                     |
| I-7  | wrapper scripts      | claude-wrapper.sh / opencode-wrapper.sh present and executable (per agent type) | Present but not executable                 | Missing                     |
| I-8  | trivy binary         | `command -v trivy` succeeds                                                     | --                                         | trivy not found on PATH     |
| I-9  | bandit binary        | `command -v bandit` succeeds                                                    | --                                         | bandit not found on PATH    |
| I-10 | git binary           | `command -v git` succeeds                                                       | --                                         | git not found on PATH       |
| I-11 | semgrep binary       | `command -v semgrep` succeeds                                                   | --                                         | semgrep  not found on PATH  |


#### Configuration Checks

| ID  | Check                     | OK                                                                                                        | WARN                                                        | FAIL                                                        |
|-----|---------------------------|-----------------------------------------------------------------------------------------------------------|-------------------------------------------------------------|-------------------------------------------------------------|
| C-1 | security mode             | Detects strict vs balanced from CLAUDE.md content                                                         | --                                                          | Cannot determine mode (file corrupt or unrecognized format) |
| C-2 | agent type                | Detects which agents are configured (claude/opencode/both) based on presence of config files and wrappers | --                                                          | No agent configs found despite `$PLSEC_DIR` existing        |
| C-3 | pre-commit hook (project) | `.git/hooks/pre-commit` exists, is executable, and contains plsec reference                               | Hook exists but does not reference plsec                    | No hook or not in a git repo                                |
| C-4 | CLAUDE.md (project)       | `./CLAUDE.md` exists in current working directory                                                         | Present but differs from `$PLSEC_DIR/configs/CLAUDE.md`     | Not present                                                 |
| C-5 | opencode.json (project)   | `./opencode.json` exists in current working directory                                                     | Present but differs from `$PLSEC_DIR/configs/opencode.json` | Not present                                                 |
| C-6 | global opencode config    | `~/.config/opencode/opencode.json` exists                                                                 | Exists but differs from plsec version                       | Missing                                                     |
| C-7 | version check             | Running version matches installed version in `$PLSEC_DIR`                                                 | Version mismatch (stale install)                            | Cannot determine version                                    |

#### Activity Checks

| ID  | Check         | OK                                                  | WARN                                       | FAIL                                    |
|-----|---------------|-----------------------------------------------------|--------------------------------------------|-----------------------------------------|
| A-1 | wrapper logs  | Log files in `$PLSEC_DIR/logs/` modified within 24h | Log files exist but stale (>24h, <7d)      | No log files, or all logs older than 7d |
| A-2 | session count | Parse log files for session count today             | Zero sessions today but sessions this week | No sessions found in any logs           |
| A-3 | last scan     | Parse scan.sh output or trivy invocation from logs  | Last scan >24h ago                         | No scan evidence in logs                |

#### Findings Checks

| ID  | Check            | OK                                     | WARN                              | FAIL                                                                  |
|-----|------------------|----------------------------------------|-----------------------------------|-----------------------------------------------------------------------|
| F-1 | secrets detected | Last trivy scan exited 0 (no findings) | Cannot determine last scan result | Last scan exited non-zero (secrets found)                             |
| F-2 | hook blocks      | No commit rejections in recent logs    | --                                | Pre-commit hook blocked a commit (informational, not necessarily bad) |

### Check-to-Category Mapping Notes

- Installation checks are evaluated first. If I-1 fails, remaining checks
  are skipped with a message directing the user to run bootstrap.
- Configuration checks assume installation succeeded.
- Activity checks may all return WARN or FAIL if plsec was just installed
  and hasn't been exercised yet. This is expected and the output should
  say so explicitly ("No activity yet -- run a wrapper or scan to populate
  logs").
- Findings checks depend on activity; if no scans have run, findings
  checks should SKIP rather than FAIL.


## Output Format

### Human-readable (default)

```
plsec v0.1.1-bootstrap [strict] [claude + opencode]

  Installation
    plsec directory       OK    ~/.peerlabs/plsec/
    CLAUDE.md config      OK    strict mode
    opencode.json config  OK    strict mode, instructions: [CLAUDE.md]
    trivy                 OK    v0.58.1
    trivy config          OK    8 rules, 3 allow-rules disabled
    pre-commit template   OK    executable
    wrapper: claude       OK    executable
    wrapper: opencode     OK    executable

  Configuration (project: ~/projects/my-app)
    pre-commit hook       OK    installed, references plsec
    CLAUDE.md             WARN  present but differs from template
    opencode.json         OK    matches template

  Activity
    last session          OK    today 14:32 UTC (claude)
    sessions today        OK    3 (claude: 2, opencode: 1)
    last scan             WARN  2 days ago

  Findings
    secrets detected      OK    last scan clean
    hook blocks           OK    no recent blocks

  Overall: OK (1 warning)
```

### Machine-readable (`--json`)

```json
{
  "version": "0.1.1-bootstrap",
  "mode": "strict",
  "agents": ["claude", "opencode"],
  "overall": "ok",
  "warnings": 1,
  "errors": 0,
  "checks": [
    {
      "id": "I-1",
      "category": "installation",
      "name": "plsec directory",
      "verdict": "ok",
      "detail": "~/.peerlabs/plsec/",
      "timestamp": "2026-02-15T14:35:00Z"
    }
  ]
}
```

The JSON schema should be considered unstable until version 1.0. Consumers
should tolerate unknown fields and missing optional fields.

### Quiet mode (`--quiet`)

Exit code only. 0 = all OK. 1 = warnings present. 2 = failures present.
No output. Intended for CI and scripting.


## Watch Mode

`plsec-status --watch [--interval N]`

Default interval: 5 seconds. Uses `while true; do clear; plsec-status; sleep N; done`
pattern. No curses or terminal manipulation beyond `clear`.

Additions over one-shot mode:

- Timestamp of last refresh in header
- Delta indicators for session count and scan count ("sessions today: 3 (+1)")
- Log tail (last 5 lines from most recent log file)

Watch mode reuses the same check functions as one-shot mode. No separate
code path.


## Integration Points

### bootstrap.sh

The status script is generated as `$PLSEC_DIR/plsec-status.sh` alongside
the existing wrappers. Template lives at
`templates/bootstrap/plsec-status.sh`. Shell alias `plsec-status` is added
alongside the existing `plsec-scan` alias.

### Structured Logs (prerequisite for Phase 3)

Current log format is human-readable:

```
[2026-02-15T14:32:00Z] [12345] === Session started: /path/to/project ===
[2026-02-15T14:32:00Z] [12345] Args: --help
[2026-02-15T14:35:00Z] [12345] === Session ended: exit code 0 ===
```

Phase 1 parses this with grep/awk. For Phase 3 (TUI), wrapper log format
should migrate to JSON lines:

```json
{"ts":"2026-02-15T14:32:00Z","pid":12345,"event":"session_start","cwd":"/path/to/project","args":["--help"]}
{"ts":"2026-02-15T14:35:00Z","pid":12345,"event":"session_end","exit_code":0}
```

This migration is not required for Phase 1. Noted here as a design
constraint: the status check parsing logic should be isolated into
functions so it can be swapped when log format changes.


## Implementation Plan

### Phase 1 Deliverables

1. `templates/bootstrap/plsec-status.sh` -- the status script template
2. Skeleton update -- `@@INCLUDE_SCRIPT:plsec-status.sh@@` marker and
   write/chmod block
3. Alias addition -- `plsec-status` in shell aliases section
4. BATS tests:
   - `tests/bats/unit/test_status.bats` -- check function unit tests
   - `tests/bats/integration/test_status.bats` -- full execution tests
5. Makefile -- no changes needed (assembler handles new templates
   automatically)

### Estimated Size

The status script should be approximately 150-250 lines of bash. Each
check is a function returning a verdict string. The main function iterates
checks, formats output, and computes the overall verdict.

### Dependencies on Existing Work

- Requires build system (skeleton + assembler) to be functional (done)
- Requires `$PLSEC_DIR` layout to be stable (stable since v0.1.0)
- Requires wrapper log format to be parseable (current format is sufficient)

### What This Does Not Cover

- Log rotation or retention policy (separate concern)
- Remote status reporting or metrics export
- Scan scheduling or automation
- Pipelock status integration (deferred until pipelock package is verified)
- TUI implementation (Phase 3, separate design document)


## Open Questions

1. **Project-level vs global-level checks.** Should `plsec-status` always
   check the current working directory for project-level config, or should
   there be an explicit `--project /path` flag? Current design assumes CWD
   is the project.

2. **Staleness thresholds.** The 24h/7d thresholds for activity checks are
   arbitrary. Should these be configurable, or are fixed thresholds
   sufficient for the initial release?

3. **Hook introspection depth.** C-3 checks for plsec references in the
   pre-commit hook. Should it also validate the hook actually calls trivy
   correctly, or is presence-checking sufficient?

4. **Multi-project awareness.** Users may have plsec deployed across
   multiple projects. Should status report on all known projects (by
   scanning log directories) or only the current one?

5. **Exit code semantics.** Should WARN produce exit code 0 or 1? CI
   pipelines may want to distinguish "all green" from "green with
   warnings." Current proposal: 0=OK, 1=WARN, 2=FAIL.


## Appendix A: Phase 3 TUI Sketch

For roadmap context only. Not in scope for this specification.

A Textual-based TUI (`pip install plsec-tui`) would provide:

- Live dashboard with auto-refreshing health checks
- Log tailing pane (filterable by agent, severity)
- Interactive scan trigger (run trivy from the TUI)
- Session history browser
- Configuration viewer/editor

The TUI reads the same `$PLSEC_DIR` state and parses the same log format.
The JSON output from `plsec-status --json` serves as the data contract
between the bash layer and the Python TUI layer. If structured logs
(JSON lines) are implemented before the TUI, the TUI can stream logs
directly rather than parsing text.

Community contribution target: the TUI is a good candidate for community
ownership once the data contracts from Phases 1-2 are stable.
