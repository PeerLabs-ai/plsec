# HANDOFF.md - bootstrap.sh Refactoring Session

## Context

Ongoing refactoring of `bootstrap.sh` (v0.1.1-bootstrap), the Peerlabs Security
(plsec) bootstrap script for AI coding assistant security. The script sets up
CLAUDE.md, OpenCode configuration, Trivy secret scanning, logging wrappers, and
pre-commit hooks.

Prior work in chat "AI code tool usage policies":
https://claude.ai/chat/75f76a63-5a05-4250-9aa7-a9d72227209b

OpenCode permissions research:
https://claude.ai/chat/f87d9ff2-2669-4341-88d3-69c9167996f8

## Changes Made This Session

### 1. Log function naming consistency

- Renamed `log_success()` to `log_ok()` (label `[OK]`)
- Renamed `log_warning()` to `log_warn()` (label `[WARN]`)
- All call sites already used `log_ok` / `log_warn`; definitions now match
- Kept verbose multi-line definition style (not the one-liner form from the
  original chat)

### 2. Replaced hallucinated `.opencode.toml` with correct `opencode.json`

The `.opencode.toml` format with `[shell]`, `[filesystem]`, `[security]`,
`[behavior]`, `[logging]` sections was fabricated in the original chat session.
OpenCode uses `opencode.json` with a `permission` key supporting `allow`/`ask`/`deny`
actions and pattern-based rules.

**What changed:**

- Variable: `OPENCODE_TOML_CONTENT` -> `OPENCODE_JSON_CONTENT`
- File: `.opencode.toml` -> `opencode.json` (all references)
- Global config: `~/.config/opencode/config.toml` -> `~/.config/opencode/opencode.json`
- Wrapper script: copies `opencode.json` instead of `.opencode.toml`
- Summary output: all path references updated
- Added block comment documenting known bypass issues with issue numbers

**Strict mode mapping (TOML -> JSON):**

| Old TOML concept | New JSON equivalent |
|---|---|
| `[shell].allow_network = false` | `"webfetch": "deny"`, `"websearch": "deny"` |
| `[shell].dangerous_commands` | `"bash"` permission with per-command patterns |
| `[filesystem].sandbox = true` | `"external_directory": "deny"` |
| `[filesystem].allowed_paths` | Implicit via `"edit"` / `"read"` defaults |
| `[filesystem].denied_paths` | Per-path `"deny"` rules under `"read"` and `"edit"` |
| `[security].confirm_commands` | `"*": "ask"` as global default |
| `[behavior].max_file_size` etc. | No equivalent in OpenCode schema; dropped |
| `[logging]` | Handled by wrapper scripts, not OpenCode config |
| `[ai].provider` / `[ai].model` | Dropped; not a security concern |

**Known caveats documented in script comments:**
- SDK may ignore custom agent deny permissions (anomalyco/opencode#6396)
- Agents can circumvent denied tools via bash (sst/opencode#4642)
- Plan agent may ignore edit permissions (sst/opencode#3991)

### 3. Added --dry-run / --simulate mode

Allows running the script to see all operations without making filesystem changes.

**Design decisions:**

- `--dry-run` is the primary flag; `--simulate` is an alias (Unix convention:
  make, rsync, apt all use `--dry-run`)
- Helper functions (`run_cmd`, `write_file`, `write_file_from_var`, `copy_file`,
  `make_executable`, `ensure_dir`, `append_to_file`) wrap all destructive
  operations and check a `DRY_RUN` flag
- All dry-run output uses `[DRY RUN]` prefix via `log_info` for grep-ability
- Interactive prompts (dependency installation) are skipped in dry-run mode;
  missing deps are reported without prompting
- Pipelock `command -v` check is relaxed in dry-run mode (`|| [[ "$DRY_RUN" == true ]]`)
  so the full plan is shown even when pipelock isn't installed
- Heredoc content inside wrapper scripts (claude-wrapper.sh, opencode-wrapper.sh)
  is NOT affected by dry-run -- those are file contents, not bootstrap operations
- `write_file` consumes stdin to `/dev/null` in dry-run mode to prevent heredoc
  content from leaking to stdout

### 4. Consolidated PLSEC_DIR to single declaration

Previously the path `${HOME}/.peerlabs/plsec` appeared in 11 places. Now
`PLSEC_DIR` is declared once (line 22) and all other references derive from it.

**Approach by category:**

| Location | Before | After |
|---|---|---|
| Main declaration (line 22) | `PLSEC_DIR="${HOME}/.peerlabs/plsec"` | Unchanged -- source of truth |
| CLAUDE.md balanced content | Hardcoded `~/.peerlabs/plsec/logs/` | Double-quoted string with `${PLSEC_DIR}/logs/` |
| 5 generated scripts (heredocs) | Each redeclared `PLSEC_DIR="${HOME}/.peerlabs/plsec"` | Unquoted heredocs (`<< EOF`), `PLSEC_DIR="${PLSEC_DIR}"` interpolates from bootstrap |
| 4 alias definitions | Single-quoted with `${HOME}/.peerlabs/plsec/...` | Double-quoted with `${PLSEC_DIR}/...` |

**Heredoc escaping convention for generated scripts:**

Generated scripts use unquoted heredoc delimiters (`<< EOF` instead of `<< 'EOF'`)
so `${PLSEC_DIR}` resolves from the bootstrap context. All variables intended to
remain as runtime references in the generated script are escaped:

- `\$LOG_FILE`, `\$TARGET`, `\$EXIT_CODE` etc. -- script-local variables
- `\$(date ...)`, `\$(pwd)` -- command substitutions
- `\$\$`, `\$*`, `\$@`, `\$?` -- special parameters
- `\${PLSEC_DIR}` -- references to the script's own PLSEC_DIR after its assignment
- `\${1:-.}` -- positional parameter expansion

The first `PLSEC_DIR="${PLSEC_DIR}"` line in each generated script is NOT escaped,
so it receives the interpolated path value (e.g. `PLSEC_DIR="/home/user/.peerlabs/plsec"`).
Subsequent `\${PLSEC_DIR}` references ARE escaped so they use the script's own variable
at runtime.

**Consequence:** To change the base path, edit line 22 only. Re-running bootstrap
regenerates all scripts and aliases with the new path.

## In-Progress / Not Yet Done

### 5. main() function guard for testability

Wrapped all execution logic (argument parsing through summary output) in a
`main()` function with a source guard at the bottom of the file:

```bash
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
```

**Changes:**

- `check_command()` moved from inline in section 1 up to the function
  definitions block (between `detect_os` and `main`)
- Configuration variables made overridable via environment:
  `PLSEC_DIR="${PLSEC_DIR:-${HOME}/.peerlabs/plsec}"` etc.
- `main()` opens after the last function definition, closes before the
  source guard
- No indentation change inside `main()` -- at 700+ lines, adding a nesting
  level would produce noisy diffs and hurt readability

**Verified behavior:**

- `source bootstrap.sh` loads all functions without executing main
- Direct execution (`bash bootstrap.sh --dry-run`) works as before
- All functions available after sourcing: log_ok, log_warn, log_info,
  log_error, detect_os, check_command, write_file, run_cmd, ensure_dir,
  make_executable, main
- `PLSEC_DIR` overridable via environment for test isolation

**Why this matters:**

BATS unit tests need to source bootstrap.sh for its function definitions
without triggering the full execution flow. Without the guard, sourcing
causes side effects (argument parsing, filesystem operations). With it,
tests can `source bootstrap.sh` then call individual functions in isolation.

See `docs/bootstrap-testing.md` for the full design document. Key decisions:

- BATS (bats-core) chosen over ShellSpec and shUnit2
- Three test tiers: unit (functions), integration (file generation, idempotency),
  platform (macOS/Linux CI matrix)
- main() function guard: DONE (see change 5 above)
- Container-based integration tests using Podman (preferred) or Docker (fallback)
- bashcov for bash coverage reporting (add once test suite stabilizes)
- Golden files in tests/bats/golden/ with build step assembling bootstrap.sh
  from templates/bootstrap/ (next significant refactor)
- GitHub Actions CI with matrix: os x mode x agent
- shasum -a 256 for all checksum operations (no md5sum)

### `detect_os` integration

The `detect_os()` function exists but is not called anywhere yet. V is planning
to use it to branch OS-specific behavior including:

- `sed -i` portability (GNU vs BSD)
- Package manager selection (`brew` vs `apt-get` for Debian-based Linux)
- Potentially other OS-specific paths or commands

### Pre-commit hook subshell bug

The pipe-based `while read` loop means `exit 1` terminates the subshell, not
the hook script. Needs process substitution or a flag variable:

```bash
# Current (broken):
git diff --cached --name-only | while read -r file; do
    ...
    exit 1  # exits subshell only
done

# Fix option 1 - process substitution:
while read -r file; do
    ...
    exit 1  # exits the hook
done < <(git diff --cached --name-only)

# Fix option 2 - flag variable:
FAILED=0
git diff --cached --name-only | while read -r file; do
    ...
    FAILED=1
done
[[ $FAILED -ne 0 ]] && exit 1
```

Note: option 2 still has the subshell issue; the flag won't propagate. Process
substitution is the correct fix.

### Trivy regex concerns

- `generic-secret` rule may be overly broad (`.{0,40}` gap)
- `openai-legacy` uses negative lookahead; may not work in RE2-based Trivy
- Not addressed this session

### Pipelock

References `github.com/luckyPipewrench/pipelock` which is unverified. If this
is a placeholder for future internal tooling, should be commented as such.

## File Locations

- Script: `bootstrap.sh` (this session's output)
- Base directory: `~/.peerlabs/plsec/` (changed from `~/.plsec/` in original chat)
- OpenCode config schema: https://opencode.ai/config.json
- OpenCode permissions docs: https://opencode.ai/docs/permissions/
