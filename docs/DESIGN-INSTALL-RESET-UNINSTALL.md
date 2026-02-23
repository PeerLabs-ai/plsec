# Design: `plsec install`, `plsec reset`, `plsec uninstall`

**Status:** IMPLEMENTED (Phases 1-6)
**Version:** 0.2
**Date:** 2026-02-22
**Author:** Graham Toppin / Claude

---

## Problem Statement

plsec has no mechanism for clean removal, factory reset, or explicit global
installation. This causes two concrete problems:

1. **Testing flaw**: `make scan` depends on state in `~/.peerlabs/plsec/` from
   previous runs. We never test from a vanilla state, so we cannot be confident
   the tool works correctly on a fresh install.

2. **User experience gap**: Users cannot:
   - Remove plsec cleanly from their system
   - Reset to a known-good default state after experimentation
   - Understand what plsec has left behind on their system
   - Distinguish between "plsec is not installed" and "plsec is
     installed but misconfigured"

Both are symptoms of the same missing abstraction: plsec has no model
of its own installation footprint.

## Design Goals

- Users can install, reset, and uninstall plsec with single commands
- Every artifact plsec creates is tracked and reversible
- `plsec scan` fails clearly when prerequisites are missing
- CI can test from a clean slate: uninstall, install, scan
- External tools (trivy, bandit, etc.) are reported but never
  uninstalled by plsec (we did not install them)

## Non-Goals

- Uninstalling external tools (trivy, bandit, semgrep, etc.)
- Uninstalling the plsec Python package itself (that is the user's
  package manager's job)
- Managing bootstrap.sh installations (separate lifecycle)
- Modifying `.gitignore` during uninstall (too risky -- we append
  patterns but cannot safely determine which lines are ours vs the
  user's)

---

## plsec Filesystem Footprint

Everything plsec creates on a user's system, organised by scope.

### Global artifacts (`~/.peerlabs/plsec/`)

Created by `plsec install` (and currently `plsec init --global`).

| Path                                        | Type      | Description                           |
|---------------------------------------------|-----------|---------------------------------------|
| `~/.peerlabs/plsec/`                        | directory | Root directory                        |
| `~/.peerlabs/plsec/configs/CLAUDE.md`       | config    | Claude Code agent config              |
| `~/.peerlabs/plsec/configs/opencode.json`   | config    | OpenCode agent config                 |
| `~/.peerlabs/plsec/configs/pre-commit`      | config    | Pre-commit hook template (executable) |
| `~/.peerlabs/plsec/trivy/trivy-secret.yaml` | config    | Trivy secret scanning rules           |
| `~/.peerlabs/plsec/trivy/trivy.yaml`        | config    | Trivy configuration                   |
| `~/.peerlabs/plsec/trivy/policies/`         | directory | Custom trivy policies (empty)         |
| `~/.peerlabs/plsec/logs/`                   | directory | Log directory                         |
| `~/.peerlabs/plsec/manifests/`              | directory | Integrity manifests                   |

### Global runtime artifacts

Created at runtime by `plsec proxy` and future `plsec run`.

| Path                                  | Type    | Description             |
|---------------------------------------|---------|-------------------------|
| `~/.peerlabs/plsec/pipelock.pid`      | runtime | Pipelock proxy PID file |
| `~/.peerlabs/plsec/pipelock.yaml`     | runtime | Pipelock proxy config   |
| `~/.peerlabs/plsec/logs/pipelock.log` | runtime | Pipelock proxy log      |

### External global configs (outside `~/.peerlabs/`)

Created by `plsec install` when deploying agent configs to their
native locations.

| Path                               | Created when            | Description                     |
|------------------------------------|-------------------------|---------------------------------|
| `~/.config/opencode/opencode.json` | OpenCode agent selected | OpenCode native config location |

Future agents may add additional external paths (e.g., Gemini CLI,
Codex). Each `AgentSpec.global_config_dir` defines where the agent's
native config lives.

### Project-local artifacts

Created by `plsec init`, `plsec secure`, `plsec create`, and
`plsec integrity`.

| Path                      | Created by       | Description                               |
|---------------------------|------------------|-------------------------------------------|
| `CLAUDE.md`               | `init`, `secure` | Claude Code agent config                  |
| `opencode.json`           | `init`, `secure` | OpenCode agent config                     |
| `plsec.yaml`              | `init`, `secure` | Project security configuration            |
| `.pre-commit-config.yaml` | `secure`         | Git pre-commit hook config                |
| `.plsec-manifest.json`    | `integrity`      | File integrity manifest                   |
| `.gitignore` (modified)   | `secure`         | Appends security patterns between markers |

### External tools

plsec does not install these. Users install them based on `plsec doctor`
guidance. plsec should report their presence during uninstall.

| Tool           | Required                | Typical install              |
|----------------|-------------------------|------------------------------|
| trivy          | Yes                     | `brew install trivy`         |
| bandit         | No (recommended)        | `pip install bandit`         |
| semgrep        | No (recommended)        | `pip install semgrep`        |
| detect-secrets | No (optional)           | `pip install detect-secrets` |
| pipelock       | No (strict/paranoid)    | `go install ...`             |
| podman         | No (container mode)     | `brew install podman`        |
| docker         | No (container fallback) | `brew install --cask docker` |

---

## Command Specifications

### `plsec install`

Deploy global configuration to `~/.peerlabs/plsec/`. This is the
explicit global setup command.

```
plsec install                          # deploy with balanced preset
plsec install --preset strict          # deploy with specific preset
plsec install --force                  # overwrite existing configs
plsec install --check                  # verify installation after deploy
plsec install --agent claude           # only deploy for specific agent
```

#### Behaviour

1. Create directory structure (`configs/`, `logs/`, `manifests/`,
   `trivy/`, `trivy/policies/`)
2. Deploy agent config templates to `~/.peerlabs/plsec/configs/`
3. Deploy agent configs to native locations (e.g.,
   `~/.config/opencode/opencode.json`)
4. Deploy scanner configs (`trivy-secret.yaml`, `trivy.yaml`)
5. Deploy pre-commit hook template
6. If `--check`: run a subset of `plsec doctor` to verify deployment

#### Idempotency

Without `--force`, existing files are preserved and a warning is shown.
With `--force`, all files are overwritten with fresh templates.

#### Exit codes

| Code | Meaning                                |
|------|----------------------------------------|
| 0    | Installation successful                |
| 1    | Installation failed (filesystem error) |

#### Relationship to `plsec init`

`plsec init` currently does both global and project-local setup. After
this change:

- `plsec install` = global setup only (replaces `plsec init --global`)
- `plsec init` = project-local setup (calls `plsec install` internally
  if global configs are missing)
- `plsec init --global` = deprecated alias for `plsec install`

### `plsec reset`

Stop managed processes, wipe all global state, redeploy fresh defaults.

```
plsec reset                            # interactive confirmation, balanced preset
plsec reset --preset strict            # reset to specific preset
plsec reset --yes                      # skip confirmation
plsec reset --dry-run                  # show what would happen, do nothing
```

#### Behaviour

1. Stop any running managed processes (pipelock)
2. Inventory all files under `~/.peerlabs/plsec/`
3. Show summary: file count, total size, preset that will be deployed
4. Confirm with user (unless `--yes`)
5. Remove all files and subdirectories under `~/.peerlabs/plsec/`
   (preserve the root directory itself)
6. Remove external agent configs (e.g., `~/.config/opencode/opencode.json`)
7. Run `plsec install --preset <preset> --force`
8. Report result

#### What reset preserves

- Project-local files (CLAUDE.md, plsec.yaml, etc.)
- External tool installations
- The plsec Python package

#### What reset destroys

- All global configs (replaced with fresh defaults)
- All logs
- All manifests
- All runtime artifacts (PID files, proxy configs)
- External agent configs (redeployed fresh)

#### Exit codes

| Code | Meaning                           |
|------|-----------------------------------|
| 0    | Reset successful                  |
| 1    | Reset failed                      |
| 2    | User cancelled (interactive mode) |

### `plsec uninstall`

Clean removal of plsec artifacts from the system.

```
plsec uninstall                        # interactive mode
plsec uninstall --global               # remove global configs only
plsec uninstall --project              # remove project-local files only
plsec uninstall --all                  # remove everything
plsec uninstall --dry-run              # show what would be removed
plsec uninstall --yes                  # skip confirmation
```

#### Behaviour

1. Stop any running managed processes (pipelock)
2. Discover all plsec artifacts (global + project-local)
3. Present inventory to user
4. In interactive mode: let user select what to remove
5. In flag mode: select the scoped set
6. Confirm with user (unless `--yes`)
7. Remove selected files/directories
8. Report:
   - What was removed (file count, size)
   - What remains (external tools with paths and versions)
   - How to remove plsec itself (`pipx uninstall plsec` / `uv tool
     uninstall plsec`)

#### Interactive mode output

```
plsec uninstall

Discovering plsec artifacts...

Global configuration (~/.peerlabs/plsec/):
  configs/            3 files    12.4 KB
  trivy/              3 files     8.1 KB
  logs/               2 files     1.2 MB
  manifests/          0 files     0   B
  pipelock.yaml       1 file      2.3 KB

External configs:
  ~/.config/opencode/opencode.json    1.1 KB

Project files (/Users/you/myproject):
  CLAUDE.md                           3.2 KB
  plsec.yaml                         0.8 KB
  .plsec-manifest.json               4.5 KB

Remove global configuration? [Y/n] y
Remove external configs? [Y/n] y
Remove project files? [y/N] n

Removing global configuration... done
Removing external configs... done

Removed: 9 files (1.22 MB)

The following remain on your system:

  External tools (not installed by plsec):
    trivy      v0.69.1    /opt/homebrew/bin/trivy
    bandit     v1.9.3     /opt/homebrew/bin/bandit
    semgrep    v1.152.0   /opt/homebrew/bin/semgrep

  Project files (not selected):
    /Users/you/myproject/CLAUDE.md
    /Users/you/myproject/plsec.yaml
    /Users/you/myproject/.plsec-manifest.json

  To remove plsec itself:
    pipx uninstall plsec
```

#### Project-local file safety

Before removing project-local files, plsec should check if they match
our templates or have been customised:

- **Matches template**: safe to remove silently
- **Modified from template**: warn the user, ask for explicit
  confirmation
- **`.gitignore`**: never modified during uninstall (we append patterns
  between `# === plsec security patterns ===` / `# === end plsec
  patterns ===` markers, but removing them risks breaking the
  gitignore)

Template matching can be approximate: check for a plsec header comment
or known structure rather than exact content match.

#### Exit codes

| Code | Meaning                                     |
|------|---------------------------------------------|
| 0    | Uninstall successful (or nothing to remove) |
| 1    | Uninstall failed (filesystem error)         |
| 2    | User cancelled (interactive mode)           |

---

## `plsec scan` Pre-flight Check

`plsec scan` gains a pre-flight check that verifies required scanner
configs exist before running any scanners.

```python
def _check_scanner_prerequisites(plsec_home: Path) -> None:
    """Verify required scanner configs exist before scanning."""
    missing = []
    for rel_path, description in PLSEC_EXPECTED_FILES:
        if not (plsec_home / rel_path).exists():
            missing.append((rel_path, description))
    if missing:
        print_error("Scanner configuration not found.")
        for rel_path, description in missing:
            console.print(f"  Missing: {description} ({rel_path})")
        console.print("\nRun 'plsec install' to deploy scanner configs.")
        raise typer.Exit(1)
```

This ensures `plsec scan` fails fast with a clear message rather than
producing confusing trivy errors when configs are absent.

---

## Artifact Inventory Model

The `plsec uninstall` and `plsec reset` commands need to discover what
plsec has created on the system. This is modelled as an inventory.

```python
@dataclass
class Artifact:
    """A file or directory created by plsec."""

    # Absolute path to the artifact
    path: Path
    # Classification for grouping in output
    category: Literal[
        "global_config",
        "global_log",
        "global_runtime",
        "global_directory",
        "external_config",
        "project_config",
        "project_manifest",
    ]
    # Human-readable description
    description: str
    # Size in bytes (0 for directories, computed at discovery time)
    size_bytes: int = 0
    # Whether the file can be safely removed
    removable: bool = True
    # Whether the file matches a plsec template (for project files)
    matches_template: bool = True


@dataclass
class Inventory:
    """Complete inventory of plsec artifacts on the system."""

    # All discovered artifacts
    artifacts: list[Artifact]

    @property
    def global_artifacts(self) -> list[Artifact]:
        """Artifacts under ~/.peerlabs/plsec/ and external configs."""
        return [a for a in self.artifacts
                if a.category.startswith("global_") or
                   a.category == "external_config"]

    @property
    def project_artifacts(self) -> list[Artifact]:
        """Artifacts in the current project directory."""
        return [a for a in self.artifacts
                if a.category.startswith("project_")]

    @property
    def total_size(self) -> int:
        """Total size of all artifacts in bytes."""
        return sum(a.size_bytes for a in self.artifacts)
```

### Discovery functions

```python
def discover_global_artifacts(plsec_home: Path) -> list[Artifact]:
    """Discover all plsec artifacts under the global home directory."""

def discover_external_artifacts(agents: dict[str, AgentSpec]) -> list[Artifact]:
    """Discover agent configs in native locations (e.g., ~/.config/opencode/)."""

def discover_project_artifacts(
    project_dir: Path,
    agents: dict[str, AgentSpec],
) -> list[Artifact]:
    """Discover plsec files in a project directory."""

def discover_all(
    plsec_home: Path,
    project_dir: Path,
    agents: dict[str, AgentSpec],
) -> Inventory:
    """Build complete inventory of all plsec artifacts."""
```

These functions belong in `src/plsec/core/inventory.py` -- a new core
module following the existing registry pattern.

---

## Changes to Existing Commands

### `plsec init`

`plsec init` is refocused on **project-local** setup:

1. Check if global configs exist
2. If missing: print "Global configs not found, running plsec install..."
   and call the shared deployment function
3. Proceed with project-local setup as before
4. `--global` flag becomes a deprecated alias that prints a deprecation
   warning and delegates to `plsec install`

The global deployment logic (currently lines 143-188 of `init.py`) is
extracted into a shared function that both `plsec install` and
`plsec init` call.

### `plsec scan`

Add pre-flight check at the top of scan execution:

1. Resolve `plsec_home`
2. Call `_check_scanner_prerequisites(plsec_home)`
3. If check fails: exit 1 with "Run 'plsec install' first"
4. If check passes: proceed with scanning as before

### `make` targets

| Target               | Command                                | Purpose                                         |
|----------------------|----------------------------------------|-------------------------------------------------|
| `make install`       | `uv run plsec install --check`         | Deploy + verify global configs                  |
| `make deploy`        | `uv run plsec install --force --check` | Force redeploy (replaces current `make deploy`) |
| `make reset`         | `uv run plsec reset --yes`             | Factory reset global state                      |
| `make clean-install` | `plsec reset --yes && make scan`       | Test from clean slate                           |

---

## File Structure

```
src/plsec/
├── core/
│   └── inventory.py         # NEW: Artifact, Inventory, discover_*()
├── commands/
│   ├── install.py            # NEW: plsec install
│   ├── reset.py              # NEW: plsec reset
│   ├── uninstall.py          # NEW: plsec uninstall
│   ├── init.py               # MODIFIED: delegates global to install
│   └── scan.py               # MODIFIED: adds pre-flight check
└── cli.py                    # MODIFIED: register new commands
```

### Module dependencies

```
cli.py
  ├── commands/install.py  -> core/inventory.py, core/agents.py, configs/templates.py
  ├── commands/reset.py    -> commands/install.py, core/inventory.py, core/processes.py
  ├── commands/uninstall.py -> core/inventory.py, core/agents.py, core/tools.py, core/processes.py
  ├── commands/init.py     -> commands/install.py (shared deployment function)
  └── commands/scan.py     -> core/health.py (PLSEC_EXPECTED_FILES)
```

---

## Testing Strategy

### Unit tests (pytest)

| Test file                 | Tests | What                                                                       |
|---------------------------|-------|----------------------------------------------------------------------------|
| `tests/test_inventory.py` | ~20   | Artifact dataclass, Inventory properties, discover functions with tmp_path |
| `tests/test_install.py`   | ~12   | Deploy logic, idempotency, --force, --check, preset selection              |
| `tests/test_reset.py`     | ~10   | Process stop, wipe, redeploy, --dry-run, --yes                             |
| `tests/test_uninstall.py` | ~15   | Scope selection, interactive prompts, file removal, remainder reporting    |
| `tests/test_scan.py`      | +3    | Pre-flight check: missing configs, all present, partial                    |

### Integration tests

```
make clean-install    # plsec reset --yes && plsec install --check && plsec scan .
```

This replaces the current `make deploy && make scan` pattern and
guarantees we test from a clean slate.

### Test isolation

The `discover_*` functions take explicit path arguments (not
`get_plsec_home()`) so they can be tested with `tmp_path` and no
filesystem side effects.

---

## Implementation Phases

### Phase 1: Core inventory model

1. Create `src/plsec/core/inventory.py` with `Artifact`, `Inventory`,
   and `discover_*()` functions
2. Write `tests/test_inventory.py`
3. All pure logic, no CLI integration yet

### Phase 2: `plsec install`

1. Create `src/plsec/commands/install.py`
2. Extract global deployment logic from `init.py` into shared function
3. Register in `cli.py`
4. Write `tests/test_install.py`
5. Update `plsec init` to call shared function
6. Add `make install` target

### Phase 3: `plsec scan` pre-flight

1. Add `_check_scanner_prerequisites()` to `scan.py`
2. Add tests for missing/present/partial configs
3. Verify `make scan` fails cleanly on vanilla state

### Phase 4: `plsec reset`

1. Create `src/plsec/commands/reset.py`
2. Wire process stopping, inventory wipe, redeploy
3. Register in `cli.py`
4. Write `tests/test_reset.py`
5. Add `make reset` and `make clean-install` targets

### Phase 5: `plsec uninstall`

1. Create `src/plsec/commands/uninstall.py`
2. Interactive mode with scope selection
3. External tool reporting via `ToolChecker`
4. Template matching for project-local files
5. Register in `cli.py`
6. Write `tests/test_uninstall.py`

### Phase 6: Documentation and deprecation

1. Deprecate `plsec init --global` (warning message, delegates to
   `plsec install`)
2. Update `docs/INSTALL.md` with new commands
3. Update `plsec doctor` output to reference `plsec install` instead
   of `plsec init`
4. Update HANDOFF.md and PROJECT.md

---

## Open Questions

1. **Should `plsec uninstall --project` scan subdirectories?** A user
   might run `plsec secure` in multiple projects. Should `--project`
   only clean the current directory, or should it search for plsec
   artifacts recursively? **Recommendation:** current directory only.
   Users can `cd` to other projects and run again.

2. **Should `plsec install --check` be the default?** Running doctor
   checks after every install adds latency (tool version checks via
   subprocess). **Recommendation:** off by default, on in `make`
   targets.

3. **Should we track installation metadata?** We could write a
   `~/.peerlabs/plsec/.installed.json` with timestamp, preset, version,
   and agent list. This would let `plsec doctor` report "installed at
   <time> with <preset>" and help `plsec reset` know what preset to
   restore. **Recommendation:** yes, implement in Phase 2.

4. **How should `plsec init --global` deprecation work?** Options:
   (a) print warning and delegate to `plsec install`, (b) remove the
   flag entirely (breaking change). **Recommendation:** (a) for at
   least one minor version, then (b).

5. **Should `.gitignore` modifications be reversible?** Currently
   `plsec secure` appends patterns between `# === plsec security
   patterns ===` markers. We could remove content between those markers
   during uninstall. **Recommendation:** implement this -- the markers
   exist precisely for this purpose. But confirm with user first and
   show what will be removed.

---

## References

- [Trivy filtering docs](https://trivy.dev/docs/latest/configuration/filtering/)
  (`.trivyignore.yaml` format)
- [docs/DESIGN-PLSEC-REFACTOR.md](DESIGN-PLSEC-REFACTOR.md) (registry
  pattern used by inventory model)
- [docs/plsec-status-design.md](plsec-status-design.md) (check IDs
  referenced by install --check)
