# Build Process -- Developer Guide

This document covers the common workflows, Make targets, and state
management for developing plsec.  For the internal design of the
bootstrap assembler, see `build-process-design.md`.

## Prerequisites

| Tool       | Required | Purpose                          | Install                    |
|------------|----------|----------------------------------|----------------------------|
| Python 3.12+ | Yes   | Runtime                          | `brew install python@3.12` |
| uv         | Yes      | Package management and lockfile  | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| BATS       | No       | Shell script tests               | `make setup-bats`          |
| Trivy      | No       | Security scanning (`make scan`)  | `brew install trivy`       |

## Getting Started

```bash
git clone https://github.com/peerlabs/plsec
cd plsec
make setup          # uv sync --dev
make dev-check      # quick local validation
```

## Common Workflows

### Daily development

```bash
make dev-check      # lint + types + tests + build + verify (~15s)
```

This runs the fast feedback loop: ruff lint, ty type check, all pytest
and BATS tests, bootstrap assembly, and reference verification.

### Before committing / CI

```bash
make ci             # full pipeline (~20s)
```

This is a superset of `dev-check`.  It adds:
- Template assembler escaping tests (44 tests)
- Golden file drift checks

`make all` is an alias for `make ci`.

### After changing bootstrap templates

```bash
make build          # reassemble build/bootstrap.sh
make promote        # update bin/bootstrap.default.sh (skips if unchanged)
make golden         # regenerate golden test fixtures
make ci             # verify everything
```

`make promote` is smart -- it skips the copy if the build output is
identical to the reference, avoiding false git diffs.

### Deploying global configuration

```bash
make install        # deploy to ~/.peerlabs/plsec (preserve existing)
make deploy         # force-overwrite all configs
make reset          # factory reset (preserves logs, re-injects aliases)
```

### Running security scans on plsec itself

```bash
make scan           # plsec scan . (dogfood)
```

## Target Reference

### Build targets (project-local, safe)

| Target       | What it does                                    | Idempotent |
|--------------|-------------------------------------------------|------------|
| `dev-check`  | lint + check + test + build + verify            | Yes        |
| `ci` / `all` | Full pipeline (dev-check + assembler + golden)  | Yes        |
| `build`      | Assemble `build/bootstrap.sh` from templates    | Yes (Make) |
| `verify`     | Diff build against promoted reference           | Yes        |
| `promote`    | Copy build to `bin/bootstrap.default.sh`        | Content-yes|
| `golden`     | Regenerate golden test fixtures                 | No         |
| `golden-check`| Verify golden files match templates            | Yes        |
| `clean`      | Remove `build/bootstrap.sh` and `.ruff_cache`   | Yes        |

### Test targets (project-local, safe)

| Target            | What it does                          | Idempotent |
|-------------------|---------------------------------------|------------|
| `test`            | All tests (pytest + BATS)             | Yes        |
| `test-python`     | pytest suite                          | Yes        |
| `test-unit`       | BATS unit tests                       | Yes        |
| `test-integration`| BATS integration tests (needs build)  | Yes        |
| `test-assembler`  | Template escaping tests               | Yes        |
| `test-container`  | BATS tests in container               | Yes        |

### Quality targets (project-local, safe)

| Target        | What it does                            | Idempotent |
|---------------|-----------------------------------------|------------|
| `lint`        | All linting (Python + templates + shell)| Yes        |
| `lint-python` | ruff check + format --check             | Yes        |
| `check`       | ty type check                           | Yes        |
| `format`      | ruff format (mutating, not in CI)       | No         |
| `scan`        | plsec scan . (appends to scan logs)     | No*        |

\* `scan` appends to `~/.peerlabs/plsec/logs/scan-*.jsonl` each run.

### Lifecycle targets (modifies ~/.peerlabs/plsec)

These targets modify state outside the project directory.

| Target         | What it does                                   | Idempotent | Destructive |
|----------------|------------------------------------------------|------------|-------------|
| `install`      | `plsec install --check` (write-if-missing)     | Yes        | No          |
| `install-global`| Same as `install`                             | Yes        | No          |
| `deploy`       | `plsec install --force --check` (overwrite)    | Yes        | No          |
| `reset`        | Wipe configs + redeploy (preserves logs)        | No         | Configs     |
| `clean-install`| `reset` then `install`                         | No         | Configs     |

**What `reset` does NOT delete:** The `logs/` directory (session logs,
scan logs, audit logs).  Use `plsec reset --wipe-logs` to remove
everything including logs.

**What `reset` now does:** Re-injects shell aliases after redeploying
configs, ensuring a consistent known-good state.

### Packaging targets

| Target        | What it does                             | Idempotent |
|---------------|------------------------------------------|------------|
| `build-dist`  | Build sdist + wheel to `dist/`           | No         |
| `install-test`| Clean install test in temp venv          | Yes        |

## State Management

### What lives at `~/.peerlabs/plsec/`

```
~/.peerlabs/plsec/
├── configs/            # Agent configs (CLAUDE.md, opencode.json, pre-commit)
├── trivy/              # Scanner configs (trivy.yaml, trivy-secret.yaml)
├── logs/               # Session logs, scan logs, audit logs
├── manifests/          # Integrity manifests
├── claude-wrapper.sh   # Wrapper script (Tier 1 + 2 logging)
├── opencode-wrapper.sh # Wrapper script (Tier 1 logging)
├── plsec-audit.sh      # Audit script for CLAUDE_CODE_SHELL_PREFIX
└── .installed.json     # Installation metadata
```

### Lifecycle command comparison

| Operation | `install` | `deploy` | `reset` |
|-----------|-----------|----------|---------|
| Creates missing files | Yes | Yes | Yes |
| Overwrites existing files | No | Yes | Yes (after wipe) |
| Wipes configs first | No | No | Yes |
| Deletes logs | No | No | No (use `--wipe-logs`) |
| Injects shell aliases | Yes | Yes | Yes |
| Writes `.installed.json` | Yes | Yes | Yes |

All three commands produce the same end state when starting from an
empty `~/.peerlabs/plsec/` -- the difference is how they handle
pre-existing files.

### Shell aliases

Shell aliases (`claude-safe`, `opencode-safe`, `plsec-logs`) are
managed by `plsec install` and `plsec reset` (injection) and
`plsec uninstall` (removal).  They are injected into `~/.zshrc`
(or `~/.bashrc` / `~/.profile`) with delimited markers.

| Command | Alias behavior |
|---------|---------------|
| `plsec install` | Injects (skip if present, `--force` to replace) |
| `plsec reset` | Re-injects with `--force` |
| `plsec uninstall` | Removes alias block |
| `--no-aliases` | Skips injection (on install or reset) |

## Anti-patterns

### Running `make all && make ci`

`make all` is an alias for `make ci`.  Running both is the same as
running `make ci` twice -- wasteful but harmless.

### Running `make promote` routinely

`make promote` should only be run after intentionally changing
bootstrap templates.  It now skips the copy when content is
identical, but there's no reason to run it unless `make verify`
fails.

### Running `make reset` to "fix" things

`make reset` is destructive to configs (though not to logs).  If
you just need fresh configs, `make deploy` is the right choice --
it force-overwrites without wiping first.
