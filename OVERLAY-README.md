# claude-bootstrap-overlay

Overlay archive for the plsec project. Extract into the plsec repo root
to add/update bootstrap.sh and its test infrastructure.

## Usage

```bash
cd plsec
tar xvzf ~/Downloads/claude-bootstrap-overlay.tgz
```

## Post-extraction setup

```bash
# 1. Initialize BATS submodules
chmod +x scripts/setup-bats.sh
scripts/setup-bats.sh

# 2. Make scripts executable
chmod +x bin/bootstrap.sh
chmod +x tests/bats/run-in-container.sh

# 3. Verify
bats tests/bats/unit/
bats tests/bats/integration/

# 4. (Optional) Run in container
tests/bats/run-in-container.sh
```

## What this overlay contains

### Modified files

- `bin/bootstrap.sh` - Updated with main() guard, PLSEC_DIR consolidation,
  dry-run mode, opencode.json (replacing hallucinated .opencode.toml),
  and log function naming fixes

### New files

- `docs/bootstrap-testing.md` - Testing strategy design document
- `docs/HANDOFF-bootstrap.md` - Session handoff with all design decisions
- `tests/bats/test_helper/common.bash` - Shared BATS test setup
- `tests/bats/unit/test_helpers.bats` - Unit tests for helper functions
- `tests/bats/unit/test_args.bats` - Unit tests for argument parsing
- `tests/bats/unit/test_detect_os.bats` - Unit tests for OS detection
- `tests/bats/integration/test_bootstrap.bats` - Integration tests
- `tests/bats/integration/test_generated_files.bats` - Generated file tests
- `tests/bats/integration/test_idempotency.bats` - Idempotency tests
- `tests/bats/integration/test_dry_run.bats` - Dry-run mode tests
- `tests/bats/Containerfile` - Container image for hermetic testing
- `tests/bats/run-in-container.sh` - Podman/Docker auto-detect runner
- `tests/bats/golden/README.md` - Placeholder for snapshot golden files
- `.github/workflows/test-bootstrap.yml` - CI workflow for bootstrap tests
- `scripts/setup-bats.sh` - One-time BATS submodule initialization

### Files NOT included (to avoid conflicts)

- `HANDOFF.md` (project root) - Not touched; bootstrap handoff is in docs/
- `.github/workflows/test.yml` - Not touched; bootstrap CI has its own file
- `pyproject.toml` - Not touched
- `src/` - Not touched
- `tests/__init__.py`, `tests/test_plsec.py` - Not touched
