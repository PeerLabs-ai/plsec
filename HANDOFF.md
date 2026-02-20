# plsec - HANDOFF

**Last Updated:** 2026-02-19
**Status:** `make ci` green, all quality gates passing

---

## Goal

Get `make ci` passing end-to-end after the infrastructure work from the previous session (Makefile rewrite, uv migration, versioning, path migration, ty integration).

## Instructions

- **Read AGENTS.md** for coding standards, build commands, and project conventions
- **Read PROJECT.md** for TODOs, architecture decisions, and outstanding items
- **Read TESTING.md** for the full pytest test plan (3 tiers, 14 test files)
- **Use uv** for all Python toolchain operations (not pip/venv directly)
- **Use Make** as the unified entry point for all build/test/lint operations
- **Follow semver** conventions - `VERSION` file is single source of truth
- The user prefers to review plans before execution - present proposals, get approval, then build
- Keep PROJECT.md updated with completed TODOs (mark with `[x]`)

## Accomplished (this session)

### `make ci` brought to green
All quality gates now pass: ruff check, ruff format, ty check, template lint, bootstrap syntax, assembler escaping tests (44/44), BATS tests, and pytest.

### Ruff lint fixes (60 errors -> 0)
- **Auto-fixed 35 errors** via `ruff check . --fix`: unsorted imports (I001), unused imports (F401), f-string without placeholders (F541), `collections.abc` imports (UP035), whitespace (W293)
- **B008 suppressed** in `pyproject.toml` for `src/plsec/commands/*.py` - typer requires `Option()`/`Argument()` in function defaults; this is standard practice
- **S105 + E501 suppressed** for `src/plsec/configs/templates.py` - false positive on YAML template variable name, long YAML lines in embedded templates
- **B904 fixed** in `proxy.py` - `raise typer.Exit(1) from err` (2 occurrences)
- **S110 annotated** with `# noqa: S110` comments in `detector.py` (3) and `proxy.py` (1) - intentional best-effort file scanning where ignoring errors is correct
- **F841 fixed** in `cli.py` (removed dead `ctx = typer.Context` assignment) and `validate.py` (removed unused `config` variable)

### Ruff format fix
- **tools.py** reformatted (1 file)

### ty type checker fixes (4 diagnostics -> 0)
- **init.py:222** - `detect_project_type()` return type changed from `str` to `Literal["python", "node", "go", "mixed"]`; also fixed a bug where Rust projects returned `"rust"` which wasn't in `ProjectConfig.type`'s Literal (now falls back to `"mixed"`)
- **integrity.py:89** - replaced deprecated `datetime.utcnow()` with `datetime.now(UTC)` using `from datetime import UTC`
- **proxy.py:192** - added `assert pid is not None` before `os.kill(pid, ...)` to narrow `int | None` type
- **detector.py:213** - removed unused `# type: ignore` comment

### Assembler escaping test fix (43/44 -> 44/44)
- **trivy-secret.yaml test** was a pre-existing failure - the test's `eval`-based escaping simulation didn't match the real assembler's single-quote embedding. `eval` interprets `\\s` as `\s`, but the real assembler embeds content in single-quoted strings where backslashes are literal. Fixed by generating a helper script that mirrors the actual bootstrap assembly process.
- Also changed `python3` -> `uv run python` in the test for `pyyaml` availability

## Discoveries

1. **Ruff B008 is universal in typer projects** - every typer CLI will trigger this rule; per-file-ignores in pyproject.toml is the standard solution
2. **`detect_project_type()` had a Literal mismatch** - it could return `"rust"` but `ProjectConfig.type` only accepts `["python", "node", "go", "mixed"]`
3. **`datetime.utcnow()` is deprecated since Python 3.12** - must use `datetime.now(UTC)` with `from datetime import UTC`
4. **The assembler escaping test didn't match the real assembler** - using `eval` for testing single-quote embedding loses backslashes; the real assembler writes content into a `.sh` file with single-quoted strings where backslashes are literal
5. **`.venv.make` warning** - user's shell has `VIRTUAL_ENV=.venv.make` set from the old stale venv; `uv` ignores it but prints a warning. Running `deactivate` or deleting `.venv.make` eliminates the warning

## Relevant files modified (this session)

### Configuration
- `pyproject.toml` - Added `[tool.ruff.lint.per-file-ignores]` for B008, S105, E501

### Python source
- `src/plsec/cli.py` - Removed dead `ctx = typer.Context` assignment
- `src/plsec/commands/init.py` - Added `ProjectType` Literal alias; fixed `detect_project_type()` return type; Rust fallback to "mixed"
- `src/plsec/commands/integrity.py` - `datetime.utcnow()` -> `datetime.now(UTC)`
- `src/plsec/commands/proxy.py` - `raise from err` (B904); `assert pid is not None` (ty); `# noqa: S110`
- `src/plsec/commands/validate.py` - Removed unused `config` variable
- `src/plsec/commands/create.py` - Import cleanup (ruff auto-fix)
- `src/plsec/commands/doctor.py` - Import cleanup, removed `f""` prefix (ruff auto-fix)
- `src/plsec/commands/scan.py` - Import cleanup (ruff auto-fix)
- `src/plsec/commands/secure.py` - Import cleanup (ruff auto-fix)
- `src/plsec/commands/__init__.py` - Import sort (ruff auto-fix)
- `src/plsec/configs/__init__.py` - Import sort (ruff auto-fix)
- `src/plsec/core/__init__.py` - Import sort (ruff auto-fix)
- `src/plsec/core/detector.py` - `# noqa: S110` annotations; removed `# type: ignore`
- `src/plsec/core/output.py` - Import cleanup (ruff auto-fix)
- `src/plsec/core/tools.py` - Import cleanup (ruff auto-fix); reformatted
- `src/plsec/core/wizard.py` - Import cleanup, whitespace (ruff auto-fix)
- `tests/test_plsec.py` - Import sort (ruff auto-fix)

### Test/scripts
- `scripts/test-assembler-escaping.sh` - Fixed YAML escaping test to match real assembler behavior

## Next Steps

1. **Build pytest test cases** for Python CLI (plan in TESTING.md, 14 test files across 3 tiers)
2. **`plsec-status` Phase 1** implementation (design doc at `docs/plsec-status-design.md`)
3. **Delete `.venv.make`** - stale venv from before uv migration; causes harmless but noisy warnings
4. **Consider golden file regeneration** - the opencode-json-strict template was modified in the previous session (added ty permission); verify golden files are current
