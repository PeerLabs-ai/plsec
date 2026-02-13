# plsec - HANDOFF

**Last Updated:** 2026-02-10
**Status:** Skeleton complete, ready for development

---

## Summary

This is the skeleton for `plsec`, a Python CLI providing turnkey security setup for AI coding assistants (Claude Code, Opencode).

## Package Structure

```
plsec/
  pyproject.toml           # Package config (hatch build, uv compatible)
  README.md                # Package documentation
  src/plsec/
    __init__.py            # Version, exports
    cli.py                 # Typer app entry point
    commands/
      __init__.py
      create.py            # plsec create - new secure project
      secure.py            # plsec secure - retrofit existing project
      doctor.py            # plsec doctor - check dependencies
      init.py              # plsec init - setup project
      scan.py              # plsec scan - run scanners
      validate.py          # plsec validate - check configs
      proxy.py             # plsec proxy - Pipelock management
      integrity.py         # plsec integrity - workspace monitoring
    core/
      __init__.py
      config.py            # Pydantic config models
      tools.py             # Tool checking utilities
      output.py            # Rich console output
      wizard.py            # Interactive wizard prompts
      detector.py          # Project analysis and detection
    configs/
      __init__.py
      templates.py         # Embedded CLAUDE.md, opencode.json
  homebrew/
    plsec.rb               # Homebrew formula
    README.md              # Tap setup instructions
  docs/
    DESIGN-CREATE-SECURE.md # Design doc for create/secure
  tests/
    __init__.py
    test_plsec.py          # Basic tests
```

## Installation

### Using uv (Recommended)

```bash
# Install globally
uv tool install plsec

# Or run without installing
uvx plsec doctor

# Development install
cd plsec
uv pip install -e ".[dev]"
```

### Using pip/pipx

```bash
# With pipx (isolated)
pipx install plsec

# Development install
cd plsec
pip install -e ".[dev]"
```

### Using Homebrew

```bash
# Add tap and install
brew tap peerlabs/tap
brew install plsec

# With optional dependencies
brew install plsec pipelock podman
```

### Verify Installation

```bash
plsec --version
plsec --help
```

## Known Issues / Fixes Applied

### OpenCode Configuration Fix (2026-02-12)

**Problem:** Initial implementation used hallucinated `.opencode.toml` format with invented schema sections (`[ai]`, `[security]`, `[shell]`, `[filesystem]`).

**Actual Format:** OpenCode uses `opencode.json` with a specific schema:
- Schema: `https://opencode.ai/config.json`
- Key field: `permission` with tool-level controls
- Permission values: `"allow"`, `"ask"`, `"deny"`
- Tools: `bash`, `edit`, `read`, `webfetch`, `external_directory`, etc.

**Files Updated:**
- `src/plsec/configs/templates.py` - Replaced TOML templates with JSON
- `src/plsec/commands/init.py` - Changed file creation to opencode.json
- `src/plsec/commands/create.py` - Changed file creation to opencode.json
- `src/plsec/commands/secure.py` - Changed detection and creation
- `src/plsec/commands/validate.py` - Changed validation to JSON
- `src/plsec/commands/doctor.py` - Changed template checking
- `src/plsec/core/detector.py` - Changed detection field
- `tests/test_plsec.py` - Updated template tests
- Documentation (README.md, HANDOFF.md, DESIGN-CREATE-SECURE.md)

---

## Implemented Commands

| Command           | Status   | Notes                                          |
|-------------------|----------|------------------------------------------------|
| `plsec create`    | **New**  | Create new secure project with wizard          |
| `plsec secure`    | **New**  | Retrofit security onto existing project        |
| `plsec doctor`    | Complete | Checks dependencies, directories, configs      |
| `plsec init`      | Complete | Generates CLAUDE.md, opencode.json, plsec.yaml |
| `plsec scan`      | Complete | Wraps Trivy, Bandit, Semgrep                   |
| `plsec validate`  | Complete | Validates config files                         |
| `plsec proxy`     | Complete | Start/stop/status/logs for Pipelock            |
| `plsec integrity` | Complete | Init/check/update workspace manifests          |

## Dependencies

### Runtime
- typer >= 0.12.0 (CLI framework)
- rich >= 13.0.0 (Terminal output)
- pyyaml >= 6.0 (YAML parsing)
- pydantic >= 2.0 (Config validation)
- pydantic-settings >= 2.0 (Environment settings)

### Development
- pytest >= 8.0
- pytest-cov >= 4.0
- ruff >= 0.4
- mypy >= 1.10

### External Tools (checked by `plsec doctor`)
- trivy (required)
- bandit (optional)
- semgrep (optional)
- pipelock (optional)
- podman/docker (optional)

## Key Design Decisions

| Decision          | Choice   | Rationale                         |
|-------------------|----------|-----------------------------------|
| CLI framework     | Typer    | Modern, type hints, auto-help     |
| Build system      | Hatch    | Modern, PEP 621 compliant         |
| Config format     | YAML     | Consistency with existing configs |
| Config validation | Pydantic | Type safety, validation           |
| Output            | Rich     | Consistent, colorful terminal UI  |

## Next Steps

1. **Test locally**: Install with `uv pip install -e .` and run commands
2. **Run tests**: `uv run pytest`
3. **Validate Pipelock**: Work through PIPELOCK-VALIDATION.md
4. **Create Homebrew tap**:
   - Create `github.com/peerlabs/homebrew-tap` repository
   - Copy `homebrew/plsec.rb` to `Formula/`
   - Update SHA256 hashes after first release
5. **Publish to PyPI**: `uv build && uv publish`
6. **CI/CD**: Add GitHub Actions for testing and releases

## Testing

```bash
# Using uv (recommended)
uv run pytest
uv run pytest --cov=plsec --cov-report=html
uv run mypy src/
uv run ruff check .

# Using pip
pytest
pytest --cov=plsec --cov-report=html
mypy src/
ruff check .
```

## Configuration File Location

plsec searches for config in this order:
1. `./plsec.yaml` (current directory)
2. Parent directories up to home
3. `~/.plsec/plsec.yaml` (global)

