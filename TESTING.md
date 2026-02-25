# TESTING.md - plsec Test Plan

## Current State

666 pytest tests across 22 files, 77% coverage. 83 BATS tests across 2 files
for plsec-status (58 unit + 25 integration). All three pytest tiers are
implemented. The original `test_plsec.py` has been redistributed:
duplicate tests deleted, unique tests moved to `test_cli.py` and
`test_config.py`.

| Test file | Tests | Tier | Target module |
|-----------|-------|------|---------------|
| `test_cli.py` | 4 | -- | `cli.py` (top-level app smoke tests) |
| `test_config.py` | 28 | 1 | `core/config.py` + package version |
| `test_tools.py` | 21 | 1 | `core/tools.py` |
| `test_templates.py` | 66 | 1 | `configs/templates.py` (+ wrapper cross-checks) |
| `test_integrity.py` | 29 | 1 | `commands/integrity.py` |
| `test_validate.py` | 18 | 1 | `commands/validate.py` |
| `test_agents.py` | 40 | 1 | `core/agents.py` (registry) |
| `test_scanners.py` | 58 | 1+3 | `core/scanners.py` (registry + ScanResult/ScanSummary) |
| `test_processes.py` | 23 | 1+3 | `core/processes.py` (registry) |
| `test_health.py` | 55 | 1+2 | `core/health.py` (+ wrapper script checks) |
| `test_inventory.py` | 43 | 1+2 | `core/inventory.py` (artifact model) |
| `test_detector.py` | 34 | 2 | `core/detector.py` |
| `test_init.py` | 19 | 2 | `commands/init.py` |
| `test_create.py` | 20 | 2 | `commands/create.py` |
| `test_output.py` | 20 | 2 | `core/output.py` |
| `test_install_cmd.py` | 67 | 2+3 | `commands/install.py` (+ wrappers, aliases) |
| `test_reset.py` | 20 | 2+3 | `commands/reset.py` (lifecycle, log preservation) |
| `test_uninstall.py` | 19 | 2+3 | `commands/uninstall.py` (lifecycle) |
| `test_secure.py` | 39 | 3 | `commands/secure.py` |
| `test_scan.py` | 29 | 3 | `commands/scan.py` (+ persistence, JSON output) |
| `test_doctor.py` | 14 | 3 | `commands/doctor.py` |
| `test_proxy.py` | 14 | 3 | `commands/proxy.py` |

### BATS Tests (Bootstrap Scripts)

| Test file | Tests | Target module |
|-----------|-------|---------------|
| `bats/unit/test_status.bats` | 58 | `plsec-status.sh` (health check functions) |
| `bats/integration/test_status.bats` | 25 | `plsec-status.sh` (full execution, JSON, flags) |

## Test Structure (implemented)

Per-module test files plus registry module tests:

```
tests/
├── conftest.py                # 3 shared fixtures
├── test_config.py             # core/config.py - models, load/save, find
├── test_tools.py              # core/tools.py - checker, version compare
├── test_output.py             # core/output.py - Rich console helpers
├── test_detector.py           # core/detector.py - project analysis
├── test_templates.py          # configs/templates.py - embedded templates
├── test_integrity.py          # commands/integrity.py - manifest ops
├── test_validate.py           # commands/validate.py - config validation
├── test_init.py               # commands/init.py - project init
├── test_install_cmd.py        # commands/install.py - lifecycle install
├── test_reset.py              # commands/reset.py - lifecycle reset
├── test_uninstall.py          # commands/uninstall.py - lifecycle uninstall
├── test_inventory.py          # core/inventory.py - artifact model
├── test_scan.py               # commands/scan.py - scanner wrappers
├── test_doctor.py             # commands/doctor.py - health check
├── test_create.py             # commands/create.py - project scaffolding
├── test_secure.py             # commands/secure.py - retrofit security
├── test_proxy.py              # commands/proxy.py - pipelock management
├── test_agents.py             # core/agents.py - agent registry
├── test_scanners.py           # core/scanners.py - scanner registry
├── test_processes.py          # core/processes.py - process registry
├── test_health.py             # core/health.py - health check functions
└── bats/                      # BATS shell script tests
    ├── unit/
    │   └── test_status.bats   # plsec-status.sh unit tests (58 tests)
    └── integration/
        └── test_status.bats   # plsec-status.sh integration tests (25 tests)
```

## Priority Tiers

### Tier 1 - Pure Logic (no mocking, highest value) -- IMPLEMENTED

Pure functions and data structures. Fast, reliable, no side effects.

**test_config.py**
- All Pydantic model defaults and validation
- `PlsecConfig()` nested structure (project, agent, layers, credentials)
- `StaticLayerConfig`, `IsolationLayerConfig`, etc. defaults and Literal constraints
- Config roundtrip: save then load via `tmp_path`
- `load_config` with missing file raises `FileNotFoundError`
- `load_config` with empty YAML returns defaults
- `find_config_file` with `tmp_path` + monkeypatched `Path.cwd()`

**test_tools.py**
- `_version_gte`: equal, greater, less, short versions (1.2 vs 1.2.0),
  non-numeric input (returns True as fallback), major version difference
- `Tool` dataclass construction and default field values
- `ToolChecker` with pre-populated tool statuses:
  `get_missing()`, `get_outdated()`, `all_required_ok()`
- `REQUIRED_TOOLS` and `OPTIONAL_TOOLS` lists are non-empty and well-formed

**test_templates.py**
- All template constants are non-empty strings
- `CLAUDE_MD_STRICT` contains "NEVER", "ALWAYS", "RESTRICTED"
- `CLAUDE_MD_BALANCED` contains "NEVER", "ALWAYS", not "RESTRICTED"
- `OPENCODE_JSON_STRICT` is valid JSON with `$schema` and `permission`
- `OPENCODE_JSON_BALANCED` is valid JSON with `$schema` and `permission`
- `PLSEC_YAML_TEMPLATE` contains all expected placeholders
  (`{project_name}`, `{project_type}`, etc.)
- `TRIVY_SECRET_YAML` is valid YAML with expected rule IDs
- `PRE_COMMIT_HOOK` starts with shebang, references trivy

**test_integrity.py**
- `should_include`: paths matching/not matching exclude patterns
- `hash_file`: known content produces expected SHA256
- `compare_manifests`: added, removed, modified, unchanged entries
- `create_manifest` with `tmp_path` containing known files
- Full init/check/update cycle with `tmp_path`

**test_validate.py**
- `validate_yaml_syntax` with valid YAML, broken YAML, empty file
- `validate_claude_md` with complete template, missing "NEVER", missing "ALWAYS"
- `validate_opencode_json` with valid config, missing `$schema`,
  missing `permission`, missing `bash` rules

### Tier 2 - Filesystem with tmp_path -- IMPLEMENTED

Synthetic project structures tested with `tmp_path`.

**test_detector.py**
- `_detect_type` with marker files: pyproject.toml (python), package.json (node),
  go.mod (go), multiple (mixed), none (unknown)
- `_detect_package_manager` from lock files (uv.lock, poetry.lock, etc.)
- `_detect_test_framework` from config files (pytest.ini, jest.config.js, etc.)
- `_parse_gitignore` with sample .gitignore content
- `_scan_file` with known secret patterns (API keys, tokens, AWS keys)
- `_detect_cloud_providers` with dependency files containing AWS/GCP/Azure refs
- `_count_files` with various file extensions

**test_init.py**
- `detect_project_type` with tmp_path marker files
- `get_preset_config` for each preset (minimal, balanced, strict, paranoid):
  assert correct layer enable/disable states
- `init` command via CliRunner with monkeypatched paths, verify generated files

**test_create.py**
- `create_python_template`: verify src/, tests/, pyproject.toml, __init__.py
- `create_node_template`: verify src/, package.json, index.js
- `create_go_template`: verify go.mod, main.go
- `create_gitignore`: verify security patterns present
- `create_pre_commit_config`: verify hook configuration
- `create_readme`: verify plsec section present

**test_output.py**
- `print_ok`, `print_error`, `print_warning`, `print_info` produce
  expected markers in captured output
- `print_summary` with various ok/warn/error counts
- `print_header` and `print_table` produce structured output

### Tier 3 - Subprocess Mocking -- IMPLEMENTED

Mock `subprocess.run`, `shutil.which`, and `os.kill`.

**test_tools.py (extended)**
- `check_tool` with mocked `shutil.which` returning path + `subprocess.run`
  returning version output: OK scenario
- `check_tool` with `shutil.which` returning None: MISSING scenario
- `check_tool` with version below minimum: OUTDATED scenario
- `check_tool` with `subprocess.TimeoutExpired`: ERROR scenario
- `check_tool` with custom `version_parser` callable

**test_scan.py**
- `run_trivy_secrets`: mock subprocess pass (rc=0) and fail (rc=1)
- `run_trivy_misconfig`: mock subprocess pass and fail
- `run_bandit`: mock `shutil.which` present/absent, mock subprocess
- `run_semgrep`: mock `shutil.which` present/absent, mock subprocess, timeout
- `scan` orchestrator: mock individual run functions, verify summary counts
  and exit codes for all-pass, some-fail, all-fail

**test_doctor.py**
- Via CliRunner with mocked `get_plsec_home` (tmp_path) and mocked `ToolChecker`
- Healthy system (all tools OK, dirs exist): exit code 0
- Missing required tools: exit code 1
- Missing optional dirs with `--fix`: dirs created, exit code 0

**test_proxy.py**
- `find_pipelock` with mocked `shutil.which` present/absent
- `is_pipelock_running` with mocked PID file + `os.kill` success/failure
- `get_pid_file` with mocked `get_plsec_home`

**test_secure.py**
- `Change` and `ChangeSet` dataclass construction
- `ChangeSet.has_changes()` and `has_conflicts()` logic
- `calculate_changes` with synthetic `ProjectInfo` and `WizardState`:
  new project (all creates), existing project (mix of creates/skips/conflicts)
- `apply_changes` with `tmp_path`: verify files written correctly
- `--dry-run` via CliRunner: verify no files modified

## Test Patterns

### Fixtures

```python
@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    """Create a minimal Python project structure."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test'\n")
    (tmp_path / "src").mkdir()
    return tmp_path

@pytest.fixture
def mock_plsec_home(tmp_path: Path, monkeypatch):
    """Redirect plsec home to tmp_path."""
    home = tmp_path / ".peerlabs" / "plsec"
    home.mkdir(parents=True)
    monkeypatch.setattr("plsec.core.config.get_plsec_home", lambda: home)
    return home
```

### Mocking subprocess

```python
from unittest.mock import patch, MagicMock

def test_check_tool_found():
    tool = Tool(name="test", command="test-cmd", required=True)
    with patch("shutil.which", return_value="/usr/bin/test-cmd"), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout="test-cmd version 1.2.3\n", stderr="", returncode=0
        )
        checker = ToolChecker([tool])
        checker.check_all()
        assert tool.status == ToolStatus.OK
```

### CLI integration

```python
from typer.testing import CliRunner
from plsec.cli import app

runner = CliRunner()

def test_command_help():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout
```

### Output capture

```python
from io import StringIO
from rich.console import Console

def test_print_ok():
    buf = StringIO()
    console = Console(file=buf, force_terminal=True)
    # call output function with console
    output = buf.getvalue()
    assert "[OK]" in output
```

## Running Tests

```bash
# All Python tests
pytest

# Single file
pytest tests/test_config.py -v

# Single class
pytest tests/test_config.py::TestPlsecConfig -v

# Single test
pytest tests/test_config.py::TestPlsecConfig::test_default_config -v

# By keyword
pytest -k "version_gte"

# With coverage
pytest --cov=plsec --cov-report=html

# Skip slow tests (if marked)
pytest -m "not slow"
```
