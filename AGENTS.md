# AGENTS.md - Peerlabs Security Tools

## Technology Stack

- **Language**: Python 3.12+
- **CLI Framework**: typer + rich
- **Data Validation**: pydantic, pydantic-settings
- **Configuration**: pyyaml
- **Build System**: hatchling, make
- **Package Manager**: uv (recommended), pip, homebrew (macOS), apt (linux)
- **Testing**: pytest + pytest-cov (Python), BATS (shell scripts)
- **Quality**: ruff (lint + format), ty
- **Line Length**: 100 characters
- **Development**: emacs, neovim, venv for isolation, env for shipping

## Project Structure

```
plsec/
├── src/plsec/              # Main package
│   ├── __init__.py         # Version, exports
│   ├── cli.py              # Entry point, typer app
│   ├── commands/           # Subcommands (doctor, init, scan, etc.)
│   ├── core/               # Business logic
│   │   ├── config.py       # Configuration loading/saving
│   │   ├── tools.py        # Tool checking utilities
│   │   └── output.py       # Rich console output helpers
│   └── configs/            # Embedded templates
├── tests/
│   ├── test_plsec.py       # pytest tests
│   └── bats/               # BATS shell script tests
│       ├── unit/           # Unit tests
│       ├── integration/    # Integration tests
│       └── golden/         # Golden file fixtures
├── templates/bootstrap/    # Bootstrap script templates
├── scripts/                # Build/setup scripts
├── build/                  # Assembled output (bootstrap.sh)
└── bin/                    # Promoted reference scripts
```

## Commands

### Development Setup

```bash
# Install with dev dependencies (recommended)
uv pip install -e ".[dev]"

# Or with pip
pip install -e ".[dev]"
```

### Running Tests

```bash
# Python tests (pytest)
pytest                                              # All Python tests
pytest tests/test_plsec.py -v                      # Single file
pytest tests/test_plsec.py::TestCLI -v             # Single test class
pytest tests/test_plsec.py::TestCLI::test_help -v  # Single test method
pytest -k "version"                                 # Tests matching keyword
pytest --cov=plsec --cov-report=html               # With HTML coverage

# Shell tests (BATS)
make test-unit              # BATS unit tests only
make test-integration       # BATS integration tests
make test                   # All BATS tests (unit + integration)

# All tests
make test-python            # pytest only
make ci                     # Full CI (lint + build + all tests)
```

### Linting & Formatting

```bash
# Linting
ruff check .                # Check for issues
ruff check . --fix          # Auto-fix issues
ruff check src/ tests/      # Specific directories

# Formatting
ruff format .               # Format all files
ruff format . --check       # Check without modifying

# Type checking
ty check src/                   # Type check (strict mode enabled)
```

### Build Commands

```bash
make build                  # Assemble build/bootstrap.sh from templates
make lint                   # Validate JSON/YAML/shell templates
make lint-bootstrap         # Check assembled bootstrap.sh syntax
make verify                 # Ensure build matches promoted reference
make promote                # Copy build to bin/bootstrap.default.sh
make golden                 # Regenerate golden test fixtures
make clean                  # Remove build artifacts and venv
```

## Architecture and Design Guidelines

Follow John Ousterhout's *A Philosophy of Software Design*:

- **Push complexity down**: Hide complexity in lower layers
- **Modules should be deep**: Simple interfaces, rich functionality
- **General purpose modules are deeper**: Favour refactoring and generalization
- **Different layer, different abstraction**: Favour layered designs
- **Separate general purpose and special purpose code**
- **Avoid duplication**: Extract common code to shared modules
- **Favour shorter functions for clarity** (heuristic, not rule)
- **DRY**: Do not repeat yourself. If you find yourself repeating the same code
  in multiple places, extract that to a common file. For example, do NOT have
  multiple stylesheets with the same properties, tags or styles. Use the same
  stylesheets.

## Code Style and Code Design Guidelines

When coding, use the following rules:
- Use descriptive names for globals, short names for locals
- Be consistent, give related things related names that show their relationship
  and highlight their differences
- Use active names for functions
- Be accurate
- Use the natural form for expressions. Avoid conditional expressions that
  include negations.
- Parenthesize to avoid ambiguity
- Break up complex expressions
- Use idioms for consistency.
- In Python, use 3.12+
- In Python, when designing APIs and external interfaces, use annotations
- In Python, favour the use of dictionary comprehensions
- In Python, prefer the use of @dataclasses
- Avoid using emoticons in print statements and output. Keep the output clean,
  readable and without unnecessary decoration.
- Write test cases first - describe the end-to-end behaviour that we want and
  then tie in the unit test cases and integration test cases.
- Use mkdocs for user documentation.
- Use tox for test coordination/orchestration.
- Use pytest for unit tests.
- Use Behave for user level tests (directly from specification) and Playwright
  for acceptance tests and integration testing in Python.
- Use BATS for Bash/shell script testing
- Use ruff for linting
- Use ty for type checking
- When developing TUI, use textual.pilot for testing where appropriate
- Use ruff format for formatting
- Use Gherkin to describe user journeys before switching to Behave
- Comment functions and global data
- Don't contradict your code! When code changes, make sure you update the
  comments and documentation!
- Try to be pythonic always!
- Write secure code - correct, secure and *then* fast.

## Code Style Guidelines

### Type Annotations

- **Required** for all public function signatures
- Use union syntax: `str | None` (not `Optional[str]`)
- Use generic syntax: `list[str]`, `dict[str, int]` (not `List`, `Dict`)
- Use `Literal["a", "b"]` for constrained string values
- Use `Callable[[str], str]` for function types

### Data Models

- Use **pydantic.BaseModel** for configuration and API models
- Use **@dataclass** for internal data structures
- Use `Field(default_factory=...)` for mutable defaults

### Naming Conventions

| Type      | Convention               | Examples                                        |
|-----------|--------------------------|-------------------------------------------------|
| Classes   | PascalCase               | `PlsecConfig`, `ToolChecker`, `ToolStatus`      |
| Functions | snake_case, active verbs | `load_config`, `check_tool`, `find_config_file` |
| Constants | UPPER_SNAKE_CASE         | `REQUIRED_TOOLS`, `OPTIONAL_TOOLS`              |
| Private   | underscore prefix        | `_version_gte`, `_parse_output`                 |
| Variables | snake_case               | `config_path`, `error_count`                    |

