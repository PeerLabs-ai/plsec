# Contributing to plsec

Thank you for your interest in contributing to plsec.

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (package manager)
- GNU Make
- [Trivy](https://aquasecurity.github.io/trivy/) (for running scans)
- [BATS](https://github.com/bats-core/bats-core) (for shell tests)

## Setup

```bash
git clone https://github.com/PeerLabs-ai/plsec
cd plsec
make setup    # installs all dev dependencies via uv
```

## Development Workflow

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/my-feature main
   ```

2. Make your changes. Write tests first -- tests define the contracts.

3. Run the quick local check before pushing:
   ```bash
   make dev-check    # lint + types + tests + build
   ```

4. For full validation (matches CI):
   ```bash
   make ci           # lint + types + build + all tests + golden
   ```

5. Open a pull request against `main`.

## Coding Standards

The full coding standards are in [AGENTS.md](AGENTS.md). Key points:

- **Python 3.12+** -- use modern syntax (`str | None`, `list[str]`)
- **Line length**: 100 characters
- **Linter**: ruff (`ruff check .`, `ruff format .`)
- **Type checker**: ty (`ty check src/`)
- **Data models**: `@dataclass` (no Pydantic)
- **CLI parameters**: `Annotated` typer syntax
- **No `except Exception`** -- catch specific exception types
- **No `# noqa`** -- fix the underlying code, don't suppress lint warnings
- **Scanner false positive suppressions** (`.trivyignore.yaml`, `# nosemgrep`)
  are acceptable -- these are different from lint suppressions

## Testing

Tests are the primary contract. Write them before implementation.

- **pytest** for Python code (`tests/`)
- **BATS** for shell scripts (`tests/bats/`)
- Engine tests live in `tests/engine/` and must cover JSON parsing
  failures, non-zero exit codes, and prefixed stdout recovery

```bash
make test-python       # pytest only
make test-unit         # BATS unit tests
make test-integration  # BATS integration tests
make test              # all of the above
```

## Project Structure

```
src/plsec/
  cli.py             # Entry point, typer app
  commands/          # Subcommands (doctor, init, scan, etc.)
  core/              # Business logic (config, tools, output)
  engine/            # Scanner engines (trivy, bandit, semgrep)
  configs/           # Embedded templates
tests/
  test_*.py          # pytest tests
  engine/            # Engine-specific tests
  bats/              # BATS shell tests
templates/bootstrap/ # Bootstrap script templates
```

## Pull Request Process

- Feature branches + PRs to `main`
- `make ci` must pass (CI runs automatically via GitHub Actions)
- Keep PRs focused -- one concern per PR
- Update tests and documentation as needed

## Questions?

Open an issue on [GitHub](https://github.com/PeerLabs-ai/plsec/issues).
