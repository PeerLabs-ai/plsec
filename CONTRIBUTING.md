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

This project uses
[GitHub Flow](https://docs.github.com/en/get-started/using-github/github-flow).
There is no `develop` branch and no release branches. All work branches
off `main` and merges back to `main`.

### Branch naming

| Prefix     | Use                                     |
|------------|-----------------------------------------|
| `feature/` | New functionality                       |
| `fix/`     | Bug fixes                               |
| `chore/`   | Maintenance, CI, docs, dependency bumps |

### Steps

1. **Create an issue** (required for non-trivial changes):
   ```bash
   gh issue create --title "Add feature X" --body "Description..."
   ```

2. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/my-feature main
   ```

3. **Make your changes.** Write tests first -- tests define the contracts.

4. **Run the quick local check** before pushing:
   ```bash
   make dev-check    # lint + types + tests + build
   ```

5. **For full validation** (matches CI):
   ```bash
   make ci           # lint + types + build + all tests + golden
   ```

6. **Create a pull request** against `main`:
   ```bash
   gh pr create --title "Add feature X"
   gh pr checks      # view CI status
   ```

7. **Merge** after approval:
   ```bash
   gh pr merge --delete-branch
   ```

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

- Feature branches off `main`, PRs back to `main`
- Create an issue first for non-trivial changes
- `make ci` must pass (CI runs automatically via GitHub Actions)
- Keep PRs focused -- one concern per PR
- Update tests and documentation as needed
- Delete the branch after merge (`gh pr merge --delete-branch`)

## Questions?

Open an issue on [GitHub](https://github.com/PeerLabs-ai/plsec/issues).
