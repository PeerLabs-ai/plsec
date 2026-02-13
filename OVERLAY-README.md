# claude-bootstrap-overlay

Overlay archive for the plsec project. Extract into the plsec repo root
to add/update the bootstrap.sh build system, templates, tests, and docs.

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
chmod +x scripts/assemble-bootstrap.sh
chmod +x scripts/test-assembler-escaping.sh
chmod +x tests/bats/run-in-container.sh

# 3. Build bootstrap.sh from templates
make build

# 4. Verify build matches the promoted reference
make verify

# 5. Run tests
make test

# 6. (Optional) Run full CI pipeline
make ci
```

## Build workflow

```
templates/bootstrap/*.{md,json,yaml,sh}
        |
        v
scripts/assemble-bootstrap.sh  -->  build/bootstrap.sh  (curl target)
        |
        v (make promote)
bin/bootstrap.default.sh  (known-good reference)
```

Edit templates, run `make build`, test, then `make promote` to update
the reference. CI validates build/bootstrap.sh matches
bin/bootstrap.default.sh.

## Files NOT included (to avoid conflicts)

HANDOFF.md (project root), .github/workflows/test.yml or other existing
workflows, pyproject.toml, src/, tests/__init__.py, tests/test_plsec.py
