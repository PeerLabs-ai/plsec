# Testing Strategy: bootstrap.sh

## Summary

- BATS is the right choice for unit and integration testing of bin/bootstrap.sh
- Testing breaks into three tiers: unit (helper functions, argument parsing), integration (file generation, idempotency), and platform (macOS/Linux in CI)
- BATS tests coexist with the existing pytest suite under tests/bats/
- The existing --dry-run mode serves double duty: user-facing feature and test scaffolding
- CI runs both pytest (Python CLI) and BATS (bootstrap) on GitHub Actions with a platform matrix

## Why BATS

Three frameworks warrant consideration for bash script testing:

**BATS (Bash Automated Testing System)**

- Purpose-built for bash; TAP-compliant output integrates with CI systems
- bats-core is actively maintained (forked from original sstephenson/bats)
- Companion libraries: bats-support, bats-assert, bats-file cover assertions
  and filesystem checks
- Widely adopted in infrastructure tooling (Homebrew, rbenv, nvm all use it)
- Low ceremony: test files are bash scripts with minimal syntax overhead

**ShellSpec**

- More feature-rich (mocking, parameterized tests, coverage reporting)
- BDD-style syntax (Describe, It, When, The result should)
- Steeper learning curve; heavier dependency footprint
- Better for large shell projects with complex function libraries

**shUnit2**

- xUnit-style; mature but less actively maintained
- Familiar if coming from JUnit/pytest patterns
- Weaker ecosystem for filesystem assertions

**Recommendation: BATS.** The bootstrap script has straightforward input/output
contracts (flags in, files out). BATS matches the complexity level, has strong CI
integration, and tests are readable without learning a DSL. ShellSpec would be
worth revisiting if plsec grows into a large multi-script bash suite -- but for
bin/bootstrap.sh and the near-term roadmap, BATS is sufficient.

Caveat: bats-file maintenance status should be verified before committing. If
undermaintained, filesystem assertions (assert_dir_exists, etc.) are trivial to
implement as thin wrappers in common.bash.


## Project Layout (additions to existing structure)

The plsec project already has a pytest-based test suite. BATS tests nest under
tests/bats/ to coexist without interference.

```
plsec/
  bin/
    bootstrap.sh                   # existing - system under test
  docs/
    DESIGN-CREATE-SECURE.md        # existing
    bootstrap-testing.md           # this document
  src/plsec/                       # existing - unchanged
  tests/
    __init__.py                    # existing
    test_plsec.py                  # existing pytest tests
    bats/                          # new - BATS test tree
      test_helper/
        bats-support/              # git submodule
        bats-assert/               # git submodule
        bats-file/                 # git submodule
        common.bash                # shared setup
      unit/
        test_helpers.bats
        test_args.bats
        test_detect_os.bats
      integration/
        test_bootstrap.bats
        test_generated_files.bats
        test_idempotency.bats
        test_dry_run.bats
  .github/
    workflows/
      test.yml                     # runs both pytest and bats
  homebrew/                        # existing - unchanged
  pyproject.toml                   # existing
  HANDOFF.md                       # existing
  README.md                        # existing
```

**Why tests/bats/ rather than a separate test/ tree:**

- Single tests/ directory, two test ecosystems partitioned by subdirectory
- pyproject.toml already configures testpaths = ["tests"] for pytest; .bats files
  won't interfere with pytest discovery
- CI workflow runs both: pytest tests/ for the Python CLI, bats tests/bats/ for
  the bash bootstrap
- BATS submodules scoped under tests/bats/test_helper/ to avoid polluting the
  Python test namespace


## Structural Prerequisite: main() Function Guard [DONE]

Bootstrap.sh now has a main function guard. The script can be sourced for its
function definitions without triggering execution.

Changes made:

- check_command() moved from inline in section 1 to the function definitions block
- Configuration variables made overridable via environment:
  `PLSEC_DIR="${PLSEC_DIR:-${HOME}/.peerlabs/plsec}"` etc.
- main() wraps everything from argument parsing through summary output
- Source guard at bottom:

```bash
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
```

- No indentation change inside main() -- at 700+ lines, an extra nesting
  level would produce noisy diffs

Verified: sourcing loads all functions silently, direct execution works as
before, PLSEC_DIR overridable via environment for test isolation.


## Test Architecture

### Shared Setup: common.bash

```bash
# tests/bats/test_helper/common.bash

BOOTSTRAP="${BATS_TEST_DIRNAME}/../../bin/bootstrap.sh"

setup_fake_home() {
    export HOME="${BATS_TEST_TMPDIR}/fakehome"
    mkdir -p "${HOME}"
    touch "${HOME}/.zshrc"
    export PLSEC_DIR="${HOME}/.peerlabs/plsec"
}

teardown_fake_home() {
    # BATS_TEST_TMPDIR is cleaned up automatically
    unset HOME PLSEC_DIR
}
```


### Tier 1: Unit Tests (fast, no side effects)

Test individual functions in isolation by sourcing bootstrap.sh without
executing the main flow. Requires the main() guard described above.

**What to test:**

- log_info, log_ok, log_warn, log_error -- correct labels and stderr output
- detect_os -- mock sw_vers and /etc/debian_version to test platform detection
- check_command -- mock command -v to test found/not-found paths
- Argument parsing -- all flag combinations, invalid flags, help text
- Dry-run helpers -- write_file, run_cmd, etc. produce [DRY RUN] output
  when DRY_RUN=true and execute when DRY_RUN=false

**Example: tests/bats/unit/test_helpers.bats**

```bash
setup() {
    load '../test_helper/bats-support/load'
    load '../test_helper/bats-assert/load'
    load '../test_helper/common'

    # Source bootstrap without executing main
    source "${BOOTSTRAP}"

    # Isolate from host filesystem
    setup_fake_home
}

teardown() {
    teardown_fake_home
}

@test "log_ok writes [OK] to stderr" {
    run log_ok "test message"
    assert_output --partial "[OK]"
    assert_output --partial "test message"
}

@test "log_warn writes [WARN] to stderr" {
    run log_warn "something concerning"
    assert_output --partial "[WARN]"
    assert_output --partial "something concerning"
}

@test "write_file creates file in normal mode" {
    DRY_RUN=false
    echo "hello" | write_file "${BATS_TEST_TMPDIR}/test.txt"
    assert [ -f "${BATS_TEST_TMPDIR}/test.txt" ]
    assert_equal "$(cat "${BATS_TEST_TMPDIR}/test.txt")" "hello"
}

@test "write_file skips in dry-run mode" {
    DRY_RUN=true
    local target="${BATS_TEST_TMPDIR}/should_not_exist.txt"
    run bash -c "source '${BOOTSTRAP}'; DRY_RUN=true; echo 'hello' | write_file '${target}'"
    assert [ ! -f "${target}" ]
}

@test "write_file_from_var creates file with correct content" {
    DRY_RUN=false
    write_file_from_var "${BATS_TEST_TMPDIR}/test.txt" "file content here"
    assert_equal "$(cat "${BATS_TEST_TMPDIR}/test.txt")" "file content here"
}

@test "ensure_dir creates directory in normal mode" {
    DRY_RUN=false
    ensure_dir "${BATS_TEST_TMPDIR}/new/nested/dir"
    assert [ -d "${BATS_TEST_TMPDIR}/new/nested/dir" ]
}

@test "ensure_dir skips in dry-run mode" {
    DRY_RUN=true
    run ensure_dir "${BATS_TEST_TMPDIR}/should_not_exist"
    assert [ ! -d "${BATS_TEST_TMPDIR}/should_not_exist" ]
}

@test "make_executable sets +x in normal mode" {
    DRY_RUN=false
    touch "${BATS_TEST_TMPDIR}/script.sh"
    make_executable "${BATS_TEST_TMPDIR}/script.sh"
    assert [ -x "${BATS_TEST_TMPDIR}/script.sh" ]
}

@test "copy_file copies in normal mode" {
    DRY_RUN=false
    echo "source" > "${BATS_TEST_TMPDIR}/src.txt"
    copy_file "${BATS_TEST_TMPDIR}/src.txt" "${BATS_TEST_TMPDIR}/dst.txt"
    assert [ -f "${BATS_TEST_TMPDIR}/dst.txt" ]
    assert_equal "$(cat "${BATS_TEST_TMPDIR}/dst.txt")" "source"
}
```

**Example: tests/bats/unit/test_args.bats**

```bash
setup() {
    load '../test_helper/bats-support/load'
    load '../test_helper/bats-assert/load'
    load '../test_helper/common'
}

@test "--help exits 0 and shows usage" {
    run "${BOOTSTRAP}" --help
    assert_success
    assert_output --partial "Usage:"
    assert_output --partial "--dry-run"
    assert_output --partial "--strict"
    assert_output --partial "--agent"
}

@test "--simulate is accepted as alias for --dry-run" {
    run "${BOOTSTRAP}" --simulate --help
    assert_success
}

@test "invalid --agent value exits 1" {
    run "${BOOTSTRAP}" --agent invalid
    assert_failure
    assert_output --partial "Invalid agent type"
}

@test "unknown flag exits 1" {
    run "${BOOTSTRAP}" --nonexistent
    assert_failure
    assert_output --partial "Unknown option"
}
```


### Tier 2: Integration Tests (filesystem, generated content)

Run bin/bootstrap.sh in a controlled environment and verify outcomes. These use
BATS_TEST_TMPDIR with a fake HOME as the sandbox.

**What to test:**

- Directory structure: all expected directories created under PLSEC_DIR
- Generated file content:
  - CLAUDE.md contains expected constraint sections for strict/balanced
  - opencode.json is valid JSON conforming to schema
  - opencode.json contains correct permission rules per mode
  - Trivy configs are valid YAML
  - Wrapper scripts have correct shebang, are executable
  - Wrapper scripts contain the interpolated PLSEC_DIR path (not ${HOME}/...)
  - Pre-commit hook is executable
- Idempotency: second run produces identical results; no duplicate aliases
- Dry-run fidelity: running with --dry-run produces zero filesystem changes
- Agent filtering: --agent claude produces no opencode files; vice versa

**Example: tests/bats/integration/test_bootstrap.bats**

```bash
setup() {
    load '../test_helper/bats-support/load'
    load '../test_helper/bats-assert/load'
    load '../test_helper/bats-file/load'
    load '../test_helper/common'

    setup_fake_home
}

teardown() {
    teardown_fake_home
}

@test "bootstrap creates expected directory structure" {
    run "${BOOTSTRAP}" --agent claude --strict
    assert_success
    assert_dir_exists "${PLSEC_DIR}/configs"
    assert_dir_exists "${PLSEC_DIR}/logs"
    assert_dir_exists "${PLSEC_DIR}/manifests"
    assert_dir_exists "${PLSEC_DIR}/trivy/policies"
}

@test "--agent claude does not create opencode files" {
    run "${BOOTSTRAP}" --agent claude
    assert_success
    assert [ -f "${PLSEC_DIR}/configs/CLAUDE.md" ]
    assert [ ! -f "${PLSEC_DIR}/configs/opencode.json" ]
    assert [ ! -f "${PLSEC_DIR}/opencode-wrapper.sh" ]
}

@test "--agent opencode does not create CLAUDE.md" {
    run "${BOOTSTRAP}" --agent opencode
    assert_success
    assert [ -f "${PLSEC_DIR}/configs/opencode.json" ]
    # Note: opencode wrapper still copies CLAUDE.md if available,
    # but the config file itself should not be generated
    assert [ ! -f "${PLSEC_DIR}/configs/CLAUDE.md" ]
}

@test "generated opencode.json is valid JSON" {
    "${BOOTSTRAP}" --agent opencode
    run python3 -m json.tool "${PLSEC_DIR}/configs/opencode.json"
    assert_success
}

@test "strict opencode.json denies .env read access" {
    "${BOOTSTRAP}" --agent opencode --strict
    run python3 -c "
import json, sys
with open('${PLSEC_DIR}/configs/opencode.json') as f:
    cfg = json.load(f)
assert cfg['permission']['read']['.env'] == 'deny'
"
    assert_success
}

@test "balanced opencode.json allows git by default" {
    "${BOOTSTRAP}" --agent opencode
    run python3 -c "
import json
with open('${PLSEC_DIR}/configs/opencode.json') as f:
    cfg = json.load(f)
assert cfg['permission']['bash']['git *'] == 'allow'
"
    assert_success
}

@test "strict CLAUDE.md contains RESTRICTED" {
    "${BOOTSTRAP}" --agent claude --strict
    run grep "RESTRICTED" "${PLSEC_DIR}/configs/CLAUDE.md"
    assert_success
}

@test "balanced CLAUDE.md does not contain RESTRICTED" {
    "${BOOTSTRAP}" --agent claude
    run grep "RESTRICTED" "${PLSEC_DIR}/configs/CLAUDE.md"
    assert_failure
}

@test "trivy-secret.yaml is valid YAML" {
    "${BOOTSTRAP}" --agent claude
    run python3 -c "
import yaml
with open('${PLSEC_DIR}/trivy/trivy-secret.yaml') as f:
    yaml.safe_load(f)
"
    assert_success
}
```

**Example: tests/bats/integration/test_generated_files.bats**

```bash
setup() {
    load '../test_helper/bats-support/load'
    load '../test_helper/bats-assert/load'
    load '../test_helper/common'

    setup_fake_home
}

teardown() {
    teardown_fake_home
}

@test "wrapper scripts contain interpolated PLSEC_DIR" {
    "${BOOTSTRAP}" --agent both
    # Should NOT contain the variable reference
    run grep 'PLSEC_DIR="${HOME}' "${PLSEC_DIR}/claude-wrapper.sh"
    assert_failure
    # Should contain the resolved path
    run grep "PLSEC_DIR=\"${PLSEC_DIR}\"" "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

@test "wrapper scripts are executable" {
    "${BOOTSTRAP}" --agent both
    assert [ -x "${PLSEC_DIR}/claude-wrapper.sh" ]
    assert [ -x "${PLSEC_DIR}/opencode-wrapper.sh" ]
    assert [ -x "${PLSEC_DIR}/scan.sh" ]
}

@test "wrapper scripts pass syntax check" {
    "${BOOTSTRAP}" --agent both
    run bash -n "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
    run bash -n "${PLSEC_DIR}/opencode-wrapper.sh"
    assert_success
    run bash -n "${PLSEC_DIR}/scan.sh"
    assert_success
}

@test "pre-commit hook is executable" {
    "${BOOTSTRAP}" --agent claude
    assert [ -x "${PLSEC_DIR}/configs/pre-commit" ]
}

@test "pre-commit hook passes syntax check" {
    "${BOOTSTRAP}" --agent claude
    run bash -n "${PLSEC_DIR}/configs/pre-commit"
    assert_success
}

@test "opencode.json contains schema reference" {
    "${BOOTSTRAP}" --agent opencode
    run grep 'opencode.ai/config.json' "${PLSEC_DIR}/configs/opencode.json"
    assert_success
}

@test "balanced CLAUDE.md references PLSEC_DIR logs path" {
    "${BOOTSTRAP}" --agent claude
    run grep "${PLSEC_DIR}/logs/" "${PLSEC_DIR}/configs/CLAUDE.md"
    assert_success
}
```

**Example: tests/bats/integration/test_idempotency.bats**

```bash
setup() {
    load '../test_helper/bats-support/load'
    load '../test_helper/bats-assert/load'
    load '../test_helper/common'

    setup_fake_home
}

teardown() {
    teardown_fake_home
}

@test "second run does not duplicate aliases in shell rc" {
    "${BOOTSTRAP}" --agent claude
    "${BOOTSTRAP}" --agent claude
    local count
    count=$(grep -c "Peerlabs Security aliases" "${HOME}/.zshrc")
    assert_equal "$count" "1"
}

@test "second run produces identical config files" {
    "${BOOTSTRAP}" --agent both --strict
    local first_claude first_opencode
    first_claude=$(shasum -a 256 "${PLSEC_DIR}/configs/CLAUDE.md" | cut -d' ' -f1)
    first_opencode=$(shasum -a 256 "${PLSEC_DIR}/configs/opencode.json" | cut -d' ' -f1)

    "${BOOTSTRAP}" --agent both --strict
    local second_claude second_opencode
    second_claude=$(shasum -a 256 "${PLSEC_DIR}/configs/CLAUDE.md" | cut -d' ' -f1)
    second_opencode=$(shasum -a 256 "${PLSEC_DIR}/configs/opencode.json" | cut -d' ' -f1)

    assert_equal "$first_claude" "$second_claude"
    assert_equal "$first_opencode" "$second_opencode"
}

@test "existing global opencode config is not overwritten" {
    ensure_dir "${HOME}/.config/opencode"
    echo '{"custom": true}' > "${HOME}/.config/opencode/opencode.json"

    "${BOOTSTRAP}" --agent opencode
    run grep '"custom"' "${HOME}/.config/opencode/opencode.json"
    assert_success
}
```

**Example: tests/bats/integration/test_dry_run.bats**

```bash
setup() {
    load '../test_helper/bats-support/load'
    load '../test_helper/bats-assert/load'
    load '../test_helper/common'

    setup_fake_home
}

teardown() {
    teardown_fake_home
}

@test "dry-run produces zero filesystem changes" {
    local before after
    before=$(find "${HOME}" -type f 2>/dev/null | sort | shasum -a 256)

    run "${BOOTSTRAP}" --dry-run --agent both --strict
    assert_success

    after=$(find "${HOME}" -type f 2>/dev/null | sort | shasum -a 256)
    assert_equal "$before" "$after"
}

@test "dry-run output contains DRY RUN markers" {
    run "${BOOTSTRAP}" --dry-run --agent both
    assert_output --partial "[DRY RUN]"
    assert_output --partial "DRY RUN MODE"
}

@test "dry-run reports directory creation intent" {
    run "${BOOTSTRAP}" --dry-run --agent both
    assert_output --partial "Would create directory"
}

@test "dry-run reports file write intent" {
    run "${BOOTSTRAP}" --dry-run --agent both
    assert_output --partial "Would write"
}

@test "--simulate behaves identically to --dry-run" {
    local dry_run_output simulate_output
    dry_run_output=$("${BOOTSTRAP}" --dry-run --agent claude 2>&1)
    simulate_output=$("${BOOTSTRAP}" --simulate --agent claude 2>&1)
    assert_equal "$dry_run_output" "$simulate_output"
}
```


### Tier 3: Platform Tests (CI matrix)

Run the full bootstrap on actual macOS and Linux runners to catch
platform-specific issues.

**Matrix:**

| Runner         | Agent | Mode     | Notes                    |
|----------------|-------|----------|--------------------------|
| macos-latest   | both  | strict   | Primary target           |
| macos-latest   | both  | balanced | Verify balanced defaults |
| ubuntu-latest  | both  | strict   | Linux path               |
| ubuntu-latest  | both  | balanced | Linux path               |

**What to test:**

- detect_os returns correct value on each platform
- Dependencies detected or installable
- Generated scripts execute without syntax errors (bash -n)
- sed -i works correctly per platform (once detect_os integration lands)


## Container-Based Integration Testing

Integration tests run inside containers for hermetic isolation. The CI workflow
detects Podman first, falling back to Docker. The CLIs are nearly identical for
build and run operations.

**Containerfile:**

```dockerfile
# tests/bats/Containerfile
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    bash \
    bats \
    git \
    python3 \
    python3-yaml \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install bats helpers
RUN mkdir -p /opt/bats-helpers
COPY tests/bats/test_helper/ /opt/bats-helpers/

WORKDIR /workspace
COPY bin/bootstrap.sh /workspace/bin/bootstrap.sh
COPY tests/bats/ /workspace/tests/bats/

ENTRYPOINT ["bats"]
CMD ["tests/bats/"]
```

**Container runner helper (tests/bats/run-in-container.sh):**

```bash
#!/bin/bash
# Detect container runtime: prefer podman, fall back to docker
if command -v podman &>/dev/null; then
    RUNTIME=podman
elif command -v docker &>/dev/null; then
    RUNTIME=docker
else
    echo "ERROR: Neither podman nor docker found" >&2
    exit 1
fi

echo "Using container runtime: ${RUNTIME}"
"${RUNTIME}" build -t plsec-test -f tests/bats/Containerfile .
"${RUNTIME}" run --rm plsec-test "$@"
```

**macOS integration tests** run natively (not in containers) since macOS-specific
behavior (detect_os, sed -i) cannot be tested inside Linux containers.


## Coverage Reporting

bashcov instruments bash scripts for line-level coverage reporting. Add it to
the CI pipeline once the test suite stabilizes.

**Installation:**

```bash
gem install bashcov    # Ruby gem
# or via container: include in Containerfile
```

**Usage:**

```bash
# Run BATS under bashcov
bashcov -- bats tests/bats/unit/
bashcov -- bats tests/bats/integration/

# Generate HTML report
# Output lands in ./coverage/ by default
```

**CI integration:**

```yaml
- name: Run tests with coverage
  run: |
    gem install bashcov simplecov
    bashcov -- bats tests/bats/
- name: Upload coverage
  uses: actions/upload-artifact@v4
  with:
    name: bash-coverage
    path: coverage/
```

Not required on day one. Add once the test suite is stable and the main()
refactor has landed.


## Golden Files and Build Step

Rather than maintaining bootstrap.sh as a monolithic 900-line script with large
heredoc strings, extract templates into standalone files and assemble them via a
build step.

**Proposed layout:**

```
plsec/
  bin/
    bootstrap.sh               # build artifact (generated)
  templates/
    bootstrap/
      claude-md-strict.md
      claude-md-balanced.md
      opencode-json-strict.json
      opencode-json-balanced.json
      trivy-secret.yaml
      trivy.yaml
      wrapper-claude.sh
      wrapper-opencode.sh
      wrapper-scan.sh
      hook-pre-commit.sh
      pipelock-start.sh
  tests/
    bats/
      golden/                  # expected outputs for snapshot testing
        claude-md-strict.md
        claude-md-balanced.md
        opencode-json-strict.json
        opencode-json-balanced.json
      ...
  scripts/
    build-bootstrap.sh         # assembles bin/bootstrap.sh from templates
```

**Benefits:**

- Templates are independently lintable and diffable (JSON validated against
  schema, YAML parsed, markdown rendered)
- Golden file comparison becomes trivial: expected output IS the template or
  a known transform of it
- Reviewers see CLAUDE.md changes as CLAUDE.md diffs, not heredoc diffs inside bash
- opencode.json can be validated against https://opencode.ai/config.json in CI
  as a standalone file
- Wrapper scripts can be syntax-checked individually before assembly

**Build step:**

The build script reads templates, applies interpolation placeholders (PLSEC_DIR
markers for runtime substitution), and emits the final bootstrap.sh. The build
step should be minimal -- essentially concatenation with heredoc wrapping. The
interpolation convention from the current script (unquoted heredocs with escaped
runtime variables) remains the same.

**Golden file convention:**

- Golden files live in tests/bats/golden/
- They are committed to the repository and represent the expected output of
  a bootstrap run for a given mode
- Test assertions diff generated output against golden files using shasum
- When templates change intentionally, golden files are regenerated:
  `scripts/update-golden.sh`

This is the next significant refactor after the main() guard lands. It changes
the project structure meaningfully and should be its own PR.


## CI Workflow

```yaml
# .github/workflows/test.yml
name: Tests

on:
  push:
    paths: ['bin/**', 'src/**', 'tests/**', 'templates/**']
  pull_request:
    paths: ['bin/**', 'src/**', 'tests/**', 'templates/**']
  release:
    types: [published]

jobs:
  python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install dependencies
        run: pip install -e ".[dev]"
      - name: Run pytest
        run: pytest tests/ --ignore=tests/bats

  bats-unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: true
      - name: Install BATS
        run: sudo apt-get update && sudo apt-get install -y bats
      - name: Run unit tests
        run: bats tests/bats/unit/

  bats-integration-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: true
      - name: Detect container runtime
        id: runtime
        run: |
          if command -v podman &>/dev/null; then
            echo "cmd=podman" >> "$GITHUB_OUTPUT"
          else
            echo "cmd=docker" >> "$GITHUB_OUTPUT"
          fi
      - name: Run integration tests in container
        run: |
          ${{ steps.runtime.outputs.cmd }} build -t plsec-test -f tests/bats/Containerfile .
          ${{ steps.runtime.outputs.cmd }} run --rm plsec-test tests/bats/integration/

  bats-integration-macos:
    strategy:
      matrix:
        mode: ['--strict', '']
        agent: [claude, opencode, both]
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: true
      - name: Install BATS
        run: brew install bats-core
      - name: Install Python (for JSON/YAML validation)
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install PyYAML
        run: pip install pyyaml
      - name: Run integration tests
        run: bats tests/bats/integration/
        env:
          TEST_MODE: ${{ matrix.mode }}
          TEST_AGENT: ${{ matrix.agent }}
```


## Resolved Design Decisions

1. **Container runtime**: Podman preferred, Docker as fallback. Detection is
   automatic. macOS platform tests run natively (not containerized) since
   macOS-specific behavior cannot be tested inside Linux containers.

2. **Coverage**: bashcov for bash coverage reporting. Add to CI once the test
   suite stabilizes, not on day one.

3. **Golden files + build step**: Templates extracted to templates/bootstrap/,
   golden files in tests/bats/golden/, build step assembles bin/bootstrap.sh.
   This is the next significant refactor after the main() guard.

4. **bats-file**: Use if actively maintained; otherwise implement filesystem
   assertions as thin wrappers in common.bash.

5. **main() refactor**: Done. bootstrap.sh now has a source guard; functions
   are available when sourced without triggering execution.

6. **Checksums**: Use shasum -a 256 everywhere. Do not use md5sum.
