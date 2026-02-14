#!/usr/bin/env bats
# test_generated_files.bats - Verify content and correctness of generated files
#
# Checks file permissions, syntax validity, interpolated paths, and
# structural properties of configs.

setup() {
    load '../test_helper/bats-support/load'
    load '../test_helper/bats-assert/load'
    load '../test_helper/common'

    setup_fake_home
}

teardown() {
    teardown_fake_home
}

# ---------------------------------------------------------------------------
# Wrapper script correctness
# ---------------------------------------------------------------------------

@test "wrapper scripts contain interpolated PLSEC_DIR (not variable)" {
    "${BOOTSTRAP}" --agent both
    # Should NOT contain the unexpanded ${HOME} reference
    run grep 'PLSEC_DIR="${HOME}' "${PLSEC_DIR}/claude-wrapper.sh"
    assert_failure
    # Should contain the actual resolved path
    run grep "PLSEC_DIR=\"${PLSEC_DIR}\"" "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

@test "opencode wrapper contains interpolated PLSEC_DIR" {
    "${BOOTSTRAP}" --agent opencode
    run grep 'PLSEC_DIR="${HOME}' "${PLSEC_DIR}/opencode-wrapper.sh"
    assert_failure
    run grep "PLSEC_DIR=\"${PLSEC_DIR}\"" "${PLSEC_DIR}/opencode-wrapper.sh"
    assert_success
}

@test "scan.sh contains interpolated PLSEC_DIR" {
    "${BOOTSTRAP}" --agent claude
    run grep 'PLSEC_DIR="${HOME}' "${PLSEC_DIR}/scan.sh"
    assert_failure
    run grep "PLSEC_DIR=\"${PLSEC_DIR}\"" "${PLSEC_DIR}/scan.sh"
    assert_success
}

# ---------------------------------------------------------------------------
# File permissions
# ---------------------------------------------------------------------------

@test "claude-wrapper.sh is executable" {
    "${BOOTSTRAP}" --agent claude
    assert [ -x "${PLSEC_DIR}/claude-wrapper.sh" ]
}

@test "opencode-wrapper.sh is executable" {
    "${BOOTSTRAP}" --agent opencode
    assert [ -x "${PLSEC_DIR}/opencode-wrapper.sh" ]
}

@test "scan.sh is executable" {
    "${BOOTSTRAP}" --agent claude
    assert [ -x "${PLSEC_DIR}/scan.sh" ]
}

@test "pre-commit hook is executable" {
    "${BOOTSTRAP}" --agent claude
    assert [ -x "${PLSEC_DIR}/configs/pre-commit" ]
}

# ---------------------------------------------------------------------------
# Syntax validity (bash -n)
# ---------------------------------------------------------------------------

@test "claude-wrapper.sh passes syntax check" {
    "${BOOTSTRAP}" --agent claude
    run bash -n "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

@test "opencode-wrapper.sh passes syntax check" {
    "${BOOTSTRAP}" --agent opencode
    run bash -n "${PLSEC_DIR}/opencode-wrapper.sh"
    assert_success
}

@test "scan.sh passes syntax check" {
    "${BOOTSTRAP}" --agent claude
    run bash -n "${PLSEC_DIR}/scan.sh"
    assert_success
}

@test "pre-commit hook passes syntax check" {
    "${BOOTSTRAP}" --agent claude
    run bash -n "${PLSEC_DIR}/configs/pre-commit"
    assert_success
}

# ---------------------------------------------------------------------------
# opencode.json validity
# ---------------------------------------------------------------------------

@test "generated opencode.json is valid JSON" {
    "${BOOTSTRAP}" --agent opencode
    run ${PYTHON} -m json.tool "${PLSEC_DIR}/configs/opencode.json"
    assert_success
}

@test "strict opencode.json denies .env read access" {
    "${BOOTSTRAP}" --agent opencode --strict
    run ${PYTHON} -c "
import json
with open('${PLSEC_DIR}/configs/opencode.json') as f:
    cfg = json.load(f)
assert cfg['permission']['read']['.env'] == 'deny', 'Expected .env read deny'
"
    assert_success
}

@test "strict opencode.json denies .env edit access" {
    "${BOOTSTRAP}" --agent opencode --strict
    run ${PYTHON} -c "
import json
with open('${PLSEC_DIR}/configs/opencode.json') as f:
    cfg = json.load(f)
assert cfg['permission']['edit']['.env'] == 'deny', 'Expected .env edit deny'
"
    assert_success
}

@test "opencode.json contains schema reference" {
    "${BOOTSTRAP}" --agent opencode
    run grep 'opencode.ai/config.json' "${PLSEC_DIR}/configs/opencode.json"
    assert_success
}

# ---------------------------------------------------------------------------
# Trivy config validity
# ---------------------------------------------------------------------------

@test "trivy-secret.yaml is valid YAML" {
    "${BOOTSTRAP}" --agent claude
    run ${PYTHON} -c "
import yaml
with open('${PLSEC_DIR}/trivy/trivy-secret.yaml') as f:
    yaml.safe_load(f)
"
    assert_success
}

# ---------------------------------------------------------------------------
# CLAUDE.md content
# ---------------------------------------------------------------------------

@test "balanced CLAUDE.md references PLSEC_DIR logs path" {
    "${BOOTSTRAP}" --agent claude
    run grep "${PLSEC_DIR}/logs/" "${PLSEC_DIR}/configs/CLAUDE.md"
    assert_success
}

@test "CLAUDE.md contains NEVER section" {
    "${BOOTSTRAP}" --agent claude
    run grep "NEVER" "${PLSEC_DIR}/configs/CLAUDE.md"
    assert_success
}

@test "CLAUDE.md contains ALWAYS section" {
    "${BOOTSTRAP}" --agent claude
    run grep "ALWAYS" "${PLSEC_DIR}/configs/CLAUDE.md"
    assert_success
}

# ---------------------------------------------------------------------------
# Aliases
# ---------------------------------------------------------------------------

@test "aliases reference PLSEC_DIR path (not hardcoded)" {
    "${BOOTSTRAP}" --agent claude
    run grep "${PLSEC_DIR}" "${HOME}/.zshrc"
    assert_success
}

@test "claude alias points to claude-wrapper.sh" {
    "${BOOTSTRAP}" --agent claude
    run grep "claude-wrapper.sh" "${HOME}/.zshrc"
    assert_success
}

@test "opencode alias points to opencode-wrapper.sh" {
    "${BOOTSTRAP}" --agent opencode
    run grep "opencode-wrapper.sh" "${HOME}/.zshrc"
    assert_success
}
