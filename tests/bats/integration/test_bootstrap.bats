#!/usr/bin/env bats
# test_bootstrap.bats - Integration tests for full bootstrap execution
#
# Runs bin/bootstrap.sh in a sandboxed HOME and verifies directory structure,
# agent filtering, and mode selection.

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
# Directory structure
# ---------------------------------------------------------------------------

@test "bootstrap creates expected directory structure" {
    run "${BOOTSTRAP}" --agent claude --strict
    assert_success
    assert [ -d "${PLSEC_DIR}/configs" ]
    assert [ -d "${PLSEC_DIR}/logs" ]
    assert [ -d "${PLSEC_DIR}/manifests" ]
    assert [ -d "${PLSEC_DIR}/trivy/policies" ]
}

@test "bootstrap creates logs directory" {
    run "${BOOTSTRAP}" --agent claude
    assert_success
    assert [ -d "${PLSEC_DIR}/logs" ]
}

# ---------------------------------------------------------------------------
# Agent filtering: claude
# ---------------------------------------------------------------------------

@test "--agent claude creates CLAUDE.md" {
    run "${BOOTSTRAP}" --agent claude
    assert_success
    assert [ -f "${PLSEC_DIR}/configs/CLAUDE.md" ]
}

@test "--agent claude creates claude-wrapper.sh" {
    run "${BOOTSTRAP}" --agent claude
    assert_success
    assert [ -f "${PLSEC_DIR}/claude-wrapper.sh" ]
}

@test "--agent claude does not create opencode files" {
    run "${BOOTSTRAP}" --agent claude
    assert_success
    assert [ ! -f "${PLSEC_DIR}/configs/opencode.json" ]
    assert [ ! -f "${PLSEC_DIR}/opencode-wrapper.sh" ]
}

# ---------------------------------------------------------------------------
# Agent filtering: opencode
# ---------------------------------------------------------------------------

@test "--agent opencode creates opencode.json" {
    run "${BOOTSTRAP}" --agent opencode
    assert_success
    assert [ -f "${PLSEC_DIR}/configs/opencode.json" ]
}

@test "--agent opencode creates opencode-wrapper.sh" {
    run "${BOOTSTRAP}" --agent opencode
    assert_success
    assert [ -f "${PLSEC_DIR}/opencode-wrapper.sh" ]
}

@test "--agent opencode does not create claude-specific files" {
    run "${BOOTSTRAP}" --agent opencode
    assert_success
    assert [ ! -f "${PLSEC_DIR}/configs/CLAUDE.md" ]
    assert [ ! -f "${PLSEC_DIR}/claude-wrapper.sh" ]
}

# ---------------------------------------------------------------------------
# Agent filtering: both
# ---------------------------------------------------------------------------

@test "--agent both creates all config files" {
    run "${BOOTSTRAP}" --agent both
    assert_success
    assert [ -f "${PLSEC_DIR}/configs/CLAUDE.md" ]
    assert [ -f "${PLSEC_DIR}/configs/opencode.json" ]
    assert [ -f "${PLSEC_DIR}/claude-wrapper.sh" ]
    assert [ -f "${PLSEC_DIR}/opencode-wrapper.sh" ]
}

# ---------------------------------------------------------------------------
# Mode selection
# ---------------------------------------------------------------------------

@test "--strict creates strict CLAUDE.md" {
    "${BOOTSTRAP}" --agent claude --strict
    run grep "RESTRICTED" "${PLSEC_DIR}/configs/CLAUDE.md"
    assert_success
}

@test "balanced mode (default) does not contain RESTRICTED" {
    "${BOOTSTRAP}" --agent claude
    run grep "RESTRICTED" "${PLSEC_DIR}/configs/CLAUDE.md"
    assert_failure
}

# ---------------------------------------------------------------------------
# Common artifacts
# ---------------------------------------------------------------------------

@test "bootstrap creates scan.sh" {
    run "${BOOTSTRAP}" --agent claude
    assert_success
    assert [ -f "${PLSEC_DIR}/scan.sh" ]
}

@test "bootstrap creates pre-commit hook" {
    run "${BOOTSTRAP}" --agent claude
    assert_success
    assert [ -f "${PLSEC_DIR}/configs/pre-commit" ]
}

@test "bootstrap creates trivy-secret.yaml" {
    run "${BOOTSTRAP}" --agent claude
    assert_success
    assert [ -f "${PLSEC_DIR}/trivy/trivy-secret.yaml" ]
}

@test "bootstrap writes aliases to shell rc" {
    "${BOOTSTRAP}" --agent claude
    run grep "Peerlabs Security aliases" "${HOME}/.zshrc"
    assert_success
}

# ---------------------------------------------------------------------------
# PLSEC_DIR override via environment
# ---------------------------------------------------------------------------

@test "PLSEC_DIR can be overridden via environment" {
    export PLSEC_DIR="${BATS_TEST_TMPDIR}/custom/plsec"
    run "${BOOTSTRAP}" --agent claude
    assert_success
    assert [ -d "${BATS_TEST_TMPDIR}/custom/plsec/configs" ]
    assert [ -f "${BATS_TEST_TMPDIR}/custom/plsec/configs/CLAUDE.md" ]
}
