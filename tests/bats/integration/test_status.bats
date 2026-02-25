#!/usr/bin/env bats
# test_status.bats - Integration tests for plsec-status full execution
#
# Tests the complete plsec-status command in realistic scenarios:
# healthy system, partial failures, fresh install, JSON output, and
# error handling. Runs against a sandboxed HOME.

setup() {
    load '../test_helper/bats-support/load'
    load '../test_helper/bats-assert/load'
    load '../test_helper/common'

    setup_fake_home
}

teardown() {
    teardown_fake_home
}

# ===========================================================================
# Healthy system
# ===========================================================================

@test "plsec-status exits 0 on fully healthy system" {
    "${BOOTSTRAP}" --agent both
    # Populate minimal activity so activity checks don't warn
    local today
    today=$(date +%Y%m%d)
    printf '[%s] [100] === Session started: /tmp/project ===\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${PLSEC_DIR}/logs/claude-${today}.log"
    printf '[%s] [100] === Session ended: exit code 0 ===\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${PLSEC_DIR}/logs/claude-${today}.log"
    printf '{"overall_passed": true}\n' > "${PLSEC_DIR}/logs/scan-latest.json"
    printf '{"scanner_id":"trivy-secrets","verdict":"pass"}\n' > "${PLSEC_DIR}/logs/scan-${today}.jsonl"

    run "${PLSEC_DIR}/plsec-status.sh"
    assert_success
}

@test "plsec-status shows overall verdict" {
    "${BOOTSTRAP}" --agent both
    local today
    today=$(date +%Y%m%d)
    printf '[%s] [100] === Session started: /tmp/p ===\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${PLSEC_DIR}/logs/claude-${today}.log"
    printf '{"overall_passed": true}\n' > "${PLSEC_DIR}/logs/scan-latest.json"
    printf '{"scanner_id":"trivy-secrets","verdict":"pass"}\n' > "${PLSEC_DIR}/logs/scan-${today}.jsonl"

    run "${PLSEC_DIR}/plsec-status.sh"
    assert_output --partial "Overall"
}

@test "plsec-status displays Installation section" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh"
    assert_output --partial "Installation"
}

@test "plsec-status displays Configuration section" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh"
    assert_output --partial "Configuration"
}

@test "plsec-status displays Activity section" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh"
    assert_output --partial "Activity"
}

# ===========================================================================
# Partial failures
# ===========================================================================

@test "plsec-status exits 0 with warnings only (warnings acceptable)" {
    "${BOOTSTRAP}" --agent claude
    # Activity checks will warn (no sessions yet), but that's just warnings
    run "${PLSEC_DIR}/plsec-status.sh"
    # Exit code 0 because warnings are acceptable
    assert_success
}

@test "plsec-status shows warning for missing optional tools" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh"
    # bandit/semgrep might not be installed - that's fine, just checking
    # the output mentions WARN for at least one thing (activity logs will warn)
    assert_output --partial "WARN"
}

# ===========================================================================
# Fresh install scenario
# ===========================================================================

@test "plsec-status shows activity warnings after fresh install" {
    "${BOOTSTRAP}" --agent claude
    # No sessions, no scans - activity checks should warn/fail
    run "${PLSEC_DIR}/plsec-status.sh"
    assert_output --partial "WARN"
}

@test "plsec-status findings checks SKIP when no scan data" {
    "${BOOTSTRAP}" --agent claude
    # No scan logs exist after fresh install
    run "${PLSEC_DIR}/plsec-status.sh"
    assert_output --partial "SKIP"
}

# ===========================================================================
# JSON output
# ===========================================================================

@test "plsec-status --json produces valid JSON" {
    "${BOOTSTRAP}" --agent both
    run "${PLSEC_DIR}/plsec-status.sh" --json
    assert_success
    # Validate JSON with python (always available in our test environment)
    echo "$output" | $PYTHON -m json.tool > /dev/null 2>&1
    assert [ $? -eq 0 ]
}

@test "plsec-status --json includes version field" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --json
    assert_success
    assert_output --partial '"version"'
}

@test "plsec-status --json includes mode field" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --json
    assert_success
    assert_output --partial '"mode"'
}

@test "plsec-status --json includes agents array" {
    "${BOOTSTRAP}" --agent both
    run "${PLSEC_DIR}/plsec-status.sh" --json
    assert_success
    assert_output --partial '"agents"'
}

@test "plsec-status --json includes checks array" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --json
    assert_success
    assert_output --partial '"checks"'
}

@test "plsec-status --json includes overall verdict" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --json
    assert_success
    assert_output --partial '"overall"'
}

# ===========================================================================
# Quiet mode
# ===========================================================================

@test "plsec-status --quiet produces no output on success" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --quiet
    assert_success
    assert_output ""
}

@test "plsec-status --quiet produces no output on warnings" {
    "${BOOTSTRAP}" --agent claude
    # Fresh install has warnings but exit 0
    run "${PLSEC_DIR}/plsec-status.sh" --quiet
    assert_output ""
}

# ===========================================================================
# Error handling
# ===========================================================================

@test "plsec-status exits 1 when PLSEC_DIR missing" {
    export PLSEC_DIR="${BATS_TEST_TMPDIR}/nonexistent"
    # Create a minimal status script that reads from the env
    # (we need the script to exist somewhere to run it)
    "${BOOTSTRAP}" --agent claude
    # Now point PLSEC_DIR to nonexistent location but run from original
    local status_script="${HOME}/.peerlabs/plsec/plsec-status.sh"
    PLSEC_DIR="${BATS_TEST_TMPDIR}/nonexistent" run "$status_script"
    assert_failure
}

@test "plsec-status handles missing .git directory gracefully" {
    "${BOOTSTRAP}" --agent claude
    # Run from a non-git directory
    run "${PLSEC_DIR}/plsec-status.sh" --project "${BATS_TEST_TMPDIR}"
    # Should still succeed (just warn about missing hook)
    assert_success
}

@test "plsec-status --project flag sets project path" {
    "${BOOTSTRAP}" --agent claude
    local project="${BATS_TEST_TMPDIR}/myproject"
    mkdir -p "$project"
    run "${PLSEC_DIR}/plsec-status.sh" --project "$project"
    assert_success
    assert_output --partial "$project"
}

# ===========================================================================
# Agent-specific output
# ===========================================================================

@test "plsec-status shows claude artifacts when claude configured" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh"
    assert_output --partial "CLAUDE.md"
}

@test "plsec-status shows opencode artifacts when opencode configured" {
    "${BOOTSTRAP}" --agent opencode
    run "${PLSEC_DIR}/plsec-status.sh"
    assert_output --partial "opencode.json"
}

@test "plsec-status shows both agents when both configured" {
    "${BOOTSTRAP}" --agent both
    run "${PLSEC_DIR}/plsec-status.sh"
    assert_output --partial "CLAUDE.md"
    assert_output --partial "opencode.json"
}

# ===========================================================================
# Mode detection in output
# ===========================================================================

@test "plsec-status shows strict mode when configured strict" {
    "${BOOTSTRAP}" --agent claude --strict
    run "${PLSEC_DIR}/plsec-status.sh"
    assert_output --partial "strict"
}

@test "plsec-status shows balanced mode when configured balanced" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh"
    assert_output --partial "balanced"
}
