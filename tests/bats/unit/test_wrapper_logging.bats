#!/usr/bin/env bats
# test_wrapper_logging.bats - Unit tests for enhanced wrapper logging
#
# Tests Tier 1 (session enrichment) and Tier 2 (audit script) features
# in the generated wrapper scripts. Runs bootstrap in a fake HOME, then
# inspects the generated wrapper content and exercises the audit script.

setup() {
    load '../test_helper/bats-support/load'
    load '../test_helper/bats-assert/load'
    load '../test_helper/common'

    setup_fake_home

    # Run bootstrap to generate wrapper scripts
    "${BOOTSTRAP}" --agent both
}

teardown() {
    teardown_fake_home
}

# ---------------------------------------------------------------------------
# Tier 1: Claude wrapper -- session enrichment fields
# ---------------------------------------------------------------------------

@test "claude wrapper logs git_branch field" {
    run grep "git_branch=" "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

@test "claude wrapper logs git_sha field" {
    run grep "git_sha=" "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

@test "claude wrapper logs preset field" {
    run grep "preset=" "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

@test "claude wrapper logs agent_version field" {
    run grep "agent_version=" "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

@test "claude wrapper logs duration on session end" {
    run grep "duration=" "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

@test "claude wrapper captures SECONDS for timing" {
    run grep "START_SECONDS" "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

@test "claude wrapper calculates ELAPSED time" {
    run grep "ELAPSED=" "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

# ---------------------------------------------------------------------------
# Tier 1: Opencode wrapper -- session enrichment fields
# ---------------------------------------------------------------------------

@test "opencode wrapper logs git_branch field" {
    run grep "git_branch=" "${PLSEC_DIR}/opencode-wrapper.sh"
    assert_success
}

@test "opencode wrapper logs git_sha field" {
    run grep "git_sha=" "${PLSEC_DIR}/opencode-wrapper.sh"
    assert_success
}

@test "opencode wrapper logs preset field" {
    run grep "preset=" "${PLSEC_DIR}/opencode-wrapper.sh"
    assert_success
}

@test "opencode wrapper logs agent_version field" {
    run grep "agent_version=" "${PLSEC_DIR}/opencode-wrapper.sh"
    assert_success
}

@test "opencode wrapper logs duration on session end" {
    run grep "duration=" "${PLSEC_DIR}/opencode-wrapper.sh"
    assert_success
}

# ---------------------------------------------------------------------------
# Tier 1: Preset detection function
# ---------------------------------------------------------------------------

@test "claude wrapper contains _detect_preset function" {
    run grep "_detect_preset" "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

@test "opencode wrapper contains _detect_preset function" {
    run grep "_detect_preset" "${PLSEC_DIR}/opencode-wrapper.sh"
    assert_success
}

@test "preset detection checks plsec.yaml first" {
    run grep "plsec.yaml" "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

@test "preset detection falls back to CLAUDE.md heuristic" {
    run grep "Strict Security" "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

@test "preset detection returns unknown as last resort" {
    run grep '"unknown"' "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

# ---------------------------------------------------------------------------
# Tier 1: Git info uses best-effort (never blocks)
# ---------------------------------------------------------------------------

@test "git branch detection uses 2>/dev/null fallback" {
    run grep 'git rev-parse --abbrev-ref HEAD 2>/dev/null' "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

@test "git sha detection uses 2>/dev/null fallback" {
    run grep 'git rev-parse --short HEAD 2>/dev/null' "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

@test "git branch fallback is n/a" {
    run grep 'echo "n/a"' "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

# ---------------------------------------------------------------------------
# Tier 2: CLAUDE_CODE_SHELL_PREFIX in claude wrapper
# ---------------------------------------------------------------------------

@test "claude wrapper references CLAUDE_CODE_SHELL_PREFIX" {
    run grep "CLAUDE_CODE_SHELL_PREFIX" "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

@test "claude wrapper sets CLAUDE_CODE_SHELL_PREFIX to audit script" {
    run grep 'export CLAUDE_CODE_SHELL_PREFIX=' "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

@test "claude wrapper checks audit script is executable before enabling" {
    run grep '\-x "$AUDIT_SCRIPT"' "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

@test "opencode wrapper does NOT set CLAUDE_CODE_SHELL_PREFIX" {
    run grep "CLAUDE_CODE_SHELL_PREFIX" "${PLSEC_DIR}/opencode-wrapper.sh"
    assert_failure
}

# ---------------------------------------------------------------------------
# Tier 2: Audit script deployment
# ---------------------------------------------------------------------------

@test "audit script is deployed" {
    assert [ -f "${PLSEC_DIR}/plsec-audit.sh" ]
}

@test "audit script is executable" {
    assert [ -x "${PLSEC_DIR}/plsec-audit.sh" ]
}

@test "audit script passes syntax check" {
    run bash -n "${PLSEC_DIR}/plsec-audit.sh"
    assert_success
}

@test "audit script has PLSEC_DIR baked in" {
    run grep "PLSEC_DIR=\"${PLSEC_DIR}\"" "${PLSEC_DIR}/plsec-audit.sh"
    assert_success
}

@test "audit script writes to daily audit log" {
    run grep "claude-audit-" "${PLSEC_DIR}/plsec-audit.sh"
    assert_success
}

@test "audit script uses exec to preserve exit codes" {
    run grep 'exec "$@"' "${PLSEC_DIR}/plsec-audit.sh"
    assert_success
}

@test "audit script logs command with cwd" {
    run grep 'cwd=$(pwd)' "${PLSEC_DIR}/plsec-audit.sh"
    assert_success
}

@test "audit script logs command arguments" {
    run grep 'cmd=$*' "${PLSEC_DIR}/plsec-audit.sh"
    assert_success
}

# ---------------------------------------------------------------------------
# Tier 2: Audit script execution
# ---------------------------------------------------------------------------

@test "audit script executes wrapped command" {
    run "${PLSEC_DIR}/plsec-audit.sh" echo "hello from audit"
    assert_success
    assert_output "hello from audit"
}

@test "audit script preserves exit code on success" {
    run "${PLSEC_DIR}/plsec-audit.sh" true
    assert_success
}

@test "audit script preserves exit code on failure" {
    run "${PLSEC_DIR}/plsec-audit.sh" false
    assert_failure
}

@test "audit script creates audit log file" {
    "${PLSEC_DIR}/plsec-audit.sh" echo "test" 2>/dev/null || true
    local log_pattern="${PLSEC_DIR}/logs/claude-audit-*.log"
    # shellcheck disable=SC2086
    assert [ -f $log_pattern ]
}

@test "audit script log contains command" {
    "${PLSEC_DIR}/plsec-audit.sh" echo "audit-marker-test" 2>/dev/null || true
    local log_pattern="${PLSEC_DIR}/logs/claude-audit-*.log"
    # shellcheck disable=SC2086
    run grep "audit-marker-test" $log_pattern
    assert_success
}

@test "audit script log contains timestamp" {
    "${PLSEC_DIR}/plsec-audit.sh" echo "ts-test" 2>/dev/null || true
    local log_pattern="${PLSEC_DIR}/logs/claude-audit-*.log"
    # shellcheck disable=SC2086
    run grep -E '^\[20[0-9]{2}-[0-9]{2}-[0-9]{2}T' $log_pattern
    assert_success
}

@test "audit script log contains cwd" {
    "${PLSEC_DIR}/plsec-audit.sh" echo "cwd-test" 2>/dev/null || true
    local log_pattern="${PLSEC_DIR}/logs/claude-audit-*.log"
    # shellcheck disable=SC2086
    run grep "cwd=" $log_pattern
    assert_success
}

# ---------------------------------------------------------------------------
# Wrapper syntax validity (updated wrappers)
# ---------------------------------------------------------------------------

@test "updated claude-wrapper.sh passes syntax check" {
    run bash -n "${PLSEC_DIR}/claude-wrapper.sh"
    assert_success
}

@test "updated opencode-wrapper.sh passes syntax check" {
    run bash -n "${PLSEC_DIR}/opencode-wrapper.sh"
    assert_success
}
