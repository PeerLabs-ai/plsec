#!/usr/bin/env bats
# test_status.bats - Integration tests for plsec-status full execution
#
# Tests the complete plsec-status command in realistic scenarios:
# healthy system, partial failures, fresh install, JSON output, and
# error handling. Runs against a sandboxed HOME.
#
# Key: plsec-status checks the project CWD by default. To avoid failures
# from the real CWD (missing hooks, different configs), we use --project
# pointed at a sandboxed project directory.

setup() {
    load '../test_helper/bats-support/load'
    load '../test_helper/bats-assert/load'
    load '../test_helper/common'

    setup_fake_home

    # Create a sandboxed project with a git repo and plsec hook
    PROJECT="${BATS_TEST_TMPDIR}/project"
    mkdir -p "${PROJECT}/.git/hooks"
}

teardown() {
    teardown_fake_home
}

# Helper: set up a fully healthy environment for tests that need exit 0.
# Deploys bootstrap, populates logs, installs pre-commit hook, copies
# project configs -- everything plsec-status checks.
setup_healthy() {
    "${BOOTSTRAP}" --agent both

    # Install pre-commit hook that references plsec
    cp "${PLSEC_DIR}/configs/pre-commit" "${PROJECT}/.git/hooks/pre-commit"
    chmod +x "${PROJECT}/.git/hooks/pre-commit"

    # Copy agent configs to project
    cp "${PLSEC_DIR}/configs/CLAUDE.md" "${PROJECT}/CLAUDE.md"
    cp "${PLSEC_DIR}/configs/opencode.json" "${PROJECT}/opencode.json"

    # Populate activity logs
    local today
    today=$(date +%Y%m%d)
    printf '[%s] [100] === Session started: /tmp/project ===\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${PLSEC_DIR}/logs/claude-${today}.log"
    printf '[%s] [100] === Session ended: exit code 0 ===\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${PLSEC_DIR}/logs/claude-${today}.log"

    # Populate scan logs
    printf '{"overall_passed": true}\n' > "${PLSEC_DIR}/logs/scan-latest.json"
    printf '{"scanner_id":"trivy-secrets","verdict":"pass"}\n' \
        > "${PLSEC_DIR}/logs/scan-${today}.jsonl"
}

# ===========================================================================
# Healthy system
# ===========================================================================

@test "plsec-status exits 0 on fully healthy system" {
    setup_healthy
    run "${PLSEC_DIR}/plsec-status.sh" --project "$PROJECT"
    assert_success
}

@test "plsec-status shows overall verdict" {
    setup_healthy
    run "${PLSEC_DIR}/plsec-status.sh" --project "$PROJECT"
    assert_output --partial "Overall"
}

@test "plsec-status displays Installation section" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --project "$PROJECT"
    assert_output --partial "Installation"
}

@test "plsec-status displays Configuration section" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --project "$PROJECT"
    assert_output --partial "Configuration"
}

@test "plsec-status displays Activity section" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --project "$PROJECT"
    assert_output --partial "Activity"
}

# ===========================================================================
# Partial failures
# ===========================================================================

@test "plsec-status exits 1 when checks fail" {
    "${BOOTSTRAP}" --agent claude
    # Fresh install, no hook, no sessions -- multiple failures expected
    run "${PLSEC_DIR}/plsec-status.sh" --project "$PROJECT"
    assert_failure
}

# ===========================================================================
# Fresh install scenario
# ===========================================================================

@test "plsec-status shows activity failures after fresh install" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --project "$PROJECT"
    # No sessions, no scans -- activity checks report FAIL
    assert_output --partial "FAIL"
}

@test "plsec-status findings checks SKIP when no scan data" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --project "$PROJECT"
    assert_output --partial "SKIP"
}

# ===========================================================================
# JSON output
# ===========================================================================

@test "plsec-status --json produces valid JSON" {
    setup_healthy
    "${PLSEC_DIR}/plsec-status.sh" --json --project "$PROJECT" > "${BATS_TEST_TMPDIR}/status.json"
    run $PYTHON -m json.tool "${BATS_TEST_TMPDIR}/status.json"
    assert_success
}

@test "plsec-status --json includes version field" {
    setup_healthy
    run "${PLSEC_DIR}/plsec-status.sh" --json --project "$PROJECT"
    assert_output --partial '"version"'
}

@test "plsec-status --json includes mode field" {
    setup_healthy
    run "${PLSEC_DIR}/plsec-status.sh" --json --project "$PROJECT"
    assert_output --partial '"mode"'
}

@test "plsec-status --json includes agents array" {
    setup_healthy
    run "${PLSEC_DIR}/plsec-status.sh" --json --project "$PROJECT"
    assert_output --partial '"agents"'
}

@test "plsec-status --json includes checks array" {
    setup_healthy
    run "${PLSEC_DIR}/plsec-status.sh" --json --project "$PROJECT"
    assert_output --partial '"checks"'
}

@test "plsec-status --json includes overall verdict" {
    setup_healthy
    run "${PLSEC_DIR}/plsec-status.sh" --json --project "$PROJECT"
    assert_output --partial '"overall"'
}

# ===========================================================================
# Quiet mode
# ===========================================================================

@test "plsec-status --quiet produces no output on success" {
    setup_healthy
    run "${PLSEC_DIR}/plsec-status.sh" --quiet --project "$PROJECT"
    assert_success
    assert_output ""
}

@test "plsec-status --quiet exits 1 with no output on failure" {
    "${BOOTSTRAP}" --agent claude
    # Fresh install has failures (no hook, no activity)
    run "${PLSEC_DIR}/plsec-status.sh" --quiet --project "$PROJECT"
    assert_failure
    assert_output ""
}

# ===========================================================================
# Error handling
# ===========================================================================

@test "plsec-status exits 1 when PLSEC_DIR does not exist" {
    # Deploy first so the script exists, then break PLSEC_DIR
    "${BOOTSTRAP}" --agent claude
    # The PLSEC_DIR is baked into the script, so we simulate by removing the dir
    local status_script="${PLSEC_DIR}/plsec-status.sh"
    # Copy script out, then wipe the plsec dir
    cp "$status_script" "${BATS_TEST_TMPDIR}/plsec-status-copy.sh"
    chmod +x "${BATS_TEST_TMPDIR}/plsec-status-copy.sh"
    # The copied script still points to the original PLSEC_DIR which we now remove
    rm -r "${PLSEC_DIR}"
    run "${BATS_TEST_TMPDIR}/plsec-status-copy.sh" --project "$PROJECT"
    assert_failure
}

@test "plsec-status handles missing .git directory gracefully" {
    setup_healthy
    # Point to a project without .git
    local nogit="${BATS_TEST_TMPDIR}/nogit"
    mkdir -p "$nogit"
    cp "${PLSEC_DIR}/configs/CLAUDE.md" "${nogit}/CLAUDE.md"
    cp "${PLSEC_DIR}/configs/opencode.json" "${nogit}/opencode.json"
    run "${PLSEC_DIR}/plsec-status.sh" --project "$nogit"
    # Should mention pre-commit hook failure but not crash
    assert_output --partial "pre-commit hook"
}

@test "plsec-status --project flag sets project path" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --project "$PROJECT"
    assert_output --partial "$PROJECT"
}

# ===========================================================================
# Agent-specific output
# ===========================================================================

@test "plsec-status shows claude artifacts when claude configured" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --project "$PROJECT"
    assert_output --partial "CLAUDE.md"
}

@test "plsec-status shows opencode artifacts when opencode configured" {
    "${BOOTSTRAP}" --agent opencode
    run "${PLSEC_DIR}/plsec-status.sh" --project "$PROJECT"
    assert_output --partial "opencode.json"
}

@test "plsec-status shows both agents when both configured" {
    "${BOOTSTRAP}" --agent both
    run "${PLSEC_DIR}/plsec-status.sh" --project "$PROJECT"
    assert_output --partial "CLAUDE.md"
    assert_output --partial "opencode.json"
}

# ===========================================================================
# Mode detection in output
# ===========================================================================

@test "plsec-status shows strict mode when configured strict" {
    "${BOOTSTRAP}" --agent claude --strict
    run "${PLSEC_DIR}/plsec-status.sh" --project "$PROJECT"
    assert_output --partial "strict"
}

@test "plsec-status shows balanced mode when configured balanced" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --project "$PROJECT"
    assert_output --partial "balanced"
}

# ===========================================================================
# Watch mode: argument validation
# ===========================================================================

@test "plsec-status --watch rejects --json" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --watch --json
    assert_failure
    assert_output --partial "incompatible"
}

@test "plsec-status --watch rejects --quiet" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --watch --quiet
    assert_failure
    assert_output --partial "incompatible"
}

@test "plsec-status --interval requires numeric argument" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --interval abc
    assert_failure
    assert_output --partial "positive integer"
}

@test "plsec-status --interval rejects zero" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --interval 0
    assert_failure
    assert_output --partial "positive integer"
}

@test "plsec-status --tail-lines requires numeric argument" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --tail-lines abc
    assert_failure
    assert_output --partial "positive integer"
}

@test "plsec-status --tail-lines rejects zero" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --tail-lines 0
    assert_failure
    assert_output --partial "positive integer"
}

@test "plsec-status --help mentions watch mode" {
    "${BOOTSTRAP}" --agent claude
    run "${PLSEC_DIR}/plsec-status.sh" --help
    assert_success
    assert_output --partial "--watch"
    assert_output --partial "--interval"
    assert_output --partial "--tail-lines"
}

# ===========================================================================
# Watch mode: smoke tests
#
# Watch mode calls `clear` between iterations, which erases captured
# output in non-TTY environments.  We stub `clear` to a no-op so
# BATS can inspect accumulated output across refreshes.
# See docs/plsec-status-design.md "Open Design Questions" for the
# longer-term plan (--batch-mode, data/display separation).
# ===========================================================================

# Helper: find timeout command (GNU coreutils on macOS installs as gtimeout).
timeout_cmd() {
    if command -v timeout >/dev/null 2>&1; then
        echo timeout
    elif command -v gtimeout >/dev/null 2>&1; then
        echo gtimeout
    else
        echo ""
    fi
}

# Helper: set up watch mode environment with clear stubbed out.
# Places a no-op `clear` script on PATH ahead of the real one.
setup_watch() {
    setup_healthy

    STUB_BIN="$(mktemp -d)"
    printf '#!/bin/sh\ntrue\n' > "$STUB_BIN/clear"
    chmod +x "$STUB_BIN/clear"
    export PATH="$STUB_BIN:$PATH"
}

@test "plsec-status --watch runs and can be killed by timeout" {
    setup_watch
    local t
    t="$(timeout_cmd)"
    [[ -n "$t" ]] || skip "timeout/gtimeout not available"
    # timeout sends SIGTERM which triggers our trap -> exit 0
    run "$t" 3 "${PLSEC_DIR}/plsec-status.sh" \
        --watch --interval 1 --project "$PROJECT"
    # Exit code 0 (trap caught SIGTERM) or 124 (timeout killed it)
    [[ "$status" -eq 0 ]] || [[ "$status" -eq 124 ]]
}

@test "plsec-status --watch shows log tail content" {
    setup_watch
    local t
    t="$(timeout_cmd)"
    [[ -n "$t" ]] || skip "timeout/gtimeout not available"
    local today
    today=$(date +%Y%m%d)
    echo "WATCH_LOG_MARKER" >> "${PLSEC_DIR}/logs/claude-${today}.log"

    run "$t" 3 "${PLSEC_DIR}/plsec-status.sh" \
        --watch --interval 1 --project "$PROJECT"
    assert_output --partial "WATCH_LOG_MARKER"
}

@test "plsec-status --watch shows key hints" {
    setup_watch
    local t
    t="$(timeout_cmd)"
    [[ -n "$t" ]] || skip "timeout/gtimeout not available"
    run "$t" 3 "${PLSEC_DIR}/plsec-status.sh" \
        --watch --interval 1 --project "$PROJECT"
    assert_output --partial "[q]uit"
    assert_output --partial "[r]efresh"
    assert_output --partial "[p]ause"
}

@test "plsec-status --watch respects --tail-lines count" {
    setup_watch
    local t
    t="$(timeout_cmd)"
    [[ -n "$t" ]] || skip "timeout/gtimeout not available"
    local today
    today=$(date +%Y%m%d)
    local log="${PLSEC_DIR}/logs/claude-${today}.log"
    # Write 10 distinct lines
    for i in $(seq 1 10); do
        echo "TAIL_LINE_${i}" >> "$log"
    done

    # Request only 3 lines
    run "$t" 3 "${PLSEC_DIR}/plsec-status.sh" \
        --watch --tail-lines 3 --interval 1 --project "$PROJECT"
    # Should see the last 3 lines
    assert_output --partial "TAIL_LINE_8"
    assert_output --partial "TAIL_LINE_9"
    assert_output --partial "TAIL_LINE_10"
    # Should NOT see early lines (use TAIL_LINE_2 to avoid prefix match on TAIL_LINE_10)
    refute_output --partial "TAIL_LINE_2"
}

# ---------------------------------------------------------------------------
# stdin pipe (curl | bash simulation)
# ---------------------------------------------------------------------------

@test "plsec-status.sh works when piped via stdin" {
    # BASH_SOURCE[0] is unset when reading from stdin; set -u must not abort.
    # Use the source template (not deployed copy, which requires plsec install).
    local script_dir
    script_dir="$(cd "${BATS_TEST_DIRNAME}/../../.." > /dev/null && pwd)"
    run bash < "${script_dir}/src/plsec/configs/_template_files/plsec-status.sh"
    refute_output --partial "unbound variable"
}
