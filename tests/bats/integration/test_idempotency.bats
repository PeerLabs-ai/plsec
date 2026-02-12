#!/usr/bin/env bats
# test_idempotency.bats - Verify bootstrap is safe to run multiple times
#
# Running bootstrap twice should produce identical results: no duplicate
# aliases, no file corruption, stable checksums.

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
# Alias deduplication
# ---------------------------------------------------------------------------

@test "second run does not duplicate aliases in shell rc" {
    "${BOOTSTRAP}" --agent claude
    "${BOOTSTRAP}" --agent claude
    local count
    count=$(grep -c "Peerlabs Security aliases" "${HOME}/.zshrc")
    assert_equal "$count" "1"
}

@test "switching agent type does not duplicate alias block" {
    "${BOOTSTRAP}" --agent claude
    "${BOOTSTRAP}" --agent both
    local count
    count=$(grep -c "Peerlabs Security aliases" "${HOME}/.zshrc")
    assert_equal "$count" "1"
}

# ---------------------------------------------------------------------------
# Config file stability
# ---------------------------------------------------------------------------

@test "second run produces identical CLAUDE.md" {
    "${BOOTSTRAP}" --agent claude --strict
    local first
    first=$(shasum -a 256 "${PLSEC_DIR}/configs/CLAUDE.md" | cut -d' ' -f1)

    "${BOOTSTRAP}" --agent claude --strict
    local second
    second=$(shasum -a 256 "${PLSEC_DIR}/configs/CLAUDE.md" | cut -d' ' -f1)

    assert_equal "$first" "$second"
}

@test "second run produces identical opencode.json" {
    "${BOOTSTRAP}" --agent opencode --strict
    local first
    first=$(shasum -a 256 "${PLSEC_DIR}/configs/opencode.json" | cut -d' ' -f1)

    "${BOOTSTRAP}" --agent opencode --strict
    local second
    second=$(shasum -a 256 "${PLSEC_DIR}/configs/opencode.json" | cut -d' ' -f1)

    assert_equal "$first" "$second"
}

@test "second run produces identical wrapper scripts" {
    "${BOOTSTRAP}" --agent both
    local first_claude first_opencode first_scan
    first_claude=$(shasum -a 256 "${PLSEC_DIR}/claude-wrapper.sh" | cut -d' ' -f1)
    first_opencode=$(shasum -a 256 "${PLSEC_DIR}/opencode-wrapper.sh" | cut -d' ' -f1)
    first_scan=$(shasum -a 256 "${PLSEC_DIR}/scan.sh" | cut -d' ' -f1)

    "${BOOTSTRAP}" --agent both
    local second_claude second_opencode second_scan
    second_claude=$(shasum -a 256 "${PLSEC_DIR}/claude-wrapper.sh" | cut -d' ' -f1)
    second_opencode=$(shasum -a 256 "${PLSEC_DIR}/opencode-wrapper.sh" | cut -d' ' -f1)
    second_scan=$(shasum -a 256 "${PLSEC_DIR}/scan.sh" | cut -d' ' -f1)

    assert_equal "$first_claude" "$second_claude"
    assert_equal "$first_opencode" "$second_opencode"
    assert_equal "$first_scan" "$second_scan"
}

# ---------------------------------------------------------------------------
# Directory structure stability
# ---------------------------------------------------------------------------

@test "second run does not create extra directories" {
    "${BOOTSTRAP}" --agent both --strict
    local first
    first=$(find "${PLSEC_DIR}" -type d | sort | shasum -a 256)

    "${BOOTSTRAP}" --agent both --strict
    local second
    second=$(find "${PLSEC_DIR}" -type d | sort | shasum -a 256)

    assert_equal "$first" "$second"
}
