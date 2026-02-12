#!/usr/bin/env bats
# test_dry_run.bats - Verify --dry-run makes no filesystem changes
#
# The dry-run flag should show the full execution plan without creating
# any files or directories.

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
# Zero filesystem changes
# ---------------------------------------------------------------------------

@test "dry-run produces zero filesystem changes" {
    local before after
    before=$(find "${HOME}" -type f 2>/dev/null | sort | shasum -a 256)

    run "${BOOTSTRAP}" --dry-run --agent both --strict
    assert_success

    after=$(find "${HOME}" -type f 2>/dev/null | sort | shasum -a 256)
    assert_equal "$before" "$after"
}

@test "dry-run creates no directories under PLSEC_DIR" {
    run "${BOOTSTRAP}" --dry-run --agent both
    assert_success
    assert [ ! -d "${PLSEC_DIR}" ]
}

@test "dry-run does not modify shell rc" {
    local before
    before=$(shasum -a 256 "${HOME}/.zshrc" | cut -d' ' -f1)

    "${BOOTSTRAP}" --dry-run --agent both

    local after
    after=$(shasum -a 256 "${HOME}/.zshrc" | cut -d' ' -f1)
    assert_equal "$before" "$after"
}

# ---------------------------------------------------------------------------
# Output markers
# ---------------------------------------------------------------------------

@test "dry-run output contains DRY RUN MODE banner" {
    run "${BOOTSTRAP}" --dry-run --agent both
    assert_output --partial "DRY RUN MODE"
}

@test "dry-run output contains [DRY RUN] markers" {
    run "${BOOTSTRAP}" --dry-run --agent both
    assert_output --partial "[DRY RUN]"
}

@test "dry-run reports directory creation intent" {
    run "${BOOTSTRAP}" --dry-run --agent both
    assert_output --partial "Would create directory"
}

@test "dry-run reports file write intent" {
    run "${BOOTSTRAP}" --dry-run --agent both
    assert_output --partial "Would write"
}

# ---------------------------------------------------------------------------
# Alias: --simulate
# ---------------------------------------------------------------------------

@test "--simulate behaves identically to --dry-run" {
    local dry_run_output simulate_output
    dry_run_output=$("${BOOTSTRAP}" --dry-run --agent claude 2>&1)
    simulate_output=$("${BOOTSTRAP}" --simulate --agent claude 2>&1)
    assert_equal "$dry_run_output" "$simulate_output"
}

# ---------------------------------------------------------------------------
# Dry-run after a real run should still be clean
# ---------------------------------------------------------------------------

@test "dry-run after real run shows no additional changes" {
    # First: real run
    "${BOOTSTRAP}" --agent claude

    # Capture state
    local before
    before=$(find "${HOME}" -type f 2>/dev/null | sort | shasum -a 256)

    # Second: dry-run
    run "${BOOTSTRAP}" --dry-run --agent claude
    assert_success

    # No changes
    local after
    after=$(find "${HOME}" -type f 2>/dev/null | sort | shasum -a 256)
    assert_equal "$before" "$after"
}
