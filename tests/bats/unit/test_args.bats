#!/usr/bin/env bats
# test_args.bats - Unit tests for bootstrap.sh argument parsing
#
# Tests CLI flag handling: --help, --strict, --dry-run, --simulate,
# --agent, --with-pipelock, and error cases.

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
# --help
# ---------------------------------------------------------------------------

@test "--help exits 0" {
    run "${BOOTSTRAP}" --help
    assert_success
}

@test "--help shows usage information" {
    run "${BOOTSTRAP}" --help
    assert_output --partial "Usage:"
    assert_output --partial "--dry-run"
    assert_output --partial "--strict"
    assert_output --partial "--agent"
    assert_output --partial "--with-pipelock"
}

# ---------------------------------------------------------------------------
# --agent validation
# ---------------------------------------------------------------------------

@test "--agent claude is accepted" {
    run "${BOOTSTRAP}" --dry-run --agent claude
    assert_success
    assert_output --partial "Agent type: claude"
}

@test "--agent opencode is accepted" {
    run "${BOOTSTRAP}" --dry-run --agent opencode
    assert_success
    assert_output --partial "Agent type: opencode"
}

@test "--agent both is accepted" {
    run "${BOOTSTRAP}" --dry-run --agent both
    assert_success
    assert_output --partial "Agent type: both"
}

@test "--agent invalid exits with error" {
    run "${BOOTSTRAP}" --agent invalid
    assert_failure
    assert_output --partial "Invalid agent type"
}

@test "--agent with missing value exits with error" {
    run "${BOOTSTRAP}" --agent
    assert_failure
}

# ---------------------------------------------------------------------------
# --dry-run / --simulate
# ---------------------------------------------------------------------------

@test "--dry-run shows DRY RUN MODE banner" {
    run "${BOOTSTRAP}" --dry-run --agent claude
    assert_success
    assert_output --partial "DRY RUN MODE"
}

@test "--simulate behaves identically to --dry-run" {
    local dry_run_output simulate_output
    dry_run_output=$("${BOOTSTRAP}" --dry-run --agent claude 2>&1)
    simulate_output=$("${BOOTSTRAP}" --simulate --agent claude 2>&1)
    assert_equal "$dry_run_output" "$simulate_output"
}

# ---------------------------------------------------------------------------
# --strict
# ---------------------------------------------------------------------------

@test "--strict sets strict mode" {
    run "${BOOTSTRAP}" --dry-run --strict --agent claude
    assert_success
    assert_output --partial "strict"
}

# ---------------------------------------------------------------------------
# Unknown flags
# ---------------------------------------------------------------------------

@test "unknown flag exits with error" {
    run "${BOOTSTRAP}" --nonexistent
    assert_failure
    assert_output --partial "Unknown option"
}

# ---------------------------------------------------------------------------
# Default behavior
# ---------------------------------------------------------------------------

@test "default agent type is both" {
    run "${BOOTSTRAP}" --dry-run
    assert_success
    assert_output --partial "Agent type: both"
}
