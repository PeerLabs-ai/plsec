#!/usr/bin/env bats
# test_helpers.bats - Unit tests for bootstrap.sh helper functions
#
# Tests log functions and dry-run helper functions in isolation.
# Requires the main() guard in bootstrap.sh so sourcing doesn't
# trigger execution.

setup() {
    load '../test_helper/bats-support/load'
    load '../test_helper/bats-assert/load'
    load '../test_helper/common'

    setup_fake_home

    # Source bootstrap for function definitions only
    source "${BOOTSTRAP}"
}

teardown() {
    teardown_fake_home
}

# ---------------------------------------------------------------------------
# Log functions
# ---------------------------------------------------------------------------

@test "log_ok writes [OK] label" {
    run log_ok "test message"
    assert_output --partial "[OK]"
    assert_output --partial "test message"
}

@test "log_warn writes [WARN] label" {
    run log_warn "something concerning"
    assert_output --partial "[WARN]"
    assert_output --partial "something concerning"
}

@test "log_info writes [INFO] label" {
    run log_info "informational"
    assert_output --partial "[INFO]"
    assert_output --partial "informational"
}

@test "log_error writes [ERROR] label" {
    run log_error "failure occurred"
    assert_output --partial "[ERROR]"
    assert_output --partial "failure occurred"
}

# ---------------------------------------------------------------------------
# write_file
# ---------------------------------------------------------------------------

@test "write_file creates file in normal mode" {
    DRY_RUN=false
    echo "hello" | write_file "${BATS_TEST_TMPDIR}/test.txt"
    assert [ -f "${BATS_TEST_TMPDIR}/test.txt" ]
    run cat "${BATS_TEST_TMPDIR}/test.txt"
    assert_output "hello"
}

@test "write_file skips in dry-run mode" {
    DRY_RUN=true
    echo "hello" | write_file "${BATS_TEST_TMPDIR}/should_not_exist.txt"
    assert [ ! -f "${BATS_TEST_TMPDIR}/should_not_exist.txt" ]
}

@test "write_file dry-run reports intent" {
    DRY_RUN=true
    run bash -c "echo 'hello' | DRY_RUN=true source '${BOOTSTRAP}' 2>/dev/null; echo 'x' | write_file '/tmp/test' 2>&1"
    assert_output --partial "Would write"
}

# ---------------------------------------------------------------------------
# write_file_from_var
# ---------------------------------------------------------------------------

@test "write_file_from_var creates file with correct content" {
    DRY_RUN=false
    write_file_from_var "${BATS_TEST_TMPDIR}/test.txt" "file content here"
    assert [ -f "${BATS_TEST_TMPDIR}/test.txt" ]
    run cat "${BATS_TEST_TMPDIR}/test.txt"
    assert_output "file content here"
}

@test "write_file_from_var skips in dry-run mode" {
    DRY_RUN=true
    write_file_from_var "${BATS_TEST_TMPDIR}/should_not_exist.txt" "content"
    assert [ ! -f "${BATS_TEST_TMPDIR}/should_not_exist.txt" ]
}

# ---------------------------------------------------------------------------
# ensure_dir
# ---------------------------------------------------------------------------

@test "ensure_dir creates directory in normal mode" {
    DRY_RUN=false
    ensure_dir "${BATS_TEST_TMPDIR}/new/nested/dir"
    assert [ -d "${BATS_TEST_TMPDIR}/new/nested/dir" ]
}

@test "ensure_dir skips in dry-run mode" {
    DRY_RUN=true
    ensure_dir "${BATS_TEST_TMPDIR}/should_not_exist"
    assert [ ! -d "${BATS_TEST_TMPDIR}/should_not_exist" ]
}

# ---------------------------------------------------------------------------
# make_executable
# ---------------------------------------------------------------------------

@test "make_executable sets +x in normal mode" {
    DRY_RUN=false
    touch "${BATS_TEST_TMPDIR}/script.sh"
    make_executable "${BATS_TEST_TMPDIR}/script.sh"
    assert [ -x "${BATS_TEST_TMPDIR}/script.sh" ]
}

@test "make_executable skips in dry-run mode" {
    DRY_RUN=true
    touch "${BATS_TEST_TMPDIR}/script.sh"
    chmod -x "${BATS_TEST_TMPDIR}/script.sh"
    make_executable "${BATS_TEST_TMPDIR}/script.sh"
    assert [ ! -x "${BATS_TEST_TMPDIR}/script.sh" ]
}

# ---------------------------------------------------------------------------
# copy_file
# ---------------------------------------------------------------------------

@test "copy_file copies in normal mode" {
    DRY_RUN=false
    echo "source content" > "${BATS_TEST_TMPDIR}/src.txt"
    copy_file "${BATS_TEST_TMPDIR}/src.txt" "${BATS_TEST_TMPDIR}/dst.txt"
    assert [ -f "${BATS_TEST_TMPDIR}/dst.txt" ]
    run cat "${BATS_TEST_TMPDIR}/dst.txt"
    assert_output "source content"
}

@test "copy_file skips in dry-run mode" {
    DRY_RUN=true
    echo "source content" > "${BATS_TEST_TMPDIR}/src.txt"
    copy_file "${BATS_TEST_TMPDIR}/src.txt" "${BATS_TEST_TMPDIR}/dst.txt"
    assert [ ! -f "${BATS_TEST_TMPDIR}/dst.txt" ]
}

# ---------------------------------------------------------------------------
# append_to_file
# ---------------------------------------------------------------------------

@test "append_to_file appends in normal mode" {
    DRY_RUN=false
    echo "line1" > "${BATS_TEST_TMPDIR}/append.txt"
    append_to_file "${BATS_TEST_TMPDIR}/append.txt" "line2"
    run cat "${BATS_TEST_TMPDIR}/append.txt"
    assert_line --index 0 "line1"
    assert_line --index 1 "line2"
}

@test "append_to_file skips in dry-run mode" {
    DRY_RUN=true
    echo "line1" > "${BATS_TEST_TMPDIR}/append.txt"
    append_to_file "${BATS_TEST_TMPDIR}/append.txt" "line2"
    run cat "${BATS_TEST_TMPDIR}/append.txt"
    assert_output "line1"
}

# ---------------------------------------------------------------------------
# check_command
# ---------------------------------------------------------------------------

@test "check_command succeeds for available command" {
    run check_command bash
    assert_success
    assert_output --partial "[OK]"
}

@test "check_command fails for missing command" {
    run check_command nonexistent_command_xyz
    assert_failure
    assert_output --partial "[WARN]"
}
