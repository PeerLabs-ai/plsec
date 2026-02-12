#!/usr/bin/env bats
# test_detect_os.bats - Unit tests for bootstrap.sh detect_os function
#
# Platform-dependent tests. Some tests will be skipped based on the
# host OS since detect_os checks actual system state.

setup() {
    load '../test_helper/bats-support/load'
    load '../test_helper/bats-assert/load'
    load '../test_helper/common'

    source "${BOOTSTRAP}"
}

# ---------------------------------------------------------------------------
# Platform-specific tests
# ---------------------------------------------------------------------------

@test "detect_os returns 'macos' on macOS" {
    if [[ "$OSTYPE" != "darwin"* ]]; then
        skip "Not running on macOS"
    fi
    run detect_os
    assert_success
    assert_output "macos"
}

@test "detect_os returns 'linux' on Debian-based Linux" {
    if [[ ! -f /etc/debian_version ]]; then
        skip "Not running on Debian-based Linux"
    fi
    run detect_os
    assert_success
    assert_output "linux"
}

# ---------------------------------------------------------------------------
# Function existence
# ---------------------------------------------------------------------------

@test "detect_os function is defined" {
    run type detect_os
    assert_success
    assert_output --partial "function"
}
