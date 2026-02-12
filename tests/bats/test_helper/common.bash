# common.bash - Shared setup for plsec BATS tests
#
# Provides:
#   BOOTSTRAP   - path to bin/bootstrap.sh
#   setup_fake_home / teardown_fake_home - isolated HOME directory
#   PLSEC_DIR   - points into fake HOME

# Resolve path to bootstrap.sh relative to test file location.
# Works from both unit/ and integration/ subdirectories.
BOOTSTRAP="${BATS_TEST_DIRNAME}/../../bin/bootstrap.sh"

# Verify bootstrap exists at the expected path
if [[ ! -f "${BOOTSTRAP}" ]]; then
    # Try one level up (in case test is run from tests/bats/ directly)
    BOOTSTRAP="${BATS_TEST_DIRNAME}/../bin/bootstrap.sh"
fi

if [[ ! -f "${BOOTSTRAP}" ]]; then
    echo "ERROR: Cannot find bootstrap.sh (looked relative to ${BATS_TEST_DIRNAME})" >&2
    return 1
fi

# Create an isolated HOME directory for testing.
# All bootstrap output lands here instead of the real HOME.
setup_fake_home() {
    export ORIGINAL_HOME="${HOME}"
    export HOME="${BATS_TEST_TMPDIR}/fakehome"
    mkdir -p "${HOME}"
    touch "${HOME}/.zshrc"
    export PLSEC_DIR="${HOME}/.peerlabs/plsec"
}

teardown_fake_home() {
    export HOME="${ORIGINAL_HOME}"
    unset ORIGINAL_HOME PLSEC_DIR
}
