# common.bash - Shared setup for plsec BATS tests
#
# Provides:
#   BOOTSTRAP   - path to bin/bootstrap.sh
#   setup_fake_home / teardown_fake_home - isolated HOME directory
#   PLSEC_DIR   - points into fake HOME

# Resolve path to bootstrap.sh relative to this helper file.
# Uses BASH_SOURCE[0] so the path is stable regardless of which
# test file loads us (safe here — BATS always runs under bash).
# Primary: build/bootstrap.sh (assembled output)
# Fallback: bin/bootstrap.default.sh (promoted reference)
_HELPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_PROJECT_ROOT="${_HELPER_DIR}/../../.."

BOOTSTRAP="${_PROJECT_ROOT}/build/bootstrap.sh"

if [[ ! -f "${BOOTSTRAP}" ]]; then
    BOOTSTRAP="${_PROJECT_ROOT}/bin/bootstrap.default.sh"
fi

if [[ ! -f "${BOOTSTRAP}" ]]; then
    echo "ERROR: Cannot find bootstrap.sh (looked in build/ and bin/ relative to ${_PROJECT_ROOT})" >&2
    return 1
fi

# Python interpreter: prefer uv run, fall back to system python3.
if command -v uv &> /dev/null; then
    PYTHON="uv run python"
else
    PYTHON="${PYTHON:-python3}"
fi

unset _HELPER_DIR _PROJECT_ROOT

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
