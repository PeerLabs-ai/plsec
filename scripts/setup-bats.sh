#!/bin/bash
# setup-bats.sh - Initialize BATS test helper submodules
#
# Run once after cloning the repo or extracting the overlay:
#   scripts/setup-bats.sh
#
# This adds bats-support, bats-assert, and bats-file as git submodules
# under tests/bats/test_helper/.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HELPER_DIR="${PROJECT_ROOT}/tests/bats/test_helper"

cd "${PROJECT_ROOT}"

echo "Setting up BATS test helpers..."

# bats-support (required by bats-assert)
if [[ ! -d "${HELPER_DIR}/bats-support/.git" ]]; then
    echo "Adding bats-support..."
    git submodule add \
        https://github.com/bats-core/bats-support.git \
        tests/bats/test_helper/bats-support
else
    echo "bats-support already present"
fi

# bats-assert
if [[ ! -d "${HELPER_DIR}/bats-assert/.git" ]]; then
    echo "Adding bats-assert..."
    git submodule add \
        https://github.com/bats-core/bats-assert.git \
        tests/bats/test_helper/bats-assert
else
    echo "bats-assert already present"
fi

# bats-file
if [[ ! -d "${HELPER_DIR}/bats-file/.git" ]]; then
    echo "Adding bats-file..."
    git submodule add \
        https://github.com/bats-core/bats-file.git \
        tests/bats/test_helper/bats-file
else
    echo "bats-file already present"
fi

echo ""
echo "BATS helpers installed. Run tests with:"
echo "  bats tests/bats/unit/"
echo "  bats tests/bats/integration/"
echo "  bats tests/bats/"
