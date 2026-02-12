#!/bin/bash
# run-in-container.sh - Run BATS tests in a container
#
# Detects podman (preferred) or docker and runs integration tests
# in a hermetic environment.
#
# Usage:
#   tests/bats/run-in-container.sh                    # run all tests
#   tests/bats/run-in-container.sh tests/bats/unit/   # run unit tests only
#   tests/bats/run-in-container.sh --build-only       # build image only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMAGE_NAME="plsec-test"
CONTAINERFILE="${SCRIPT_DIR}/Containerfile"

# Detect container runtime: prefer podman, fall back to docker
if command -v podman &>/dev/null; then
    RUNTIME=podman
elif command -v docker &>/dev/null; then
    RUNTIME=docker
else
    echo "ERROR: Neither podman nor docker found" >&2
    echo "Install one of:" >&2
    echo "  brew install podman    # macOS" >&2
    echo "  apt install podman     # Debian/Ubuntu" >&2
    echo "  apt install docker.io  # Debian/Ubuntu (fallback)" >&2
    exit 1
fi

echo "Using container runtime: ${RUNTIME}"

# Build
echo "Building test image..."
"${RUNTIME}" build \
    -t "${IMAGE_NAME}" \
    -f "${CONTAINERFILE}" \
    "${PROJECT_ROOT}"

if [[ "${1:-}" == "--build-only" ]]; then
    echo "Image built: ${IMAGE_NAME}"
    exit 0
fi

# Run
echo "Running tests..."
"${RUNTIME}" run --rm "${IMAGE_NAME}" "$@"
