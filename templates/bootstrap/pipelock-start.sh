#!/bin/bash
PLSEC_DIR="@@PLSEC_DIR@@"
LOG_FILE="${PLSEC_DIR}/logs/pipelock.log"

echo "Starting Pipelock proxy (audit mode)..."
pipelock run --config "${PLSEC_DIR}/pipelock.yaml" 2>&1 | tee -a "$LOG_FILE"
