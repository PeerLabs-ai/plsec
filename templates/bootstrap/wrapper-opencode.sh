#!/bin/bash
# opencode-wrapper.sh - Logging wrapper for Opencode

PLSEC_DIR="@@PLSEC_DIR@@"
LOG_FILE="${PLSEC_DIR}/logs/opencode-$(date +%Y%m%d).log"

log() {
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [$$] $*" >> "$LOG_FILE"
}

log "=== Session started: $(pwd) ==="
log "Args: $*"

# Copy opencode.json to project if not present
if [[ ! -f "./opencode.json" ]] && [[ -f "${PLSEC_DIR}/configs/opencode.json" ]]; then
    cp "${PLSEC_DIR}/configs/opencode.json" ./opencode.json
    log "Copied opencode.json to project"
fi

# Check for CLAUDE.md as well (Opencode respects it for system prompts)
if [[ ! -f "./CLAUDE.md" ]] && [[ -f "${PLSEC_DIR}/configs/CLAUDE.md" ]]; then
    cp "${PLSEC_DIR}/configs/CLAUDE.md" ./CLAUDE.md
    log "Copied CLAUDE.md to project (Opencode reads this too)"
fi

# Run Opencode
opencode "$@"
EXIT_CODE=$?

log "=== Session ended: exit code $EXIT_CODE ==="
exit $EXIT_CODE
