#!/bin/bash
# claude-wrapper.sh - Logging wrapper for Claude Code

PLSEC_DIR="@@PLSEC_DIR@@"
LOG_FILE="${PLSEC_DIR}/logs/claude-$(date +%Y%m%d).log"

log() {
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [$$] $*" >> "$LOG_FILE"
}

log "=== Session started: $(pwd) ==="
log "Args: $*"

# Copy CLAUDE.md to project if not present
if [[ ! -f "./CLAUDE.md" ]] && [[ -f "${PLSEC_DIR}/configs/CLAUDE.md" ]]; then
    cp "${PLSEC_DIR}/configs/CLAUDE.md" ./CLAUDE.md
    log "Copied CLAUDE.md to project"
fi

# Run Claude Code
claude "$@"
EXIT_CODE=$?

log "=== Session ended: exit code $EXIT_CODE ==="
exit $EXIT_CODE
