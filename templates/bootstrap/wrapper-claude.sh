#!/bin/bash
# claude-wrapper.sh - Logging wrapper for Claude Code
#
# Tier 1: Session enrichment (git info, duration, preset, agent version)
# Tier 2: CLAUDE_CODE_SHELL_PREFIX audit logging

PLSEC_DIR="@@PLSEC_DIR@@"
LOG_FILE="${PLSEC_DIR}/logs/claude-$(date +%Y%m%d).log"

log() {
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [$$] $*" >> "$LOG_FILE"
}

# ---------------------------------------------------------------------------
# Tier 1: Gather session context (best-effort, never block startup)
# ---------------------------------------------------------------------------

_git_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "n/a")
_git_sha=$(git rev-parse --short HEAD 2>/dev/null || echo "n/a")
_agent_version=$(claude --version 2>/dev/null | head -1 || echo "n/a")

# Detect preset from plsec.yaml or CLAUDE.md heuristic
_detect_preset() {
    local yaml="${PLSEC_DIR}/configs/plsec.yaml"
    if [[ -f "$yaml" ]]; then
        local val
        val=$(awk '/^preset:/ { print $2 }' "$yaml" 2>/dev/null)
        if [[ -n "$val" ]]; then echo "$val"; return; fi
    fi
    local claude_md="${PLSEC_DIR}/configs/CLAUDE.md"
    if [[ -f "$claude_md" ]]; then
        if grep -q "Strict Security" "$claude_md" 2>/dev/null; then
            echo "strict"
        else
            echo "balanced"
        fi
        return
    fi
    echo "unknown"
}
_preset=$(_detect_preset)

START_SECONDS=$SECONDS

log "=== Session started: $(pwd) ==="
log "git_branch=${_git_branch} git_sha=${_git_sha} preset=${_preset} agent_version=${_agent_version}"
log "Args: $*"

# Copy CLAUDE.md to project if not present
if [[ ! -f "./CLAUDE.md" ]] && [[ -f "${PLSEC_DIR}/configs/CLAUDE.md" ]]; then
    cp "${PLSEC_DIR}/configs/CLAUDE.md" ./CLAUDE.md
    log "Copied CLAUDE.md to project"
fi

# ---------------------------------------------------------------------------
# Tier 2: CLAUDE_CODE_SHELL_PREFIX audit logging
# ---------------------------------------------------------------------------

AUDIT_SCRIPT="${PLSEC_DIR}/plsec-audit.sh"
if [[ -x "$AUDIT_SCRIPT" ]]; then
    export CLAUDE_CODE_SHELL_PREFIX="$AUDIT_SCRIPT"
    log "Audit logging enabled via CLAUDE_CODE_SHELL_PREFIX"
fi

# Run Claude Code
claude "$@"
EXIT_CODE=$?

ELAPSED=$(( SECONDS - START_SECONDS ))
log "=== Session ended: exit code ${EXIT_CODE} duration=${ELAPSED}s ==="
exit $EXIT_CODE
