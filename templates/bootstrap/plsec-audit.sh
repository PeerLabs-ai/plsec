#!/bin/bash
# plsec-audit.sh - Audit logging for CLAUDE_CODE_SHELL_PREFIX
#
# Claude Code sets CLAUDE_CODE_SHELL_PREFIX to this script. When Claude
# executes a shell command, it becomes:
#   /path/to/plsec-audit.sh <original-command...>
#
# This script logs the command to a daily audit log, then executes it.
# The audit log is separate from the session log to avoid mixing concerns.
#
# Design constraints:
#   - Must be fast (runs on EVERY shell command Claude executes)
#   - Must preserve exit codes exactly
#   - Must not interfere with stdin/stdout/stderr of the wrapped command
#   - Logging failures must never prevent command execution

PLSEC_DIR="@@PLSEC_DIR@@"
AUDIT_LOG="${PLSEC_DIR}/logs/claude-audit-$(date +%Y%m%d).log"

# Log to audit file (append, fire-and-forget)
{
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [$$] cwd=$(pwd) cmd=$*"
} >> "$AUDIT_LOG" 2>/dev/null

# Execute the original command, preserving exit code
exec "$@"
