#!/bin/bash
# plsec-audit.sh - Audit logging for CLAUDE_CODE_SHELL_PREFIX
#
# Claude Code sets CLAUDE_CODE_SHELL_PREFIX to this script.
#
# Current observed calling convention:
#   /path/to/plsec-audit.sh "<complete shell command>"
#
# In other words, Claude currently passes the full command as a single
# shell-source blob in $1. This script intentionally treats any other
# calling shape as an error, so changes in Claude's behaviour fail clearly
# instead of silently changing execution semantics.
#
# This script logs the command to a daily audit log, then executes it.
# The audit log is separate from the session log to avoid mixing concerns.
#
# Design constraints:
#   - Must be fast; runs on every shell command Claude executes
#   - Must preserve command exit codes exactly
#   - Must not interfere with stdin/stdout/stderr of the wrapped command
#   - Logging failures must never prevent command execution
#   - Must fail cleanly if Claude stops passing exactly one command blob

PLSEC_DIR="@@PLSEC_DIR@@"
AUDIT_DIR="${PLSEC_DIR}/logs"
AUDIT_LOG="${AUDIT_DIR}/claude-audit-$(date +%Y%m%d).log"

timestamp() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

mkdir -p "$AUDIT_DIR" 2>/dev/null || :

case $# in
0)
  # No command was provided. Nothing to execute.
  {
    printf '[%s] [%d] cwd=%q event=no-command\n' \
      "$(timestamp)" "$$" "$PWD"
  } >>"$AUDIT_LOG" 2>/dev/null || :
  exit 0
  ;;

1)
  # Expected path: one complete shell command string in $1.
  {
    printf '[%s] [%d] cwd=%q cmd=%q\n' \
      "$(timestamp)" "$$" "$PWD" "$1"
  } >>"$AUDIT_LOG" 2>/dev/null || :

  # Replace this wrapper with a clean non-interactive Bash running the
  # provided command string. This preserves the command's exit status and
  # avoids returning to the wrapper after execution.
  exec bash --noprofile --norc -c "$1"
  ;;

*)
  # Claude's calling convention changed. Fail clearly rather than guessing.
  {
    printf '[%s] [%d] cwd=%q error=unexpected-argv argc=%d argv=' \
      "$(timestamp)" "$$" "$PWD" "$#"
    printf '%q ' "$@"
    printf '\n'
  } >>"$AUDIT_LOG" 2>/dev/null || :

  printf 'plsec-audit: expected exactly 1 command argument, got %d\n' "$#" >&2
  exit 64
  ;;
esac
