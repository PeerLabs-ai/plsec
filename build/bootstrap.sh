#!/bin/bash
# bootstrap.sh - Immediate security setup for AI coding assistants
#
# GENERATED FILE - do not edit directly.
# Edit templates in templates/bootstrap/ and run 'make build'.
#
# This script provides minimal viable security for Claude Code and Opencode
# while the full plsec tooling is developed.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/.../build/bootstrap.sh | bash
#   # or
#   ./bootstrap.sh [--with-pipelock] [--strict] [--agent claude|opencode|both]
#
# What it does:
#   1. Checks dependencies
#   2. Creates restrictive CLAUDE.md and/or opencode.json
#   3. Installs Trivy with LLM-tuned secret scanning
#   4. Sets up pre-commit hooks
#   5. (Optional) Installs and configures Pipelock in audit mode

set -euo pipefail

# Configuration (overridable via environment for testing)
PLSEC_DIR="${PLSEC_DIR:-${HOME}/.peerlabs/plsec}"
PLSEC_VERSION="${PLSEC_VERSION:-0.1.0+bootstrap}"
WITH_PIPELOCK="${WITH_PIPELOCK:-false}"
STRICT_MODE="${STRICT_MODE:-false}"
DRY_RUN="${DRY_RUN:-false}"
AGENT_TYPE="${AGENT_TYPE:-both}"  # claude, opencode, or both

# Colors (disable if not tty)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' NC=''
fi

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_ok() {
    echo -e "${GREEN}[OK]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Dry-run-aware helpers

run_cmd() {
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would run: $*"
    else
        "$@"
    fi
}

write_file() {
    local dest="$1"
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would write: $dest"
        cat > /dev/null  # consume stdin
    else
        cat > "$dest"
    fi
}

write_file_from_var() {
    local dest="$1"
    local content="$2"
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would write: $dest"
    else
        printf '%s\n' "$content" > "$dest"
    fi
}

# Write a content template, substituting @@PLSEC_DIR@@ at write time
write_content_file() {
    local dest="$1"
    local content="$2"
    local resolved="${content//@@PLSEC_DIR@@/${PLSEC_DIR}}"
    write_file_from_var "$dest" "$resolved"
}

copy_file() {
    local src="$1"
    local dest="$2"
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would copy: $src -> $dest"
    else
        cp "$src" "$dest"
    fi
}

make_executable() {
    local target="$1"
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would chmod +x: $target"
    else
        chmod +x "$target"
    fi
}

ensure_dir() {
    local dir="$1"
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would create directory: $dir"
    else
        mkdir -p "$dir"
    fi
}

append_to_file() {
    local dest="$1"
    local content="$2"
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would append to: $dest"
    else
        printf '%s\n' "$content" >> "$dest"
    fi
}

# Platform detection (reserved for future use)
detect_os() {
    case "$OSTYPE" in
        darwin*)
            echo "macos"
            ;;
        linux*)
            if [[ -f /etc/debian_version ]]; then
                echo "linux"
            elif [[ -f /etc/redhat-release ]]; then
                echo "linux"
            else
                echo "linux"
            fi
            ;;
        *)
            log_warn "Unknown OS: $OSTYPE"
            echo "unknown"
            ;;
    esac
}

# Check if a command exists
check_command() {
    local cmd="$1"
    if command -v "$cmd" &> /dev/null; then
        log_ok "Found: $cmd ($(command -v "$cmd"))"
        return 0
    else
        log_warn "Missing: $cmd"
        return 1
    fi
}

# =============================================================================
# Content templates (embedded by assembler - do not edit inline)
# =============================================================================

CLAUDE_MD_STRICT='# CLAUDE.md - Strict Security Configuration

## Critical Security Constraints

You are operating in a RESTRICTED security environment. Violations will terminate the session.

### NEVER (Hard Blocks)

- NEVER read, write, or access files outside the current project directory
- NEVER read, write, or access any dotfiles (.env, .bashrc, .zshrc, .ssh/*, .aws/*, .config/*)
- NEVER read, write, or access home directory files (~/* or $HOME/*)
- NEVER access /etc/*, /var/*, /tmp/*, /private/*
- NEVER execute curl, wget, nc, or any network commands
- NEVER execute ssh, scp, rsync, or remote access commands
- NEVER read environment variables containing secrets (API keys, tokens, passwords)
- NEVER write secrets, API keys, or credentials to any file
- NEVER execute commands that modify system state outside the project
- NEVER use eval, exec, or dynamic code execution
- NEVER access clipboard or pasteboard
- NEVER spawn background processes or daemons
- NEVER modify git config or hooks outside the project

### ALWAYS (Required Actions)

- ALWAYS confirm destructive operations before executing
- ALWAYS show the full command before execution
- ALWAYS limit file reads to <500 lines unless explicitly requested
- ALWAYS use relative paths within the project
- ALWAYS report if a requested action would violate these constraints

### Project Boundaries

- Working directory: Current directory only
- Allowed paths: ./, src/, tests/, docs/, scripts/
- Denied patterns: **/.*, **/node_modules/**, **/__pycache__/**

### Logging

All commands will be logged for security audit.'

CLAUDE_MD_BALANCED='# CLAUDE.md - Balanced Security Configuration

## Security Constraints

You are operating with security monitoring enabled.

### NEVER (Hard Blocks)

- NEVER access files outside the current project without explicit approval
- NEVER read .env files, .ssh/*, .aws/*, or credential files
- NEVER write secrets or API keys to files
- NEVER execute curl/wget to unknown domains
- NEVER modify system configuration files

### ASK FIRST (Soft Blocks)

- Creating files outside src/, tests/, docs/
- Installing new dependencies
- Running commands with network access
- Modifying git configuration
- Accessing parent directories (../)

### ALWAYS

- Show commands before execution
- Confirm destructive operations
- Use relative paths when possible
- Report constraint violations

### Allowed Operations

- Read/write within project directory
- Run tests and linters
- Git operations (status, diff)
- Package manager commands (pip, npm) with review

### Logging

Commands are logged to @@PLSEC_DIR@@/logs/'

OPENCODE_JSON_STRICT='{
  "$schema": "https://opencode.ai/config.json",
  "instructions": ["CLAUDE.md"],
  "permission": {
    "*": "ask",
    "read": {
      "*": "allow",
      ".env": "deny",
      ".env.*": "deny",
      "**/.ssh/*": "deny",
      "**/.aws/*": "deny",
      "**/.config/*": "deny",
      "**/secrets*": "deny",
      "**/credentials*": "deny",
      "**/*.pem": "deny",
      "**/*.key": "deny"
    },
    "edit": {
      "*": "ask",
      ".env": "deny",
      ".env.*": "deny",
      "**/.git/config": "deny",
      "**/.ssh/*": "deny",
      "**/.aws/*": "deny",
      "**/.config/*": "deny",
      "**/secrets*": "deny",
      "**/credentials*": "deny",
      "**/*.pem": "deny",
      "**/*.key": "deny"
    },
    "bash": {
      "*": "deny",
      "git status *": "allow",
      "git diff *": "allow",
      "git log *": "allow",
      "git add *": "ask",
      "git commit *": "ask",
      "python -m pytest *": "allow",
      "python -m ruff *": "allow",
      "python -m mypy *": "allow",
      "python -m ty *": "allow",
      "python manage.py *": "ask"
    },
    "external_directory": "deny",
    "webfetch": "deny",
    "websearch": "deny",
    "doom_loop": "deny"
  }
}'

OPENCODE_JSON_BALANCED='{
  "$schema": "https://opencode.ai/config.json",
  "instructions": ["CLAUDE.md"],
  "permission": {
    "*": "allow",
    "read": {
      "*": "allow",
      ".env": "deny",
      ".env.*": "deny",
      "**/.ssh/*": "deny",
      "**/.aws/*": "deny",
      "**/secrets*": "deny",
      "**/*.pem": "deny",
      "**/*.key": "deny"
    },
    "edit": {
      "*": "allow",
      ".env": "deny",
      ".env.*": "deny",
      "**/.ssh/*": "deny",
      "**/.aws/*": "deny",
      "**/secrets*": "deny",
      "**/*.pem": "deny",
      "**/*.key": "deny"
    },
    "bash": {
      "*": "ask",
      "git *": "ask",
      "rm -rf *": "deny",
      "sudo *": "deny",
      "chmod 777 *": "deny",
      "curl *": "ask",
      "wget *": "ask"
    },
    "external_directory": "ask",
    "doom_loop": "ask"
  }
}'

TRIVY_SECRET_YAML='# trivy-secret.yaml - LLM-tuned secret detection
# Disable allow-rules: LLMs put secrets in unexpected places

disable-allow-rules:
  - markdown
  - tests
  - testdata

rules:
  # Generic patterns (catch hallucinated secrets)
  - id: generic-api-key
    category: generic
    title: Generic API Key
    severity: HIGH
    keywords: [api_key, apikey, api-key, API_KEY]
    regex: (?i)(api[_-]?key|apikey)['\''":\s]*[=:]\s*['\''"]?([A-Za-z0-9_\-\/+=]{20,})['\''"]?

  - id: generic-secret
    category: generic
    title: Generic Secret/Token
    severity: HIGH
    keywords: [secret, token, password, auth]
    regex: (?i)(secret|token|password|auth[_-]?token)\b.{0,40}['\''"]?[A-Za-z0-9_\-\/+=]{12,}['\''"]?

  - id: private-key
    category: generic
    title: Private Key
    severity: CRITICAL
    keywords: ["BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN PRIVATE KEY"]
    regex: "-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----"

  # Provider-specific
  - id: anthropic-api-key
    category: Anthropic
    title: Anthropic API Key
    severity: CRITICAL
    keywords: [ANTHROPIC_API_KEY, sk-ant-, anthropic]
    regex: \bsk-ant-[A-Za-z0-9_-]{32,200}\b

  - id: openai-api-key
    category: OpenAI
    title: OpenAI API Key
    severity: CRITICAL
    keywords: [OPENAI_API_KEY, sk-proj-, sk-]
    regex: \bsk-(proj|svcacct|None)-[A-Za-z0-9_-]{32,200}\b

  - id: openai-legacy
    category: OpenAI
    title: OpenAI Legacy Key
    severity: CRITICAL
    keywords: [OPENAI_API_KEY, sk-]
    # Legacy keys are sk- followed by pure alphanumeric (no hyphens).
    # Modern formats (sk-proj-, sk-ant-, sk-svcacct-) contain hyphens
    # and are caught by the openai-api-key and anthropic-api-key rules.
    # RE2-compatible: no negative lookahead needed.
    regex: \bsk-[A-Za-z0-9]{40,64}\b

  - id: github-token
    category: GitHub
    title: GitHub Token
    severity: CRITICAL
    keywords: [ghp_, gho_, GITHUB_TOKEN]
    regex: \bgh[pousr]_[A-Za-z0-9]{36}\b

  - id: aws-access-key
    category: AWS
    title: AWS Access Key
    severity: CRITICAL
    keywords: [AWS_ACCESS_KEY_ID, AKIA, ASIA]
    regex: \b(AKIA|ASIA)[0-9A-Z]{16}\b

  - id: aws-secret-key
    category: AWS
    title: AWS Secret Key
    severity: CRITICAL
    keywords: [AWS_SECRET_ACCESS_KEY, aws_secret_key]
    regex: (?i)(aws_secret_access_key|aws_secret_key)\b.{0,40}['\''"]?[0-9A-Za-z\/+=]{40}['\''"]?'

TRIVY_YAML='scan:
  scanners:
    - vuln
    - secret
    - misconfig
  skip-dirs:
    - .venv
    - .tox
    - node_modules
    - build
    - dist
    - .eggs
    - __pycache__
  skip-files:
    - "**/*.pyc"

secret:
  config: trivy-secret.yaml

severity:
  - CRITICAL
  - HIGH
  - MEDIUM

format: table
exit-code: 1'

# =============================================================================
main() {

# -----------------------------------------------------------------------------
# 0. Parse arguments
# -----------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            echo "Usage: bootstrap.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --strict          Strict security mode (restrictive defaults)"
            echo "  --dry-run         Show what would be done without making changes"
            echo "  --simulate        Alias for --dry-run"
            echo "  --agent TYPE      Agent type: claude, opencode, or both (default: both)"
            echo "  --with-pipelock   Install and configure Pipelock network proxy"
            echo "  --help            Show this help message"
            exit 0
            ;;
        --strict) STRICT_MODE=true; shift ;;
        --dry-run|--simulate) DRY_RUN=true; shift ;;
        --with-pipelock) WITH_PIPELOCK=true; shift ;;
        --agent)
            shift
            if [[ $# -eq 0 ]]; then
                log_error "--agent requires a value: claude, opencode, or both"
                exit 1
            fi
            AGENT_TYPE="$1"
            if [[ "$AGENT_TYPE" != "claude" && "$AGENT_TYPE" != "opencode" && "$AGENT_TYPE" != "both" ]]; then
                log_error "Invalid agent type: $AGENT_TYPE (must be claude, opencode, or both)"
                exit 1
            fi
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Show configuration
echo ""
echo "========================================"
echo "Peerlabs Security Bootstrap v${PLSEC_VERSION}"
echo "========================================"
echo ""
echo "  Mode: $(if [[ "$STRICT_MODE" == true ]]; then echo "strict"; else echo "balanced"; fi)"
echo "  Agent type: $AGENT_TYPE"
echo "  Pipelock: $WITH_PIPELOCK"
echo "  Base dir: $PLSEC_DIR"
echo ""

if [[ "$DRY_RUN" == true ]]; then
    echo "=========================================="
    echo "  DRY RUN MODE - no changes will be made"
    echo "=========================================="
    echo ""
fi

# -----------------------------------------------------------------------------
# 1. Check dependencies
# -----------------------------------------------------------------------------
log_info "Checking dependencies..."

check_command git || true
check_command trivy || log_warn "Install trivy: brew install trivy (macOS) or see https://aquasecurity.github.io/trivy/"
check_command bandit || log_warn "Install bandit: pip install bandit"
check_command semgrep || log_warn "Install semgrep: pip install semgrep"

if [[ "$WITH_PIPELOCK" == true ]]; then
    check_command go || log_warn "Go required for Pipelock: brew install go"
fi

echo ""

# -----------------------------------------------------------------------------
# 2. Create directory structure
# -----------------------------------------------------------------------------
log_info "Creating directory structure..."

ensure_dir "${PLSEC_DIR}/configs"
ensure_dir "${PLSEC_DIR}/logs"
ensure_dir "${PLSEC_DIR}/manifests"
ensure_dir "${PLSEC_DIR}/trivy"
ensure_dir "${PLSEC_DIR}/trivy/policies"

log_ok "Created ${PLSEC_DIR}/"

# -----------------------------------------------------------------------------
# 3. Create restrictive CLAUDE.md template
# -----------------------------------------------------------------------------
log_info "Creating CLAUDE.md template..."

if [[ "$STRICT_MODE" == true ]]; then
    CLAUDE_MD_CONTENT="$CLAUDE_MD_STRICT"
else
    CLAUDE_MD_CONTENT="$CLAUDE_MD_BALANCED"
fi

# Write to plsec directory
if [[ "$AGENT_TYPE" == "claude" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    write_content_file "${PLSEC_DIR}/configs/CLAUDE.md" "$CLAUDE_MD_CONTENT"
    log_ok "Created ${PLSEC_DIR}/configs/CLAUDE.md"
fi

# -----------------------------------------------------------------------------
# 3b. Create Opencode configuration template (opencode.json)
# -----------------------------------------------------------------------------
# OpenCode uses opencode.json with a permission system supporting allow/ask/deny
# actions and pattern-based rules. Schema: https://opencode.ai/config.json
#
# Known caveats (as of January 2026):
#   - SDK may ignore custom agent deny permissions (anomalyco/opencode#6396)
#   - Agents can circumvent denied tools via bash (sst/opencode#4642)
#   - Plan agent may ignore edit permissions (sst/opencode#3991)
# See: https://opencode.ai/docs/permissions/
# -----------------------------------------------------------------------------
if [[ "$AGENT_TYPE" == "opencode" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    log_info "Creating opencode.json template..."

    if [[ "$STRICT_MODE" == true ]]; then
        OPENCODE_JSON_CONTENT="$OPENCODE_JSON_STRICT"
    else
        OPENCODE_JSON_CONTENT="$OPENCODE_JSON_BALANCED"
    fi

    write_file_from_var "${PLSEC_DIR}/configs/opencode.json" "$OPENCODE_JSON_CONTENT"
    log_ok "Created ${PLSEC_DIR}/configs/opencode.json"

    # Warn about known permission bypass issues
    log_warn "OpenCode permission enforcement has known bypass issues (see script comments)"
    log_warn "Strict mode is aspirational; review https://opencode.ai/docs/permissions/"

    # Also create global config location
    ensure_dir "${HOME}/.config/opencode"
    if [[ ! -f "${HOME}/.config/opencode/opencode.json" ]] || [[ "$DRY_RUN" == true ]]; then
        copy_file "${PLSEC_DIR}/configs/opencode.json" "${HOME}/.config/opencode/opencode.json"
        log_ok "Installed global config: ~/.config/opencode/opencode.json"
    else
        log_warn "Global opencode config exists, not overwriting"
        log_info "Review: ${HOME}/.config/opencode/opencode.json"
    fi
fi

# -----------------------------------------------------------------------------
# 4. Create Trivy secret scanning config
# -----------------------------------------------------------------------------
log_info "Creating Trivy configuration..."

write_content_file "${PLSEC_DIR}/trivy/trivy-secret.yaml" "$TRIVY_SECRET_YAML"
log_ok "Created ${PLSEC_DIR}/trivy/trivy-secret.yaml"

write_content_file "${PLSEC_DIR}/trivy/trivy.yaml" "$TRIVY_YAML"
log_ok "Created ${PLSEC_DIR}/trivy/trivy.yaml"

# -----------------------------------------------------------------------------
# 5. Create wrapper scripts
# -----------------------------------------------------------------------------
log_info "Creating wrapper scripts..."

# Claude Code logging wrapper
if [[ "$AGENT_TYPE" == "claude" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    write_file "${PLSEC_DIR}/claude-wrapper.sh" << EOF
#!/bin/bash
# claude-wrapper.sh - Logging wrapper for Claude Code
#
# Tier 1: Session enrichment (git info, duration, preset, agent version)
# Tier 2: CLAUDE_CODE_SHELL_PREFIX audit logging

PLSEC_DIR="${PLSEC_DIR}"
LOG_FILE="\${PLSEC_DIR}/logs/claude-\$(date +%Y%m%d).log"

log() {
    echo "[\$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [\$\$] \$*" >> "\$LOG_FILE"
}

# ---------------------------------------------------------------------------
# Tier 1: Gather session context (best-effort, never block startup)
# ---------------------------------------------------------------------------

_git_branch=\$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "n/a")
_git_sha=\$(git rev-parse --short HEAD 2>/dev/null || echo "n/a")
_agent_version=\$(claude --version 2>/dev/null | head -1 || echo "n/a")

# Detect preset from plsec.yaml or CLAUDE.md heuristic
_detect_preset() {
    local yaml="\${PLSEC_DIR}/configs/plsec.yaml"
    if [[ -f "\$yaml" ]]; then
        local val
        val=\$(awk '/^preset:/ { print \$2 }' "\$yaml" 2>/dev/null)
        if [[ -n "\$val" ]]; then echo "\$val"; return; fi
    fi
    local claude_md="\${PLSEC_DIR}/configs/CLAUDE.md"
    if [[ -f "\$claude_md" ]]; then
        if grep -q "Strict Security" "\$claude_md" 2>/dev/null; then
            echo "strict"
        else
            echo "balanced"
        fi
        return
    fi
    echo "unknown"
}
_preset=\$(_detect_preset)

START_SECONDS=\$SECONDS

log "=== Session started: \$(pwd) ==="
log "git_branch=\${_git_branch} git_sha=\${_git_sha} preset=\${_preset} agent_version=\${_agent_version}"
log "Args: \$*"

# Copy CLAUDE.md to project if not present
if [[ ! -f "./CLAUDE.md" ]] && [[ -f "\${PLSEC_DIR}/configs/CLAUDE.md" ]]; then
    cp "\${PLSEC_DIR}/configs/CLAUDE.md" ./CLAUDE.md
    log "Copied CLAUDE.md to project"
fi

# ---------------------------------------------------------------------------
# Tier 2: CLAUDE_CODE_SHELL_PREFIX audit logging
# ---------------------------------------------------------------------------

AUDIT_SCRIPT="\${PLSEC_DIR}/plsec-audit.sh"
if [[ -x "\$AUDIT_SCRIPT" ]]; then
    export CLAUDE_CODE_SHELL_PREFIX="\$AUDIT_SCRIPT"
    log "Audit logging enabled via CLAUDE_CODE_SHELL_PREFIX"
fi

# Run Claude Code
claude "\$@"
EXIT_CODE=\$?

ELAPSED=\$(( SECONDS - START_SECONDS ))
log "=== Session ended: exit code \${EXIT_CODE} duration=\${ELAPSED}s ==="
exit \$EXIT_CODE
EOF
    make_executable "${PLSEC_DIR}/claude-wrapper.sh"
    log_ok "Created Claude Code wrapper"
fi

# Opencode logging wrapper
if [[ "$AGENT_TYPE" == "opencode" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    write_file "${PLSEC_DIR}/opencode-wrapper.sh" << EOF
#!/bin/bash
# opencode-wrapper.sh - Logging wrapper for Opencode
#
# Tier 1: Session enrichment (git info, duration, preset, agent version)

PLSEC_DIR="${PLSEC_DIR}"
LOG_FILE="\${PLSEC_DIR}/logs/opencode-\$(date +%Y%m%d).log"

log() {
    echo "[\$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [\$\$] \$*" >> "\$LOG_FILE"
}

# ---------------------------------------------------------------------------
# Tier 1: Gather session context (best-effort, never block startup)
# ---------------------------------------------------------------------------

_git_branch=\$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "n/a")
_git_sha=\$(git rev-parse --short HEAD 2>/dev/null || echo "n/a")
_agent_version=\$(opencode --version 2>/dev/null | head -1 || echo "n/a")

# Detect preset from plsec.yaml or CLAUDE.md heuristic
_detect_preset() {
    local yaml="\${PLSEC_DIR}/configs/plsec.yaml"
    if [[ -f "\$yaml" ]]; then
        local val
        val=\$(awk '/^preset:/ { print \$2 }' "\$yaml" 2>/dev/null)
        if [[ -n "\$val" ]]; then echo "\$val"; return; fi
    fi
    local claude_md="\${PLSEC_DIR}/configs/CLAUDE.md"
    if [[ -f "\$claude_md" ]]; then
        if grep -q "Strict Security" "\$claude_md" 2>/dev/null; then
            echo "strict"
        else
            echo "balanced"
        fi
        return
    fi
    echo "unknown"
}
_preset=\$(_detect_preset)

START_SECONDS=\$SECONDS

log "=== Session started: \$(pwd) ==="
log "git_branch=\${_git_branch} git_sha=\${_git_sha} preset=\${_preset} agent_version=\${_agent_version}"
log "Args: \$*"

# Copy opencode.json to project if not present
if [[ ! -f "./opencode.json" ]] && [[ -f "\${PLSEC_DIR}/configs/opencode.json" ]]; then
    cp "\${PLSEC_DIR}/configs/opencode.json" ./opencode.json
    log "Copied opencode.json to project"
fi

# Check for CLAUDE.md as well (Opencode respects it for system prompts)
if [[ ! -f "./CLAUDE.md" ]] && [[ -f "\${PLSEC_DIR}/configs/CLAUDE.md" ]]; then
    cp "\${PLSEC_DIR}/configs/CLAUDE.md" ./CLAUDE.md
    log "Copied CLAUDE.md to project (Opencode reads this too)"
fi

# Run Opencode
opencode "\$@"
EXIT_CODE=\$?

ELAPSED=\$(( SECONDS - START_SECONDS ))
log "=== Session ended: exit code \${EXIT_CODE} duration=\${ELAPSED}s ==="
exit \$EXIT_CODE
EOF
    make_executable "${PLSEC_DIR}/opencode-wrapper.sh"
    log_ok "Created Opencode wrapper"
fi

# Scan script
write_file "${PLSEC_DIR}/scan.sh" << EOF
#!/bin/bash
# scan.sh - Run security scans

PLSEC_DIR="${PLSEC_DIR}"
TARGET="\${1:-.}"

echo "Running security scans on: \$TARGET"
echo ""

# Trivy secrets
if command -v trivy &> /dev/null; then
    echo "=== Trivy Secret Scan ==="
    trivy fs --secret-config "\${PLSEC_DIR}/trivy/trivy-secret.yaml" "\$TARGET"
    echo ""
fi

# Bandit (Python)
if command -v bandit &> /dev/null && [[ -d "\$TARGET" ]]; then
    if find "\$TARGET" -name "*.py" -type f | head -1 | grep -q .; then
        echo "=== Bandit (Python) ==="
        bandit -r "\$TARGET" -ll 2>/dev/null || true
        echo ""
    fi
fi

# Semgrep
if command -v semgrep &> /dev/null; then
    echo "=== Semgrep ==="
    semgrep --config auto "\$TARGET" --quiet 2>/dev/null || true
    echo ""
fi

echo "Scan complete."
EOF
make_executable "${PLSEC_DIR}/scan.sh"

# Audit script (used by CLAUDE_CODE_SHELL_PREFIX for command-level logging)
write_file "${PLSEC_DIR}/plsec-audit.sh" << EOF
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

PLSEC_DIR="${PLSEC_DIR}"
AUDIT_LOG="\${PLSEC_DIR}/logs/claude-audit-\$(date +%Y%m%d).log"

# Log to audit file (append, fire-and-forget)
{
    echo "[\$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [\$\$] cwd=\$(pwd) cmd=\$*"
} >> "\$AUDIT_LOG" 2>/dev/null

# Execute the original command, preserving exit code
exec "\$@"
EOF
make_executable "${PLSEC_DIR}/plsec-audit.sh"

# Status script (health check dashboard)
write_file "${PLSEC_DIR}/plsec-status.sh" << EOF
#!/bin/bash
# plsec-status.sh - Health status for plsec installation
#
# Answers: "Is plsec installed, configured, and active in this environment?"
#
# Design: docs/plsec-status-design.md
# Exit codes: 0 = OK (warnings acceptable), 1 = failures present
#
# Usage:
#   plsec-status               # Human-readable colored output
#   plsec-status --json        # Machine-readable JSON
#   plsec-status --quiet       # Exit code only (for CI)
#   plsec-status --project .   # Check specific project directory

PLSEC_DIR="${PLSEC_DIR}"
PLSEC_VERSION="\${PLSEC_VERSION:-unknown}"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Staleness thresholds (seconds)
STALE_WARN_SECONDS=\$((24 * 60 * 60))   # 24 hours
STALE_FAIL_SECONDS=\$((7 * 24 * 60 * 60))  # 7 days

# Expected subdirectories
EXPECTED_SUBDIRS="configs logs manifests trivy trivy/policies"

# Expected scanner config files (relative to PLSEC_DIR)
EXPECTED_SCANNER_CONFIGS="trivy/trivy-secret.yaml trivy/trivy.yaml configs/pre-commit"

# ---------------------------------------------------------------------------
# Color support
# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    RED='\033[0;31m'
    GREY='\033[0;90m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    GREEN='' YELLOW='' RED='' GREY='' BOLD='' RESET=''
fi

# ---------------------------------------------------------------------------
# Global state (accumulated by check functions)
# ---------------------------------------------------------------------------

declare -a VERDICTS=()
declare -a CHECK_IDS=()
declare -a CHECK_NAMES=()
declare -a CHECK_CATEGORIES=()
declare -a CHECK_DETAILS=()

WARNING_COUNT=0
ERROR_COUNT=0

# ---------------------------------------------------------------------------
# Result recording
# ---------------------------------------------------------------------------

# Record a check result.
# Usage: record_check "I-1" "installation" "plsec directory" "ok" "~/.peerlabs/plsec"
record_check() {
    local id="\$1" category="\$2" name="\$3" verdict="\$4" detail="\${5:-}"

    CHECK_IDS+=("\$id")
    CHECK_CATEGORIES+=("\$category")
    CHECK_NAMES+=("\$name")
    VERDICTS+=("\$verdict")
    CHECK_DETAILS+=("\$detail")

    case "\$verdict" in
        warn) WARNING_COUNT=\$((WARNING_COUNT + 1)) ;;
        fail) ERROR_COUNT=\$((ERROR_COUNT + 1)) ;;
    esac
}

# ---------------------------------------------------------------------------
# Verdict helpers
# ---------------------------------------------------------------------------

# Compute overall verdict from the VERDICTS array.
# ok = no failures. fail = any failure. Warnings are acceptable.
compute_overall() {
    local v
    for v in "\${VERDICTS[@]}"; do
        if [[ "\$v" == "fail" ]]; then
            echo "fail"
            return
        fi
    done
    echo "ok"
}

# Format a verdict string for display.
format_verdict() {
    local verdict="\$1"
    case "\$verdict" in
        ok)   printf "\${GREEN}%-4s\${RESET}" "OK" ;;
        warn) printf "\${YELLOW}%-4s\${RESET}" "WARN" ;;
        fail) printf "\${RED}%-4s\${RESET}" "FAIL" ;;
        skip) printf "\${GREY}%-4s\${RESET}" "SKIP" ;;
        *)    printf "%-4s" "????" ;;
    esac
}

# ---------------------------------------------------------------------------
# Installation checks
# ---------------------------------------------------------------------------

# I-1: Check PLSEC_DIR exists
check_plsec_dir() {
    if [[ -d "\$PLSEC_DIR" ]]; then
        record_check "I-1" "installation" "plsec directory" "ok" "\$PLSEC_DIR"
        echo "ok"
    else
        record_check "I-1" "installation" "plsec directory" "fail" "\$PLSEC_DIR"
        echo "fail"
    fi
}

# I-1 (sub): Check expected subdirectories
check_subdirs() {
    local missing=0
    local subdir
    for subdir in \$EXPECTED_SUBDIRS; do
        if [[ ! -d "\${PLSEC_DIR}/\${subdir}" ]]; then
            missing=\$((missing + 1))
        fi
    done

    if [[ \$missing -eq 0 ]]; then
        record_check "I-1" "installation" "subdirectories" "ok" "all present"
        echo "ok"
    else
        record_check "I-1" "installation" "subdirectories" "warn" "\${missing} missing"
        echo "warn"
    fi
}

# I-2, I-3: Check agent config file in configs/
# Usage: check_agent_config "CLAUDE.md"
check_agent_config() {
    local filename="\$1"
    local config_path="\${PLSEC_DIR}/configs/\${filename}"

    if [[ -f "\$config_path" ]]; then
        if [[ ! -s "\$config_path" ]]; then
            record_check "I-agent" "installation" "\${filename} config" "warn" "empty file"
            echo "warn"
        else
            record_check "I-agent" "installation" "\${filename} config" "ok" "\$config_path"
            echo "ok"
        fi
    else
        record_check "I-agent" "installation" "\${filename} config" "fail" "missing"
        echo "fail"
    fi
}

# I-4 through I-11: Check a tool binary
# Usage: check_tool "trivy" "required"
check_tool() {
    local tool_name="\$1"
    local requirement="\${2:-required}"  # "required" or "optional"

    if command -v "\$tool_name" &> /dev/null; then
        local tool_path
        tool_path=\$(command -v "\$tool_name")
        record_check "I-tool" "installation" "\$tool_name" "ok" "\$tool_path"
        echo "ok"
    else
        if [[ "\$requirement" == "required" ]]; then
            record_check "I-tool" "installation" "\$tool_name" "fail" "not found"
            echo "fail"
        else
            record_check "I-tool" "installation" "\$tool_name" "warn" "not found (optional)"
            echo "warn"
        fi
    fi
}

# I-5, I-6: Check scanner config file
# Usage: check_scanner_config "trivy/trivy-secret.yaml" "Trivy secret rules"
check_scanner_config() {
    local rel_path="\$1"
    local description="\$2"
    local full_path="\${PLSEC_DIR}/\${rel_path}"

    if [[ -f "\$full_path" ]]; then
        record_check "I-scanner" "installation" "\$description" "ok" "\$full_path"
        echo "ok"
    else
        record_check "I-scanner" "installation" "\$description" "warn" "\${rel_path} missing"
        echo "warn"
    fi
}

# I-7: Check wrapper script exists and is executable
# Usage: check_wrapper_script "claude-wrapper.sh" "Claude Code wrapper"
check_wrapper_script() {
    local filename="\$1"
    local description="\$2"
    local full_path="\${PLSEC_DIR}/\${filename}"

    if [[ -f "\$full_path" ]]; then
        if [[ -x "\$full_path" ]]; then
            record_check "I-7" "installation" "\$description" "ok" "\$full_path"
            echo "ok"
        else
            record_check "I-7" "installation" "\$description" "warn" "not executable"
            echo "warn"
        fi
    else
        record_check "I-7" "installation" "\$description" "fail" "missing"
        echo "fail"
    fi
}

# ---------------------------------------------------------------------------
# Configuration checks
# ---------------------------------------------------------------------------

# C-1: Detect security mode from CLAUDE.md content
detect_security_mode() {
    local claude_md="\${PLSEC_DIR}/configs/CLAUDE.md"
    if [[ ! -f "\$claude_md" ]]; then
        echo "unknown"
        return
    fi
    if grep -q "RESTRICTED" "\$claude_md" 2>/dev/null; then
        echo "strict"
    elif grep -q "Security Constraints" "\$claude_md" 2>/dev/null; then
        echo "balanced"
    else
        echo "unknown"
    fi
}

# C-2: Detect which agents are configured
detect_agents() {
    local agents=()
    if [[ -f "\${PLSEC_DIR}/configs/CLAUDE.md" ]]; then
        agents+=("claude")
    fi
    if [[ -f "\${PLSEC_DIR}/configs/opencode.json" ]]; then
        agents+=("opencode")
    fi

    if [[ \${#agents[@]} -eq 0 ]]; then
        echo "none"
    else
        echo "\${agents[*]}"
    fi
}

# C-3: Check pre-commit hook in project
# Usage: check_precommit_hook "/path/to/project"
check_precommit_hook() {
    local project_path="\$1"
    local hook_path="\${project_path}/.git/hooks/pre-commit"

    if [[ ! -d "\${project_path}/.git" ]]; then
        record_check "C-3" "configuration" "pre-commit hook" "fail" "not a git repo"
        echo "fail"
        return
    fi

    if [[ ! -f "\$hook_path" ]]; then
        record_check "C-3" "configuration" "pre-commit hook" "fail" "hook missing"
        echo "fail"
        return
    fi

    if grep -q "plsec\|trivy" "\$hook_path" 2>/dev/null; then
        record_check "C-3" "configuration" "pre-commit hook" "ok" "references plsec"
        echo "ok"
    else
        record_check "C-3" "configuration" "pre-commit hook" "warn" "no plsec reference"
        echo "warn"
    fi
}

# C-4, C-5: Check project-level config file
# Usage: check_project_config "/path/to/project" "CLAUDE.md"
check_project_config() {
    local project_path="\$1"
    local filename="\$2"
    local project_config="\${project_path}/\${filename}"
    local template_config="\${PLSEC_DIR}/configs/\${filename}"

    if [[ ! -f "\$project_config" ]]; then
        record_check "C-project" "configuration" "\${filename} (project)" "fail" "not found"
        echo "fail"
        return
    fi

    if [[ -f "\$template_config" ]] && diff -q "\$project_config" "\$template_config" > /dev/null 2>&1; then
        record_check "C-project" "configuration" "\${filename} (project)" "ok" "matches template"
        echo "ok"
    else
        record_check "C-project" "configuration" "\${filename} (project)" "warn" "differs from template"
        echo "warn"
    fi
}

# ---------------------------------------------------------------------------
# Activity checks
# ---------------------------------------------------------------------------

# A-1: Check wrapper log freshness
check_log_freshness() {
    local log_dir="\${PLSEC_DIR}/logs"
    local newest_log=""
    local newest_age=""

    # Find the most recently modified .log file
    if [[ -d "\$log_dir" ]]; then
        newest_log=\$(find "\$log_dir" -name "*.log" -type f -print 2>/dev/null | head -1)
    fi

    if [[ -z "\$newest_log" ]]; then
        record_check "A-1" "activity" "wrapper logs" "fail" "no log files found"
        echo "fail"
        return
    fi

    # Get age of newest log in seconds
    local now
    now=\$(date +%s)
    local mod_time
    # macOS stat vs GNU stat
    if stat -f %m "\$newest_log" > /dev/null 2>&1; then
        mod_time=\$(stat -f %m "\$newest_log")
    else
        mod_time=\$(stat -c %Y "\$newest_log")
    fi
    newest_age=\$((now - mod_time))

    if [[ \$newest_age -lt \$STALE_WARN_SECONDS ]]; then
        record_check "A-1" "activity" "wrapper logs" "ok" "active within 24h"
        echo "ok"
    elif [[ \$newest_age -lt \$STALE_FAIL_SECONDS ]]; then
        record_check "A-1" "activity" "wrapper logs" "warn" "stale (>24h, <7d)"
        echo "warn"
    else
        record_check "A-1" "activity" "wrapper logs" "fail" "inactive (>7d)"
        echo "fail"
    fi
}

# A-2: Count sessions in today's logs
check_session_count() {
    local log_dir="\${PLSEC_DIR}/logs"
    local today
    today=\$(date +%Y%m%d)
    local count=0

    # Count "Session started" lines in today's log files
    if [[ -d "\$log_dir" ]]; then
        local log_file
        for log_file in "\${log_dir}/"*"-\${today}.log"; do
            if [[ -f "\$log_file" ]]; then
                local file_count
                file_count=\$(grep -c "Session started" "\$log_file" 2>/dev/null || echo 0)
                count=\$((count + file_count))
            fi
        done
    fi

    if [[ \$count -gt 0 ]]; then
        record_check "A-2" "activity" "sessions today" "ok" "\${count} session(s)"
        echo "ok \${count}"
    elif [[ -d "\$log_dir" ]] && find "\$log_dir" -name "*.log" -type f | grep -q . 2>/dev/null; then
        # Logs exist but no sessions today
        record_check "A-2" "activity" "sessions today" "warn" "no sessions today"
        echo "warn 0"
    else
        record_check "A-2" "activity" "sessions today" "fail" "no session logs found"
        echo "fail 0"
    fi
}

# A-3: Check for recent scan evidence
check_last_scan() {
    local log_dir="\${PLSEC_DIR}/logs"
    local today
    today=\$(date +%Y%m%d)

    # Check for scan-YYYYMMDD.jsonl files or scan-latest.json
    if [[ -f "\${log_dir}/scan-\${today}.jsonl" ]]; then
        record_check "A-3" "activity" "last scan" "ok" "scan run today"
        echo "ok"
        return
    fi

    if [[ -f "\${log_dir}/scan-latest.json" ]]; then
        # Scan data exists but not from today - check age
        local now
        now=\$(date +%s)
        local mod_time
        if stat -f %m "\${log_dir}/scan-latest.json" > /dev/null 2>&1; then
            mod_time=\$(stat -f %m "\${log_dir}/scan-latest.json")
        else
            mod_time=\$(stat -c %Y "\${log_dir}/scan-latest.json")
        fi
        local age=\$((now - mod_time))

        if [[ \$age -lt \$STALE_WARN_SECONDS ]]; then
            record_check "A-3" "activity" "last scan" "ok" "within 24h"
            echo "ok"
        else
            record_check "A-3" "activity" "last scan" "warn" "last scan >24h ago"
            echo "warn"
        fi
        return
    fi

    # Check for any scan JSONL files
    if find "\$log_dir" -name "scan-*.jsonl" -type f 2>/dev/null | grep -q .; then
        record_check "A-3" "activity" "last scan" "warn" "no recent scan"
        echo "warn"
        return
    fi

    record_check "A-3" "activity" "last scan" "fail" "no scan evidence"
    echo "fail"
}

# ---------------------------------------------------------------------------
# Findings checks
# ---------------------------------------------------------------------------

# F-1: Check secrets detection findings
check_secrets_findings() {
    local latest="\${PLSEC_DIR}/logs/scan-latest.json"

    if [[ ! -f "\$latest" ]]; then
        record_check "F-1" "findings" "secrets detected" "skip" "no scan data"
        echo "skip"
        return
    fi

    # Parse overall_passed field (simple grep, no jq dependency)
    if grep -q '"overall_passed": true' "\$latest" 2>/dev/null || \
       grep -q '"overall_passed":true' "\$latest" 2>/dev/null; then
        record_check "F-1" "findings" "secrets detected" "ok" "last scan clean"
        echo "ok"
    else
        record_check "F-1" "findings" "secrets detected" "fail" "findings in last scan"
        echo "fail"
    fi
}

# F-2: Check for pre-commit hook blocks
check_hook_blocks() {
    local log_dir="\${PLSEC_DIR}/logs"

    if [[ ! -d "\$log_dir" ]] || ! find "\$log_dir" -name "*.log" -type f 2>/dev/null | grep -q .; then
        record_check "F-2" "findings" "hook blocks" "skip" "no logs"
        echo "skip"
        return
    fi

    # Look for hook rejection evidence in recent logs
    if grep -rq "ERROR.*secret\|hook.*blocked\|commit.*rejected" "\${log_dir}/"*.log 2>/dev/null; then
        record_check "F-2" "findings" "hook blocks" "fail" "rejection detected"
        echo "fail"
    else
        record_check "F-2" "findings" "hook blocks" "ok" "no recent blocks"
        echo "ok"
    fi
}

# ---------------------------------------------------------------------------
# Human-readable output
# ---------------------------------------------------------------------------

print_header() {
    local mode
    mode=\$(detect_security_mode)
    local agents
    agents=\$(detect_agents)

    printf "\n\${BOLD}plsec v%s [%s] [%s]\${RESET}\n\n" "\$PLSEC_VERSION" "\$mode" "\$agents"
}

print_section() {
    local section="\$1"
    printf "\n  \${BOLD}%s\${RESET}\n" "\$section"
}

print_check_line() {
    local name="\$1" verdict="\$2" detail="\$3"
    local verdict_str
    verdict_str=\$(format_verdict "\$verdict")
    if [[ -n "\$detail" ]]; then
        printf "    %-25s %s  %s\n" "\$name" "\$verdict_str" "\$detail"
    else
        printf "    %-25s %s\n" "\$name" "\$verdict_str"
    fi
}

print_summary() {
    local overall
    overall=\$(compute_overall)
    local verdict_str
    verdict_str=\$(format_verdict "\$overall")

    printf "\n  Overall: %s" "\$verdict_str"
    if [[ \$WARNING_COUNT -gt 0 ]] || [[ \$ERROR_COUNT -gt 0 ]]; then
        printf " ("
        local parts=()
        if [[ \$ERROR_COUNT -gt 0 ]]; then
            parts+=("\${ERROR_COUNT} error(s)")
        fi
        if [[ \$WARNING_COUNT -gt 0 ]]; then
            parts+=("\${WARNING_COUNT} warning(s)")
        fi
        local IFS=", "
        printf "%s" "\${parts[*]}"
        printf ")"
    fi
    printf "\n\n"
}

# ---------------------------------------------------------------------------
# JSON output (pure bash, no jq dependency)
# ---------------------------------------------------------------------------

# Escape a string for JSON output
json_escape() {
    local s="\$1"
    s="\${s//\\/\\\\}"
    s="\${s//\"/\\\"}"
    s="\${s//\$'\n'/\\n}"
    s="\${s//\$'\r'/\\r}"
    s="\${s//\$'\t'/\\t}"
    printf '%s' "\$s"
}

print_json() {
    local mode
    mode=\$(detect_security_mode)
    local agents_str
    agents_str=\$(detect_agents)
    local overall
    overall=\$(compute_overall)
    local timestamp
    timestamp=\$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    printf '{\n'
    printf '  "version": "%s",\n' "\$(json_escape "\$PLSEC_VERSION")"
    printf '  "mode": "%s",\n' "\$(json_escape "\$mode")"

    # Agents array
    printf '  "agents": ['
    local first=true
    local agent
    for agent in \$agents_str; do
        if [[ "\$agent" != "none" ]]; then
            if [[ "\$first" == true ]]; then
                first=false
            else
                printf ', '
            fi
            printf '"%s"' "\$(json_escape "\$agent")"
        fi
    done
    printf '],\n'

    printf '  "overall": "%s",\n' "\$overall"
    printf '  "warnings": %d,\n' "\$WARNING_COUNT"
    printf '  "errors": %d,\n' "\$ERROR_COUNT"
    printf '  "timestamp": "%s",\n' "\$timestamp"

    # Checks array
    printf '  "checks": [\n'
    local i
    local count=\${#CHECK_IDS[@]}
    for ((i = 0; i < count; i++)); do
        printf '    {\n'
        printf '      "id": "%s",\n' "\$(json_escape "\${CHECK_IDS[\$i]}")"
        printf '      "category": "%s",\n' "\$(json_escape "\${CHECK_CATEGORIES[\$i]}")"
        printf '      "name": "%s",\n' "\$(json_escape "\${CHECK_NAMES[\$i]}")"
        printf '      "verdict": "%s",\n' "\$(json_escape "\${VERDICTS[\$i]}")"
        printf '      "detail": "%s"\n' "\$(json_escape "\${CHECK_DETAILS[\$i]}")"
        if [[ \$((i + 1)) -lt \$count ]]; then
            printf '    },\n'
        else
            printf '    }\n'
        fi
    done
    printf '  ]\n'
    printf '}\n'
}

# ---------------------------------------------------------------------------
# Run all checks
# ---------------------------------------------------------------------------

run_all_checks() {
    local project_path="\$1"

    # -- Installation checks --
    local dir_verdict
    dir_verdict=\$(check_plsec_dir)
    if [[ "\$dir_verdict" == "fail" ]]; then
        # If PLSEC_DIR doesn't exist, skip remaining checks
        return
    fi
    check_subdirs > /dev/null

    # Agent configs
    if [[ -f "\${PLSEC_DIR}/configs/CLAUDE.md" ]] || true; then
        check_agent_config "CLAUDE.md" > /dev/null
    fi
    if [[ -f "\${PLSEC_DIR}/configs/opencode.json" ]] || true; then
        check_agent_config "opencode.json" > /dev/null
    fi

    # Required tools
    check_tool "git" "required" > /dev/null
    check_tool "trivy" "required" > /dev/null

    # Scanner configs
    local cfg
    for cfg in \$EXPECTED_SCANNER_CONFIGS; do
        local desc
        case "\$cfg" in
            trivy/trivy-secret.yaml) desc="Trivy secret rules" ;;
            trivy/trivy.yaml)        desc="Trivy configuration" ;;
            configs/pre-commit)      desc="Pre-commit hook template" ;;
            *)                       desc="\$cfg" ;;
        esac
        check_scanner_config "\$cfg" "\$desc" > /dev/null
    done

    # Wrapper scripts
    check_wrapper_script "claude-wrapper.sh" "Claude Code wrapper" > /dev/null
    check_wrapper_script "opencode-wrapper.sh" "OpenCode wrapper" > /dev/null

    # Optional tools
    check_tool "detect-secrets" "optional" > /dev/null
    check_tool "bandit" "optional" > /dev/null
    check_tool "semgrep" "optional" > /dev/null

    # -- Configuration checks --
    local mode
    mode=\$(detect_security_mode)
    record_check "C-1" "configuration" "security mode" "ok" "\$mode"

    local agents
    agents=\$(detect_agents)
    if [[ "\$agents" == "none" ]]; then
        record_check "C-2" "configuration" "agent type" "fail" "no agents configured"
    else
        record_check "C-2" "configuration" "agent type" "ok" "\$agents"
    fi

    check_precommit_hook "\$project_path" > /dev/null

    # Project-level config checks
    if [[ -f "\${PLSEC_DIR}/configs/CLAUDE.md" ]]; then
        check_project_config "\$project_path" "CLAUDE.md" > /dev/null
    fi
    if [[ -f "\${PLSEC_DIR}/configs/opencode.json" ]]; then
        check_project_config "\$project_path" "opencode.json" > /dev/null
    fi

    # -- Activity checks --
    check_log_freshness > /dev/null
    check_session_count > /dev/null
    check_last_scan > /dev/null

    # -- Findings checks --
    check_secrets_findings > /dev/null
    check_hook_blocks > /dev/null
}

# ---------------------------------------------------------------------------
# Human-readable display (reads from accumulated global arrays)
# ---------------------------------------------------------------------------

print_human_readable() {
    local project_path="\$1"

    print_header

    local current_category=""
    local i
    local count=\${#CHECK_IDS[@]}

    for ((i = 0; i < count; i++)); do
        local cat="\${CHECK_CATEGORIES[\$i]}"
        if [[ "\$cat" != "\$current_category" ]]; then
            current_category="\$cat"
            local section_title
            case "\$cat" in
                installation)  section_title="Installation" ;;
                configuration)
                    section_title="Configuration (project: \${project_path})"
                    ;;
                activity)      section_title="Activity" ;;
                findings)      section_title="Findings" ;;
                *)             section_title="\$cat" ;;
            esac
            print_section "\$section_title"
        fi
        print_check_line "\${CHECK_NAMES[\$i]}" "\${VERDICTS[\$i]}" "\${CHECK_DETAILS[\$i]}"
    done

    print_summary
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    local json_mode=false
    local quiet_mode=false
    local project_path=""

    # Parse arguments
    while [[ \$# -gt 0 ]]; do
        case "\$1" in
            --json)    json_mode=true; shift ;;
            --quiet)   quiet_mode=true; shift ;;
            --project)
                shift
                if [[ \$# -eq 0 ]]; then
                    echo "ERROR: --project requires a path argument" >&2
                    exit 1
                fi
                project_path="\$1"
                shift
                ;;
            --help|-h)
                echo "Usage: plsec-status [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --json        Machine-readable JSON output"
                echo "  --quiet       Exit code only (no output)"
                echo "  --project DIR Check specific project directory"
                echo "  --help        Show this help message"
                exit 0
                ;;
            *)
                echo "ERROR: Unknown option: \$1" >&2
                exit 1
                ;;
        esac
    done

    # Default project path to current directory
    if [[ -z "\$project_path" ]]; then
        project_path="\$(pwd)"
    fi

    # Run all checks
    run_all_checks "\$project_path"

    # Output
    if \$json_mode; then
        print_json
    elif ! \$quiet_mode; then
        print_human_readable "\$project_path"
    fi

    # Exit code: 0 = ok (warnings acceptable), 1 = failures
    local overall
    overall=\$(compute_overall)
    if [[ "\$overall" == "fail" ]]; then
        exit 1
    fi
    exit 0
}

# Source guard: execute main only when run directly, not when sourced
if [[ "\${BASH_SOURCE[0]}" == "\${0}" ]]; then
    main "\$@"
fi
EOF
make_executable "${PLSEC_DIR}/plsec-status.sh"

log_ok "Created wrapper scripts"

# -----------------------------------------------------------------------------
# 6. Create pre-commit hook template
# -----------------------------------------------------------------------------
log_info "Creating pre-commit hook template..."

write_file "${PLSEC_DIR}/configs/pre-commit" << EOF
#!/bin/bash
# Pre-commit hook for secret scanning

PLSEC_DIR="${PLSEC_DIR}"

echo "Running pre-commit security scan..."

# Check staged files for secrets
if command -v trivy &> /dev/null; then
    # Scan staged files
    git diff --cached --name-only | while read -r file; do
        if [[ -f "\$file" ]]; then
            trivy fs --secret-config "\${PLSEC_DIR}/trivy/trivy-secret.yaml" \
                --exit-code 1 --quiet "\$file" 2>/dev/null
            if [[ \$? -ne 0 ]]; then
                echo "ERROR: Potential secret detected in: \$file"
                echo "Run 'trivy fs \$file' for details"
                exit 1
            fi
        fi
    done
fi

exit 0
EOF
make_executable "${PLSEC_DIR}/configs/pre-commit"

log_ok "Created pre-commit hook template"

# -----------------------------------------------------------------------------
# 7. (Optional) Install Pipelock
# -----------------------------------------------------------------------------
if [[ "$WITH_PIPELOCK" == true ]]; then
    log_info "Installing Pipelock..."

    if ! command -v go &> /dev/null; then
        log_error "Go is required for Pipelock. Install with: brew install go"
        log_warn "Skipping Pipelock installation"
    else
        # Install Pipelock
        run_cmd go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest

        if command -v pipelock &> /dev/null || [[ "$DRY_RUN" == true ]]; then
            log_ok "Pipelock installed"

            # Generate audit config
            run_cmd pipelock generate config --preset balanced -o "${PLSEC_DIR}/pipelock.yaml"

            # Modify to audit mode (log only, don't block)
            if [[ "$DRY_RUN" == true ]]; then
                log_info "[DRY RUN] Would modify ${PLSEC_DIR}/pipelock.yaml: enforce: true -> enforce: false"
            else
                sed -i.bak 's/enforce: true/enforce: false/' "${PLSEC_DIR}/pipelock.yaml" 2>/dev/null || \
                sed -i '' 's/enforce: true/enforce: false/' "${PLSEC_DIR}/pipelock.yaml"
            fi

            log_ok "Pipelock configured in AUDIT mode (logging only)"
            log_warn "Review logs before enabling enforcement"

            # Create start script
            write_file "${PLSEC_DIR}/pipelock-start.sh" << EOF
#!/bin/bash
PLSEC_DIR="${PLSEC_DIR}"
LOG_FILE="\${PLSEC_DIR}/logs/pipelock.log"

echo "Starting Pipelock proxy (audit mode)..."
pipelock run --config "\${PLSEC_DIR}/pipelock.yaml" 2>&1 | tee -a "\$LOG_FILE"
EOF
            make_executable "${PLSEC_DIR}/pipelock-start.sh"
        else
            log_error "Pipelock installation failed"
        fi
    fi
fi

# -----------------------------------------------------------------------------
# 8. Create shell aliases
# -----------------------------------------------------------------------------
log_info "Setting up shell aliases..."

# Build aliases based on agent type
ALIASES="
# Peerlabs Security aliases
alias plsec-scan=\"${PLSEC_DIR}/scan.sh\"
alias plsec-status=\"${PLSEC_DIR}/plsec-status.sh\"
alias plsec-logs=\"tail -f ${PLSEC_DIR}/logs/*.log\"
"

if [[ "$AGENT_TYPE" == "claude" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    ALIASES+="alias claude-safe=\"${PLSEC_DIR}/claude-wrapper.sh\"
"
fi

if [[ "$AGENT_TYPE" == "opencode" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    ALIASES+="alias opencode-safe=\"${PLSEC_DIR}/opencode-wrapper.sh\"
"
fi

# Detect shell config file
if [[ -f "${HOME}/.zshrc" ]]; then
    SHELL_RC="${HOME}/.zshrc"
elif [[ -f "${HOME}/.bashrc" ]]; then
    SHELL_RC="${HOME}/.bashrc"
else
    SHELL_RC="${HOME}/.profile"
fi

# Check if already added
if ! grep -q "Peerlabs Security aliases" "$SHELL_RC" 2>/dev/null; then
    append_to_file "$SHELL_RC" "$ALIASES"
    log_ok "Added aliases to $SHELL_RC"
    log_warn "Run 'source $SHELL_RC' or restart terminal to use aliases"
else
    log_ok "Aliases already present in $SHELL_RC"
fi

# -----------------------------------------------------------------------------
# 9. Summary
# -----------------------------------------------------------------------------
echo ""
echo "========================================"
log_ok "Bootstrap complete!"
echo "========================================"
echo ""
echo "What was set up:"
if [[ "$AGENT_TYPE" == "claude" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    echo "  - CLAUDE.md template: ${PLSEC_DIR}/configs/CLAUDE.md"
fi
if [[ "$AGENT_TYPE" == "opencode" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    echo "  - opencode.json template: ${PLSEC_DIR}/configs/opencode.json"
    echo "  - Global opencode config: ~/.config/opencode/opencode.json"
fi
echo "  - Trivy config: ${PLSEC_DIR}/trivy/"
echo "  - Wrapper scripts: ${PLSEC_DIR}/"
echo "  - Logs directory: ${PLSEC_DIR}/logs/"
if [[ "$WITH_PIPELOCK" == true ]] && command -v pipelock &> /dev/null; then
    echo "  - Pipelock: ${PLSEC_DIR}/pipelock.yaml (audit mode)"
fi
echo ""
echo "Quick start:"
echo "  1. cd your-project"
if [[ "$AGENT_TYPE" == "claude" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    echo "  2. cp ${PLSEC_DIR}/configs/CLAUDE.md ."
fi
if [[ "$AGENT_TYPE" == "opencode" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    echo "  2. cp ${PLSEC_DIR}/configs/opencode.json ."
fi
echo ""
echo "  Use safe wrappers instead of direct commands:"
if [[ "$AGENT_TYPE" == "claude" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    echo "    claude-safe     # Instead of 'claude'"
fi
if [[ "$AGENT_TYPE" == "opencode" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    echo "    opencode-safe   # Instead of 'opencode'"
fi
echo ""
echo "  Run 'plsec-scan' to check for secrets before commits"
echo "  Run 'plsec-status' to check system health"
echo ""
echo "To install pre-commit hook in a project:"
echo "  cp ${PLSEC_DIR}/configs/pre-commit .git/hooks/"
echo ""
if [[ "$WITH_PIPELOCK" == true ]] && command -v pipelock &> /dev/null; then
    echo "To start Pipelock proxy (audit mode):"
    echo "  ${PLSEC_DIR}/pipelock-start.sh"
    echo ""
fi
echo "View logs:"
echo "  plsec-logs"
echo ""
echo "Documentation: ${PLSEC_DIR}/README.md"

} # end main

# Source guard: execute main only when run directly, not when sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
