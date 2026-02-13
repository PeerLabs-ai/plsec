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
PLSEC_VERSION="${PLSEC_VERSION:-0.1.0}"
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
    regex: \bsk-(?!proj|svcacct|None|ant)[A-Za-z0-9]{40,64}\b

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

PLSEC_DIR="${PLSEC_DIR}"
LOG_FILE="\${PLSEC_DIR}/logs/claude-\$(date +%Y%m%d).log"

log() {
    echo "[\$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [\$\$] \$*" >> "\$LOG_FILE"
}

log "=== Session started: \$(pwd) ==="
log "Args: \$*"

# Copy CLAUDE.md to project if not present
if [[ ! -f "./CLAUDE.md" ]] && [[ -f "\${PLSEC_DIR}/configs/CLAUDE.md" ]]; then
    cp "\${PLSEC_DIR}/configs/CLAUDE.md" ./CLAUDE.md
    log "Copied CLAUDE.md to project"
fi

# Run Claude Code
claude "\$@"
EXIT_CODE=\$?

log "=== Session ended: exit code \$EXIT_CODE ==="
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

PLSEC_DIR="${PLSEC_DIR}"
LOG_FILE="\${PLSEC_DIR}/logs/opencode-\$(date +%Y%m%d).log"

log() {
    echo "[\$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [\$\$] \$*" >> "\$LOG_FILE"
}

log "=== Session started: \$(pwd) ==="
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

log "=== Session ended: exit code \$EXIT_CODE ==="
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
