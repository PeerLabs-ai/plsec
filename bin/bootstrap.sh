#!/bin/bash
# bootstrap.sh - Immediate security setup for AI coding assistants
#
# This script provides minimal viable security for Claude Code and Opencode
# while the full plsec tooling is developed.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/.../bootstrap.sh | bash
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

# Configuration
PLSEC_DIR="${HOME}/.peerlabs/plsec"
PLSEC_VERSION="0.1.1-bootstrap"
WITH_PIPELOCK=false
STRICT_MODE=false
DRY_RUN=false
AGENT_TYPE="both"  # claude, opencode, or both

# Colors (disable if not tty)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' NC=''
fi

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_ok() {
    echo -e "${GREEN}[OK]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Dry-run helpers
# These wrap destructive operations so --dry-run shows intent without acting.

run_cmd() {
    # Execute a command, or print it in dry-run mode
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would run: $*"
    else
        "$@"
    fi
}

write_file() {
    # Write content (stdin) to a file, or describe the write in dry-run mode
    local target="$1"
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would write: ${target}"
        cat > /dev/null  # consume stdin
    else
        cat > "$target"
    fi
}

write_file_from_var() {
    # Write a variable's contents to a file, or describe the write in dry-run mode
    local target="$1"
    local content="$2"
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would write: ${target}"
    else
        echo "$content" > "$target"
    fi
}

copy_file() {
    # Copy a file, or describe the copy in dry-run mode
    local src="$1"
    local dst="$2"
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would copy: ${src} -> ${dst}"
    else
        cp "$src" "$dst"
    fi
}

make_executable() {
    # chmod +x a file, or describe it in dry-run mode
    local target="$1"
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would chmod +x: ${target}"
    else
        chmod +x "$target"
    fi
}

ensure_dir() {
    # mkdir -p, or describe it in dry-run mode
    local target="$1"
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would create directory: ${target}"
    else
        mkdir -p "$target"
    fi
}

append_to_file() {
    # Append content to a file, or describe it in dry-run mode
    local target="$1"
    local content="$2"
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would append to: ${target}"
    else
        echo "$content" >> "$target"
    fi
}

# Check OS type
detect_os() {
    log_info "Detecting details of ${OSTYPE}"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # Check macOS version
        log_info "Found darwin based system"
        macos_version=$(sw_vers -productVersion | cut -d. -f1)
        if [[ $macos_version -ge 26 ]]; then
            log_info "Detected macOS Tahoe (${macos_version}) or later"
            echo "macos"
        else
            log_error "macOS version ${macos_version} is not supported. Requires macOS 26 (Tahoe) or later."
            exit 1
        fi
    elif [[ -f /etc/debian_version ]]; then
        log_info "Detected Debian-based Linux (Ubuntu/Debian)"
        echo "linux"
    else
        log_error "Unsupported operating system"
        exit 1
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --with-pipelock) WITH_PIPELOCK=true; shift ;;
        --strict) STRICT_MODE=true; shift ;;
        --dry-run|--simulate) DRY_RUN=true; shift ;;
        --agent)
            AGENT_TYPE="$2"
            if [[ ! "$AGENT_TYPE" =~ ^(claude|opencode|both)$ ]]; then
                log_error "Invalid agent type: $AGENT_TYPE (use: claude, opencode, or both)"
                exit 1
            fi
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--with-pipelock] [--strict] [--dry-run] [--agent TYPE]"
            echo ""
            echo "Options:"
            echo "  --with-pipelock  Install and configure Pipelock proxy (audit mode)"
            echo "  --strict         Use strict deny patterns (more restrictive)"
            echo "  --dry-run        Show what would be done without making changes"
            echo "  --simulate       Alias for --dry-run"
            echo "  --agent TYPE     Agent type: claude, opencode, or both (default: both)"
            exit 0
            ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

log_info "Peerlabs Security Bootstrap v${PLSEC_VERSION}"
log_info "Setting up AI coding assistant security..."
log_info "Agent type: ${AGENT_TYPE}"
if [[ "$DRY_RUN" == true ]]; then
    log_warn "DRY RUN MODE - no changes will be made"
fi
echo ""

# -----------------------------------------------------------------------------
# 1. Check dependencies
# -----------------------------------------------------------------------------
log_info "Checking dependencies..."

check_command() {
    if command -v "$1" &> /dev/null; then
        log_ok "$1 found"
        return 0
    else
        log_warn "$1 not found"
        return 1
    fi
}

MISSING_DEPS=()

check_command brew || MISSING_DEPS+=("homebrew")
check_command git || MISSING_DEPS+=("git")
check_command python3 || MISSING_DEPS+=("python3")

# Optional but recommended
check_command trivy || MISSING_DEPS+=("trivy")
check_command bandit || log_warn "bandit not found (optional)"
check_command semgrep || log_warn "semgrep not found (optional)"

if [[ "$WITH_PIPELOCK" == true ]]; then
    check_command go || MISSING_DEPS+=("go")
fi

if [[ ${#MISSING_DEPS[@]} -gt 0 ]]; then
    log_warn "Missing dependencies: ${MISSING_DEPS[*]}"
    echo ""
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would prompt to install: ${MISSING_DEPS[*]}"
    else
        read -p "Install missing dependencies via Homebrew? (y/N) " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if [[ " ${MISSING_DEPS[*]} " =~ " homebrew " ]]; then
                log_info "Installing Homebrew..."
                run_cmd /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi

            for dep in "${MISSING_DEPS[@]}"; do
                case $dep in
                    homebrew) ;; # Already handled
                    trivy) run_cmd brew install trivy ;;
                    go) run_cmd brew install go ;;
                    *) run_cmd brew install "$dep" ;;
                esac
            done
            log_ok "Dependencies installed"
        else
            log_error "Cannot continue without dependencies"
            exit 1
        fi
    fi
fi

echo ""

# -----------------------------------------------------------------------------
# 2. Create plsec directory structure
# -----------------------------------------------------------------------------
log_info "Creating plsec directory structure..."

ensure_dir "${PLSEC_DIR}/configs"
ensure_dir "${PLSEC_DIR}/logs"
ensure_dir "${PLSEC_DIR}/manifests"
ensure_dir "${PLSEC_DIR}/trivy/policies"

log_ok "Created ${PLSEC_DIR}"

# -----------------------------------------------------------------------------
# 3. Create restrictive CLAUDE.md template
# -----------------------------------------------------------------------------
log_info "Creating CLAUDE.md template..."

if [[ "$STRICT_MODE" == true ]]; then
    CLAUDE_MD_CONTENT='# CLAUDE.md - Strict Security Configuration

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

All commands will be logged for security audit.
'
else
    CLAUDE_MD_CONTENT='# CLAUDE.md - Balanced Security Configuration

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
- Git operations (add, commit, status, diff)
- Package manager commands (pip, npm) with review

### Logging

Commands are logged to ~/.peerlabs/plsec/logs/
'
fi

# Write to plsec directory
if [[ "$AGENT_TYPE" == "claude" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    write_file_from_var "${PLSEC_DIR}/configs/CLAUDE.md" "$CLAUDE_MD_CONTENT"
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
        OPENCODE_JSON_CONTENT='{
  "$schema": "https://opencode.ai/config.json",
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
    else
        OPENCODE_JSON_CONTENT='{
  "$schema": "https://opencode.ai/config.json",
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
      "git *": "allow",
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

write_file "${PLSEC_DIR}/trivy/trivy-secret.yaml" << 'EOF'
# trivy-secret.yaml - LLM-tuned secret detection
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
    regex: (?i)(api[_-]?key|apikey)['":\s]*[=:]\s*['"]?([A-Za-z0-9_\-\/+=]{20,})['"]?

  - id: generic-secret
    category: generic
    title: Generic Secret/Token
    severity: HIGH
    keywords: [secret, token, password, auth]
    regex: (?i)(secret|token|password|auth[_-]?token)\b.{0,40}['"]?[A-Za-z0-9_\-\/+=]{12,}['"]?

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
    regex: (?i)(aws_secret_access_key|aws_secret_key)\b.{0,40}['"]?[0-9A-Za-z\/+=]{40}['"]?
EOF

log_ok "Created ${PLSEC_DIR}/trivy/trivy-secret.yaml"

# Main trivy config
write_file "${PLSEC_DIR}/trivy/trivy.yaml" << 'EOF'
scan:
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
exit-code: 1
EOF

log_ok "Created ${PLSEC_DIR}/trivy/trivy.yaml"

# -----------------------------------------------------------------------------
# 5. Create wrapper scripts
# -----------------------------------------------------------------------------
log_info "Creating wrapper scripts..."

# Claude Code logging wrapper
if [[ "$AGENT_TYPE" == "claude" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    write_file "${PLSEC_DIR}/claude-wrapper.sh" << 'EOF'
#!/bin/bash
# claude-wrapper.sh - Logging wrapper for Claude Code

PLSEC_DIR="${HOME}/.peerlabs/plsec"
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
EOF
    make_executable "${PLSEC_DIR}/claude-wrapper.sh"
    log_ok "Created Claude Code wrapper"
fi

# Opencode logging wrapper
if [[ "$AGENT_TYPE" == "opencode" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    write_file "${PLSEC_DIR}/opencode-wrapper.sh" << 'EOF'
#!/bin/bash
# opencode-wrapper.sh - Logging wrapper for Opencode

PLSEC_DIR="${HOME}/.peerlabs/plsec"
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
EOF
    make_executable "${PLSEC_DIR}/opencode-wrapper.sh"
    log_ok "Created Opencode wrapper"
fi

# Scan script
write_file "${PLSEC_DIR}/scan.sh" << 'EOF'
#!/bin/bash
# scan.sh - Run security scans

PLSEC_DIR="${HOME}/.peerlabs/plsec"
TARGET="${1:-.}"

echo "Running security scans on: $TARGET"
echo ""

# Trivy secrets
if command -v trivy &> /dev/null; then
    echo "=== Trivy Secret Scan ==="
    trivy fs --secret-config "${PLSEC_DIR}/trivy/trivy-secret.yaml" "$TARGET"
    echo ""
fi

# Bandit (Python)
if command -v bandit &> /dev/null && [[ -d "$TARGET" ]]; then
    if find "$TARGET" -name "*.py" -type f | head -1 | grep -q .; then
        echo "=== Bandit (Python) ==="
        bandit -r "$TARGET" -ll 2>/dev/null || true
        echo ""
    fi
fi

# Semgrep
if command -v semgrep &> /dev/null; then
    echo "=== Semgrep ==="
    semgrep --config auto "$TARGET" --quiet 2>/dev/null || true
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

write_file "${PLSEC_DIR}/configs/pre-commit" << 'EOF'
#!/bin/bash
# Pre-commit hook for secret scanning

PLSEC_DIR="${HOME}/.peerlabs/plsec"

echo "Running pre-commit security scan..."

# Check staged files for secrets
if command -v trivy &> /dev/null; then
    # Scan staged files
    git diff --cached --name-only | while read -r file; do
        if [[ -f "$file" ]]; then
            trivy fs --secret-config "${PLSEC_DIR}/trivy/trivy-secret.yaml" \
                --exit-code 1 --quiet "$file" 2>/dev/null
            if [[ $? -ne 0 ]]; then
                echo "ERROR: Potential secret detected in: $file"
                echo "Run 'trivy fs $file' for details"
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
            write_file "${PLSEC_DIR}/pipelock-start.sh" << 'EOF'
#!/bin/bash
PLSEC_DIR="${HOME}/.peerlabs/plsec"
LOG_FILE="${PLSEC_DIR}/logs/pipelock.log"

echo "Starting Pipelock proxy (audit mode)..."
pipelock run --config "${PLSEC_DIR}/pipelock.yaml" 2>&1 | tee -a "$LOG_FILE"
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
ALIASES='
# Peerlabs Security aliases
alias plsec-scan="${HOME}/.peerlabs/plsec/scan.sh"
alias plsec-logs="tail -f ${HOME}/.peerlabs/plsec/logs/*.log"
'

if [[ "$AGENT_TYPE" == "claude" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    ALIASES+='alias claude-safe="${HOME}/.peerlabs/plsec/claude-wrapper.sh"
'
fi

if [[ "$AGENT_TYPE" == "opencode" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    ALIASES+='alias opencode-safe="${HOME}/.peerlabs/plsec/opencode-wrapper.sh"
'
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
