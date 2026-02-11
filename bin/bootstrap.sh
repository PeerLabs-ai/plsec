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
#   2. Creates restrictive CLAUDE.md and/or .opencode.toml
#   3. Installs Trivy with LLM-tuned secret scanning
#   4. Sets up pre-commit hooks
#   5. (Optional) Installs and configures Pipelock in audit mode

set -euo pipefail

# Configuration
PLSEC_DIR="${HOME}/.plsec"
PLSEC_VERSION="0.1.1-bootstrap"
WITH_PIPELOCK=false
STRICT_MODE=false
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

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --with-pipelock) WITH_PIPELOCK=true; shift ;;
        --strict) STRICT_MODE=true; shift ;;
        --agent)
            AGENT_TYPE="$2"
            if [[ ! "$AGENT_TYPE" =~ ^(claude|opencode|both)$ ]]; then
                log_error "Invalid agent type: $AGENT_TYPE (use: claude, opencode, or both)"
                exit 1
            fi
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--with-pipelock] [--strict] [--agent TYPE]"
            echo ""
            echo "Options:"
            echo "  --with-pipelock  Install and configure Pipelock proxy (audit mode)"
            echo "  --strict         Use strict deny patterns (more restrictive)"
            echo "  --agent TYPE     Agent type: claude, opencode, or both (default: both)"
            exit 0
            ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

log_info "Peerlabs Security Bootstrap v${PLSEC_VERSION}"
log_info "Setting up AI coding assistant security..."
log_info "Agent type: ${AGENT_TYPE}"
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
    read -p "Install missing dependencies via Homebrew? (y/N) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [[ " ${MISSING_DEPS[*]} " =~ " homebrew " ]]; then
            log_info "Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        
        for dep in "${MISSING_DEPS[@]}"; do
            case $dep in
                homebrew) ;; # Already handled
                trivy) brew install trivy ;;
                go) brew install go ;;
                *) brew install "$dep" ;;
            esac
        done
        log_ok "Dependencies installed"
    else
        log_error "Cannot continue without dependencies"
        exit 1
    fi
fi

echo ""

# -----------------------------------------------------------------------------
# 2. Create plsec directory structure
# -----------------------------------------------------------------------------
log_info "Creating plsec directory structure..."

mkdir -p "${PLSEC_DIR}"/{configs,logs,manifests}
mkdir -p "${PLSEC_DIR}/trivy/policies"

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

Commands are logged to ~/.plsec/logs/
'
fi

# Write to plsec directory
if [[ "$AGENT_TYPE" == "claude" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    echo "$CLAUDE_MD_CONTENT" > "${PLSEC_DIR}/configs/CLAUDE.md"
    log_ok "Created ${PLSEC_DIR}/configs/CLAUDE.md"
fi

# -----------------------------------------------------------------------------
# 3b. Create Opencode configuration template
# -----------------------------------------------------------------------------
if [[ "$AGENT_TYPE" == "opencode" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    log_info "Creating .opencode.toml template..."

    if [[ "$STRICT_MODE" == true ]]; then
        OPENCODE_TOML_CONTENT='# .opencode.toml - Strict Security Configuration
# Place in project root or ~/.config/opencode/config.toml

[ai]
provider = "anthropic"  # or "openai", "openrouter"
model = "claude-sonnet-4-20250514"

[security]
# Require confirmation for all shell commands
confirm_commands = true
# Log all operations
audit_logging = true

[shell]
# Restricted shell - no network, limited filesystem
allow_network = false
# Commands requiring explicit approval
dangerous_commands = [
    "rm -rf",
    "curl",
    "wget",
    "ssh",
    "scp",
    "rsync",
    "nc",
    "netcat",
    "eval",
    "exec",
    "sudo",
    "chmod 777",
    "pip install",
    "npm install",
    "go install",
]

[filesystem]
# Restrict to project directory
sandbox = true
# Allowed paths (relative to project root)
allowed_paths = [
    ".",
    "src",
    "tests",
    "docs",
    "scripts",
]
# Explicitly denied paths
denied_paths = [
    ".env",
    ".env.*",
    "**/.git/config",
    "**/.ssh",
    "**/.aws",
    "**/.config",
    "**/secrets*",
    "**/credentials*",
    "**/*.pem",
    "**/*.key",
]

[logging]
# Log directory
dir = "~/.plsec/logs"
# Log level: debug, info, warn, error
level = "info"
# Include command output in logs
include_output = true

[behavior]
# Maximum file size to read (bytes)
max_file_size = 1048576  # 1MB
# Maximum lines to display
max_lines = 500
# Require confirmation for file writes outside allowed paths
confirm_writes = true
# Show full command before execution
show_commands = true
'
    else
        OPENCODE_TOML_CONTENT='# .opencode.toml - Balanced Security Configuration
# Place in project root or ~/.config/opencode/config.toml

[ai]
provider = "anthropic"  # or "openai", "openrouter"
model = "claude-sonnet-4-20250514"

[security]
# Require confirmation for dangerous commands
confirm_commands = true
# Log operations
audit_logging = true

[shell]
# Allow network but monitor
allow_network = true
# Commands requiring explicit approval
dangerous_commands = [
    "rm -rf",
    "curl",
    "wget",
    "ssh",
    "sudo",
    "chmod 777",
]

[filesystem]
# Soft sandbox - warn but allow
sandbox = false
# Denied paths (always blocked)
denied_paths = [
    ".env",
    ".env.*",
    "**/.ssh",
    "**/.aws",
    "**/secrets*",
    "**/*.pem",
    "**/*.key",
]

[logging]
dir = "~/.plsec/logs"
level = "info"
include_output = false

[behavior]
max_file_size = 5242880  # 5MB
max_lines = 1000
confirm_writes = false
show_commands = true
'
    fi

    echo "$OPENCODE_TOML_CONTENT" > "${PLSEC_DIR}/configs/.opencode.toml"
    log_ok "Created ${PLSEC_DIR}/configs/.opencode.toml"
    
    # Also create global config location
    mkdir -p "${HOME}/.config/opencode"
    if [[ ! -f "${HOME}/.config/opencode/config.toml" ]]; then
        cp "${PLSEC_DIR}/configs/.opencode.toml" "${HOME}/.config/opencode/config.toml"
        log_ok "Installed global config: ~/.config/opencode/config.toml"
    else
        log_warn "Global opencode config exists, not overwriting"
        log_info "Review: ${HOME}/.config/opencode/config.toml"
    fi
fi

# -----------------------------------------------------------------------------
# 4. Create Trivy secret scanning config
# -----------------------------------------------------------------------------
log_info "Creating Trivy configuration..."

cat > "${PLSEC_DIR}/trivy/trivy-secret.yaml" << 'EOF'
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
cat > "${PLSEC_DIR}/trivy/trivy.yaml" << 'EOF'
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
    cat > "${PLSEC_DIR}/claude-wrapper.sh" << 'EOF'
#!/bin/bash
# claude-wrapper.sh - Logging wrapper for Claude Code

PLSEC_DIR="${HOME}/.plsec"
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
    chmod +x "${PLSEC_DIR}/claude-wrapper.sh"
    log_ok "Created Claude Code wrapper"
fi

# Opencode logging wrapper
if [[ "$AGENT_TYPE" == "opencode" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    cat > "${PLSEC_DIR}/opencode-wrapper.sh" << 'EOF'
#!/bin/bash
# opencode-wrapper.sh - Logging wrapper for Opencode

PLSEC_DIR="${HOME}/.plsec"
LOG_FILE="${PLSEC_DIR}/logs/opencode-$(date +%Y%m%d).log"

log() {
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [$$] $*" >> "$LOG_FILE"
}

log "=== Session started: $(pwd) ==="
log "Args: $*"

# Copy .opencode.toml to project if not present
if [[ ! -f "./.opencode.toml" ]] && [[ -f "${PLSEC_DIR}/configs/.opencode.toml" ]]; then
    cp "${PLSEC_DIR}/configs/.opencode.toml" ./.opencode.toml
    log "Copied .opencode.toml to project"
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
    chmod +x "${PLSEC_DIR}/opencode-wrapper.sh"
    log_ok "Created Opencode wrapper"
fi

# Scan script
cat > "${PLSEC_DIR}/scan.sh" << 'EOF'
#!/bin/bash
# scan.sh - Run security scans

PLSEC_DIR="${HOME}/.plsec"
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
chmod +x "${PLSEC_DIR}/scan.sh"

log_ok "Created wrapper scripts"

# -----------------------------------------------------------------------------
# 6. Create pre-commit hook template
# -----------------------------------------------------------------------------
log_info "Creating pre-commit hook template..."

cat > "${PLSEC_DIR}/configs/pre-commit" << 'EOF'
#!/bin/bash
# Pre-commit hook for secret scanning

PLSEC_DIR="${HOME}/.plsec"

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
chmod +x "${PLSEC_DIR}/configs/pre-commit"

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
        go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest
        
        if command -v pipelock &> /dev/null; then
            log_ok "Pipelock installed"
            
            # Generate audit config
            pipelock generate config --preset balanced -o "${PLSEC_DIR}/pipelock.yaml"
            
            # Modify to audit mode (log only, don't block)
            sed -i.bak 's/enforce: true/enforce: false/' "${PLSEC_DIR}/pipelock.yaml" 2>/dev/null || \
            sed -i '' 's/enforce: true/enforce: false/' "${PLSEC_DIR}/pipelock.yaml"
            
            log_ok "Pipelock configured in AUDIT mode (logging only)"
            log_warn "Review logs before enabling enforcement"
            
            # Create start script
            cat > "${PLSEC_DIR}/pipelock-start.sh" << 'EOF'
#!/bin/bash
PLSEC_DIR="${HOME}/.plsec"
LOG_FILE="${PLSEC_DIR}/logs/pipelock.log"

echo "Starting Pipelock proxy (audit mode)..."
pipelock run --config "${PLSEC_DIR}/pipelock.yaml" 2>&1 | tee -a "$LOG_FILE"
EOF
            chmod +x "${PLSEC_DIR}/pipelock-start.sh"
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
alias plsec-scan="${HOME}/.plsec/scan.sh"
alias plsec-logs="tail -f ${HOME}/.plsec/logs/*.log"
'

if [[ "$AGENT_TYPE" == "claude" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    ALIASES+='alias claude-safe="${HOME}/.plsec/claude-wrapper.sh"
'
fi

if [[ "$AGENT_TYPE" == "opencode" ]] || [[ "$AGENT_TYPE" == "both" ]]; then
    ALIASES+='alias opencode-safe="${HOME}/.plsec/opencode-wrapper.sh"
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
    echo "$ALIASES" >> "$SHELL_RC"
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
    echo "  - .opencode.toml template: ${PLSEC_DIR}/configs/.opencode.toml"
    echo "  - Global opencode config: ~/.config/opencode/config.toml"
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
    echo "  2. cp ${PLSEC_DIR}/configs/.opencode.toml ."
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
