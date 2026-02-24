"""
Embedded configuration templates.

These templates are used by plsec install and plsec init to generate configuration files.
"""

CLAUDE_MD_STRICT = """# CLAUDE.md - Strict Security Configuration

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
"""

CLAUDE_MD_BALANCED = """# CLAUDE.md - Balanced Security Configuration

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
"""

OPENCODE_JSON_STRICT = """{
  "$schema": "https://opencode.ai/config.json",
  "model": "anthropic/claude-sonnet-4-5",
  "permission": {
    "*": "deny",
    "bash": {
      "*": "deny",
      "git status": "allow",
      "git status *": "allow",
      "git diff": "allow",
      "git diff *": "allow",
      "git log": "allow",
      "git log *": "allow",
      "git branch": "allow",
      "git branch *": "allow",
      "ls *": "allow",
      "cat *": "ask",
      "head *": "allow",
      "tail *": "allow",
      "wc *": "allow",
      "grep *": "allow",
      "find *": "allow",
      "pwd": "allow",
      "echo *": "ask"
    },
    "edit": "ask",
    "read": {
      "*": "ask",
      "*.env": "deny",
      "*.env.*": "deny",
      ".env": "deny",
      ".env.*": "deny",
      "*.pem": "deny",
      "*.key": "deny",
      "*.p12": "deny",
      ".aws/**": "deny",
      ".ssh/**": "deny",
      ".config/**": "deny",
      "**/secrets/**": "deny",
      "**/credentials/**": "deny"
    },
    "webfetch": "deny",
    "external_directory": "deny",
    "doom_loop": "deny"
  }
}
"""

OPENCODE_JSON_BALANCED = """{
  "$schema": "https://opencode.ai/config.json",
  "model": "anthropic/claude-sonnet-4-5",
  "permission": {
    "*": "ask",
    "bash": {
      "*": "ask",
      "git status": "allow",
      "git status *": "allow",
      "git diff": "allow",
      "git diff *": "allow",
      "git log": "allow",
      "git log *": "allow",
      "git branch": "allow",
      "git branch *": "allow",
      "git add *": "ask",
      "git commit *": "ask",
      "git push *": "ask",
      "ls *": "allow",
      "cat *": "allow",
      "head *": "allow",
      "tail *": "allow",
      "wc *": "allow",
      "grep *": "allow",
      "find *": "allow",
      "pwd": "allow",
      "rm -rf *": "deny",
      "rm -r *": "ask",
      "curl *": "ask",
      "wget *": "ask",
      "ssh *": "deny",
      "scp *": "deny",
      "sudo *": "deny"
    },
    "edit": "ask",
    "read": {
      "*": "allow",
      "*.env": "deny",
      "*.env.*": "deny",
      ".env": "deny",
      ".env.*": "deny",
      ".env.example": "allow",
      "*.pem": "deny",
      "*.key": "deny",
      "*.p12": "deny",
      ".aws/**": "deny",
      ".ssh/**": "deny"
    },
    "webfetch": "ask",
    "external_directory": "ask",
    "doom_loop": "ask"
  }
}
"""

PLSEC_YAML_TEMPLATE = """# plsec.yaml - Security configuration
# Generated by plsec init

version: 1

project:
  name: {project_name}
  type: {project_type}

agent:
  type: {agent_type}
  config_path: ./CLAUDE.md

layers:
  static:
    enabled: true
    scanners:
      - trivy-secrets
      - trivy-misconfig
      - bandit
      - semgrep

  isolation:
    enabled: {isolation_enabled}
    runtime: podman

  proxy:
    enabled: {proxy_enabled}
    binary: pipelock
    mode: {proxy_mode}
    config: ./pipelock.yaml

  audit:
    enabled: true
    log_dir: ~/.peerlabs/plsec/logs
    integrity: {integrity_enabled}

credentials:
  storage: keychain
  keys: []
"""

# Content must stay in sync with templates/bootstrap/trivy-secret.yaml.
# The bootstrap template is the authoritative source; this Python string
# is the CLI-side copy used by plsec init and plsec create.
TRIVY_SCAN_RULES_YAML = """# trivy-secret.yaml - LLM-tuned secret detection
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
    regex: (?i)(api[_-]?key|apikey)['":\\s]*[=:]\\s*['"]?([A-Za-z0-9_\\-\\/+=]{20,})['"]?

  - id: generic-secret
    category: generic
    title: Generic Secret/Token
    severity: HIGH
    keywords: [secret, token, password, auth]
    regex: (?i)(secret|token|password|auth[_-]?token)\\b.{0,40}['"]?[A-Za-z0-9_\\-\\/+=]{12,}['"]?

  - id: private-key
    category: generic
    title: Private Key
    severity: CRITICAL
    keywords:
      - "BEGIN RSA PRIVATE KEY"
      - "BEGIN EC PRIVATE KEY"
      - "BEGIN OPENSSH PRIVATE KEY"
      - "BEGIN PRIVATE KEY"
    regex: "-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----"

  # Provider-specific
  - id: anthropic-api-key
    category: Anthropic
    title: Anthropic API Key
    severity: CRITICAL
    keywords: [ANTHROPIC_API_KEY, sk-ant-, anthropic]
    regex: \\bsk-ant-[A-Za-z0-9_-]{32,200}\\b

  - id: openai-api-key
    category: OpenAI
    title: OpenAI API Key
    severity: CRITICAL
    keywords: [OPENAI_API_KEY, sk-proj-, sk-]
    regex: \\bsk-(proj|svcacct|None)-[A-Za-z0-9_-]{32,200}\\b

  - id: openai-legacy
    category: OpenAI
    title: OpenAI Legacy Key
    severity: CRITICAL
    keywords: [OPENAI_API_KEY, sk-]
    # Legacy keys are sk- followed by pure alphanumeric (no hyphens).
    # Modern formats (sk-proj-, sk-ant-, sk-svcacct-) contain hyphens
    # and are caught by the openai-api-key and anthropic-api-key rules.
    # RE2-compatible: no negative lookahead needed.
    regex: \\bsk-[A-Za-z0-9]{40,64}\\b

  - id: github-token
    category: GitHub
    title: GitHub Token
    severity: CRITICAL
    keywords: [ghp_, gho_, GITHUB_TOKEN]
    regex: \\bgh[pousr]_[A-Za-z0-9]{36}\\b

  - id: aws-access-key
    category: AWS
    title: AWS Access Key
    severity: CRITICAL
    keywords: [AWS_ACCESS_KEY_ID, AKIA, ASIA]
    regex: \\b(AKIA|ASIA)[0-9A-Z]{16}\\b

  - id: aws-secret-key
    category: AWS
    title: AWS Secret Key
    severity: CRITICAL
    keywords: [AWS_SECRET_ACCESS_KEY, aws_secret_key]
    regex: (?i)(aws_secret_access_key|aws_secret_key)\\b.{0,40}['"]?[0-9A-Za-z\\/+=]{40}['"]?
"""

# Content must stay in sync with templates/bootstrap/trivy.yaml.
TRIVY_CONFIG_YAML = """scan:
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
exit-code: 1
"""

# ---------------------------------------------------------------------------
# Wrapper scripts -- deployed by plsec install to ~/.peerlabs/plsec/
#
# These templates use {plsec_dir} as a format placeholder, substituted at
# deploy time with the actual plsec home path.  Content must stay in sync
# with the corresponding files in templates/bootstrap/.
# ---------------------------------------------------------------------------

# Placeholder sentinel -- deploy code replaces this with the real path.
_PLSEC_DIR_PLACEHOLDER = "@@PLSEC_DIR@@"

WRAPPER_CLAUDE_SH = """#!/bin/bash
# claude-wrapper.sh - Logging wrapper for Claude Code
#
# Tier 1: Session enrichment (git info, duration, preset, agent version)
# Tier 2: CLAUDE_CODE_SHELL_PREFIX audit logging

PLSEC_DIR="@@PLSEC_DIR@@"
LOG_FILE="${PLSEC_DIR}/logs/claude-$(date +%Y%m%d).log"

log() {
    echo "[$(date -u +\\"%Y-%m-%dT%H:%M:%SZ\\")] [$$] $*" >> "$LOG_FILE"
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
log "branch=${_git_branch} sha=${_git_sha} preset=${_preset} agent=${_agent_version}"
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
"""

WRAPPER_OPENCODE_SH = """#!/bin/bash
# opencode-wrapper.sh - Logging wrapper for Opencode
#
# Tier 1: Session enrichment (git info, duration, preset, agent version)

PLSEC_DIR="@@PLSEC_DIR@@"
LOG_FILE="${PLSEC_DIR}/logs/opencode-$(date +%Y%m%d).log"

log() {
    echo "[$(date -u +\\"%Y-%m-%dT%H:%M:%SZ\\")] [$$] $*" >> "$LOG_FILE"
}

# ---------------------------------------------------------------------------
# Tier 1: Gather session context (best-effort, never block startup)
# ---------------------------------------------------------------------------

_git_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "n/a")
_git_sha=$(git rev-parse --short HEAD 2>/dev/null || echo "n/a")
_agent_version=$(opencode --version 2>/dev/null | head -1 || echo "n/a")

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
log "branch=${_git_branch} sha=${_git_sha} preset=${_preset} agent=${_agent_version}"
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

ELAPSED=$(( SECONDS - START_SECONDS ))
log "=== Session ended: exit code ${EXIT_CODE} duration=${ELAPSED}s ==="
exit $EXIT_CODE
"""

PLSEC_AUDIT_SH = """#!/bin/bash
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
    echo "[$(date -u +\\"%Y-%m-%dT%H:%M:%SZ\\")] [$$] cwd=$(pwd) cmd=$*"
} >> "$AUDIT_LOG" 2>/dev/null

# Execute the original command, preserving exit code
exec "$@"
"""

# Map from wrapper template name (in AgentSpec) to template constant.
# Used by deploy_global_configs() to resolve wrapper content.
WRAPPER_TEMPLATES: dict[str, str] = {
    "wrapper-claude.sh": WRAPPER_CLAUDE_SH,
    "wrapper-opencode.sh": WRAPPER_OPENCODE_SH,
}

# Scripts deployed alongside wrappers (not agent-specific).
# Each tuple is (filename, content).
STANDALONE_SCRIPTS: list[tuple[str, str]] = [
    ("plsec-audit.sh", PLSEC_AUDIT_SH),
]


PRE_COMMIT_HOOK = """#!/bin/bash
# Pre-commit hook for secret scanning

PLSEC_DIR="${HOME}/.peerlabs/plsec"

echo "Running pre-commit security scan..."

# Check staged files for secrets
if command -v trivy &> /dev/null; then
    # Scan staged files
    git diff --cached --name-only | while read -r file; do
        if [[ -f "$file" ]]; then
            trivy fs --secret-config "${PLSEC_DIR}/trivy/trivy-secret.yaml" \\
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
"""
