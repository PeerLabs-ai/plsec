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

PLSEC_STATUS_SH = """#!/bin/bash
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

PLSEC_DIR="@@PLSEC_DIR@@"
PLSEC_VERSION="${PLSEC_VERSION:-unknown}"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Staleness thresholds (seconds)
STALE_WARN_SECONDS=$((24 * 60 * 60))   # 24 hours
STALE_FAIL_SECONDS=$((7 * 24 * 60 * 60))  # 7 days

# Expected subdirectories
EXPECTED_SUBDIRS="configs logs manifests trivy trivy/policies"

# Expected scanner config files (relative to PLSEC_DIR)
EXPECTED_SCANNER_CONFIGS="trivy/trivy-secret.yaml trivy/trivy.yaml configs/pre-commit"

# ---------------------------------------------------------------------------
# Color support
# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then
    GREEN='\\033[0;32m'
    YELLOW='\\033[0;33m'
    RED='\\033[0;31m'
    GREY='\\033[0;90m'
    BOLD='\\033[1m'
    RESET='\\033[0m'
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
    local id="$1" category="$2" name="$3" verdict="$4" detail="${5:-}"

    CHECK_IDS+=("$id")
    CHECK_CATEGORIES+=("$category")
    CHECK_NAMES+=("$name")
    VERDICTS+=("$verdict")
    CHECK_DETAILS+=("$detail")

    case "$verdict" in
        warn) WARNING_COUNT=$((WARNING_COUNT + 1)) ;;
        fail) ERROR_COUNT=$((ERROR_COUNT + 1)) ;;
    esac
}

# ---------------------------------------------------------------------------
# Verdict helpers
# ---------------------------------------------------------------------------

# Compute overall verdict from the VERDICTS array.
# ok = no failures. fail = any failure. Warnings are acceptable.
compute_overall() {
    local v
    for v in "${VERDICTS[@]}"; do
        if [[ "$v" == "fail" ]]; then
            echo "fail"
            return
        fi
    done
    echo "ok"
}

# Format a verdict string for display.
format_verdict() {
    local verdict="$1"
    case "$verdict" in
        ok)   printf "${GREEN}%-4s${RESET}" "OK" ;;
        warn) printf "${YELLOW}%-4s${RESET}" "WARN" ;;
        fail) printf "${RED}%-4s${RESET}" "FAIL" ;;
        skip) printf "${GREY}%-4s${RESET}" "SKIP" ;;
        *)    printf "%-4s" "????" ;;
    esac
}

# ---------------------------------------------------------------------------
# Installation checks
# ---------------------------------------------------------------------------

# I-1: Check PLSEC_DIR exists
check_plsec_dir() {
    if [[ -d "$PLSEC_DIR" ]]; then
        record_check "I-1" "installation" "plsec directory" "ok" "$PLSEC_DIR"
        echo "ok"
    else
        record_check "I-1" "installation" "plsec directory" "fail" "$PLSEC_DIR"
        echo "fail"
    fi
}

# I-1 (sub): Check expected subdirectories
check_subdirs() {
    local missing=0
    local subdir
    for subdir in $EXPECTED_SUBDIRS; do
        if [[ ! -d "${PLSEC_DIR}/${subdir}" ]]; then
            missing=$((missing + 1))
        fi
    done

    if [[ $missing -eq 0 ]]; then
        record_check "I-1" "installation" "subdirectories" "ok" "all present"
        echo "ok"
    else
        record_check "I-1" "installation" "subdirectories" "warn" "${missing} missing"
        echo "warn"
    fi
}

# I-2, I-3: Check agent config file in configs/
# Usage: check_agent_config "CLAUDE.md"
check_agent_config() {
    local filename="$1"
    local config_path="${PLSEC_DIR}/configs/${filename}"

    if [[ -f "$config_path" ]]; then
        if [[ ! -s "$config_path" ]]; then
            record_check "I-agent" "installation" "${filename} config" "warn" "empty file"
            echo "warn"
        else
            record_check "I-agent" "installation" "${filename} config" "ok" "$config_path"
            echo "ok"
        fi
    else
        record_check "I-agent" "installation" "${filename} config" "fail" "missing"
        echo "fail"
    fi
}

# I-4 through I-11: Check a tool binary
# Usage: check_tool "trivy" "required"
check_tool() {
    local tool_name="$1"
    local requirement="${2:-required}"  # "required" or "optional"

    if command -v "$tool_name" &> /dev/null; then
        local tool_path
        tool_path=$(command -v "$tool_name")
        record_check "I-tool" "installation" "$tool_name" "ok" "$tool_path"
        echo "ok"
    else
        if [[ "$requirement" == "required" ]]; then
            record_check "I-tool" "installation" "$tool_name" "fail" "not found"
            echo "fail"
        else
            record_check "I-tool" "installation" "$tool_name" "warn" "not found (optional)"
            echo "warn"
        fi
    fi
}

# I-5, I-6: Check scanner config file
# Usage: check_scanner_config "trivy/trivy-secret.yaml" "Trivy secret rules"
check_scanner_config() {
    local rel_path="$1"
    local description="$2"
    local full_path="${PLSEC_DIR}/${rel_path}"

    if [[ -f "$full_path" ]]; then
        record_check "I-scanner" "installation" "$description" "ok" "$full_path"
        echo "ok"
    else
        record_check "I-scanner" "installation" "$description" "warn" "${rel_path} missing"
        echo "warn"
    fi
}

# I-7: Check wrapper script exists and is executable
# Usage: check_wrapper_script "claude-wrapper.sh" "Claude Code wrapper"
check_wrapper_script() {
    local filename="$1"
    local description="$2"
    local full_path="${PLSEC_DIR}/${filename}"

    if [[ -f "$full_path" ]]; then
        if [[ -x "$full_path" ]]; then
            record_check "I-7" "installation" "$description" "ok" "$full_path"
            echo "ok"
        else
            record_check "I-7" "installation" "$description" "warn" "not executable"
            echo "warn"
        fi
    else
        record_check "I-7" "installation" "$description" "fail" "missing"
        echo "fail"
    fi
}

# ---------------------------------------------------------------------------
# Configuration checks
# ---------------------------------------------------------------------------

# C-1: Detect security mode from CLAUDE.md content
detect_security_mode() {
    local claude_md="${PLSEC_DIR}/configs/CLAUDE.md"
    if [[ ! -f "$claude_md" ]]; then
        echo "unknown"
        return
    fi
    if grep -q "RESTRICTED" "$claude_md" 2>/dev/null; then
        echo "strict"
    elif grep -q "Security Constraints" "$claude_md" 2>/dev/null; then
        echo "balanced"
    else
        echo "unknown"
    fi
}

# C-2: Detect which agents are configured
detect_agents() {
    local agents=()
    if [[ -f "${PLSEC_DIR}/configs/CLAUDE.md" ]]; then
        agents+=("claude")
    fi
    if [[ -f "${PLSEC_DIR}/configs/opencode.json" ]]; then
        agents+=("opencode")
    fi

    if [[ ${#agents[@]} -eq 0 ]]; then
        echo "none"
    else
        echo "${agents[*]}"
    fi
}

# C-3: Check pre-commit hook in project
# Usage: check_precommit_hook "/path/to/project"
check_precommit_hook() {
    local project_path="$1"
    local hook_path="${project_path}/.git/hooks/pre-commit"

    if [[ ! -d "${project_path}/.git" ]]; then
        record_check "C-3" "configuration" "pre-commit hook" "fail" "not a git repo"
        echo "fail"
        return
    fi

    if [[ ! -f "$hook_path" ]]; then
        record_check "C-3" "configuration" "pre-commit hook" "fail" "hook missing"
        echo "fail"
        return
    fi

    if grep -q "plsec\\|trivy" "$hook_path" 2>/dev/null; then
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
    local project_path="$1"
    local filename="$2"
    local project_config="${project_path}/${filename}"
    local template_config="${PLSEC_DIR}/configs/${filename}"

    if [[ ! -f "$project_config" ]]; then
        record_check "C-project" "configuration" "${filename} (project)" "fail" "not found"
        echo "fail"
        return
    fi

    if [[ -f "$template_config" ]] && \\
       diff -q "$project_config" "$template_config" > /dev/null 2>&1; then
        record_check "C-project" "configuration" "${filename} (project)" "ok" \\
                     "matches template"
        echo "ok"
    else
        record_check "C-project" "configuration" "${filename} (project)" "warn" \\
                     "differs from template"
        echo "warn"
    fi
}

# ---------------------------------------------------------------------------
# Activity checks
# ---------------------------------------------------------------------------

# A-1: Check wrapper log freshness
check_log_freshness() {
    local log_dir="${PLSEC_DIR}/logs"
    local newest_log=""
    local newest_age=""

    # Find the most recently modified .log file
    if [[ -d "$log_dir" ]]; then
        newest_log=$(find "$log_dir" -name "*.log" -type f -print 2>/dev/null | head -1)
    fi

    if [[ -z "$newest_log" ]]; then
        record_check "A-1" "activity" "wrapper logs" "fail" "no log files found"
        echo "fail"
        return
    fi

    # Get age of newest log in seconds
    local now
    now=$(date +%s)
    local mod_time
    # macOS stat vs GNU stat
    if stat -f %m "$newest_log" > /dev/null 2>&1; then
        mod_time=$(stat -f %m "$newest_log")
    else
        mod_time=$(stat -c %Y "$newest_log")
    fi
    newest_age=$((now - mod_time))

    if [[ $newest_age -lt $STALE_WARN_SECONDS ]]; then
        record_check "A-1" "activity" "wrapper logs" "ok" "active within 24h"
        echo "ok"
    elif [[ $newest_age -lt $STALE_FAIL_SECONDS ]]; then
        record_check "A-1" "activity" "wrapper logs" "warn" "stale (>24h, <7d)"
        echo "warn"
    else
        record_check "A-1" "activity" "wrapper logs" "fail" "inactive (>7d)"
        echo "fail"
    fi
}

# A-2: Count sessions in today's logs
check_session_count() {
    local log_dir="${PLSEC_DIR}/logs"
    local today
    today=$(date +%Y%m%d)
    local count=0

    # Count "Session started" lines in today's log files
    if [[ -d "$log_dir" ]]; then
        local log_file
        for log_file in "${log_dir}/"*"-${today}.log"; do
            if [[ -f "$log_file" ]]; then
                local file_count
                file_count=$(grep -c "Session started" "$log_file" 2>/dev/null || echo 0)
                count=$((count + file_count))
            fi
        done
    fi

    if [[ $count -gt 0 ]]; then
        record_check "A-2" "activity" "sessions today" "ok" "${count} session(s)"
        echo "ok ${count}"
    elif [[ -d "$log_dir" ]] && find "$log_dir" -name "*.log" -type f | grep -q . 2>/dev/null; then
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
    local log_dir="${PLSEC_DIR}/logs"
    local today
    today=$(date +%Y%m%d)

    # Check for scan-YYYYMMDD.jsonl files or scan-latest.json
    if [[ -f "${log_dir}/scan-${today}.jsonl" ]]; then
        record_check "A-3" "activity" "last scan" "ok" "scan run today"
        echo "ok"
        return
    fi

    if [[ -f "${log_dir}/scan-latest.json" ]]; then
        # Scan data exists but not from today - check age
        local now
        now=$(date +%s)
        local mod_time
        if stat -f %m "${log_dir}/scan-latest.json" > /dev/null 2>&1; then
            mod_time=$(stat -f %m "${log_dir}/scan-latest.json")
        else
            mod_time=$(stat -c %Y "${log_dir}/scan-latest.json")
        fi
        local age=$((now - mod_time))

        if [[ $age -lt $STALE_WARN_SECONDS ]]; then
            record_check "A-3" "activity" "last scan" "ok" "within 24h"
            echo "ok"
        else
            record_check "A-3" "activity" "last scan" "warn" "last scan >24h ago"
            echo "warn"
        fi
        return
    fi

    # Check for any scan JSONL files
    if find "$log_dir" -name "scan-*.jsonl" -type f 2>/dev/null | grep -q .; then
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
    local latest="${PLSEC_DIR}/logs/scan-latest.json"

    if [[ ! -f "$latest" ]]; then
        record_check "F-1" "findings" "secrets detected" "skip" "no scan data"
        echo "skip"
        return
    fi

    # Parse overall_passed field (simple grep, no jq dependency)
    if grep -q '"overall_passed": true' "$latest" 2>/dev/null || \\
       grep -q '"overall_passed":true' "$latest" 2>/dev/null; then
        record_check "F-1" "findings" "secrets detected" "ok" "last scan clean"
        echo "ok"
    else
        record_check "F-1" "findings" "secrets detected" "fail" "findings in last scan"
        echo "fail"
    fi
}

# F-2: Check for pre-commit hook blocks
check_hook_blocks() {
    local log_dir="${PLSEC_DIR}/logs"

    if [[ ! -d "$log_dir" ]] || \\
       ! find "$log_dir" -name "*.log" -type f 2>/dev/null | grep -q .; then
        record_check "F-2" "findings" "hook blocks" "skip" "no logs"
        echo "skip"
        return
    fi

    # Look for hook rejection evidence in recent logs
    if grep -rq "ERROR.*secret\\|hook.*blocked\\|commit.*rejected" \\
            "${log_dir}/"*.log 2>/dev/null; then
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
    mode=$(detect_security_mode)
    local agents
    agents=$(detect_agents)

    printf "\\n${BOLD}plsec v%s [%s] [%s]${RESET}\\n\\n" "$PLSEC_VERSION" "$mode" "$agents"
}

print_section() {
    local section="$1"
    printf "\\n  ${BOLD}%s${RESET}\\n" "$section"
}

print_check_line() {
    local name="$1" verdict="$2" detail="$3"
    local verdict_str
    verdict_str=$(format_verdict "$verdict")
    if [[ -n "$detail" ]]; then
        printf "    %-25s %s  %s\\n" "$name" "$verdict_str" "$detail"
    else
        printf "    %-25s %s\\n" "$name" "$verdict_str"
    fi
}

print_summary() {
    local overall
    overall=$(compute_overall)
    local verdict_str
    verdict_str=$(format_verdict "$overall")

    printf "\\n  Overall: %s" "$verdict_str"
    if [[ $WARNING_COUNT -gt 0 ]] || [[ $ERROR_COUNT -gt 0 ]]; then
        printf " ("
        local parts=()
        if [[ $ERROR_COUNT -gt 0 ]]; then
            parts+=("${ERROR_COUNT} error(s)")
        fi
        if [[ $WARNING_COUNT -gt 0 ]]; then
            parts+=("${WARNING_COUNT} warning(s)")
        fi
        local IFS=", "
        printf "%s" "${parts[*]}"
        printf ")"
    fi
    printf "\\n\\n"
}

# ---------------------------------------------------------------------------
# JSON output (pure bash, no jq dependency)
# ---------------------------------------------------------------------------

# Escape a string for JSON output (awk-based to avoid assembler escaping conflicts)
json_escape() {
    printf '%s' "$1" | awk '
    BEGIN { ORS="" }
    {
        gsub(/\\\\/, "\\\\\\\\")
        gsub(/"/, "\\\\\\"")
        gsub(/\\t/, "\\\\t")
        print
    }'
}

print_json() {
    local mode
    mode=$(detect_security_mode)
    local agents_str
    agents_str=$(detect_agents)
    local overall
    overall=$(compute_overall)
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    printf '{\\n'
    printf '  "version": "%s",\\n' "$(json_escape "$PLSEC_VERSION")"
    printf '  "mode": "%s",\\n' "$(json_escape "$mode")"

    # Agents array
    printf '  "agents": ['
    local first=true
    local agent
    for agent in $agents_str; do
        if [[ "$agent" != "none" ]]; then
            if [[ "$first" == true ]]; then
                first=false
            else
                printf ', '
            fi
            printf '"%s"' "$(json_escape "$agent")"
        fi
    done
    printf '],\\n'

    printf '  "overall": "%s",\\n' "$overall"
    printf '  "warnings": %d,\\n' "$WARNING_COUNT"
    printf '  "errors": %d,\\n' "$ERROR_COUNT"
    printf '  "timestamp": "%s",\\n' "$timestamp"

    # Checks array
    printf '  "checks": [\\n'
    local i
    local count=${#CHECK_IDS[@]}
    for ((i = 0; i < count; i++)); do
        printf '    {\\n'
        printf '      "id": "%s",\\n' "$(json_escape "${CHECK_IDS[$i]}")"
        printf '      "category": "%s",\\n' "$(json_escape "${CHECK_CATEGORIES[$i]}")"
        printf '      "name": "%s",\\n' "$(json_escape "${CHECK_NAMES[$i]}")"
        printf '      "verdict": "%s",\\n' "$(json_escape "${VERDICTS[$i]}")"
        printf '      "detail": "%s"\\n' "$(json_escape "${CHECK_DETAILS[$i]}")"
        if [[ $((i + 1)) -lt $count ]]; then
            printf '    },\\n'
        else
            printf '    }\\n'
        fi
    done
    printf '  ]\\n'
    printf '}\\n'
}

# ---------------------------------------------------------------------------
# Run all checks
# ---------------------------------------------------------------------------

run_all_checks() {
    local project_path="$1"

    # -- Installation checks --
    # Note: check functions are called without subshells so record_check
    # can modify the global VERDICTS array. Stdout is discarded.
    check_plsec_dir > /dev/null
    if [[ ! -d "$PLSEC_DIR" ]]; then
        # If PLSEC_DIR doesn't exist, skip remaining checks
        return
    fi
    check_subdirs > /dev/null

    # Agent configs
    if [[ -f "${PLSEC_DIR}/configs/CLAUDE.md" ]] || true; then
        check_agent_config "CLAUDE.md" > /dev/null
    fi
    if [[ -f "${PLSEC_DIR}/configs/opencode.json" ]] || true; then
        check_agent_config "opencode.json" > /dev/null
    fi

    # Required tools
    check_tool "git" "required" > /dev/null
    check_tool "trivy" "required" > /dev/null

    # Scanner configs
    local cfg
    for cfg in $EXPECTED_SCANNER_CONFIGS; do
        local desc
        case "$cfg" in
            trivy/trivy-secret.yaml) desc="Trivy secret rules" ;;
            trivy/trivy.yaml)        desc="Trivy configuration" ;;
            configs/pre-commit)      desc="Pre-commit hook template" ;;
            *)                       desc="$cfg" ;;
        esac
        check_scanner_config "$cfg" "$desc" > /dev/null
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
    mode=$(detect_security_mode)
    record_check "C-1" "configuration" "security mode" "ok" "$mode"

    local agents
    agents=$(detect_agents)
    if [[ "$agents" == "none" ]]; then
        record_check "C-2" "configuration" "agent type" "fail" "no agents configured"
    else
        record_check "C-2" "configuration" "agent type" "ok" "$agents"
    fi

    check_precommit_hook "$project_path" > /dev/null

    # Project-level config checks
    if [[ -f "${PLSEC_DIR}/configs/CLAUDE.md" ]]; then
        check_project_config "$project_path" "CLAUDE.md" > /dev/null
    fi
    if [[ -f "${PLSEC_DIR}/configs/opencode.json" ]]; then
        check_project_config "$project_path" "opencode.json" > /dev/null
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
    local project_path="$1"

    print_header

    local current_category=""
    local i
    local count=${#CHECK_IDS[@]}

    for ((i = 0; i < count; i++)); do
        local cat="${CHECK_CATEGORIES[$i]}"
        if [[ "$cat" != "$current_category" ]]; then
            current_category="$cat"
            local section_title
            case "$cat" in
                installation)  section_title="Installation" ;;
                configuration)
                    section_title="Configuration (project: ${project_path})"
                    ;;
                activity)      section_title="Activity" ;;
                findings)      section_title="Findings" ;;
                *)             section_title="$cat" ;;
            esac
            print_section "$section_title"
        fi
        print_check_line "${CHECK_NAMES[$i]}" "${VERDICTS[$i]}" "${CHECK_DETAILS[$i]}"
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
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --json)    json_mode=true; shift ;;
            --quiet)   quiet_mode=true; shift ;;
            --project)
                shift
                if [[ $# -eq 0 ]]; then
                    echo "ERROR: --project requires a path argument" >&2
                    exit 1
                fi
                project_path="$1"
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
                echo "ERROR: Unknown option: $1" >&2
                exit 1
                ;;
        esac
    done

    # Default project path to current directory
    if [[ -z "$project_path" ]]; then
        project_path="$(pwd)"
    fi

    # Run all checks
    run_all_checks "$project_path"

    # Output
    if $json_mode; then
        print_json
    elif ! $quiet_mode; then
        print_human_readable "$project_path"
    fi

    # Exit code: 0 = ok (warnings acceptable), 1 = failures
    local overall
    overall=$(compute_overall)
    if [[ "$overall" == "fail" ]]; then
        exit 1
    fi
    exit 0
}

# Source guard: execute main only when run directly, not when sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
"""

# Scripts deployed alongside wrappers (not agent-specific).
# Each tuple is (filename, content).
STANDALONE_SCRIPTS: list[tuple[str, str]] = [
    ("plsec-audit.sh", PLSEC_AUDIT_SH),
    ("plsec-status.sh", PLSEC_STATUS_SH),
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
