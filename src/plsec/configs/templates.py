"""
Embedded configuration templates.

These templates are used by plsec init to generate configuration files.
"""

CLAUDE_MD_STRICT = '''# CLAUDE.md - Strict Security Configuration

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
'''

CLAUDE_MD_BALANCED = '''# CLAUDE.md - Balanced Security Configuration

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
'''

OPENCODE_TOML_STRICT = '''# .opencode.toml - Strict Security Configuration
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
'''

OPENCODE_TOML_BALANCED = '''# .opencode.toml - Balanced Security Configuration
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
'''

PLSEC_YAML_TEMPLATE = '''# plsec.yaml - Security configuration
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
    log_dir: ~/.plsec/logs
    integrity: {integrity_enabled}

credentials:
  storage: keychain
  keys: []
'''

TRIVY_SECRET_YAML = '''# trivy-secret.yaml - LLM-tuned secret detection
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
    keywords: ["BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN PRIVATE KEY"]
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
'''

PRE_COMMIT_HOOK = '''#!/bin/bash
# Pre-commit hook for secret scanning

PLSEC_DIR="${HOME}/.plsec"

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
'''
