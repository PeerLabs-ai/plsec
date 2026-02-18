"""
Embedded configuration templates.

These templates are used by plsec init to generate configuration files.
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

TRIVY_SECRET_YAML = """# trivy-secret.yaml - LLM-tuned secret detection
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
"""

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
