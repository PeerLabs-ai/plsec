# CLAUDE.md - Balanced Security Configuration

## Documentation

Make sure to create a HANDOFF.md after creating any major piece of work

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
- Creating or deleting git branches
- Creating issues and pull requests (gh CLI)
- Merging pull requests

### ALWAYS

- Show commands before execution
- Confirm destructive operations
- Use relative paths when possible
- Report constraint violations

### Allowed Operations

- Read/write within project directory
- Run tests and linters
- Git operations (add, commit, status, diff, branch, checkout, merge)
- GitHub CLI (gh issue, gh pr, gh run) with approval
- Package manager commands (pip, npm) with review

### Logging

Commands are logged to /Users/grahamtoppin/.peerlabs/plsec/logs/
