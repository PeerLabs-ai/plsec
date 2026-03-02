# plsec-status

Health check command for plsec installations. Answers: "Is plsec installed, configured, and active in this environment?"

## Installation

`plsec-status` is deployed by the bootstrap script:

```bash
curl -fsSL https://raw.githubusercontent.com/peerlabs/plsec/main/bin/bootstrap.default.sh | bash
source ~/.bashrc  # or ~/.zshrc
plsec-status
```

The command is **not** available via `plsec install` (Python CLI) in v0.1.x. It will be added in v0.2.0 when `plsec run` is implemented.

## Usage

```bash
plsec-status [OPTIONS]
```

### Options

| Flag             | Description                                      |
|------------------|--------------------------------------------------|
| `--help`, `-h`   | Show help message                                |
| `--json`         | Output machine-readable JSON                     |
| `--quiet`        | No output, exit code only (0=ok, 1=fail)         |
| `--watch`        | Continuous refresh mode                          |
| `--interval N`   | Refresh interval in seconds (default: 5)         |
| `--tail-lines N` | Log lines to show in watch mode (default: 5)     |
| `--project PATH` | Check specific project (default: current dir)    |

### Examples

**Default output** (human-readable, colored):

```bash
$ plsec-status

plsec v0.1.0+bootstrap [balanced] [claude]

  Installation
    plsec directory           OK    /Users/user/.peerlabs/plsec
    subdirectories            OK    all present
    CLAUDE.md config          OK    /Users/user/.peerlabs/plsec/configs/CLAUDE.md
    git                       OK    /usr/bin/git
    trivy                     OK    /opt/homebrew/bin/trivy
    Trivy secret rules        OK    /Users/user/.peerlabs/plsec/trivy/trivy-secret.yaml
    Trivy configuration       OK    /Users/user/.peerlabs/plsec/trivy/trivy.yaml
    Pre-commit hook template  OK    /Users/user/.peerlabs/plsec/configs/pre-commit
    Claude Code wrapper       OK    /Users/user/.peerlabs/plsec/claude-wrapper.sh
    OpenCode wrapper          OK    /Users/user/.peerlabs/plsec/opencode-wrapper.sh
    bandit                    WARN  not found (optional)

  Configuration (project: /Users/user/projects/my-app)
    security mode             OK    balanced
    agent type                OK    claude
    pre-commit hook           OK    references plsec
    CLAUDE.md (project)       OK    matches template

  Activity
    wrapper logs              OK    active within 24h
    sessions today            OK    3 session(s)
    last scan                 WARN  last scan >24h ago

  Findings
    secrets detected          OK    last scan clean
    hook blocks               OK    no recent blocks

  Overall: OK (2 warning(s))
```

**JSON output**:

```bash
$ plsec-status --json
{
  "version": "0.1.0+bootstrap",
  "mode": "balanced",
  "agents": ["claude"],
  "overall": "ok",
  "warnings": 2,
  "errors": 0,
  "timestamp": "2026-02-25T10:30:00Z",
  "checks": [
    {
      "id": "I-1",
      "category": "installation",
      "name": "plsec directory",
      "verdict": "ok",
      "detail": "/Users/user/.peerlabs/plsec"
    },
    {
      "id": "A-3",
      "category": "activity",
      "name": "last scan",
      "verdict": "warn",
      "detail": "last scan >24h ago"
    }
  ]
}
```

**Quiet mode**:

```bash
$ plsec-status --quiet
$ echo $?
0
```

**Check specific project**:

```bash
$ plsec-status --project /path/to/project
```

### Watch Mode

Continuous monitoring with auto-refresh:

```bash
# Watch with defaults (5s refresh, 5 lines log tail)
$ plsec-status --watch

# Custom refresh interval
$ plsec-status --watch --interval 10

# Show more log lines
$ plsec-status --watch --tail-lines 10

# Combined
$ plsec-status --watch --interval 3 --tail-lines 8 --project /path/to/project
```

**Keyboard controls** (requires interactive terminal):

| Key | Action                   |
|-----|--------------------------|
| `q` | Quit watch mode          |
| `r` | Refresh immediately      |
| `p` | Pause/resume auto-refresh|

**Display additions over one-shot mode**:

- Refresh timestamp in header
- Session count deltas: `sessions today: 3 (+1)` when count increases between refreshes
- Scan deltas: `last scan: within 24h (new scan)` when a new scan runs
- Log tail: last N lines from the most recently modified wrapper log

**Note**: `--watch` is incompatible with `--json` and `--quiet`. When stdin is not a terminal (pipes, CI), keyboard controls are disabled and the loop uses `sleep` instead.

## Health Model

### Check Categories

| Category      | What it checks                                          |
|---------------|---------------------------------------------------------|
| Installation  | Is plsec present and reachable?                         |
| Configuration | Is plsec configured correctly?                          |
| Activity      | Has plsec been active recently?                         |
| Findings      | Has plsec detected security issues?                     |

### Verdicts

| Verdict | Display | Meaning                                                |
|---------|---------|--------------------------------------------------------|
| OK      | ✓       | Component is present, configured, and active           |
| WARN    | ⚠       | Component is degraded or stale (non-blocking)          |
| FAIL    | ✗       | Component is missing, broken, or has blocking issues   |
| SKIP    | -       | Component not applicable (e.g., different agent)       |

### Exit Codes

- **0** = Healthy (OK or warnings only)
- **1** = Failures detected

**Note**: Warnings do not cause non-zero exit. They are informational. CI pipelines that want strict zero-warning enforcement should parse `--json` output.

## Checks Reference

### Installation Checks

| ID   | Name                    | OK                | WARN                   | FAIL                |
|------|-------------------------|-------------------|------------------------|---------------------|
| I-1  | plsec directory         | Exists            | -                      | Missing             |
| I-1  | subdirectories          | All present       | Some missing           | -                   |
| I-agent | CLAUDE.md config     | Exists, non-empty | Empty file             | Missing             |
| I-agent | opencode.json config | Exists, non-empty | Empty file             | Missing             |
| I-tool | git                   | Found             | -                      | Not found (required) |
| I-tool | trivy                 | Found             | -                      | Not found (required) |
| I-tool | bandit                | Found             | Not found (optional)   | -                   |
| I-tool | semgrep               | Found             | Not found (optional)   | -                   |
| I-tool | detect-secrets        | Found             | Not found (optional)   | -                   |
| I-scanner | Trivy secret rules  | Exists            | Missing                | -                   |
| I-scanner | Trivy configuration | Exists            | Missing                | -                   |
| I-scanner | Pre-commit template | Exists            | Missing                | -                   |
| I-7  | Claude Code wrapper     | Exists, executable| Not executable         | Missing             |
| I-7  | OpenCode wrapper        | Exists, executable| Not executable         | Missing             |

### Configuration Checks

| ID  | Name              | OK                     | WARN                  | FAIL           |
|-----|-------------------|------------------------|-----------------------|----------------|
| C-1 | Security mode     | Detected (strict/balanced) | -                 | Not detected   |
| C-2 | Active agents     | Detected               | -                     | No agents configured |
| C-3 | Pre-commit hook   | Installed, references plsec | No plsec reference | Not installed or not a git repo |
| C-project | CLAUDE.md (project) | Matches template   | Differs from template | Not found      |
| C-project | opencode.json (project) | Matches template | Differs from template | Not found    |

### Activity Checks

| ID  | Name          | OK          | WARN         | FAIL       |
|-----|---------------|-------------|--------------|------------|
| A-1 | Wrapper logs  | < 24h       | 24h - 7d     | > 7d or no logs |
| A-2 | Sessions today| ≥ 1 today   | 0 today (but logs exist) | No session logs |
| A-3 | Last scan     | < 24h       | > 24h        | No scan evidence |

**Staleness thresholds**:
- **24 hours** = warn threshold (logs, scans)
- **7 days** = fail threshold (logs only)

### Findings Checks

| ID  | Name           | OK              | WARN | FAIL             | SKIP |
|-----|----------------|-----------------|------|------------------|------|
| F-1 | Secrets        | None detected   | -    | Secrets detected | No scan data |
| F-2 | Hook blocks    | None detected   | -    | Blocks detected  | No logs |

**Note**: Findings checks are SKIP when there is no data to analyze (e.g., no `scan-latest.json` for F-1, no log files for F-2).

## Troubleshooting

### Command not found

**Symptom**:
```bash
$ plsec-status
bash: plsec-status: command not found
```

**Cause**: Bootstrap script not run, or shell not reloaded.

**Fix**:
```bash
# Run bootstrap
curl -fsSL https://raw.githubusercontent.com/peerlabs/plsec/main/bin/bootstrap.default.sh | bash

# Reload shell
source ~/.zshrc  # or ~/.bashrc

# Verify
plsec-status --help
```

### Missing PLSEC_DIR (I-1 FAIL)

**Symptom**:
```bash
✗ plsec directory: /Users/user/.peerlabs/plsec missing
```

**Cause**: Bootstrap not run, or directory deleted.

**Fix**:
```bash
# Re-run bootstrap
curl -fsSL https://raw.githubusercontent.com/peerlabs/plsec/main/bin/bootstrap.default.sh | bash

# Or if you have the Python CLI installed:
plsec install
```

### Stale logs (A-1 WARNING)

**Symptom**:
```bash
⚠ Last session: 4 days ago
```

**Cause**: No agent sessions in the last 24 hours.

**Fix**: This is informational. If you're actively using agents, check:
1. Wrapper scripts deployed? `ls -lh ~/.peerlabs/plsec/*-wrapper.sh`
2. Using the wrapper? `which claude-safe` should point to the wrapper
3. Logs directory exists? `ls -lh ~/.peerlabs/plsec/logs/`

### No sessions detected (A-2 WARNING)

**Symptom**:
```bash
⚠ Session count (7d): 0
```

**Cause**: No wrapper-logged sessions in the last 7 days.

**Possible reasons**:
- Running agents directly (`claude`) instead of via wrapper (`claude-safe`)
- Wrapper scripts not deployed (bootstrap not run)
- Log directory permissions issue

**Fix**:
```bash
# Check if wrappers exist
ls -lh ~/.peerlabs/plsec/*-wrapper.sh

# Check aliases
alias | grep safe

# Use the wrapper
claude-safe  # instead of: claude
```

### Secrets detected (F-1 FAILURE)

**Symptom**:
```bash
✗ Secrets detected in recent scans
```

**Cause**: `plsec scan` found secrets in your codebase.

**Fix**:
1. Review scan results: `cat ~/.peerlabs/plsec/logs/scan-latest.json`
2. Remove secrets from code
3. Add to `.gitignore` if they're in config files
4. Use environment variables or secret management instead
5. Re-scan: `plsec scan`

### Hook blocks detected (F-2 FAILURE)

**Symptom**:
```bash
✗ Pre-commit hook blocks detected
```

**Cause**: Pre-commit hook rejected commits due to security findings.

**Fix**:
1. Check recent logs: `tail -50 ~/.peerlabs/plsec/logs/*.log`
2. Review rejected files
3. Fix security issues
4. Re-commit

### Pre-commit hook not installed (C-3 FAIL)

**Symptom**:
```bash
✗ pre-commit hook: hook missing
```

**Cause**: No `.git/hooks/pre-commit` file in the project.

**Fix**:
```bash
# Copy the template
cp ~/.peerlabs/plsec/configs/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# Verify
plsec-status
```

### Not a git repo (C-3 FAIL)

**Symptom**:
```bash
✗ pre-commit hook: not a git repo
```

**Cause**: The project directory is not a git repository.

**Fix**:
```bash
# Initialize git repo
git init

# Verify
plsec-status
```

## Design

For technical details on the health model, check inventory, and implementation, see:
- [plsec-status Design Spec](../plsec-status-design.md)

## See Also

- [CI/CD Integration Examples](../ci-cd-integration.md)
- [Troubleshooting Guide](../troubleshooting.md)
- [plsec doctor](plsec-doctor.md) — Check system dependencies
- [plsec scan](plsec-scan.md) — Run security scanners
