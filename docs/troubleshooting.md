# Troubleshooting Guide

Common issues and fixes for plsec commands.

## plsec-status

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

### Missing PLSEC_DIR

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

1. **Wrapper scripts deployed?**
   ```bash
   ls -lh ~/.peerlabs/plsec/*-wrapper.sh
   ```

2. **Using the wrapper?**
   ```bash
   which claude-safe  # should point to wrapper
   alias | grep safe  # should show aliases
   ```

3. **Logs directory exists?**
   ```bash
   ls -lh ~/.peerlabs/plsec/logs/
   ```

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
opencode-safe  # instead of: opencode
```

### Secrets detected (F-1 FAILURE)

**Symptom**:
```bash
✗ Secrets detected in recent scans
```

**Cause**: `plsec scan` found secrets in your codebase.

**Fix**:
1. **Review scan results**:
   ```bash
   cat ~/.peerlabs/plsec/logs/scan-latest.json
   jq '.checks[] | select(.scanner_id == "trivy-secrets")' ~/.peerlabs/plsec/logs/scan-latest.json
   ```

2. **Remove secrets from code**:
   - Delete hardcoded API keys, tokens, passwords
   - Use environment variables: `os.getenv("API_KEY")`
   - Use secret management: AWS Secrets Manager, 1Password, etc.

3. **Add to .gitignore** if they're in config files:
   ```bash
   echo ".env" >> .gitignore
   echo "credentials.json" >> .gitignore
   ```

4. **Re-scan**:
   ```bash
   plsec scan
   plsec-status  # verify F-1 is now OK
   ```

### Hook blocks detected (F-2 FAILURE)

**Symptom**:
```bash
✗ Pre-commit hook blocks detected
```

**Cause**: Pre-commit hook rejected commits due to security findings.

**Fix**:
1. **Check recent logs**:
   ```bash
   tail -50 ~/.peerlabs/plsec/logs/*.log | grep -i "ERROR\|blocked\|rejected"
   ```

2. **Review rejected files** — the hook logs should show which files triggered the block

3. **Fix security issues** (see "Secrets detected" above)

4. **Re-commit**:
   ```bash
   git add .
   git commit -m "fix: remove secrets"
   ```

---

## plsec doctor

### Required tool missing

**Symptom**:
```bash
✗ trivy not found
```

**Fix**:

**macOS (Homebrew)**:
```bash
brew install trivy
plsec doctor
```

**Linux (Debian/Ubuntu)**:
```bash
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
plsec doctor
```

**Linux (RPM-based)**:
```bash
curl -fsSL https://aquasecurity.github.io/trivy-repo/rpm/trivy.repo | sudo tee /etc/yum.repos.d/trivy.repo
sudo yum install trivy
plsec doctor
```

**Binary install (any platform)**:
```bash
VERSION=0.58.2  # or latest from https://github.com/aquasecurity/trivy/releases
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v${VERSION}
trivy --version
plsec doctor
```

### Optional tool missing

**Symptom**:
```bash
⚠ bandit not found (optional)
```

**Fix** (if you want it):

**Using pipx (recommended)**:
```bash
pipx install bandit
plsec doctor
```

**Using pip**:
```bash
pip install bandit  # or: uv tool install bandit
plsec doctor
```

**Note**: Optional tools provide additional security coverage but are not required for basic plsec functionality.

---

## plsec scan

### Scanner config missing

**Symptom**:
```bash
ERROR: Trivy secret scanning rules not found
Run 'plsec install' to deploy scanner configs
```

**Cause**: Scanner configuration files not deployed.

**Fix**:
```bash
plsec install --force
plsec doctor  # verify configs are deployed
plsec scan
```

### Trivy permission denied

**Symptom**:
```bash
FATAL: permission denied while trying to connect to the Docker daemon socket
```

**Cause**: Trivy trying to use Docker (for container scanning) without permissions.

**Fix**: This shouldn't happen for filesystem scanning. If it does:
```bash
# Use filesystem scanning explicitly
trivy fs --scanners secret .

# Or add yourself to docker group (not recommended for security)
sudo usermod -aG docker $USER
newgrp docker
```

### Scan timeout

**Symptom**:
```bash
ERROR: Scanner timeout after 120s
```

**Cause**: Large codebase or slow scanner.

**Fix**:
1. **Exclude large directories**: Add to `.trivyignore.yaml`:
   ```yaml
   paths:
     - node_modules/
     - .venv/
     - build/
   ```

2. **Scan specific directories**:
   ```bash
   plsec scan src/  # instead of entire repo
   ```

---

## plsec init

### Config file already exists

**Symptom**:
```bash
ERROR: plsec.yaml already exists
```

**Cause**: Project already initialized.

**Fix**:
```bash
# Use --force to overwrite
plsec init --force

# Or edit manually
vim plsec.yaml
```

### Unknown project type

**Symptom**:
```bash
WARN: Could not detect project type, defaulting to 'unknown'
```

**Cause**: No recognizable project marker files (pyproject.toml, package.json, go.mod, etc.)

**Fix**: Specify the type manually:
```bash
plsec init --type python  # or: node, go, mixed
```

---

## plsec install

### Permission denied

**Symptom**:
```bash
ERROR: Permission denied: /Users/user/.peerlabs/plsec/
```

**Cause**: Directory ownership or permissions issue.

**Fix**:
```bash
# Fix ownership
chown -R $(whoami) ~/.peerlabs/plsec/

# Fix permissions
chmod -R u+rwX ~/.peerlabs/plsec/

# Re-run install
plsec install
```

### Python version too old

**Symptom**:
```bash
✗ Python 3.11.0
   Requires Python 3.12+
```

**Cause**: plsec requires Python 3.12 or later.

**Fix**:

**macOS (Homebrew)**:
```bash
brew install python@3.12
python3.12 --version
```

**Linux (pyenv recommended)**:
```bash
# Install pyenv
curl https://pyenv.run | bash

# Install Python 3.12
pyenv install 3.12.0
pyenv global 3.12.0

# Verify
python --version
```

**Linux (from deadsnakes PPA, Ubuntu)**:
```bash
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.12
```

---

## General Issues

### Shell alias not working after install

**Symptom**:
```bash
$ claude-safe
bash: claude-safe: command not found
```

**Cause**: Shell not reloaded after `plsec install` or bootstrap.

**Fix**:
```bash
source ~/.zshrc  # or ~/.bashrc
alias | grep safe  # verify aliases are loaded
```

### Logs directory full

**Symptom**:
```bash
WARN: Logs directory size: 2.3GB
```

**Cause**: Old log files accumulating over time.

**Fix**:
```bash
# List log files by size
du -sh ~/.peerlabs/plsec/logs/* | sort -h

# Remove old logs (older than 30 days)
find ~/.peerlabs/plsec/logs -name "*.log" -mtime +30 -delete
find ~/.peerlabs/plsec/logs -name "*.jsonl" -mtime +30 -delete

# Or clear all logs (preserving current day)
today=$(date +%Y%m%d)
find ~/.peerlabs/plsec/logs -name "*.log" ! -name "*${today}*" -delete
```

### Conflicting plsec installations

**Symptom**:
```bash
$ plsec --version
0.0.1  # expected 0.1.0
```

**Cause**: Multiple plsec installations (pip, pipx, homebrew).

**Fix**:
```bash
# Check which plsec is running
which plsec
type plsec

# Uninstall all versions
pip uninstall plsec
pipx uninstall plsec
brew uninstall plsec

# Install via preferred method
pipx install plsec  # recommended
plsec --version
```

### Wrapper script not executable

**Symptom**:
```bash
⚠ Claude Code wrapper: not executable
```

**Cause**: File permissions issue.

**Fix**:
```bash
chmod +x ~/.peerlabs/plsec/claude-wrapper.sh
chmod +x ~/.peerlabs/plsec/opencode-wrapper.sh
chmod +x ~/.peerlabs/plsec/plsec-audit.sh
plsec-status  # verify now OK
```

### Pre-commit hook not executable

**Symptom**:
```bash
.git/hooks/pre-commit: Permission denied
```

**Cause**: Hook file not executable.

**Fix**:
```bash
chmod +x .git/hooks/pre-commit
git commit -m "test"  # verify hook runs
```

---

## CI/CD Issues

### Command not found in CI

**Symptom**: `bash: plsec-status: command not found` in GitHub Actions

**Cause**: Shell not sourced after bootstrap, or bootstrap not run.

**Fix**:
```yaml
- name: Install plsec
  run: |
    curl -fsSL https://raw.githubusercontent.com/peerlabs/plsec/main/bin/bootstrap.default.sh | bash
    source ~/.bashrc  # Important!

- name: Check status
  run: plsec-status
```

### No .git directory in CI

**Symptom**: Pre-commit hook check (C-3) fails with "not a git repo"

**Cause**: Repository not checked out in CI.

**Fix**:
```yaml
steps:
  - uses: actions/checkout@v4  # This creates .git/
  - run: plsec-status
```

### jq not found

**Symptom**: `jq: command not found` when parsing JSON output

**Fix**: Install jq in your CI environment:
```yaml
- name: Install jq
  run: sudo apt-get install -y jq  # Ubuntu/Debian

# Or for Alpine:
- run: apk add jq

# Or for macOS:
- run: brew install jq
```

---

## Getting Help

If these fixes don't resolve your issue:

1. **Check logs**:
   ```bash
   ls -lh ~/.peerlabs/plsec/logs/
   tail -50 ~/.peerlabs/plsec/logs/*.log
   ```

2. **Run diagnostics**:
   ```bash
   plsec doctor --verbose
   plsec-status --json > status.json
   cat status.json
   ```

3. **Verify installation**:
   ```bash
   plsec --version
   which plsec
   ls -la ~/.peerlabs/plsec/
   ```

4. **File an issue**: https://github.com/peerlabs/plsec/issues

   Include:
   - plsec version (`plsec --version`)
   - OS and version (`uname -a` or `sw_vers` on macOS)
   - `status.json` (from `plsec-status --json`)
   - Relevant log excerpts (sanitized of secrets!)

## See Also

- [plsec-status Command Reference](commands/plsec-status.md)
- [CI/CD Integration](ci-cd-integration.md)
- [plsec doctor](commands/plsec-doctor.md)
