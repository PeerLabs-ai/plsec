# plsec create & secure - Command Design

**Version:** 0.1.0-draft
**Status:** Design

---

## Overview

Two complementary commands for project security setup:

| Command | Use Case | User Journey |
|---------|----------|--------------|
| `plsec create <name>` | New project | "I'm starting fresh, give me a secure foundation" |
| `plsec secure [path]` | Existing project | "I have code, help me lock it down" |

Both use an interactive wizard to understand needs and generate appropriate configuration.

---

## 1. plsec create <project>

### 1.1 Purpose

Scaffold a new project with security built-in from day one. Creates directory structure, configuration files, and optional tooling.

### 1.2 Command Signature

```bash
plsec create <name> [options]

Arguments:
  name                    Project name (creates directory)

Options:
  --template, -t TYPE     Project template: python, node, go, rust, mixed
  --preset, -p PRESET     Security preset: minimal, balanced, strict, paranoid
  --agent, -a AGENT       AI agent: claude, opencode, both
  --no-wizard             Skip wizard, use defaults/flags only
  --git/--no-git          Initialize git repository (default: yes)
  --output, -o PATH       Parent directory (default: current)
```

### 1.3 Wizard Flow

```
$ plsec create my-api

plsec create - New Secure Project
=================================

[1/5] Project Type
    What kind of project are you building?

    > Python (Django, FastAPI, CLI)
      Node.js (Express, Next.js, CLI)
      Go
      Rust
      Mixed / Polyglot
      Other

[2/5] AI Assistants
    Which AI coding assistants will you use?

    [x] Claude Code
    [x] Opencode
    [ ] GitHub Copilot
    [ ] Cursor
    [ ] Other

[3/5] Security Posture
    How strict should security controls be?

      Minimal     - Secret scanning only
    > Balanced    - Full static analysis, audit logging
      Strict      - Add container isolation, runtime proxy
      Paranoid    - Network isolation, integrity monitoring

    [i] You can always adjust this later in plsec.yaml

[4/5] Sensitive Data
    What sensitive data will this project handle?
    (Helps configure appropriate scanning rules)

    [x] API keys (cloud providers, SaaS)
    [x] Database credentials
    [ ] PII / Customer data
    [ ] Payment / Financial data
    [ ] Healthcare / HIPAA
    [ ] Secrets / Encryption keys

[5/5] Cloud Providers
    Which cloud providers will you use?
    (Adds provider-specific Trivy policies)

    [x] AWS
    [ ] Google Cloud
    [x] DigitalOcean
    [ ] Cloudflare
    [ ] Azure
    [ ] None / Self-hosted

Summary
-------
Project:     my-api
Type:        Python
Agents:      Claude Code, Opencode
Posture:     Balanced
Data:        API keys, Database credentials
Providers:   AWS, DigitalOcean

Create project? [Y/n] 

Creating my-api/
  [OK] Created directory structure
  [OK] Created CLAUDE.md
  [OK] Created .opencode.toml
  [OK] Created plsec.yaml
  [OK] Created .gitignore (security-enhanced)
  [OK] Created .pre-commit-config.yaml
  [OK] Created trivy/trivy-secret.yaml
  [OK] Initialized git repository
  [OK] Installed pre-commit hooks

Next steps:
  cd my-api
  plsec doctor          # Verify dependencies
  plsec scan            # Run initial security scan
```

### 1.4 Generated Structure

```
my-api/
  .git/
  .gitignore              # Security-enhanced
  .pre-commit-config.yaml # Pre-commit hooks
  .opencode.toml          # Opencode config
  CLAUDE.md               # Claude Code config
  plsec.yaml              # plsec configuration
  README.md               # Project readme
  trivy/
    trivy-secret.yaml     # Custom secret patterns
  
  # Python template
  pyproject.toml
  src/
    my_api/
      __init__.py
  tests/
    __init__.py
  
  # Optional (strict/paranoid)
  Dockerfile              # Isolated dev environment
  docker-compose.yaml     # Container orchestration
  .pipelock.yaml          # Runtime proxy config
```

### 1.5 Templates

Each project type has a minimal template:

**Python:**
```
pyproject.toml          # uv/pip compatible
src/{name}/__init__.py
tests/__init__.py
```

**Node.js:**
```
package.json
src/index.js
```

**Go:**
```
go.mod
main.go
```

**Mixed:**
```
# Just security files, no code template
```

---

## 2. plsec secure [path]

### 2.1 Purpose

Retrofit security onto an existing project. Analyzes current state, identifies gaps, and applies fixes with user confirmation.

### 2.2 Command Signature

```bash
plsec secure [path] [options]

Arguments:
  path                    Project path (default: current directory)

Options:
  --preset, -p PRESET     Security preset: minimal, balanced, strict, paranoid
  --agent, -a AGENT       AI agent: claude, opencode, both
  --no-wizard             Skip wizard, use detected/default values
  --dry-run               Show what would change without applying
  --force                 Overwrite existing config files
  --scan/--no-scan        Run security scan after setup (default: yes)
```

### 2.3 Wizard Flow

```
$ plsec secure

plsec secure - Secure Existing Project
======================================

Analyzing project...

[OK] Detected: Python project (pyproject.toml)
[OK] Detected: Git repository
[OK] Detected: 47 Python files, 3 config files
[WARN] No CLAUDE.md found
[WARN] No .opencode.toml found
[WARN] No pre-commit hooks installed
[WARN] .gitignore missing common secret patterns

Running quick security scan...

[!] Found 2 potential issues:
    - HIGH: Possible API key in src/config.py:23
    - MEDIUM: Hardcoded password pattern in tests/fixtures.py:45

[1/4] AI Assistants
    Which AI coding assistants do you use with this project?

    [x] Claude Code
    [x] Opencode
    [ ] GitHub Copilot
    [ ] Other

[2/4] Security Posture
    How strict should security controls be?

      Minimal     - Secret scanning only
    > Balanced    - Full static analysis, audit logging
      Strict      - Add container isolation, runtime proxy

[3/4] Review Detected Settings
    We detected the following. Adjust if needed:

    Project type:     Python
    Package manager:  uv (pyproject.toml)
    Test framework:   pytest
    Cloud providers:  AWS (detected in requirements)

    Is this correct? [Y/n/edit]

[4/4] Confirm Changes
    The following changes will be made:

    CREATE:
      + CLAUDE.md                    (AI assistant constraints)
      + .opencode.toml               (Opencode configuration)
      + plsec.yaml                   (plsec configuration)
      + trivy/trivy-secret.yaml      (Secret scanning rules)
      + .pre-commit-config.yaml      (Pre-commit hooks)

    MODIFY:
      ~ .gitignore                   (Add 12 security patterns)

    SKIP (already exists):
      - pyproject.toml               (No changes needed)

    Apply changes? [Y/n/selective]

Applying changes...
  [OK] Created CLAUDE.md
  [OK] Created .opencode.toml
  [OK] Created plsec.yaml
  [OK] Created trivy/trivy-secret.yaml
  [OK] Created .pre-commit-config.yaml
  [OK] Updated .gitignore (+12 patterns)
  [OK] Installed pre-commit hooks

Running security scan...
  [OK] No new issues found
  [!] 2 pre-existing issues remain (see above)

Next steps:
  1. Review and fix the 2 issues found:
     - src/config.py:23
     - tests/fixtures.py:45
  2. Review generated CLAUDE.md constraints
  3. Commit security configuration:
     git add -A && git commit -m "Add plsec security configuration"
```

### 2.4 Analysis Phase

Before the wizard, `plsec secure` analyzes the project:

**Detection:**
| What | How |
|------|-----|
| Project type | pyproject.toml, package.json, go.mod, Cargo.toml |
| Package manager | uv (pyproject.toml), pip (requirements.txt), npm, yarn, pnpm |
| Test framework | pytest.ini, jest.config, go test |
| Cloud providers | Requirements, imports, config files |
| Existing security | .pre-commit-config.yaml, CLAUDE.md, .gitignore |
| Git status | .git directory, uncommitted changes |

**Quick Scan:**
- Run Trivy secret scan (fast mode)
- Check for common anti-patterns
- Report findings before proceeding

### 2.5 Change Application

Changes are categorized:

| Category | Description | User Control |
|----------|-------------|--------------|
| CREATE | New files | Can skip individual files |
| MODIFY | Append/merge to existing | Shows diff, can skip |
| SKIP | Already exists, no changes | Informational |
| CONFLICT | Exists but different | Requires --force or manual resolution |

**Selective Mode:**

```
Apply changes? [Y/n/selective] s

Select changes to apply:
  [x] CREATE CLAUDE.md
  [x] CREATE .opencode.toml
  [x] CREATE plsec.yaml
  [ ] CREATE trivy/trivy-secret.yaml     # User deselected
  [x] CREATE .pre-commit-config.yaml
  [x] MODIFY .gitignore

Apply selected changes? [Y/n]
```

### 2.6 .gitignore Merging

When modifying .gitignore, we append security patterns:

```gitignore
# === plsec security patterns (added by plsec secure) ===
# Secrets and credentials
.env
.env.*
*.pem
*.key
**/secrets/
**/credentials/

# Cloud provider configs
.aws/
.azure/
.gcp/

# IDE secrets
.idea/dataSources/
.vscode/*.json

# plsec
.plsec-manifest.json
# === end plsec patterns ===
```

---

## 3. Shared Components

### 3.1 Wizard Engine

Both commands share a wizard engine:

```python
from plsec.wizard import Wizard, Question, Choice

wizard = Wizard("plsec create")

# Single select
project_type = wizard.select(
    "What kind of project are you building?",
    choices=[
        Choice("python", "Python (Django, FastAPI, CLI)"),
        Choice("node", "Node.js (Express, Next.js, CLI)"),
        Choice("go", "Go"),
        Choice("rust", "Rust"),
        Choice("mixed", "Mixed / Polyglot"),
    ],
    default="python",
)

# Multi select
agents = wizard.multi_select(
    "Which AI coding assistants will you use?",
    choices=[
        Choice("claude", "Claude Code", checked=True),
        Choice("opencode", "Opencode", checked=True),
        Choice("copilot", "GitHub Copilot"),
        Choice("cursor", "Cursor"),
    ],
)

# Confirm
if wizard.confirm("Create project?", default=True):
    # proceed
```

### 3.2 Project Detector

```python
from plsec.detector import ProjectDetector

detector = ProjectDetector(path)
info = detector.analyze()

# info.type -> "python"
# info.package_manager -> "uv"
# info.test_framework -> "pytest"
# info.cloud_providers -> ["aws", "digitalocean"]
# info.existing_security -> {"gitignore": True, "claude_md": False}
# info.issues -> [Issue(...), Issue(...)]
```

### 3.3 Template Engine

```python
from plsec.templates import render_template

# Renders with context
content = render_template(
    "CLAUDE.md",
    preset="strict",
    project_type="python",
    denied_paths=[".env", ".aws/"],
)
```

---

## 4. Non-Interactive Mode

Both commands support non-interactive execution:

```bash
# Create with all options specified
plsec create my-api \
  --template python \
  --preset strict \
  --agent both \
  --no-wizard

# Secure with defaults
plsec secure ./my-project \
  --preset balanced \
  --agent claude \
  --no-wizard \
  --force
```

**CI/CD Usage:**

```yaml
# GitHub Actions
- name: Setup plsec security
  run: |
    plsec secure . --preset balanced --no-wizard --force
    plsec scan --exit-code 1
```

---

## 5. Error Handling

### 5.1 plsec create

| Error | Handling |
|-------|----------|
| Directory exists | Abort with message, suggest `plsec secure` |
| No write permission | Abort with clear error |
| Git not installed | Warn, skip git init |
| Pre-commit not installed | Warn, skip hook installation |

### 5.2 plsec secure

| Error | Handling |
|-------|----------|
| Not a directory | Abort with message |
| No write permission | Abort with clear error |
| Not a git repo | Warn, skip git-related features |
| Uncommitted changes | Warn, suggest committing first |
| Existing conflicts | List conflicts, require --force or manual |

---

## 6. Implementation Plan

### Phase 1: Core Infrastructure

1. Wizard engine (prompts, multi-select, confirm)
2. Project detector (type, package manager, existing config)
3. Template engine (render with context)

### Phase 2: plsec create

1. Basic scaffolding (directory, files)
2. Template rendering
3. Git initialization
4. Pre-commit setup

### Phase 3: plsec secure

1. Project analysis
2. Quick security scan
3. Change calculation (create, modify, skip)
4. Change application with confirmation
5. .gitignore merging

### Phase 4: Polish

1. Dry-run mode
2. Selective application
3. Better error messages
4. Progress indicators

---

## 7. Open Questions

| Question | Options | Leaning |
|----------|---------|---------|
| Prompt library | questionary vs rich.prompt vs InquirerPy | rich.prompt (fewer deps) |
| Template format | Jinja2 vs string.Template vs f-strings | Jinja2 (powerful, familiar) |
| Config merging | Append vs deep merge vs replace | Append for .gitignore, replace for others |
| Scan before secure | Always vs optional vs skip | Always (quick scan is fast) |

---

## 8. Example Sessions

### 8.1 Quick Create (Non-Interactive)

```bash
$ plsec create my-api -t python -p balanced -a both --no-wizard

Creating my-api/
  [OK] Created directory structure
  [OK] Created CLAUDE.md
  [OK] Created .opencode.toml
  [OK] Created plsec.yaml
  [OK] Initialized git repository

Done! cd my-api && plsec doctor
```

### 8.2 Secure with Dry Run

```bash
$ plsec secure --dry-run

Analyzing project...
  [OK] Detected: Python project

Dry run - no changes will be made

Would CREATE:
  + CLAUDE.md
  + .opencode.toml
  + plsec.yaml

Would MODIFY:
  ~ .gitignore (+12 patterns)

Run without --dry-run to apply changes.
```

### 8.3 Secure with Conflicts

```bash
$ plsec secure

[!] Conflicts detected:
    CLAUDE.md exists but differs from template

Options:
  1. Keep existing (skip)
  2. Replace with template (--force)
  3. Merge manually (shows diff)
  4. Abort

Choice [1/2/3/4]: 3

--- existing CLAUDE.md
+++ template CLAUDE.md
@@ -1,5 +1,10 @@
 # CLAUDE.md
+
+## Security Constraints
+
+### NEVER
...

Save merged version? [Y/n]
```
