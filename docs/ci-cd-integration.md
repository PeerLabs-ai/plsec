# CI/CD Integration Examples

How to use `plsec-status` in continuous integration pipelines.

## Exit Codes

- **0** = Healthy (OK or warnings only)
- **1** = Failures detected

Warnings do not cause non-zero exit codes. They are informational signals that
something is degraded but not broken. CI pipelines that want strict zero-warning
enforcement should parse `--json` output.

## JSON Output

Use `--json` for machine-readable output:

```bash
plsec-status --json
```

**Schema**:

```json
{
  "version": "0.1.0+bootstrap",
  "mode": "balanced",
  "agents": ["claude"],
  "overall": "ok",
  "warnings": 1,
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

**Field reference**:

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | plsec version (includes `+bootstrap` suffix) |
| `mode` | string | Security mode: `strict`, `balanced`, or `unknown` |
| `agents` | array | Configured agents: `["claude"]`, `["opencode"]`, `["claude", "opencode"]` |
| `overall` | string | Overall verdict: `ok` or `fail` |
| `warnings` | int | Count of warnings (non-blocking) |
| `errors` | int | Count of failures (blocking) |
| `timestamp` | string | ISO 8601 UTC timestamp |
| `checks` | array | Individual check results (see below) |

**Check object**:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Check identifier (`I-1`, `C-3`, `A-1`, `F-1`, etc.) |
| `category` | string | Check category: `installation`, `configuration`, `activity`, `findings` |
| `name` | string | Human-readable check name |
| `verdict` | string | Check verdict: `ok`, `warn`, `fail`, `skip` |
| `detail` | string | Additional detail (path, message, count, etc.) |

## Quiet Mode

Use `--quiet` for exit-code-only checks (no output):

```bash
plsec-status --quiet
if [ $? -eq 0 ]; then
  echo "✓ plsec is healthy"
else
  echo "✗ plsec has failures"
  exit 1
fi
```

## GitHub Actions

### Basic Health Check

```yaml
name: plsec Health Check

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install plsec via bootstrap
        run: |
          curl -fsSL https://raw.githubusercontent.com/peerlabs/plsec/main/bin/bootstrap.default.sh | bash
          source ~/.bashrc
      
      - name: Check plsec health
        run: plsec-status
      
      - name: Run security scans
        run: plsec scan --all
```

### JSON Output with Failure Detection

```yaml
name: plsec Security Gate

on: [push, pull_request]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install plsec
        run: |
          curl -fsSL https://raw.githubusercontent.com/peerlabs/plsec/main/bin/bootstrap.default.sh | bash
          source ~/.bashrc
      
      - name: Check plsec status (JSON)
        id: status
        run: |
          plsec-status --json | tee status.json
          echo "verdict=$(jq -r '.overall' status.json)" >> $GITHUB_OUTPUT
      
      - name: Parse warnings and errors
        run: |
          warnings=$(jq -r '.warnings' status.json)
          errors=$(jq -r '.errors' status.json)
          echo "⚠️  Warnings: $warnings"
          echo "❌ Errors: $errors"
      
      - name: Fail on errors
        if: steps.status.outputs.verdict == 'fail'
        run: |
          echo "plsec health check failed"
          exit 1
      
      - name: Upload status report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: plsec-status
          path: status.json
```

## GitLab CI

### Basic Pipeline

```yaml
plsec:health:
  stage: test
  image: ubuntu:latest
  before_script:
    - apt-get update && apt-get install -y curl git
    - curl -fsSL https://raw.githubusercontent.com/peerlabs/plsec/main/bin/bootstrap.default.sh | bash
    - source ~/.bashrc
  script:
    - plsec-status --json
    - plsec scan --all
  artifacts:
    paths:
      - ~/.peerlabs/plsec/logs/
    when: always
```

### With Quiet Mode

```yaml
plsec:gate:
  stage: security
  image: ubuntu:latest
  before_script:
    - curl -fsSL https://raw.githubusercontent.com/peerlabs/plsec/main/bin/bootstrap.default.sh | bash
    - source ~/.bashrc
  script:
    - plsec-status --quiet || exit 1
    - plsec scan --all
```

## Jenkins

### Declarative Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Health') {
            steps {
                sh '''
                    curl -fsSL https://raw.githubusercontent.com/peerlabs/plsec/main/bin/bootstrap.default.sh | bash
                    source ~/.bashrc
                    plsec-status --json | tee status.json
                '''
                
                script {
                    def status = readJSON file: 'status.json'
                    echo "Overall: ${status.overall}"
                    echo "Warnings: ${status.warnings}"
                    echo "Errors: ${status.errors}"
                    
                    if (status.overall == 'fail') {
                        error "plsec health check failed with ${status.errors} error(s)"
                    }
                }
            }
        }
        
        stage('Security Scan') {
            steps {
                sh 'plsec scan --all --json'
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: '~/.peerlabs/plsec/logs/**/*.json', allowEmptyArchive: true
        }
    }
}
```

### Scripted Pipeline with jq

```groovy
node {
    stage('plsec Health') {
        sh '''
            plsec-status --json > status.json
            cat status.json | jq -e '.overall == "ok"'
        '''
    }
}
```

## CircleCI

```yaml
version: 2.1

jobs:
  security-check:
    docker:
      - image: cimg/base:2024.01
    steps:
      - checkout
      
      - run:
          name: Install plsec
          command: |
            curl -fsSL https://raw.githubusercontent.com/peerlabs/plsec/main/bin/bootstrap.default.sh | bash
            source ~/.bashrc
      
      - run:
          name: plsec health check
          command: plsec-status --json | tee status.json
      
      - run:
          name: Verify health
          command: |
            verdict=$(jq -r '.overall' status.json)
            if [ "$verdict" != "ok" ]; then
              echo "Health check failed"
              exit 1
            fi
      
      - store_artifacts:
          path: status.json
          destination: plsec-status

workflows:
  security:
    jobs:
      - security-check
```

## Parsing JSON in Scripts

### Extract Overall Verdict (bash + jq)

```bash
verdict=$(plsec-status --json | jq -r '.overall')
if [ "$verdict" != "ok" ]; then
  echo "Health check failed with verdict: $verdict"
  exit 1
fi
```

### Count Failures (bash + jq)

```bash
errors=$(plsec-status --json | jq -r '.errors')
warnings=$(plsec-status --json | jq -r '.warnings')

echo "Errors: $errors, Warnings: $warnings"

if [ "$errors" -gt 0 ]; then
  echo "❌ $errors checks failed"
  exit 1
fi
```

### Check Specific Category (Python)

```python
import json
import subprocess
import sys

result = subprocess.run(['plsec-status', '--json'], capture_output=True, text=True)
data = json.loads(result.stdout)

# Check if any installation checks failed
installation_failures = [
    check for check in data['checks']
    if check['category'] == 'installation' and check['verdict'] == 'fail'
]

if installation_failures:
    print(f"❌ {len(installation_failures)} installation checks failed:")
    for check in installation_failures:
        print(f"  - {check['name']}: {check['detail']}")
    sys.exit(1)

print("✓ All installation checks passed")
```

### Parse with Node.js

```javascript
const { execSync } = require('child_process');

const output = execSync('plsec-status --json', { encoding: 'utf-8' });
const status = JSON.parse(output);

console.log(`Overall: ${status.overall}`);
console.log(`Warnings: ${status.warnings}`);
console.log(`Errors: ${status.errors}`);

if (status.overall === 'fail') {
  console.error('❌ plsec health check failed');
  process.exit(1);
}

console.log('✓ plsec health check passed');
```

## Advanced Patterns

### Fail on Warnings (Strict Mode)

```bash
plsec-status --json > status.json
warnings=$(jq -r '.warnings' status.json)
errors=$(jq -r '.errors' status.json)

if [ "$errors" -gt 0 ] || [ "$warnings" -gt 0 ]; then
  echo "❌ Failed with $errors error(s) and $warnings warning(s)"
  jq '.checks[] | select(.verdict == "fail" or .verdict == "warn") | "\(.category): \(.name) - \(.detail)"' status.json
  exit 1
fi
```

### Check Specific Verdicts

```bash
# Fail if any "findings" checks have failures
findings_failures=$(plsec-status --json | jq '[.checks[] | select(.category == "findings" and .verdict == "fail")] | length')

if [ "$findings_failures" -gt 0 ]; then
  echo "❌ $findings_failures security findings detected"
  exit 1
fi
```

### Generate Badge from Status

```bash
plsec-status --json > status.json
verdict=$(jq -r '.overall' status.json)

if [ "$verdict" == "ok" ]; then
  badge_color="brightgreen"
  badge_message="healthy"
else
  badge_color="red"
  badge_message="failing"
fi

# Generate shields.io badge URL
echo "https://img.shields.io/badge/plsec-${badge_message}-${badge_color}"
```

## Troubleshooting CI/CD

### Command not found

**Symptom**: `bash: plsec-status: command not found`

**Fix**: Source the shell RC file after bootstrap installation:

```bash
curl -fsSL https://raw.githubusercontent.com/peerlabs/plsec/main/bin/bootstrap.default.sh | bash
source ~/.bashrc  # or ~/.zshrc
plsec-status
```

### Missing jq

**Symptom**: `jq: command not found`

**Fix**: Install jq in your CI environment:

```bash
# Debian/Ubuntu
apt-get install -y jq

# Alpine
apk add jq

# macOS
brew install jq
```

### No .git directory

**Symptom**: Pre-commit hook check (C-3) fails with "not a git repo"

**Fix**: Ensure you check out the repository before running plsec-status:

```yaml
steps:
  - uses: actions/checkout@v4  # This creates .git/
  - run: plsec-status
```

## See Also

- [plsec-status Command Reference](commands/plsec-status.md)
- [Troubleshooting Guide](troubleshooting.md)
- [plsec scan](commands/plsec-scan.md)
