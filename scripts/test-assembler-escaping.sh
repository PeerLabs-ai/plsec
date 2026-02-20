#!/bin/bash
# test-assembler-escaping.sh
#
# Validates the escaping logic proposed for assemble-bootstrap.sh.
# Tests both content templates (CLAUDE.md, JSON) and script templates
# (wrapper scripts with shell syntax).
#
# Run: bash scripts/test-assembler-escaping.sh

set -euo pipefail

PASS=0
FAIL=0
TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}"' EXIT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        echo "[PASS] ${label}"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] ${label}"
        echo "  expected: ${expected}"
        echo "  actual:   ${actual}"
        FAIL=$((FAIL + 1))
    fi
}

assert_success() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "[PASS] ${label}"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] ${label} (exit code $?)"
        FAIL=$((FAIL + 1))
    fi
}

assert_contains() {
    local label="$1" haystack="$2" needle="$3"
    if echo "$haystack" | grep -qF "$needle"; then
        echo "[PASS] ${label}"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] ${label}"
        echo "  expected to contain: ${needle}"
        FAIL=$((FAIL + 1))
    fi
}

assert_not_contains() {
    local label="$1" haystack="$2" needle="$3"
    if echo "$haystack" | grep -qF "$needle"; then
        echo "[FAIL] ${label}"
        echo "  should NOT contain: ${needle}"
        FAIL=$((FAIL + 1))
    else
        echo "[PASS] ${label}"
        PASS=$((PASS + 1))
    fi
}

# =========================================================================
# TEST GROUP 1: Content template escaping (single-quoted string embedding)
# =========================================================================
echo ""
echo "=== Content Template Escaping ==="
echo ""

# --- 1a: CLAUDE.md balanced with @@PLSEC_DIR@@ ---

cat > "${TMPDIR}/claude-md-balanced.md" << 'RAWEOF'
# CLAUDE.md - Balanced Security Configuration

## Security Constraints

You are operating with security monitoring enabled.

### NEVER (Hard Blocks)

- NEVER access files outside the current project without explicit approval
- NEVER read .env files, .ssh/*, .aws/*, or credential files
- NEVER write secrets or API keys to files
- NEVER execute curl/wget to unknown domains

### Logging

Commands are logged to @@PLSEC_DIR@@/logs/
RAWEOF

# Escaping for single-quoted string: escape single quotes
template=$(cat "${TMPDIR}/claude-md-balanced.md")
escaped=$(echo "$template" | sed "s/'/'\\\\''/g")

# Simulate what bootstrap.sh does: assign to variable, then substitute
# @@PLSEC_DIR@@ at write time
eval "CLAUDE_MD_CONTENT='${escaped}'"
TEST_PLSEC_DIR="/home/testuser/.peerlabs/plsec"
resolved="${CLAUDE_MD_CONTENT//@@PLSEC_DIR@@/${TEST_PLSEC_DIR}}"

assert_contains "CLAUDE.md: NEVER section preserved" "$resolved" "NEVER access files"
assert_contains "CLAUDE.md: @@PLSEC_DIR@@ resolved" "$resolved" "/home/testuser/.peerlabs/plsec/logs/"
assert_not_contains "CLAUDE.md: no raw markers remain" "$resolved" "@@PLSEC_DIR@@"
assert_contains "CLAUDE.md: markdown headers preserved" "$resolved" "### Logging"

# Write and validate as markdown (check structure)
echo "$resolved" > "${TMPDIR}/claude-out.md"
header_count=$(grep -c '^#' "${TMPDIR}/claude-out.md")
assert_eq "CLAUDE.md: expected header count (4)" "4" "$header_count"


# --- 1b: CLAUDE.md with single quotes in content ---

cat > "${TMPDIR}/claude-md-quotes.md" << 'RAWEOF'
# Test CLAUDE.md

Don't access files you shouldn't.
It's important to follow the project's conventions.
RAWEOF

template=$(cat "${TMPDIR}/claude-md-quotes.md")
escaped=$(echo "$template" | sed "s/'/'\\\\''/g")
eval "QUOTE_TEST='${escaped}'"

assert_contains "CLAUDE.md quotes: apostrophes preserved" "$QUOTE_TEST" "Don't access"
assert_contains "CLAUDE.md quotes: possessives preserved" "$QUOTE_TEST" "project's conventions"


# --- 1c: opencode.json strict ---

cat > "${TMPDIR}/opencode-json-strict.json" << 'RAWEOF'
{
  "$schema": "https://opencode.ai/config.json",
  "permission": {
    "*": "ask",
    "read": {
      "*": "allow",
      ".env": "deny",
      ".env.*": "deny",
      "**/.ssh/*": "deny",
      "**/*.pem": "deny",
      "**/*.key": "deny"
    },
    "edit": {
      "*": "ask",
      ".env": "deny"
    },
    "bash": {
      "*": "deny",
      "git status *": "allow",
      "git diff *": "allow",
      "python -m pytest *": "allow"
    },
    "external_directory": "deny",
    "webfetch": "deny",
    "websearch": "deny"
  }
}
RAWEOF

template=$(cat "${TMPDIR}/opencode-json-strict.json")
escaped=$(echo "$template" | sed "s/'/'\\\\''/g")
eval "JSON_CONTENT='${escaped}'"

# Validate it's still valid JSON after round-trip
echo "$JSON_CONTENT" > "${TMPDIR}/opencode-out.json"
assert_success "opencode.json: valid JSON after escaping" python3 -m json.tool "${TMPDIR}/opencode-out.json"

# Check $schema survived (the $ in $schema is the key test)
assert_contains "opencode.json: \$schema preserved" "$JSON_CONTENT" '"$schema"'

# Validate structure
schema_val=$(python3 -c "import json; print(json.load(open('${TMPDIR}/opencode-out.json'))['\$schema'])")
assert_eq "opencode.json: \$schema value correct" "https://opencode.ai/config.json" "$schema_val"

deny_val=$(python3 -c "import json; print(json.load(open('${TMPDIR}/opencode-out.json'))['permission']['read']['.env'])")
assert_eq "opencode.json: .env deny preserved" "deny" "$deny_val"


# --- 1d: JSON with no shell-like content ---

cat > "${TMPDIR}/opencode-json-balanced.json" << 'RAWEOF'
{
  "$schema": "https://opencode.ai/config.json",
  "permission": {
    "*": "allow",
    "bash": {
      "*": "ask",
      "rm -rf *": "deny",
      "sudo *": "deny"
    }
  }
}
RAWEOF

template=$(cat "${TMPDIR}/opencode-json-balanced.json")
escaped=$(echo "$template" | sed "s/'/'\\\\''/g")
eval "JSON_BAL='${escaped}'"
echo "$JSON_BAL" > "${TMPDIR}/opencode-bal-out.json"
assert_success "opencode-balanced.json: valid JSON after escaping" python3 -m json.tool "${TMPDIR}/opencode-bal-out.json"


# =========================================================================
# TEST GROUP 2: Script template escaping (unquoted heredoc embedding)
# =========================================================================
echo ""
echo "=== Script Template Escaping ==="
echo ""

# --- 2a: wrapper-claude.sh ---

cat > "${TMPDIR}/wrapper-claude.sh" << 'RAWEOF'
#!/bin/bash
# claude-wrapper.sh - Logging wrapper for Claude Code

PLSEC_DIR="@@PLSEC_DIR@@"
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
RAWEOF

template=$(cat "${TMPDIR}/wrapper-claude.sh")

# The escaping pipeline for script templates:
# 1. Escape all $ to \$
# 2. Escape all backticks to \`
# 3. Replace @@PLSEC_DIR@@ with ${PLSEC_DIR} (unescaped)
escaped=$(echo "$template" \
    | sed 's/\$/\\$/g' \
    | sed 's/`/\\`/g' \
    | sed 's/@@PLSEC_DIR@@/${PLSEC_DIR}/g')

# Now simulate what bootstrap.sh does: write via unquoted heredoc
# PLSEC_DIR is set in the bootstrap context
PLSEC_DIR="/home/testuser/.peerlabs/plsec"

eval "cat << HEREDOC_EOF > ${TMPDIR}/claude-wrapper-out.sh
${escaped}
HEREDOC_EOF"

output=$(cat "${TMPDIR}/claude-wrapper-out.sh")

# Validate: PLSEC_DIR should be baked in
assert_contains "wrapper-claude: PLSEC_DIR baked in" "$output" 'PLSEC_DIR="/home/testuser/.peerlabs/plsec"'
assert_not_contains "wrapper-claude: no @@PLSEC_DIR@@ markers" "$output" "@@PLSEC_DIR@@"

# Validate: runtime variables should be literal (not expanded)
assert_contains "wrapper-claude: \$LOG_FILE preserved" "$output" '${PLSEC_DIR}/logs/claude-$(date +%Y%m%d).log'
assert_contains "wrapper-claude: \$(date) preserved" "$output" '$(date -u'
assert_contains "wrapper-claude: \$\$ preserved" "$output" '[$$]'
assert_contains "wrapper-claude: \$* preserved" "$output" '$*'
assert_contains "wrapper-claude: \$@ preserved" "$output" '"$@"'
assert_contains "wrapper-claude: \$? preserved" "$output" '$?'
assert_contains "wrapper-claude: \$EXIT_CODE preserved" "$output" '$EXIT_CODE'

# Validate: the generated script is syntactically valid bash
assert_success "wrapper-claude: generated script passes bash -n" bash -n "${TMPDIR}/claude-wrapper-out.sh"

# Validate: shebang preserved
first_line=$(head -1 "${TMPDIR}/claude-wrapper-out.sh")
assert_eq "wrapper-claude: shebang preserved" "#!/bin/bash" "$first_line"

# Validate: ${PLSEC_DIR} references after the assignment resolve correctly
# In the generated script, PLSEC_DIR is set to the baked-in value, so
# ${PLSEC_DIR}/configs/CLAUDE.md should appear literally
assert_contains "wrapper-claude: config path reference preserved" "$output" '${PLSEC_DIR}/configs/CLAUDE.md'


# --- 2b: wrapper-scan.sh (has ${1:-.} positional parameter) ---

cat > "${TMPDIR}/wrapper-scan.sh" << 'RAWEOF'
#!/bin/bash
# scan.sh - Run security scans

PLSEC_DIR="@@PLSEC_DIR@@"
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

echo "Scan complete."
RAWEOF

template=$(cat "${TMPDIR}/wrapper-scan.sh")
escaped=$(echo "$template" \
    | sed 's/\$/\\$/g' \
    | sed 's/`/\\`/g' \
    | sed 's/@@PLSEC_DIR@@/${PLSEC_DIR}/g')

PLSEC_DIR="/home/testuser/.peerlabs/plsec"
eval "cat << HEREDOC_EOF > ${TMPDIR}/scan-out.sh
${escaped}
HEREDOC_EOF"

output=$(cat "${TMPDIR}/scan-out.sh")

assert_contains "wrapper-scan: \${1:-.} preserved" "$output" '${1:-.}'
assert_contains "wrapper-scan: \$TARGET preserved" "$output" '$TARGET'
assert_contains "wrapper-scan: PLSEC_DIR baked in" "$output" 'PLSEC_DIR="/home/testuser/.peerlabs/plsec"'
assert_success "wrapper-scan: generated script passes bash -n" bash -n "${TMPDIR}/scan-out.sh"


# --- 2c: hook-pre-commit.sh (has $? and exit codes) ---

cat > "${TMPDIR}/hook-pre-commit.sh" << 'RAWEOF'
#!/bin/bash
# Pre-commit hook for secret scanning

PLSEC_DIR="@@PLSEC_DIR@@"

echo "Running pre-commit security scan..."

if command -v trivy &> /dev/null; then
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
RAWEOF

template=$(cat "${TMPDIR}/hook-pre-commit.sh")
escaped=$(echo "$template" \
    | sed 's/\$/\\$/g' \
    | sed 's/`/\\`/g' \
    | sed 's/@@PLSEC_DIR@@/${PLSEC_DIR}/g')

PLSEC_DIR="/home/testuser/.peerlabs/plsec"
eval "cat << HEREDOC_EOF > ${TMPDIR}/pre-commit-out.sh
${escaped}
HEREDOC_EOF"

output=$(cat "${TMPDIR}/pre-commit-out.sh")

assert_contains "hook-pre-commit: \$? preserved" "$output" '$? -ne 0'
assert_contains "hook-pre-commit: \$file preserved" "$output" '$file'
assert_contains "hook-pre-commit: single quotes in echo preserved" "$output" "Run 'trivy fs"
assert_success "hook-pre-commit: generated script passes bash -n" bash -n "${TMPDIR}/pre-commit-out.sh"


# --- 2d: pipelock-start.sh (simple, minimal variables) ---

cat > "${TMPDIR}/pipelock-start.sh" << 'RAWEOF'
#!/bin/bash
PLSEC_DIR="@@PLSEC_DIR@@"
LOG_FILE="${PLSEC_DIR}/logs/pipelock.log"

echo "Starting Pipelock proxy (audit mode)..."
pipelock run --config "${PLSEC_DIR}/pipelock.yaml" 2>&1 | tee -a "$LOG_FILE"
RAWEOF

template=$(cat "${TMPDIR}/pipelock-start.sh")
escaped=$(echo "$template" \
    | sed 's/\$/\\$/g' \
    | sed 's/`/\\`/g' \
    | sed 's/@@PLSEC_DIR@@/${PLSEC_DIR}/g')

PLSEC_DIR="/home/testuser/.peerlabs/plsec"
eval "cat << HEREDOC_EOF > ${TMPDIR}/pipelock-out.sh
${escaped}
HEREDOC_EOF"

output=$(cat "${TMPDIR}/pipelock-out.sh")

assert_contains "pipelock-start: \$LOG_FILE preserved" "$output" '$LOG_FILE'
assert_contains "pipelock-start: PLSEC_DIR baked in" "$output" 'PLSEC_DIR="/home/testuser/.peerlabs/plsec"'
assert_success "pipelock-start: generated script passes bash -n" bash -n "${TMPDIR}/pipelock-out.sh"


# =========================================================================
# TEST GROUP 3: Edge cases
# =========================================================================
echo ""
echo "=== Edge Cases ==="
echo ""

# --- 3a: YAML with no shell-like content ---
# Simulate the real assembler: content is embedded in a single-quoted string
# in bootstrap.sh (VAR='content'), so we build a small script that assigns
# the escaped content and prints it, matching the actual round-trip.

cat > "${TMPDIR}/trivy-secret.yaml" << 'RAWEOF'
rules:
  - id: generic-secret
    description: "Generic secret pattern"
    regex: "(?i)(secret|password|token|key)\\s*[:=]\\s*['\"]?\\S{8,}"
    severity: HIGH
    allow-rules:
      - id: test-values
        regex: "(test|example|dummy|placeholder)"
RAWEOF

template=$(cat "${TMPDIR}/trivy-secret.yaml")
escaped=$(printf '%s\n' "$template" | sed "s/'/'\\\\''/g")
# Build a helper script that mirrors how bootstrap.sh embeds content
printf "#!/bin/bash\nYAML_CONTENT='%s'\nprintf '%%s\\\\n' \"\$YAML_CONTENT\"\n" "$escaped" > "${TMPDIR}/yaml-helper.sh"
bash "${TMPDIR}/yaml-helper.sh" > "${TMPDIR}/trivy-out.yaml"
assert_success "trivy-secret.yaml: valid YAML after escaping" uv run python -c "import yaml; yaml.safe_load(open('${TMPDIR}/trivy-out.yaml'))"


# --- 3b: Content with backticks (e.g., markdown code spans) ---

cat > "${TMPDIR}/claude-md-backticks.md" << 'RAWEOF'
# Test

Run `plsec scan` to check for secrets.
Use `trivy fs .` for manual scanning.
Configure via `@@PLSEC_DIR@@/configs/`.
RAWEOF

template=$(cat "${TMPDIR}/claude-md-backticks.md")
escaped=$(echo "$template" | sed "s/'/'\\\\''/g")
eval "BACKTICK_TEST='${escaped}'"
resolved="${BACKTICK_TEST//@@PLSEC_DIR@@//home/test/.peerlabs/plsec}"

assert_contains "backticks in markdown: code spans preserved" "$resolved" '`plsec scan`'
assert_contains "backticks in markdown: marker resolved" "$resolved" '`/home/test/.peerlabs/plsec/configs/`'


# --- 3c: Script template with backtick command substitution ---
# (Old-style backtick substitution -- shouldn't appear in our templates
# but worth testing the escaping handles it)

cat > "${TMPDIR}/backtick-script.sh" << 'RAWEOF'
#!/bin/bash
PLSEC_DIR="@@PLSEC_DIR@@"
TIMESTAMP=`date +%s`
echo "Started at $TIMESTAMP"
RAWEOF

template=$(cat "${TMPDIR}/backtick-script.sh")
escaped=$(echo "$template" \
    | sed 's/\$/\\$/g' \
    | sed 's/`/\\`/g' \
    | sed 's/@@PLSEC_DIR@@/${PLSEC_DIR}/g')

PLSEC_DIR="/tmp/test"
eval "cat << HEREDOC_EOF > ${TMPDIR}/backtick-out.sh
${escaped}
HEREDOC_EOF"

output=$(cat "${TMPDIR}/backtick-out.sh")
assert_contains "backtick cmd sub: backticks preserved" "$output" '`date +%s`'
assert_success "backtick cmd sub: passes bash -n" bash -n "${TMPDIR}/backtick-out.sh"


# --- 3d: Double-dollar ($$) in script ---

cat > "${TMPDIR}/double-dollar.sh" << 'RAWEOF'
#!/bin/bash
PLSEC_DIR="@@PLSEC_DIR@@"
echo "PID: $$"
echo "Args: $@ and $*"
echo "Last exit: $?"
echo "Param count: $#"
RAWEOF

template=$(cat "${TMPDIR}/double-dollar.sh")
escaped=$(echo "$template" \
    | sed 's/\$/\\$/g' \
    | sed 's/`/\\`/g' \
    | sed 's/@@PLSEC_DIR@@/${PLSEC_DIR}/g')

PLSEC_DIR="/tmp/test"
eval "cat << HEREDOC_EOF > ${TMPDIR}/dd-out.sh
${escaped}
HEREDOC_EOF"

output=$(cat "${TMPDIR}/dd-out.sh")
assert_contains "double-dollar: \$\$ preserved" "$output" '$$'
assert_contains "double-dollar: \$@ preserved" "$output" '$@'
assert_contains "double-dollar: \$# preserved" "$output" '$#'
assert_success "double-dollar: passes bash -n" bash -n "${TMPDIR}/dd-out.sh"


# =========================================================================
# Summary
# =========================================================================
echo ""
echo "==========================================="
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "==========================================="

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
