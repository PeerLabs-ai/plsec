#!/bin/bash
# assemble-bootstrap.sh - Build bootstrap.sh from skeleton + templates
#
# Reads templates/bootstrap/skeleton.bash and substitutes template markers:
#   @@INCLUDE:filename@@        - Content templates (embedded in single-quoted strings)
#   @@INCLUDE_SCRIPT:filename@@ - Script templates (embedded in unquoted heredocs)
#   @@PLSEC_VERSION@@           - Build-time version string
#
# Usage:
#   scripts/assemble-bootstrap.sh VERSION [OUTPUT]
#
# Examples:
#   scripts/assemble-bootstrap.sh 0.1.1-bootstrap
#   scripts/assemble-bootstrap.sh 0.1.1-bootstrap build/bootstrap.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." > /dev/null && pwd)"
TEMPLATE_DIR="${PROJECT_ROOT}/templates/bootstrap"
SKELETON="${TEMPLATE_DIR}/skeleton.bash"

VERSION="${1:?Usage: assemble-bootstrap.sh VERSION [OUTPUT]}"
OUTPUT="${2:-${PROJECT_ROOT}/build/bootstrap.sh}"

# ---------------------------------------------------------------------------
# Validate inputs
# ---------------------------------------------------------------------------

if [[ ! -f "${SKELETON}" ]]; then
    echo "ERROR: Skeleton not found: ${SKELETON}" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Read skeleton
# ---------------------------------------------------------------------------

content=$(cat "${SKELETON}")

# ---------------------------------------------------------------------------
# Process @@INCLUDE:filename@@ markers (content templates)
#
# These are embedded in single-quoted bash strings:
#   VAR='@@INCLUDE:file.md@@'
#
# Escaping: single quotes in template content become '\'' (end quote,
# escaped quote, start quote). No $ or backtick escaping needed because
# single-quoted strings prevent all interpretation.
# ---------------------------------------------------------------------------

process_content_includes() {
    local result="$1"
    # Use grep to find markers, then process each
    while printf '%s\n' "$result" | grep -q '@@INCLUDE:[^@]*@@'; do
        # Extract first marker
        local marker
        marker=$(printf '%s\n' "$result" | grep -o '@@INCLUDE:[^@]*@@' | head -1)
        local filename="${marker#@@INCLUDE:}"
        filename="${filename%@@}"
        local filepath="${TEMPLATE_DIR}/${filename}"

        if [[ ! -f "$filepath" ]]; then
            echo "ERROR: Content template not found: ${filepath}" >&2
            exit 1
        fi

        # Read template and escape single quotes
        local template_content
        template_content=$(cat "$filepath")
        local escaped
        escaped=$(printf '%s\n' "$template_content" | sed "s/'/'\\\\''/g")

        # Replace marker with escaped content
        # Use ENVIRON to pass values to awk (avoids C escape interpretation in -v)
        export MARKER="$marker" REPLACEMENT="$escaped"
        result=$(printf '%s\n' "$result" | awk '
        BEGIN { marker = ENVIRON["MARKER"]; replacement = ENVIRON["REPLACEMENT"] }
        {
            idx = index($0, marker)
            if (idx > 0) {
                before = substr($0, 1, idx - 1)
                after = substr($0, idx + length(marker))
                print before replacement after
            } else {
                print
            }
        }')
        unset MARKER REPLACEMENT
    done
    printf '%s\n' "$result"
}

# ---------------------------------------------------------------------------
# Process @@INCLUDE_SCRIPT:filename@@ markers (script templates)
#
# These are embedded in unquoted heredocs:
#   write_file "path" << EOF
#   @@INCLUDE_SCRIPT:wrapper.sh@@
#   EOF
#
# Escaping pipeline:
#   1. Escape all $ to \$  (prevent variable expansion in heredoc)
#   2. Escape all ` to \`  (prevent command substitution in heredoc)
#   3. Replace @@PLSEC_DIR@@ with ${PLSEC_DIR} (unescaped, resolves at runtime)
# ---------------------------------------------------------------------------

process_script_includes() {
    local result="$1"
    while printf '%s\n' "$result" | grep -q '@@INCLUDE_SCRIPT:[^@]*@@'; do
        local marker
        marker=$(printf '%s\n' "$result" | grep -o '@@INCLUDE_SCRIPT:[^@]*@@' | head -1)
        local filename="${marker#@@INCLUDE_SCRIPT:}"
        filename="${filename%@@}"
        local filepath="${TEMPLATE_DIR}/${filename}"

        if [[ ! -f "$filepath" ]]; then
            echo "ERROR: Script template not found: ${filepath}" >&2
            exit 1
        fi

        # Read template and apply escaping pipeline
        local template_content
        template_content=$(cat "$filepath")
        local escaped
        escaped=$(printf '%s\n' "$template_content" \
            | sed 's/\$/\\$/g' \
            | sed 's/`/\\`/g' \
            | sed 's/@@PLSEC_DIR@@/${PLSEC_DIR}/g')

        # Replace marker with escaped content
        export MARKER="$marker" REPLACEMENT="$escaped"
        result=$(printf '%s\n' "$result" | awk '
        BEGIN { marker = ENVIRON["MARKER"]; replacement = ENVIRON["REPLACEMENT"] }
        {
            idx = index($0, marker)
            if (idx > 0) {
                before = substr($0, 1, idx - 1)
                after = substr($0, idx + length(marker))
                print before replacement after
            } else {
                print
            }
        }')
        unset MARKER REPLACEMENT
    done
    printf '%s\n' "$result"
}

# ---------------------------------------------------------------------------
# Assemble
# ---------------------------------------------------------------------------

echo "Assembling bootstrap.sh..."
echo "  Skeleton: ${SKELETON}"
echo "  Templates: ${TEMPLATE_DIR}/"
echo "  Version: ${VERSION}"
echo "  Output: ${OUTPUT}"

# Step 1: Content includes
content=$(process_content_includes "$content")

# Step 2: Script includes
content=$(process_script_includes "$content")

# Step 3: Build-time markers
content="${content//@@PLSEC_VERSION@@/${VERSION}}"

# Step 4: Write output
mkdir -p "$(dirname "${OUTPUT}")"
printf '%s\n' "$content" > "${OUTPUT}"
chmod +x "${OUTPUT}"

# Step 5: Validate
echo ""
echo "Validating..."
if bash -n "${OUTPUT}"; then
    echo "  Syntax check: OK"
else
    echo "  Syntax check: FAILED" >&2
    exit 1
fi

# Count lines
line_count=$(wc -l < "${OUTPUT}")
echo "  Lines: ${line_count}"
echo ""
echo "Built: ${OUTPUT} (version ${VERSION})"
