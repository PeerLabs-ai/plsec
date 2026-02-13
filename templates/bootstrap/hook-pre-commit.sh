#!/bin/bash
# Pre-commit hook for secret scanning

PLSEC_DIR="@@PLSEC_DIR@@"

echo "Running pre-commit security scan..."

# Check staged files for secrets
if command -v trivy &> /dev/null; then
    # Scan staged files
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
