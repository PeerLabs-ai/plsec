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

# Semgrep
if command -v semgrep &> /dev/null; then
    echo "=== Semgrep ==="
    semgrep --config auto "$TARGET" --quiet 2>/dev/null || true
    echo ""
fi

echo "Scan complete."
