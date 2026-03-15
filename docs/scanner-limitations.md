# Scanner Limitations and Tradeoffs

## Overview

plsec uses multiple security scanners with carefully tuned configurations to balance
detection accuracy with false positive rates. This document explains the limitations
and tradeoffs of our scanning approach.

**Philosophy**: We believe in transparency. Users should understand what our scanners
can and cannot detect so they can make informed security decisions.

---

## Secret Detection (Trivy)

### generic-secret Rule

**What it does**: Detects common secret/token patterns in code.

**Limitation**: Requires assignment context (`=` or `:`) to reduce false positives.

**Why this tradeoff?**

plsec is designed for security-conscious projects where documentation, tests, and
code discussions frequently mention the word "secret." Without this limitation, we'd
flag hundreds of false positives in legitimate files.

**Tradeoff**:
- **Benefit**: Reduces false positives in documentation, comments, and test assertions
- **Risk**: May miss secrets in unusual formats without clear assignment operators

**Examples**:

```python
# DETECTED (assignment context present)
API_KEY = "sk-abc123456789012345678901234567890"
config = {"secret": "token123456789012345"}
export SECRET_TOKEN=xyz789012345678901234567890

# NOT DETECTED (no assignment context)
# Comment: "store your secret in environment variables"
assert "secret" in preset.description
print(f"secret value: {token}")  # May miss this pattern
```

**What's still protected**:

Provider-specific rules (AWS, GitHub, OpenAI, Anthropic, Stripe) use **exact format
matching** and do NOT require assignment context. These have higher accuracy:

- `sk-ant-...` (Anthropic)
- `sk-proj-...` (OpenAI)
- `ghp_...` (GitHub)
- `AKIA...` (AWS)
- `sk_live_...` (Stripe)

**Mitigation strategies**:

If you suspect missed secrets:

1. **Run stricter scan** with custom config:
   ```bash
   trivy fs --scanners secret --severity HIGH,CRITICAL
   ```

2. **Use additional tools**:
   ```bash
   detect-secrets scan
   ```

3. **Manual review**: Check code for hard-coded credentials, especially in:
   - Configuration files
   - Test fixtures
   - Example/demo code

4. **Custom rules**: Create your own `trivy-secret.yaml` with stricter patterns

---

## Code Analysis (Bandit)

**What it does**: Detects common Python security anti-patterns.

**Default severity**: Medium-Low (`-ll` flag) to reduce noise.

**Limitations**:
- Only scans Python code
- May miss context-dependent vulnerabilities
- Configured to skip common third-party directories (`.venv`, `node_modules`)

**Mitigation**: Run full Bandit separately for comprehensive analysis:
```bash
bandit -r . -ll  # Low-Low severity
bandit -r . -l   # Low severity (more findings)
```

---

## Semantic Analysis (Semgrep)

**What it does**: Multi-language semantic code analysis.

**Configuration**: Uses `--config auto` (community rules).

**Limitations**:
- Requires network access for rule updates
- May miss custom/proprietary patterns specific to your codebase
- Performance impact on large codebases

**Mitigation**: Add custom Semgrep rules via `.semgrep.yml`:
```yaml
rules:
  - id: custom-secret-pattern
    pattern: |
      my_custom_secret = "..."
    message: Custom secret pattern detected
    severity: ERROR
```

---

## Temporal File Handling

All tests use Python's `tmp_path` fixture (pytest) or shell's `mktemp -d` to create
secure temporary directories instead of hardcoded `/tmp` paths. This prevents:

- Race conditions in concurrent test runs
- Security issues from predictable temp paths (CWE-377)
- Permission conflicts on shared systems

---

## Configuration Philosophy

### Preset-Driven Defaults

| Preset     | Scanner Behavior       | False Positive Rate | Detection Coverage |
|------------|------------------------|---------------------|--------------------|
| `minimal`  | Aggressive suppression | Very Low            | Medium             |
| `balanced` | Reasonable defaults    | Low                 | High               |
| `strict`   | Minimal suppression    | Medium              | Very High          |
| `paranoid` | No suppression         | High                | Maximum            |

### Customization

Users can override any scanner parameter via `plsec.toml`:

```toml
[scanner]
skip_dirs = [".venv", "node_modules", "custom_vendor"]
severity_threshold = "LOW"  # More findings
```

See `docs/presets.md` for details.

---

## Known False Negatives

**Scenarios where scanners may miss issues**:

1. **Obfuscated secrets**: Base64-encoded, hex-encoded, or encrypted values
2. **Dynamic secret construction**: Secrets built from concatenation or computation
3. **Environment-only secrets**: Values only in ENV vars, never in code
4. **Custom/proprietary formats**: Secrets using company-specific patterns

**Our stance**: We optimize for common cases. For specialized detection, combine
plsec with:
- Runtime monitoring (environment variable scanning)
- Secret management audits (Vault, AWS Secrets Manager)
- Manual security reviews

---

## Reporting Issues

### False Negatives (Missed Real Issues)

If plsec's scanners miss a real security issue:

1. **Verify it's real** (not a test fixture or example)
2. **Report to**: [GitHub Issues](https://github.com/PeerLabs-ai/plsec/issues)
3. **Include**:
   - Scanner that should have caught it (Trivy, Bandit, Semgrep)
   - Minimal reproduction case (sanitized)
   - Suggested rule improvement

### False Positives (Incorrect Flags)

If plsec incorrectly flags safe code:

1. **Understand the rule**: Check this doc + scanner docs
2. **Suppress if legitimate**: Use `.trivyignore.yaml`, `# nosec`, etc.
3. **Report patterns**: If a category of false positives emerges, report it

---

## Version History

- **v0.1.0** (2026-02-25): Initial documentation
  - Documented generic-secret assignment requirement
  - Added preset philosophy and mitigation strategies

---

## See Also

- [Preset Documentation](presets.md) - Scanner preset configurations
- [Configuration Guide](configuration.md) - Customizing scanner behavior
- [Trivy Documentation](https://trivy.dev/docs/) - Upstream scanner docs
- [Bandit Documentation](https://bandit.readthedocs.io/) - Python security rules
