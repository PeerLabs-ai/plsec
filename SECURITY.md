# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in plsec, please report it
responsibly. **Do not open a public GitHub issue.**

Email: **security@peerlabs.ai**

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Impact assessment (if possible)

We will acknowledge receipt within 48 hours and aim to provide an initial
assessment within 5 business days.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Scope

plsec is a security tool that orchestrates third-party scanners (Trivy,
Bandit, Semgrep) and manages agent configurations. Vulnerabilities in
scope include:

- Command injection via crafted config files or scan targets
- Path traversal in file operations
- Secrets or credentials exposed in logs or output
- Bypass of security policies or preset enforcement
- Vulnerabilities in plsec's own code or configuration templates

Vulnerabilities in upstream tools (Trivy, Bandit, Semgrep, Pipelock)
should be reported to their respective maintainers.

## Disclosure

We follow coordinated disclosure. We will work with you on a timeline
and credit reporters in release notes (unless anonymity is preferred).
