"""
Embedded configuration templates.

Templates are loaded from files in the templates/ subdirectory using
importlib.resources. The same files are consumed by the bootstrap
assembler (scripts/assemble-bootstrap.sh) via direct filesystem reads.

This eliminates the previous DRY violation where templates existed as
both files and Python string constants with manual backslash escaping.
"""

from importlib.resources import files  # nosemgrep: python37-compatibility-importlib2

_TEMPLATES = files("plsec.configs._template_files")


def _load(name: str) -> str:
    """Load a template file from the templates package."""
    return (_TEMPLATES / name).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Agent constraint files
# ---------------------------------------------------------------------------

CLAUDE_MD_STRICT = _load("claude-md-strict.md")
CLAUDE_MD_BALANCED = _load("claude-md-balanced.md")
OPENCODE_JSON_STRICT = _load("opencode-json-strict.json")
OPENCODE_JSON_BALANCED = _load("opencode-json-balanced.json")

# ---------------------------------------------------------------------------
# Project configuration (has {format} placeholders for plsec init)
# ---------------------------------------------------------------------------

PLSEC_YAML_TEMPLATE = _load("plsec.yaml.template")

# ---------------------------------------------------------------------------
# Scanner configuration
# ---------------------------------------------------------------------------

TRIVY_SCAN_RULES_YAML = _load("trivy-secret.yaml")
TRIVY_CONFIG_YAML = _load("trivy.yaml")

# ---------------------------------------------------------------------------
# Wrapper scripts (deployed by plsec install)
# ---------------------------------------------------------------------------

WRAPPER_CLAUDE_SH = _load("wrapper-claude.sh")
WRAPPER_OPENCODE_SH = _load("wrapper-opencode.sh")

# ---------------------------------------------------------------------------
# Standalone scripts (deployed by plsec install)
# ---------------------------------------------------------------------------

PLSEC_AUDIT_SH = _load("plsec-audit.sh")
PLSEC_STATUS_SH = _load("plsec-status.sh")

# ---------------------------------------------------------------------------
# Pre-commit hook
# ---------------------------------------------------------------------------

PRE_COMMIT_HOOK = _load("hook-pre-commit.sh")

# ---------------------------------------------------------------------------
# Placeholder sentinel (used by install.py for path substitution)
# ---------------------------------------------------------------------------

_PLSEC_DIR_PLACEHOLDER = "@@PLSEC_DIR@@"

# ---------------------------------------------------------------------------
# Template registries (used by install.py to deploy scripts)
# ---------------------------------------------------------------------------

WRAPPER_TEMPLATES: dict[str, str] = {
    "wrapper-claude.sh": WRAPPER_CLAUDE_SH,
    "wrapper-opencode.sh": WRAPPER_OPENCODE_SH,
}

STANDALONE_SCRIPTS: list[tuple[str, str]] = [
    ("plsec-audit.sh", PLSEC_AUDIT_SH),
    ("plsec-status.sh", PLSEC_STATUS_SH),
]
