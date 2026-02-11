"""
plsec - Security tooling for AI coding assistants.

Provides defense-in-depth security for Claude Code, Opencode, and other
AI coding assistants through static analysis, configuration management,
runtime monitoring, and audit logging.
"""

__version__ = "0.1.0"
__author__ = "Peerlabs"

from plsec.core.config import PlsecConfig, load_config

__all__ = ["PlsecConfig", "load_config", "__version__"]
