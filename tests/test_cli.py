"""Tests for the top-level plsec CLI (cli.py).

Smoke tests that exercise the real top-level app with no mocking.
These verify app registration, global flags, and basic command routing.
"""

from typer.testing import CliRunner

from plsec import __version__
from plsec.cli import app

runner = CliRunner()


class TestCLI:
    """Top-level CLI smoke tests."""

    def test_help(self):
        """--help should exit 0 and mention plsec."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "plsec" in result.stdout

    def test_version(self):
        """--version should show the current version string."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.stdout

    def test_doctor_runs(self):
        """doctor command should run without crashing.

        This is an unmocked integration smoke test -- it exercises the
        real top-level app and command routing. May return exit code 1
        if system dependencies are missing, but should never crash.
        """
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code in (0, 1)
