"""Shared test fixtures for plsec test suite."""

from pathlib import Path

import pytest
from typer.testing import CliRunner


@pytest.fixture
def runner() -> CliRunner:
    """Typer CLI test runner."""
    return CliRunner()


@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    """Create a minimal Python project structure for testing."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test'\n")
    (tmp_path / "src").mkdir()
    return tmp_path


@pytest.fixture
def mock_plsec_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect plsec home to a temporary directory.

    Prevents tests from touching the real ~/.peerlabs/plsec.
    """
    home = tmp_path / ".peerlabs" / "plsec"
    home.mkdir(parents=True)
    monkeypatch.setattr("plsec.core.config.get_plsec_home", lambda: home)
    return home
