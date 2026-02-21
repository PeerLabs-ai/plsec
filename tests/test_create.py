"""Tests for project scaffolding functions (commands/create.py).

Covers the template creation functions (create_python_template,
create_node_template, create_go_template), gitignore generation,
pre-commit config, and README generation.

All tests use tmp_path - pure filesystem operations, no subprocess mocking.
"""

import json
from pathlib import Path

from plsec.commands.create import (
    create_gitignore,
    create_go_template,
    create_node_template,
    create_pre_commit_config,
    create_python_template,
    create_readme,
)

# -----------------------------------------------------------------------
# create_python_template
# -----------------------------------------------------------------------


class TestCreatePythonTemplate:
    """Contract: create_python_template creates a standard Python project
    layout with src/<pkg>/__init__.py, tests/__init__.py, and pyproject.toml."""

    def test_creates_package_directory(self, tmp_path: Path):
        create_python_template(tmp_path, "my-project")
        assert (tmp_path / "src" / "my_project" / "__init__.py").exists()
        assert (tmp_path / "tests" / "__init__.py").exists()

    def test_creates_pyproject_toml(self, tmp_path: Path):
        create_python_template(tmp_path, "my-project")
        pyproject = tmp_path / "pyproject.toml"
        assert pyproject.exists()
        content = pyproject.read_text()
        assert 'name = "my-project"' in content
        assert "hatchling" in content

    def test_init_has_version(self, tmp_path: Path):
        create_python_template(tmp_path, "test-pkg")
        init_content = (tmp_path / "src" / "test_pkg" / "__init__.py").read_text()
        assert "__version__" in init_content

    def test_hyphen_to_underscore_in_package_name(self, tmp_path: Path):
        create_python_template(tmp_path, "my-cool-project")
        assert (tmp_path / "src" / "my_cool_project").is_dir()


# -----------------------------------------------------------------------
# create_node_template
# -----------------------------------------------------------------------


class TestCreateNodeTemplate:
    """Contract: create_node_template creates a Node.js project
    with src/index.js and a valid package.json."""

    def test_creates_structure(self, tmp_path: Path):
        create_node_template(tmp_path, "my-app")
        assert (tmp_path / "src" / "index.js").exists()
        assert (tmp_path / "package.json").exists()

    def test_valid_package_json(self, tmp_path: Path):
        create_node_template(tmp_path, "my-app")
        data = json.loads((tmp_path / "package.json").read_text())
        assert data["name"] == "my-app"
        assert "version" in data


# -----------------------------------------------------------------------
# create_go_template
# -----------------------------------------------------------------------


class TestCreateGoTemplate:
    """Contract: create_go_template creates go.mod and main.go."""

    def test_creates_structure(self, tmp_path: Path):
        create_go_template(tmp_path, "example.com/myapp")
        assert (tmp_path / "go.mod").exists()
        assert (tmp_path / "main.go").exists()

    def test_go_mod_has_module_name(self, tmp_path: Path):
        create_go_template(tmp_path, "example.com/myapp")
        content = (tmp_path / "go.mod").read_text()
        assert "module example.com/myapp" in content


# -----------------------------------------------------------------------
# create_gitignore
# -----------------------------------------------------------------------


class TestCreateGitignore:
    """Contract: create_gitignore writes a .gitignore with common
    security patterns plus language-specific patterns."""

    def test_common_security_patterns(self, tmp_path: Path):
        create_gitignore(tmp_path, "python", [])
        content = (tmp_path / ".gitignore").read_text()
        assert ".env" in content
        assert "*.pem" in content
        assert "*.key" in content
        assert ".plsec-manifest.json" in content

    def test_python_specific_patterns(self, tmp_path: Path):
        create_gitignore(tmp_path, "python", [])
        content = (tmp_path / ".gitignore").read_text()
        assert "__pycache__/" in content
        assert ".venv/" in content

    def test_node_specific_patterns(self, tmp_path: Path):
        create_gitignore(tmp_path, "node", [])
        content = (tmp_path / ".gitignore").read_text()
        assert "node_modules/" in content
        # Should not include Python patterns
        assert "__pycache__/" not in content

    def test_go_specific_patterns(self, tmp_path: Path):
        create_gitignore(tmp_path, "go", [])
        content = (tmp_path / ".gitignore").read_text()
        assert "vendor/" in content

    def test_mixed_includes_all_languages(self, tmp_path: Path):
        create_gitignore(tmp_path, "mixed", [])
        content = (tmp_path / ".gitignore").read_text()
        assert "__pycache__/" in content
        assert "node_modules/" in content
        assert "vendor/" in content


# -----------------------------------------------------------------------
# create_pre_commit_config
# -----------------------------------------------------------------------


class TestCreatePreCommitConfig:
    """Contract: create_pre_commit_config generates a pre-commit
    configuration with security hooks."""

    def test_base_config_has_trivy(self, tmp_path: Path):
        create_pre_commit_config(tmp_path, "node")
        content = (tmp_path / ".pre-commit-config.yaml").read_text()
        assert "trivy" in content.lower()
        assert "detect-secrets" in content

    def test_python_adds_ruff_and_bandit(self, tmp_path: Path):
        create_pre_commit_config(tmp_path, "python")
        content = (tmp_path / ".pre-commit-config.yaml").read_text()
        assert "ruff" in content
        assert "bandit" in content

    def test_non_python_has_no_ruff(self, tmp_path: Path):
        create_pre_commit_config(tmp_path, "go")
        content = (tmp_path / ".pre-commit-config.yaml").read_text()
        assert "ruff" not in content


# -----------------------------------------------------------------------
# create_readme
# -----------------------------------------------------------------------


class TestCreateReadme:
    """Contract: create_readme generates a README with type-specific
    setup instructions and a plsec security section."""

    def test_python_readme(self, tmp_path: Path):
        create_readme(tmp_path, "my-project", "python")
        content = (tmp_path / "README.md").read_text()
        assert "# my-project" in content
        assert "uv pip install" in content
        assert "plsec" in content

    def test_go_readme(self, tmp_path: Path):
        create_readme(tmp_path, "my-app", "go")
        content = (tmp_path / "README.md").read_text()
        assert "go run" in content

    def test_always_has_security_section(self, tmp_path: Path):
        create_readme(tmp_path, "test", "node")
        content = (tmp_path / "README.md").read_text()
        assert "Security" in content
        assert "plsec doctor" in content
        assert "plsec scan" in content
