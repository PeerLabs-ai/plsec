"""Tests for project detection and analysis (core/detector.py).

Covers ProjectDetector's detection methods using tmp_path fixtures
to create synthetic project structures, plus direct _scan_file tests
with known secret patterns.
"""

from pathlib import Path

from plsec.core.detector import ProjectDetector, ProjectInfo, SecurityIssue

# -----------------------------------------------------------------------
# Dataclass defaults
# -----------------------------------------------------------------------


class TestProjectInfoDefaults:
    """Contract: ProjectInfo should have sensible defaults and
    independent mutable collections."""

    def test_defaults(self, tmp_path: Path):
        info = ProjectInfo(path=tmp_path, name="test")
        assert info.type == "unknown"
        assert info.package_manager is None
        assert info.is_git_repo is False
        assert info.issues == []
        assert info.file_counts == {}

    def test_mutable_defaults_independent(self, tmp_path: Path):
        a = ProjectInfo(path=tmp_path, name="a")
        b = ProjectInfo(path=tmp_path, name="b")
        a.issues.append(SecurityIssue(severity="low", message="x", file="f"))
        assert len(b.issues) == 0


# -----------------------------------------------------------------------
# _detect_type
# -----------------------------------------------------------------------


class TestDetectType:
    """Contract: ProjectDetector._detect_type returns the project type
    based on which marker files exist."""

    def test_python_project(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        detector = ProjectDetector(tmp_path)
        assert detector._detect_type() == "python"

    def test_node_project(self, tmp_path: Path):
        (tmp_path / "package.json").write_text("{}\n")
        detector = ProjectDetector(tmp_path)
        assert detector._detect_type() == "node"

    def test_go_project(self, tmp_path: Path):
        (tmp_path / "go.mod").write_text("module example.com/x\n")
        detector = ProjectDetector(tmp_path)
        assert detector._detect_type() == "go"

    def test_rust_project(self, tmp_path: Path):
        (tmp_path / "Cargo.toml").write_text("[package]\n")
        detector = ProjectDetector(tmp_path)
        assert detector._detect_type() == "rust"

    def test_mixed_project(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        (tmp_path / "package.json").write_text("{}\n")
        detector = ProjectDetector(tmp_path)
        assert detector._detect_type() == "mixed"

    def test_unknown_project(self, tmp_path: Path):
        detector = ProjectDetector(tmp_path)
        assert detector._detect_type() == "unknown"


# -----------------------------------------------------------------------
# _detect_package_manager
# -----------------------------------------------------------------------


class TestDetectPackageManager:
    """Contract: _detect_package_manager returns the package manager
    name based on lock files, or None if not detectable."""

    def test_python_uv(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        detector = ProjectDetector(tmp_path)
        assert detector._detect_package_manager("python") == "uv"

    def test_python_pip(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text("flask\n")
        detector = ProjectDetector(tmp_path)
        # pyproject.toml not present, so requirements.txt -> pip
        assert detector._detect_package_manager("python") == "pip"

    def test_node_npm(self, tmp_path: Path):
        (tmp_path / "package-lock.json").write_text("{}\n")
        detector = ProjectDetector(tmp_path)
        assert detector._detect_package_manager("node") == "npm"

    def test_unsupported_type_returns_none(self, tmp_path: Path):
        detector = ProjectDetector(tmp_path)
        assert detector._detect_package_manager("go") is None

    def test_no_lock_files_returns_none(self, tmp_path: Path):
        detector = ProjectDetector(tmp_path)
        assert detector._detect_package_manager("python") is None


# -----------------------------------------------------------------------
# _detect_test_framework
# -----------------------------------------------------------------------


class TestDetectTestFramework:
    """Contract: _detect_test_framework returns the test framework name
    or None."""

    def test_pytest_ini(self, tmp_path: Path):
        (tmp_path / "pytest.ini").write_text("[pytest]\n")
        detector = ProjectDetector(tmp_path)
        assert detector._detect_test_framework("python") == "pytest"

    def test_pytest_in_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n")
        detector = ProjectDetector(tmp_path)
        assert detector._detect_test_framework("python") == "pytest"

    def test_jest(self, tmp_path: Path):
        (tmp_path / "jest.config.js").write_text("module.exports = {};\n")
        detector = ProjectDetector(tmp_path)
        assert detector._detect_test_framework("node") == "jest"

    def test_no_framework_detected(self, tmp_path: Path):
        detector = ProjectDetector(tmp_path)
        assert detector._detect_test_framework("python") is None


# -----------------------------------------------------------------------
# _parse_gitignore
# -----------------------------------------------------------------------


class TestParseGitignore:
    """Contract: _parse_gitignore returns non-comment, non-empty lines."""

    def test_parses_patterns(self, tmp_path: Path):
        (tmp_path / ".gitignore").write_text("*.pyc\n__pycache__/\n.env\n")
        detector = ProjectDetector(tmp_path)
        patterns = detector._parse_gitignore()
        assert "*.pyc" in patterns
        assert "__pycache__/" in patterns
        assert ".env" in patterns

    def test_strips_comments_and_blanks(self, tmp_path: Path):
        (tmp_path / ".gitignore").write_text("# comment\n\n*.pyc\n  \n# another\nfoo\n")
        detector = ProjectDetector(tmp_path)
        patterns = detector._parse_gitignore()
        assert patterns == ["*.pyc", "foo"]

    def test_missing_gitignore_returns_empty(self, tmp_path: Path):
        detector = ProjectDetector(tmp_path)
        assert detector._parse_gitignore() == []


# -----------------------------------------------------------------------
# _detect_cloud_providers
# -----------------------------------------------------------------------


class TestDetectCloudProviders:
    """Contract: _detect_cloud_providers scans dependency files for
    cloud provider references."""

    def test_detects_aws_from_requirements(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text("boto3==1.34\nflask\n")
        detector = ProjectDetector(tmp_path)
        providers = detector._detect_cloud_providers()
        assert "aws" in providers

    def test_detects_gcp_from_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["google-cloud-storage"]\n'
        )
        detector = ProjectDetector(tmp_path)
        providers = detector._detect_cloud_providers()
        assert "gcp" in providers

    def test_no_providers_in_empty_project(self, tmp_path: Path):
        detector = ProjectDetector(tmp_path)
        assert detector._detect_cloud_providers() == []


# -----------------------------------------------------------------------
# _count_files
# -----------------------------------------------------------------------


class TestCountFiles:
    """Contract: _count_files counts files by extension, skipping
    standard ignored directories."""

    def test_counts_by_extension(self, tmp_path: Path):
        (tmp_path / "main.py").write_text("pass\n")
        (tmp_path / "util.py").write_text("pass\n")
        (tmp_path / "config.yaml").write_text("key: val\n")
        detector = ProjectDetector(tmp_path)
        counts = detector._count_files()
        assert counts[".py"] == 2
        assert counts[".yaml"] == 1

    def test_skips_venv(self, tmp_path: Path):
        venv = tmp_path / ".venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "site.py").write_text("pass\n")
        (tmp_path / "main.py").write_text("pass\n")
        detector = ProjectDetector(tmp_path)
        counts = detector._count_files()
        assert counts.get(".py") == 1  # only main.py, not site.py


# -----------------------------------------------------------------------
# _scan_file
# -----------------------------------------------------------------------


class TestScanFile:
    """Contract: _scan_file returns SecurityIssue list for lines
    matching SECRET_PATTERNS. Severity depends on the pattern type."""

    def _make_detector(self, tmp_path: Path) -> ProjectDetector:
        return ProjectDetector(tmp_path)

    def test_detects_api_key(self, tmp_path: Path):
        content = 'api_key = "sk_live_AAAAAAAAAAAAAAAAAAAAA"\n'
        file_path = tmp_path / "config.py"
        file_path.write_text(content)
        detector = self._make_detector(tmp_path)
        issues = detector._scan_file(file_path, content)
        assert len(issues) >= 1
        assert issues[0].severity in ("high", "critical")
        assert "API key" in issues[0].message

    def test_detects_password_as_critical(self, tmp_path: Path):
        content = 'password = "hunter2isnotapassword!"\n'
        file_path = tmp_path / "config.py"
        file_path.write_text(content)
        detector = self._make_detector(tmp_path)
        issues = detector._scan_file(file_path, content)
        assert len(issues) >= 1
        assert issues[0].severity == "critical"

    def test_detects_openai_key(self, tmp_path: Path):
        content = "OPENAI_KEY = 'sk-abcdefghijklmnopqrstuvwxyz12345678'\n"
        file_path = tmp_path / "env.py"
        file_path.write_text(content)
        detector = self._make_detector(tmp_path)
        issues = detector._scan_file(file_path, content)
        assert any("OpenAI" in i.message for i in issues)

    def test_clean_file_has_no_issues(self, tmp_path: Path):
        content = "def hello():\n    print('hello world')\n"
        file_path = tmp_path / "clean.py"
        file_path.write_text(content)
        detector = self._make_detector(tmp_path)
        issues = detector._scan_file(file_path, content)
        assert issues == []

    def test_issue_has_line_number(self, tmp_path: Path):
        content = "line1\nline2\npassword = 'mysecret123'\nline4\n"
        file_path = tmp_path / "test.py"
        file_path.write_text(content)
        detector = self._make_detector(tmp_path)
        issues = detector._scan_file(file_path, content)
        assert len(issues) >= 1
        assert issues[0].line == 3


# -----------------------------------------------------------------------
# analyze (integration)
# -----------------------------------------------------------------------


class TestAnalyze:
    """Contract: analyze() populates ProjectInfo from directory contents."""

    def test_empty_directory(self, tmp_path: Path):
        detector = ProjectDetector(tmp_path)
        info = detector.analyze()
        assert info.type == "unknown"
        assert info.name == tmp_path.name
        assert info.is_git_repo is False

    def test_python_project_with_security_configs(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        (tmp_path / "CLAUDE.md").write_text("# CLAUDE.md\n")
        (tmp_path / "plsec.yaml").write_text("version: 1\n")
        (tmp_path / ".gitignore").write_text("*.pyc\n.env\n")
        detector = ProjectDetector(tmp_path)
        info = detector.analyze()
        assert info.type == "python"
        # Registry-driven agent detection
        assert info.detected_agents["claude"] is True
        assert info.detected_agents["opencode"] is False
        assert info.has_plsec_yaml is True
        assert info.has_gitignore is True
        assert "*.pyc" in info.gitignore_patterns

    def test_nonexistent_directory(self, tmp_path: Path):
        detector = ProjectDetector(tmp_path / "does_not_exist")
        info = detector.analyze()
        assert info.type == "unknown"
