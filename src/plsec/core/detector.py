"""
Project detection and analysis.

Analyzes existing projects to detect type, dependencies, and security posture.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


@dataclass
class SecurityIssue:
    """A detected security issue."""

    severity: Literal["critical", "high", "medium", "low"]
    message: str
    file: str
    line: int | None = None


@dataclass
class ProjectInfo:
    """Detected project information."""

    # Project metadata
    path: Path
    name: str
    type: Literal["python", "node", "go", "rust", "mixed", "unknown"] = "unknown"
    package_manager: str | None = None
    test_framework: str | None = None

    # Dependencies and providers
    cloud_providers: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)

    # Git status
    is_git_repo: bool = False
    has_uncommitted_changes: bool = False

    # Existing security configuration
    has_claude_md: bool = False
    has_opencode_json: bool = False
    has_plsec_yaml: bool = False
    has_gitignore: bool = False
    has_pre_commit: bool = False
    gitignore_patterns: list[str] = field(default_factory=list)

    # Detected issues
    issues: list[SecurityIssue] = field(default_factory=list)

    # File counts
    file_counts: dict[str, int] = field(default_factory=dict)


class ProjectDetector:
    """Analyzes a project directory to detect configuration and security posture."""

    # File patterns for project type detection
    TYPE_MARKERS = {
        "python": ["pyproject.toml", "setup.py", "requirements.txt", "Pipfile"],
        "node": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
        "go": ["go.mod", "go.sum"],
        "rust": ["Cargo.toml", "Cargo.lock"],
    }

    # Package manager detection
    PACKAGE_MANAGERS = {
        "python": {
            "pyproject.toml": "uv",  # Assume uv for modern projects
            "requirements.txt": "pip",
            "Pipfile": "pipenv",
            "poetry.lock": "poetry",
        },
        "node": {
            "pnpm-lock.yaml": "pnpm",
            "yarn.lock": "yarn",
            "package-lock.json": "npm",
        },
    }

    # Cloud provider patterns (in requirements, imports, config)
    CLOUD_PATTERNS = {
        "aws": [r"boto3", r"aws-", r"amazon", r"s3://", r"AWS_"],
        "gcp": [r"google-cloud", r"gcloud", r"gs://", r"GOOGLE_"],
        "azure": [r"azure-", r"microsoft\.azure", r"AZURE_"],
        "digitalocean": [r"digitalocean", r"doctl", r"DIGITALOCEAN_", r"DO_"],
        "cloudflare": [r"cloudflare", r"CF_", r"CLOUDFLARE_"],
    }

    # Sensitive patterns for quick scan
    SECRET_PATTERNS = [
        (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][^'\"]{20,}['\"]", "API key"),
        (r"(?i)(secret|token)\s*[=:]\s*['\"][^'\"]{20,}['\"]", "Secret/Token"),
        (r"(?i)password\s*[=:]\s*['\"][^'\"]+['\"]", "Password"),
        (r"sk-[a-zA-Z0-9]{32,}", "OpenAI API key"),
        (r"sk-ant-[a-zA-Z0-9_-]{32,}", "Anthropic API key"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub token"),
        (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    ]

    def __init__(self, path: Path | str) -> None:
        """
        Initialize detector.

        Args:
            path: Project directory path.
        """
        self.path = Path(path).resolve()

    def analyze(self) -> ProjectInfo:
        """
        Analyze the project directory.

        Returns:
            ProjectInfo with detected configuration.
        """
        info = ProjectInfo(
            path=self.path,
            name=self.path.name,
        )

        # Check if directory exists
        if not self.path.is_dir():
            return info

        # Detect project type
        info.type = self._detect_type()
        info.package_manager = self._detect_package_manager(info.type)
        info.test_framework = self._detect_test_framework(info.type)

        # Detect git status
        info.is_git_repo = (self.path / ".git").is_dir()
        if info.is_git_repo:
            info.has_uncommitted_changes = self._check_uncommitted_changes()

        # Check existing security configuration
        info.has_claude_md = (self.path / "CLAUDE.md").exists()
        info.has_opencode_json = (self.path / "opencode.json").exists()
        info.has_plsec_yaml = (self.path / "plsec.yaml").exists()
        info.has_gitignore = (self.path / ".gitignore").exists()
        info.has_pre_commit = (self.path / ".pre-commit-config.yaml").exists()

        # Parse gitignore if present
        if info.has_gitignore:
            info.gitignore_patterns = self._parse_gitignore()

        # Detect cloud providers
        info.cloud_providers = self._detect_cloud_providers()

        # Count files by extension
        info.file_counts = self._count_files()

        return info

    def quick_scan(self, info: ProjectInfo) -> list[SecurityIssue]:
        """
        Run a quick security scan for obvious issues.

        Args:
            info: Project info to update.

        Returns:
            List of detected issues.
        """
        issues: list[SecurityIssue] = []

        # Scan relevant files
        extensions = {".py", ".js", ".ts", ".go", ".rs", ".toml", ".yaml", ".yml", ".json", ".env"}

        for file_path in self.path.rglob("*"):
            if file_path.is_file() and file_path.suffix in extensions:
                # Skip common non-code directories
                parts = file_path.parts
                if any(
                    p in parts
                    for p in [
                        ".git",
                        "node_modules",
                        "__pycache__",
                        ".venv",
                        "venv",
                        "dist",
                        "build",
                    ]
                ):
                    continue

                try:
                    content = file_path.read_text(errors="ignore")
                    file_issues = self._scan_file(file_path, content)
                    issues.extend(file_issues)
                except OSError:
                    continue

        info.issues = issues
        return issues

    def _detect_type(self) -> Literal["python", "node", "go", "rust", "mixed", "unknown"]:
        """Detect project type from marker files."""
        detected = []

        for proj_type, markers in self.TYPE_MARKERS.items():
            for marker in markers:
                if (self.path / marker).exists():
                    detected.append(proj_type)
                    break

        if len(detected) == 0:
            return "unknown"
        if len(detected) == 1:
            return detected[0]
        return "mixed"

    def _detect_package_manager(self, proj_type: str) -> str | None:
        """Detect package manager from lock files."""
        if proj_type not in self.PACKAGE_MANAGERS:
            return None

        for marker, manager in self.PACKAGE_MANAGERS[proj_type].items():
            if (self.path / marker).exists():
                return manager

        return None

    def _detect_test_framework(self, proj_type: str) -> str | None:
        """Detect test framework from config files."""
        if proj_type == "python":
            if (self.path / "pytest.ini").exists():
                return "pytest"
            if (self.path / "pyproject.toml").exists():
                try:
                    content = (self.path / "pyproject.toml").read_text()
                    if "pytest" in content:
                        return "pytest"
                except OSError:
                    pass
        elif proj_type == "node":
            if (self.path / "jest.config.js").exists():
                return "jest"

        return None

    def _check_uncommitted_changes(self) -> bool:
        """Check for uncommitted git changes."""
        import subprocess

        try:
            result = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=self.path,
                capture_output=True,
                text=True,
                timeout=5,
            )
            return bool(result.stdout.strip())
        except (OSError, subprocess.SubprocessError):
            return False

    def _parse_gitignore(self) -> list[str]:
        """Parse .gitignore and return patterns."""
        try:
            content = (self.path / ".gitignore").read_text()
            patterns = []
            for line in content.split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
            return patterns
        except OSError:
            return []

    def _detect_cloud_providers(self) -> list[str]:
        """Detect cloud providers from project files."""
        providers: set[str] = set()

        # Files to check
        files_to_check = [
            "requirements.txt",
            "pyproject.toml",
            "package.json",
            "go.mod",
        ]

        for filename in files_to_check:
            filepath = self.path / filename
            if filepath.exists():
                try:
                    content = filepath.read_text()
                    for provider, patterns in self.CLOUD_PATTERNS.items():
                        for pattern in patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                providers.add(provider)
                                break
                except OSError:
                    pass

        return list(providers)

    def _count_files(self) -> dict[str, int]:
        """Count files by extension."""
        counts: dict[str, int] = {}

        for file_path in self.path.rglob("*"):
            if file_path.is_file():
                # Skip common non-code directories
                parts = file_path.parts
                if any(
                    p in parts for p in [".git", "node_modules", "__pycache__", ".venv", "venv"]
                ):
                    continue

                ext = file_path.suffix or "(no extension)"
                counts[ext] = counts.get(ext, 0) + 1

        return counts

    def _scan_file(self, file_path: Path, content: str) -> list[SecurityIssue]:
        """Scan a single file for security issues."""
        issues: list[SecurityIssue] = []
        rel_path = str(file_path.relative_to(self.path))

        for line_num, line in enumerate(content.split("\n"), 1):
            for pattern, description in self.SECRET_PATTERNS:
                if re.search(pattern, line):
                    # Determine severity
                    severity: Literal["critical", "high", "medium", "low"] = "high"
                    if "password" in description.lower():
                        severity = "critical"
                    elif "token" in description.lower():
                        severity = "high"

                    issues.append(
                        SecurityIssue(
                            severity=severity,
                            message=f"Possible {description}",
                            file=rel_path,
                            line=line_num,
                        )
                    )

        return issues
