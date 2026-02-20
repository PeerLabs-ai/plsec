"""Tests for workspace integrity monitoring (commands/integrity.py).

Covers the pure utility functions (should_include, compare_manifests,
get_manifest_path) and the filesystem-dependent functions (hash_file,
create_manifest) using tmp_path fixtures.
"""

from pathlib import Path

from plsec.commands.integrity import (
    DEFAULT_EXCLUDES,
    compare_manifests,
    create_manifest,
    get_manifest_path,
    hash_file,
    should_include,
)


class TestGetManifestPath:
    """Tests for get_manifest_path - pure path construction."""

    def test_returns_manifest_in_workspace(self):
        workspace = Path("/some/project")
        result = get_manifest_path(workspace)
        assert result == Path("/some/project/.plsec-manifest.json")

    def test_return_type_is_path(self, tmp_path: Path):
        result = get_manifest_path(tmp_path)
        assert isinstance(result, Path)


class TestShouldInclude:
    """Tests for should_include - pure string matching logic.

    This function determines which files are tracked in integrity
    manifests. It uses simple substring matching and basic glob patterns.
    """

    def test_includes_normal_file(self):
        """A regular source file should be included."""
        assert should_include(Path("src/main.py"), DEFAULT_EXCLUDES) is True

    def test_excludes_git_directory(self):
        """Paths containing .git should be excluded."""
        assert should_include(Path(".git/config"), DEFAULT_EXCLUDES) is False

    def test_excludes_pycache(self):
        """Paths containing __pycache__ should be excluded."""
        assert should_include(Path("src/__pycache__/foo.pyc"), DEFAULT_EXCLUDES) is False

    def test_excludes_pyc_files(self):
        """*.pyc files should be excluded."""
        assert should_include(Path("module.pyc"), DEFAULT_EXCLUDES) is False

    def test_excludes_node_modules(self):
        assert should_include(Path("node_modules/pkg/index.js"), DEFAULT_EXCLUDES) is False

    def test_excludes_venv(self):
        assert should_include(Path(".venv/lib/python3.12/site.py"), DEFAULT_EXCLUDES) is False

    def test_excludes_manifest_itself(self):
        """The manifest file should not track itself."""
        assert should_include(Path(".plsec-manifest.json"), DEFAULT_EXCLUDES) is False

    def test_excludes_env_file(self):
        assert should_include(Path(".env"), DEFAULT_EXCLUDES) is False

    def test_empty_excludes_includes_everything(self):
        """With no exclusion patterns, all files should be included."""
        assert should_include(Path(".git/config"), []) is True
        assert should_include(Path("__pycache__/foo.pyc"), []) is True

    def test_double_star_prefix_glob(self):
        """Patterns starting with **/ should match anywhere in the path."""
        excludes = ["**/secret"]
        assert should_include(Path("deep/nested/secret/file.txt"), excludes) is False
        assert should_include(Path("secret/file.txt"), excludes) is False
        assert should_include(Path("not-a-secret.txt"), excludes) is True


class TestHashFile:
    """Tests for hash_file - SHA256 computation via tmp_path."""

    def test_known_content(self, tmp_path: Path):
        """A file with known content should produce a known SHA256."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello\n")
        result = hash_file(test_file)
        # sha256("hello\n") = 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
        assert result == "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"

    def test_empty_file(self, tmp_path: Path):
        """An empty file should produce the SHA256 of empty input."""
        test_file = tmp_path / "empty.txt"
        test_file.write_bytes(b"")
        result = hash_file(test_file)
        # sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_returns_hex_string(self, tmp_path: Path):
        """Result should be a 64-character hex string."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")
        result = hash_file(test_file)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)


class TestCompareManifests:
    """Tests for compare_manifests - pure dict/set operations.

    This function detects added, removed, and modified files between
    two manifest snapshots. It is the core of integrity checking.
    """

    def test_no_changes(self):
        """Identical manifests should produce empty diff."""
        manifest = {"files": {"a.py": {"sha256": "abc"}, "b.py": {"sha256": "def"}}}
        diff = compare_manifests(manifest, manifest)
        assert diff["added"] == []
        assert diff["removed"] == []
        assert diff["modified"] == []

    def test_added_files(self):
        """New files in the new manifest should appear in 'added'."""
        old = {"files": {"a.py": {"sha256": "abc"}}}
        new = {"files": {"a.py": {"sha256": "abc"}, "b.py": {"sha256": "def"}}}
        diff = compare_manifests(old, new)
        assert diff["added"] == ["b.py"]
        assert diff["removed"] == []
        assert diff["modified"] == []

    def test_removed_files(self):
        """Files missing from the new manifest should appear in 'removed'."""
        old = {"files": {"a.py": {"sha256": "abc"}, "b.py": {"sha256": "def"}}}
        new = {"files": {"a.py": {"sha256": "abc"}}}
        diff = compare_manifests(old, new)
        assert diff["added"] == []
        assert diff["removed"] == ["b.py"]
        assert diff["modified"] == []

    def test_modified_files(self):
        """Files with different hashes should appear in 'modified'."""
        old = {"files": {"a.py": {"sha256": "abc"}}}
        new = {"files": {"a.py": {"sha256": "changed"}}}
        diff = compare_manifests(old, new)
        assert diff["added"] == []
        assert diff["removed"] == []
        assert diff["modified"] == ["a.py"]

    def test_mixed_changes(self):
        """A combination of added, removed, and modified files."""
        old = {
            "files": {
                "keep.py": {"sha256": "aaa"},
                "remove.py": {"sha256": "bbb"},
                "modify.py": {"sha256": "old"},
            }
        }
        new = {
            "files": {
                "keep.py": {"sha256": "aaa"},
                "add.py": {"sha256": "ccc"},
                "modify.py": {"sha256": "new"},
            }
        }
        diff = compare_manifests(old, new)
        assert diff["added"] == ["add.py"]
        assert diff["removed"] == ["remove.py"]
        assert diff["modified"] == ["modify.py"]

    def test_results_are_sorted(self):
        """Result lists should be sorted alphabetically."""
        old = {"files": {}}
        new = {"files": {"z.py": {"sha256": "a"}, "a.py": {"sha256": "b"}, "m.py": {"sha256": "c"}}}
        diff = compare_manifests(old, new)
        assert diff["added"] == ["a.py", "m.py", "z.py"]

    def test_empty_manifests(self):
        """Two empty manifests should produce empty diff."""
        diff = compare_manifests({"files": {}}, {"files": {}})
        assert diff["added"] == []
        assert diff["removed"] == []
        assert diff["modified"] == []

    def test_missing_files_key(self):
        """Manifests without 'files' key should be treated as empty."""
        diff = compare_manifests({}, {})
        assert diff["added"] == []
        assert diff["removed"] == []
        assert diff["modified"] == []


class TestCreateManifest:
    """Tests for create_manifest - filesystem-dependent, uses tmp_path."""

    def test_includes_files(self, tmp_path: Path):
        """Manifest should include files in the workspace."""
        (tmp_path / "hello.txt").write_text("hello")
        (tmp_path / "world.txt").write_text("world")

        manifest = create_manifest(tmp_path)
        assert "hello.txt" in manifest["files"]
        assert "world.txt" in manifest["files"]

    def test_excludes_git_directory(self, tmp_path: Path):
        """Files inside .git/ should be excluded by default."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("git config")
        (tmp_path / "src.py").write_text("source")

        manifest = create_manifest(tmp_path)
        assert "src.py" in manifest["files"]
        assert ".git/config" not in manifest["files"]

    def test_manifest_has_metadata(self, tmp_path: Path):
        """Manifest should include version, created timestamp, and workspace path."""
        manifest = create_manifest(tmp_path)
        assert manifest["version"] == 1
        assert "created" in manifest
        assert "workspace" in manifest

    def test_file_entries_have_hash_and_size(self, tmp_path: Path):
        """Each file entry should have sha256 and size fields."""
        (tmp_path / "test.txt").write_text("content")
        manifest = create_manifest(tmp_path)
        entry = manifest["files"]["test.txt"]
        assert "sha256" in entry
        assert "size" in entry
        assert isinstance(entry["size"], int)

    def test_custom_excludes(self, tmp_path: Path):
        """Custom exclude patterns should override defaults."""
        (tmp_path / "include.txt").write_text("yes")
        (tmp_path / "exclude.txt").write_text("no")

        manifest = create_manifest(tmp_path, excludes=["exclude.txt"])
        assert "include.txt" in manifest["files"]
        assert "exclude.txt" not in manifest["files"]
