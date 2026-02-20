"""
plsec integrity - Workspace integrity monitoring.

Create and verify SHA256 manifests of workspace files.
"""

__version__ = "0.1.0"

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import typer

from plsec.core.output import (
    console,
    print_error,
    print_header,
    print_info,
    print_ok,
    print_summary,
    print_warning,
)

app = typer.Typer(
    help="Workspace integrity monitoring.",
    no_args_is_help=True,
)


# Files to exclude from integrity checks
DEFAULT_EXCLUDES = [
    ".git",
    ".git/**",
    "__pycache__",
    "**/__pycache__",
    "*.pyc",
    "node_modules",
    "**/node_modules",
    ".venv",
    "venv",
    ".env",
    ".plsec-manifest.json",
]


def get_manifest_path(workspace: Path) -> Path:
    """Get path to manifest file for a workspace."""
    return workspace / ".plsec-manifest.json"


def should_include(path: Path, excludes: list[str]) -> bool:
    """Check if a path should be included in the manifest.

    Supports three pattern styles:
    - Exact match against any path component (e.g. ".git", "__pycache__")
    - Glob patterns with fnmatch (e.g. "*.pyc")
    - **/ prefix patterns that match any path component (e.g. "**/__pycache__")
    - /** suffix patterns that match directory prefixes (e.g. ".git/**")
    """
    import fnmatch

    path_str = str(path)
    parts = path.parts

    for exclude in excludes:
        if exclude.startswith("**/"):
            # Match the sub-pattern against any component or trailing subpath
            sub = exclude[3:]
            if any(fnmatch.fnmatch(part, sub) for part in parts):
                return False
        elif exclude.endswith("/**"):
            # Match if path starts under this directory
            prefix = exclude[:-3]
            if parts and fnmatch.fnmatch(parts[0], prefix):
                return False
        elif fnmatch.fnmatch(path_str, exclude):
            # Full-path glob match (e.g. "*.pyc")
            return False
        elif any(fnmatch.fnmatch(part, exclude) for part in parts):
            # Match against any individual path component (e.g. ".git", ".env")
            return False

    return True


def hash_file(path: Path) -> str:
    """Compute SHA256 hash of a file."""
    sha256 = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def create_manifest(workspace: Path, excludes: list[str] | None = None) -> dict:
    """Create a manifest of all files in a workspace."""
    if excludes is None:
        excludes = DEFAULT_EXCLUDES

    manifest = {
        "version": 1,
        "created": datetime.now(UTC).isoformat() + "Z",
        "workspace": str(workspace.resolve()),
        "files": {},
    }

    for path in workspace.rglob("*"):
        if path.is_file():
            rel_path = path.relative_to(workspace)

            if not should_include(rel_path, excludes):
                continue

            try:
                file_hash = hash_file(path)
                manifest["files"][str(rel_path)] = {
                    "sha256": file_hash,
                    "size": path.stat().st_size,
                }
            except (PermissionError, OSError):
                # Skip files we can't read
                pass

    return manifest


def compare_manifests(old: dict, new: dict) -> dict:
    """Compare two manifests and return differences."""
    old_files = old.get("files", {})
    new_files = new.get("files", {})

    added = set(new_files.keys()) - set(old_files.keys())
    removed = set(old_files.keys()) - set(new_files.keys())
    modified = set()

    for path in set(old_files.keys()) & set(new_files.keys()):
        if old_files[path]["sha256"] != new_files[path]["sha256"]:
            modified.add(path)

    return {
        "added": sorted(added),
        "removed": sorted(removed),
        "modified": sorted(modified),
    }


@app.command("init")
def init_manifest(
    path: Path = typer.Argument(
        Path("."),
        help="Workspace path.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing manifest.",
    ),
) -> None:
    """Initialize integrity manifest for a workspace."""
    console.print("[bold]plsec integrity init[/bold]\n")

    workspace = path.resolve()
    manifest_path = get_manifest_path(workspace)

    if manifest_path.exists() and not force:
        print_warning(f"Manifest already exists: {manifest_path}")
        console.print("Use --force to overwrite")
        raise typer.Exit(1)

    print_info(f"Creating manifest for {workspace}...")

    manifest = create_manifest(workspace)
    file_count = len(manifest["files"])

    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print_ok(f"Created manifest with {file_count} files")
    console.print(f"  Manifest: {manifest_path}")
    console.print("\nRun 'plsec integrity check' to verify integrity")

    raise typer.Exit(0)


@app.command("check")
def check_integrity(
    path: Path = typer.Argument(
        Path("."),
        help="Workspace path.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Only output if changes detected.",
    ),
) -> None:
    """Check workspace integrity against manifest."""
    workspace = path.resolve()
    manifest_path = get_manifest_path(workspace)

    if not manifest_path.exists():
        print_error("No manifest found")
        console.print("Run 'plsec integrity init' first")
        raise typer.Exit(1)

    if not quiet:
        console.print("[bold]plsec integrity check[/bold]\n")

    # Load existing manifest
    with open(manifest_path) as f:
        old_manifest = json.load(f)

    # Create current manifest
    new_manifest = create_manifest(workspace)

    # Compare
    diff = compare_manifests(old_manifest, new_manifest)

    has_changes = any([diff["added"], diff["removed"], diff["modified"]])

    if not has_changes:
        if not quiet:
            print_ok("No changes detected")
            console.print(f"  Files: {len(old_manifest['files'])}")
            console.print(f"  Last verified: {old_manifest['created']}")
        raise typer.Exit(0)

    # Report changes
    print_header("Changes Detected")

    if diff["added"]:
        console.print(f"\n[green]Added ({len(diff['added'])}):[/green]")
        for f in diff["added"][:20]:
            console.print(f"  + {f}")
        if len(diff["added"]) > 20:
            console.print(f"  ... and {len(diff['added']) - 20} more")

    if diff["removed"]:
        console.print(f"\n[red]Removed ({len(diff['removed'])}):[/red]")
        for f in diff["removed"][:20]:
            console.print(f"  - {f}")
        if len(diff["removed"]) > 20:
            console.print(f"  ... and {len(diff['removed']) - 20} more")

    if diff["modified"]:
        console.print(f"\n[yellow]Modified ({len(diff['modified'])}):[/yellow]")
        for f in diff["modified"][:20]:
            console.print(f"  ~ {f}")
        if len(diff["modified"]) > 20:
            console.print(f"  ... and {len(diff['modified']) - 20} more")

    print_summary(
        "\nIntegrity check",
        warnings=len(diff["added"]) + len(diff["modified"]),
        errors=len(diff["removed"]),
    )

    console.print("\nRun 'plsec integrity update' to accept these changes")
    raise typer.Exit(1)


@app.command("update")
def update_manifest(
    path: Path = typer.Argument(
        Path("."),
        help="Workspace path.",
    ),
) -> None:
    """Update manifest to reflect current state."""
    console.print("[bold]plsec integrity update[/bold]\n")

    workspace = path.resolve()
    manifest_path = get_manifest_path(workspace)

    if not manifest_path.exists():
        print_warning("No existing manifest, creating new one")

    manifest = create_manifest(workspace)
    file_count = len(manifest["files"])

    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print_ok(f"Updated manifest with {file_count} files")

    raise typer.Exit(0)
