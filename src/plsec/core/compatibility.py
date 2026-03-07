"""Compatibility checking for agent data adapters.

Loads the compatibility registry (compatibility.yaml), probes installed
agent versions (binary + data store), and assesses whether plsec's
adapters are compatible with the detected formats.

Milestone 14a: Foundation -- probing and checking without caching.
Milestone 14b: Add local validation cache.

See docs/DESIGN-AGENT-MONITORING.md for background.
"""

import importlib.resources  # nosemgrep: python37-compatibility-importlib2
import logging
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

import semver
import yaml

from plsec.core.adapters import AdapterCompat, CompatResult, ValidatedVersion, VersionProbe
from plsec.core.adapters.claude import probe_claude_data_version
from plsec.core.adapters.opencode import probe_opencode_data_version

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Registry loading
# ---------------------------------------------------------------------------


def load_compatibility_registry() -> dict[str, AdapterCompat]:
    """Load the compatibility registry from the shipped YAML file.

    Returns:
        Dict mapping agent_id -> AdapterCompat.
    """
    compat_path = importlib.resources.files("plsec.configs") / "compatibility.yaml"
    raw = yaml.safe_load(compat_path.read_text(encoding="utf-8"))

    registry: dict[str, AdapterCompat] = {}
    for agent_id, entry in raw.get("adapters", {}).items():
        validated = [
            ValidatedVersion(
                version=v["version"],
                date=v["date"],
                status=v["status"],
            )
            for v in entry.get("validated", [])
        ]
        registry[agent_id] = AdapterCompat(
            agent_id=agent_id,
            data_dir=entry["data_dir"],
            format=entry["format"],
            binary_command=entry["binary_command"],
            version_flag=entry["version_flag"],
            validated=validated,
            untested_range=entry.get("untested_range", ""),
            known_incompatible=entry.get("known_incompatible", []),
            min_supported=entry.get("min_supported", "0.0.0"),
            stats_cache_format_version=entry.get("stats_cache_format_version"),
        )

    return registry


# ---------------------------------------------------------------------------
# Binary version probing
# ---------------------------------------------------------------------------


def probe_binary_version(command: str, version_flag: str) -> str | None:
    """Run an agent binary with its version flag and parse the output.

    Args:
        command: Binary name (e.g., "opencode", "claude").
        version_flag: Flag to pass (e.g., "--version").

    Returns:
        Version string or None if the binary is not found or
        version output cannot be parsed.
    """
    if shutil.which(command) is None:
        return None

    try:
        result = subprocess.run(
            [command, version_flag],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = (result.stdout or result.stderr).strip()
        if not output:
            return None

        # Take the first line, find the first word that looks like a version
        first_line = output.split("\n")[0]
        for word in first_line.split():
            cleaned = word.lstrip("v").rstrip(",")
            if cleaned and cleaned[0].isdigit():
                return cleaned

    except (subprocess.TimeoutExpired, OSError) as exc:
        log.debug("Binary version probe failed for %s: %s", command, exc)

    return None


# ---------------------------------------------------------------------------
# Agent probing (binary + data store)
# ---------------------------------------------------------------------------

# Map from agent_id -> data store probe function
_DATA_PROBES: dict[str, Callable[[Path], str | None]] = {
    "opencode": probe_opencode_data_version,
    "claude-code": probe_claude_data_version,
}


def probe_agent(agent_id: str, compat: AdapterCompat) -> VersionProbe:
    """Probe both binary and data store versions for an agent.

    Args:
        agent_id: Registry key (e.g., "opencode", "claude-code").
        compat: Compatibility metadata from the registry.

    Returns:
        VersionProbe with detected versions and existence flags.
    """
    data_dir = Path(compat.data_dir).expanduser()
    probe = VersionProbe(agent_id=agent_id)

    # Binary version
    binary_ver = probe_binary_version(compat.binary_command, compat.version_flag)
    if binary_ver is not None:
        probe.binary_found = True
        probe.binary_version = binary_ver

    # Data store version
    probe.data_dir_exists = data_dir.is_dir()
    if probe.data_dir_exists:
        data_probe_fn = _DATA_PROBES.get(agent_id)
        if data_probe_fn is not None:
            probe.data_version = data_probe_fn(data_dir)

    return probe


# ---------------------------------------------------------------------------
# Compatibility assessment
# ---------------------------------------------------------------------------


def _parse_version(version_str: str) -> semver.Version | None:
    """Parse a version string into a semver.Version, or None on failure."""
    try:
        return semver.Version.parse(version_str)
    except ValueError:
        # Try common non-semver patterns: "1.2" -> "1.2.0"
        parts = version_str.split(".")
        if len(parts) == 2:
            try:
                return semver.Version.parse(f"{version_str}.0")
            except ValueError:
                pass
    return None


def _parse_range_minimum(range_str: str) -> semver.Version | None:
    """Parse a >=X.Y.Z range string into a semver.Version.

    Only supports the simple >=X.Y.Z format used in compatibility.yaml.
    """
    stripped = range_str.strip()
    if stripped.startswith(">="):
        return _parse_version(stripped[2:])
    return None


def check_version_compatibility(
    probe: VersionProbe,
    compat: AdapterCompat,
) -> CompatResult:
    """Assess compatibility of a probed version against the registry.

    Uses the data store version as the effective version (preferred),
    falling back to binary version if data store is unavailable.

    Args:
        probe: Result of probe_agent().
        compat: Registry entry for this agent.

    Returns:
        CompatResult with verdict, detail, and effective version.
    """
    # Neither binary nor data dir found -> skip
    if not probe.binary_found and not probe.data_dir_exists:
        return CompatResult(
            agent_id=probe.agent_id,
            probe=probe,
            verdict="skip",
            detail=f"{probe.agent_id} not installed",
        )

    # Binary found but no data directory -> warn
    if not probe.data_dir_exists:
        return CompatResult(
            agent_id=probe.agent_id,
            probe=probe,
            verdict="warn",
            detail=f"binary found ({probe.binary_version}) but no data directory",
        )

    # Determine effective version (data preferred, binary fallback)
    effective = probe.data_version or probe.binary_version
    if effective is None:
        return CompatResult(
            agent_id=probe.agent_id,
            probe=probe,
            verdict="warn",
            detail="data directory exists but version could not be determined",
        )

    # Build drift annotation
    drift = ""
    if probe.binary_version and probe.data_version and probe.binary_version != probe.data_version:
        drift = f" (binary: {probe.binary_version}, data: {probe.data_version}, drift detected)"

    # Parse effective version for comparison
    parsed = _parse_version(effective)
    if parsed is None:
        return CompatResult(
            agent_id=probe.agent_id,
            probe=probe,
            verdict="warn",
            detail=f"version {effective!r} could not be parsed{drift}",
            effective_version=effective,
        )

    # Check: below minimum supported
    min_ver = _parse_version(compat.min_supported)
    if min_ver is not None and parsed < min_ver:
        return CompatResult(
            agent_id=probe.agent_id,
            probe=probe,
            verdict="fail",
            detail=f"{effective} below minimum {compat.min_supported}{drift}",
            effective_version=effective,
        )

    # Check: known incompatible
    if effective in compat.known_incompatible:
        return CompatResult(
            agent_id=probe.agent_id,
            probe=probe,
            verdict="fail",
            detail=f"{effective} is known incompatible{drift}",
            effective_version=effective,
        )

    # Check: validated
    validated_versions = {v.version for v in compat.validated if v.status == "compatible"}
    if effective in validated_versions:
        validated_entry = next(v for v in compat.validated if v.version == effective)
        return CompatResult(
            agent_id=probe.agent_id,
            probe=probe,
            verdict="ok",
            detail=f"{effective} (validated {validated_entry.date}){drift}",
            effective_version=effective,
        )

    # Check: untested range
    range_min = _parse_range_minimum(compat.untested_range)
    if range_min is not None and parsed >= range_min:
        latest_validated = max(
            (v.version for v in compat.validated if v.status == "compatible"),
            default="none",
        )
        return CompatResult(
            agent_id=probe.agent_id,
            probe=probe,
            verdict="warn",
            detail=(f"{effective} untested (latest validated: {latest_validated}){drift}"),
            effective_version=effective,
        )

    # Fallback: version not in any category
    return CompatResult(
        agent_id=probe.agent_id,
        probe=probe,
        verdict="warn",
        detail=f"{effective} not in compatibility registry{drift}",
        effective_version=effective,
    )


def check_all_agents() -> list[CompatResult]:
    """Probe and check all agents in the compatibility registry.

    Returns:
        List of CompatResult, one per agent in the registry.
    """
    registry = load_compatibility_registry()
    results: list[CompatResult] = []

    for agent_id, compat in registry.items():
        probe = probe_agent(agent_id, compat)
        result = check_version_compatibility(probe, compat)
        results.append(result)

    return results
