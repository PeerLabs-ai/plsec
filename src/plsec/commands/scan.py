"""
plsec scan - Run security scanners via the engine pipeline.

Orchestrates the engine registry, policy evaluation, and verdict
strategy to produce a unified scan result. Persists scan results to
``~/.peerlabs/plsec/logs/`` as JSON for consumption by ``plsec-status``.
"""

__version__ = "0.2.0"

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer

from plsec.core.config import get_plsec_home, resolve_config
from plsec.core.health import PLSEC_EXPECTED_FILES
from plsec.core.output import (
    console,
    print_error,
    print_header,
    print_info,
    print_ok,
    print_summary,
    print_warning,
)
from plsec.engine.base import ScanResult
from plsec.engine.orchestrator import build_orchestrator
from plsec.engine.registry import EngineRegistry, build_default_registry
from plsec.engine.types import Layer, Preset, Severity
from plsec.engine.verdict import VerdictStatus

logger = logging.getLogger(__name__)

app = typer.Typer(
    help="Run security scanners.",
    no_args_is_help=False,
)

# Daily scan log file pattern: scan-YYYYMMDD.jsonl
SCAN_LOG_PATTERN = "scan-{date}.jsonl"
# File for quick access to most recent scan results
SCAN_LATEST = "scan-latest.json"

# Map CLI type flags to engine layers
_FLAG_TO_LAYERS: dict[str, list[Layer]] = {
    "secrets": [Layer.STATIC],
    "code": [Layer.STATIC],
    "misconfig": [Layer.CONFIG],
}

# Preset string -> Preset enum
_PRESET_MAP: dict[str, Preset] = {p.value: p for p in Preset}


# ---------------------------------------------------------------------------
# Scan log persistence
# ---------------------------------------------------------------------------


def _result_to_summary_dict(result: ScanResult, target: str) -> dict[str, Any]:
    """Convert a ScanResult to a JSON-serializable summary dict.

    Writes ``overall_passed`` (not ``passed``) for backward compatibility
    with plsec-status which greps for ``"overall_passed": true``.
    """
    verdict = result.verdict
    counts = verdict.counts if verdict else None

    engine_results = []
    for lr in result.layer_results:
        for er in lr.engine_results:
            engine_results.append(
                {
                    "engine": er.engine_id,
                    "layer": lr.layer.value,
                    "status": er.availability.status.value,
                    "ran": er.ran,
                    "findings": er.finding_count,
                }
            )

    return {
        "ts": datetime.now(UTC).isoformat(),
        "target": target,
        "overall_passed": verdict.passed if verdict else False,
        "verdict": {
            "status": verdict.status if verdict else "error",
            "exit_code": verdict.exit_code if verdict else 2,
            "rationale": verdict.rationale if verdict else "no verdict",
        },
        "engines": engine_results,
        "counts": {
            "total": counts.total if counts else 0,
            "suppressed": counts.suppressed if counts else 0,
            "by_severity": dict(counts.by_severity) if counts else {},
            "by_category": dict(counts.by_category) if counts else {},
        },
    }


def _write_scan_log(plsec_home: Path, result: ScanResult, target: str) -> Path | None:
    """Write scan results to the daily JSON lines log and scan-latest.json.

    Returns the log file path, or None if writing failed.
    """
    logs_dir = plsec_home / "logs"
    if not logs_dir.is_dir():
        return None

    ts = datetime.now(UTC)
    date_str = ts.strftime("%Y%m%d")
    summary = _result_to_summary_dict(result, target)

    # Append to daily JSONL file
    log_path = logs_dir / SCAN_LOG_PATTERN.format(date=date_str)
    try:
        with open(log_path, "a") as f:
            f.write(json.dumps(summary) + "\n")
    except OSError:
        return None

    # Write scan-latest.json for plsec-status
    latest_path = logs_dir / SCAN_LATEST
    try:
        latest_path.write_text(json.dumps(summary, indent=2) + "\n")
    except OSError:
        pass  # Non-critical: daily log is the primary record

    return log_path


# ---------------------------------------------------------------------------
# Registry filtering
# ---------------------------------------------------------------------------


def _filter_registry(
    registry: EngineRegistry,
    *,
    engine_ids: list[str] | None = None,
    type_flags: dict[str, bool] | None = None,
) -> EngineRegistry:
    """Build a filtered registry based on CLI flags.

    If engine_ids is provided, only those engines are included.
    If type_flags are set, engines are filtered by scan type/layer.
    If neither is set, the full registry is returned.

    Raises typer.BadParameter for unknown engine IDs.
    """
    has_engine_ids = bool(engine_ids)
    has_type_flags = type_flags and any(type_flags.values())

    if not has_engine_ids and not has_type_flags:
        return registry

    # Validate engine IDs
    if has_engine_ids:
        for eid in engine_ids:  # type: ignore[union-attr]
            if eid not in registry:
                available = sorted(e.engine_id for e in registry.all_engines())
                raise typer.BadParameter(f"Unknown engine: {eid!r} (available: {available})")

    # Build filtered registry
    filtered = EngineRegistry()
    all_engines = registry.all_engines()

    if has_engine_ids:
        # Only include explicitly named engines
        for engine in all_engines:
            if engine.engine_id in engine_ids:  # type: ignore[operator]
                filtered.register(engine)
    elif has_type_flags:
        # Filter by active type flags
        active_flags = {k for k, v in type_flags.items() if v}  # type: ignore[union-attr]
        # Map flags to engine categories/layers
        for engine in all_engines:
            if _engine_matches_flags(engine, active_flags):
                filtered.register(engine)

    return filtered


def _engine_matches_flags(engine: Any, active_flags: set[str]) -> bool:
    """Check whether an engine matches one of the active CLI type flags.

    Mapping:
    - --secrets: engines with layer=STATIC and "secret" in engine_id
    - --code: engines with layer=STATIC and engine_id in {bandit, semgrep}
    - --misconfig: engines with layer=CONFIG
    """
    eid = engine.engine_id
    layer = engine.layer

    if "secrets" in active_flags and layer == Layer.STATIC and "secret" in eid:
        return True
    if "code" in active_flags and layer == Layer.STATIC and eid in {"bandit", "semgrep"}:
        return True
    if "misconfig" in active_flags and layer == Layer.CONFIG:
        return True
    return False


# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------


def _check_scanner_prerequisites(plsec_home: Path) -> None:
    """Verify required scanner configs exist before scanning.

    Fails fast with a clear message and exit code 1 when configs
    are missing, rather than letting trivy produce confusing errors.
    """
    missing: list[tuple[str, str]] = []
    for rel_path, description in PLSEC_EXPECTED_FILES:
        if not (plsec_home / rel_path).exists():
            missing.append((rel_path, description))
    if missing:
        print_error("Scanner configuration not found.")
        for rel_path, description in missing:
            console.print(f"  Missing: {description} ({rel_path})")
        console.print("\nRun 'plsec install' to deploy scanner configs.")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def _print_findings(result: ScanResult, *, verbose: bool = False) -> None:
    """Print findings grouped by layer."""
    layer_names = {
        Layer.STATIC: "Static Analysis",
        Layer.CONFIG: "Configuration",
        Layer.ISOLATION: "Isolation",
        Layer.RUNTIME: "Runtime",
        Layer.AUDIT: "Audit",
    }

    for lr in result.layer_results:
        findings = lr.unsuppressed_findings
        layer_label = layer_names.get(lr.layer, lr.layer.name)

        print_header(layer_label)

        if not findings:
            print_ok(f"{layer_label}: No issues found")
            continue

        for f in findings:
            sev_label = f.severity.name
            loc = ""
            if f.location and f.location.file_path:
                loc = f" at {f.location.file_path}"
                if f.location.line_start:
                    loc += f":{f.location.line_start}"

            if f.severity >= Severity.HIGH:
                print_error(f"[{sev_label}] {f.title}{loc}")
            elif f.severity >= Severity.MEDIUM:
                print_warning(f"[{sev_label}] {f.title}{loc}")
            else:
                print_info(f"[{sev_label}] {f.title}{loc}")

            if verbose and f.description:
                console.print(f"      {f.description}", style="dim")
            if verbose and f.remediation:
                console.print(f"      Fix: {f.remediation}", style="dim")


def _print_verdict_summary(result: ScanResult) -> None:
    """Print the final verdict summary line."""
    verdict = result.verdict
    if not verdict:
        print_error("Scan error: no verdict produced")
        return

    counts = verdict.counts
    ok_count = counts.engines_ran - (1 if counts.total > 0 else 0)
    # Count engines that produced findings as warnings/errors
    findings_count = counts.total
    suppressed_count = counts.suppressed

    if verdict.status == VerdictStatus.PASSED:
        print_summary(
            "Scan complete",
            ok=counts.engines_ran,
            warnings=0,
            errors=0,
        )
    elif verdict.status == VerdictStatus.WARN:
        print_summary(
            "Scan complete",
            ok=max(0, ok_count),
            warnings=findings_count,
            errors=0,
        )
    elif verdict.status == VerdictStatus.FAIL:
        # Count HIGH+ as errors, rest as warnings
        high_plus = sum(v for k, v in counts.by_severity.items() if k in {"CRITICAL", "HIGH"})
        warn_count = findings_count - high_plus
        print_summary(
            "Scan complete",
            ok=max(0, counts.engines_ran - (1 if high_plus > 0 else 0)),
            warnings=warn_count,
            errors=high_plus,
        )
    else:
        print_summary("Scan complete", ok=0, warnings=0, errors=1)

    if suppressed_count > 0:
        print_info(f"{suppressed_count} finding(s) suppressed by policy")


def _print_verbose_config(preset: str, registry: EngineRegistry) -> None:
    """Print detailed configuration in verbose mode."""
    engines = registry.all_engines()
    engine_names = [e.display_name for e in engines]
    console.print(f"  Preset: {preset}")
    console.print(f"  Engines: {', '.join(engine_names)}")
    console.print(f"  Engine count: {len(engines)}")
    layers = registry.layers_with_engines()
    console.print(f"  Active layers: {', '.join(layer.name for layer in layers)}")
    console.print()


# ---------------------------------------------------------------------------
# Main scan command
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def scan(
    ctx: typer.Context,
    path: Annotated[Path, typer.Argument(help="Path to scan (default: current directory).")] = Path(
        "."
    ),
    preset: Annotated[
        str | None,
        typer.Option(
            "--preset", "-p", help="Security preset: minimal, balanced, strict, paranoid."
        ),
    ] = None,
    secrets: Annotated[bool, typer.Option("--secrets", "-s", help="Run secret scanning.")] = False,
    code: Annotated[
        bool, typer.Option("--code", "-c", help="Run code analysis (Bandit, Semgrep).")
    ] = False,
    misconfig: Annotated[
        bool, typer.Option("--misconfig", "-m", help="Run misconfiguration scanning.")
    ] = False,
    scanner: Annotated[
        list[str] | None,
        typer.Option("--scanner", help="Specific engine to run (repeatable)."),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show configuration details.")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Output results as JSON.")] = False,
) -> None:
    """Run security scanners on the specified path.

    By default, runs all engines from the active preset (balanced).
    Use --preset to change the security level, or --scanner to select
    specific engines. Type flags (--code, --secrets, etc.) select
    engines of that type.

    Examples:
        plsec scan                              # balanced preset
        plsec scan --preset minimal             # secrets only
        plsec scan --code                       # code scanners only
        plsec scan --scanner bandit             # bandit only
        plsec scan --preset strict              # strict preset
    """
    # Inherit verbose from global --verbose if not set locally
    global_obj = ctx.obj or {}
    is_verbose = verbose or global_obj.get("verbose", False)

    console.print(f"[bold]plsec scan[/bold] - Scanning {path}\n")

    # 1. Resolve preset
    _config, effective_preset = resolve_config(
        cli_preset=preset,
        project_config_path=None,
    )
    preset_enum = _PRESET_MAP.get(effective_preset, Preset.BALANCED)

    # 2. Build engine registry (potentially filtered)
    registry = build_default_registry()
    type_flags = {"secrets": secrets, "code": code, "misconfig": misconfig}

    try:
        registry = _filter_registry(
            registry,
            engine_ids=scanner,
            type_flags=type_flags,
        )
    except typer.BadParameter as e:
        print_error(str(e))
        raise typer.Exit(1) from e

    # 3. Show config summary
    if is_verbose:
        _print_verbose_config(effective_preset, registry)
    else:
        print_info(f"Using preset: {effective_preset}")

    console.print()

    # 4. Validate path
    path = path.resolve()
    if not path.exists():
        print_error(f"Path not found: {path}")
        raise typer.Exit(1)

    plsec_home = get_plsec_home()
    _check_scanner_prerequisites(plsec_home)

    # 5. Build orchestrator and run scan
    orchestrator = build_orchestrator(registry)
    result = orchestrator.scan(path, preset_enum)

    # 6. Persist scan results
    _write_scan_log(plsec_home, result, str(path))

    # 7. Output
    if json_output:
        summary = _result_to_summary_dict(result, str(path))
        console.print_json(json.dumps(summary))
        exit_code = result.verdict.exit_code if result.verdict else 2
        raise typer.Exit(exit_code)

    # Print findings
    _print_findings(result, verbose=is_verbose)

    # Print verdict summary
    _print_verdict_summary(result)

    # Footer
    print()
    print_info("Scanner limitations: docs/scanner-limitations.md")
    print_info("Report issues: https://github.com/peerlabs/plsec/issues")

    # Exit with verdict exit code
    verdict = result.verdict
    if verdict and verdict.failed:
        console.print("\n[red]Critical issues found. Review and fix before committing.[/red]")
    elif verdict and verdict.status == VerdictStatus.WARN:
        console.print("\n[yellow]Warnings found. Review before committing.[/yellow]")
    else:
        console.print("\n[green]All scans passed![/green]")

    exit_code = verdict.exit_code if verdict else 2
    raise typer.Exit(exit_code)
