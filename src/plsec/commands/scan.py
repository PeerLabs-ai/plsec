"""
plsec scan - Run security scanners.

Wraps Trivy, Bandit, Semgrep, and other scanners with consistent output.
Delegates to the SCANNERS registry in core/scanners.py.  Persists scan
results to ``~/.peerlabs/plsec/logs/`` as JSON lines for consumption by
``plsec-status``.
"""

__version__ = "0.1.0"

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from plsec.core.config import PlsecConfig, get_plsec_home, resolve_config
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
from plsec.core.scanners import SCANNERS, ScanResult, ScanSummary, run_scanner

app = typer.Typer(
    help="Run security scanners.",
    no_args_is_help=False,
)

# Daily scan log file pattern: scan-YYYYMMDD.jsonl
SCAN_LOG_PATTERN = "scan-{date}.jsonl"
# Symlink/file for quick access to most recent scan results
SCAN_LATEST = "scan-latest.json"

# Section titles for grouped scanner output
_SECTION_TITLES = {
    "secrets": "Secret Scanning",
    "code": "Code Analysis",
    "misconfig": "Misconfiguration Scanning",
}


def _result_to_dict(result: ScanResult) -> dict:
    """Convert a ScanResult to a JSON-serializable dict."""
    return {
        "scanner": result.scanner_id,
        "type": result.scan_type,
        "verdict": result.verdict,
        "exit_code": result.exit_code,
        "duration": result.duration_seconds,
        "message": result.message,
    }


def _summary_to_dict(summary: ScanSummary) -> dict:
    """Convert a ScanSummary to a JSON-serializable dict."""
    return {
        "ts": datetime.now(UTC).isoformat(),
        "target": summary.target,
        "passed": summary.passed,
        "results": [_result_to_dict(r) for r in summary.results],
        "counts": {
            "pass": summary.pass_count,
            "fail": summary.fail_count,
            "skip": summary.skip_count,
        },
    }


def _write_scan_log(plsec_home: Path, summary: ScanSummary) -> Path | None:
    """Write scan results to the daily JSON lines log file.

    Each scanner result is a separate line.  A summary line follows.
    Also writes ``scan-latest.json`` with the full summary for quick
    access by ``plsec-status``.

    Returns the log file path, or None if writing failed.
    """
    logs_dir = plsec_home / "logs"
    if not logs_dir.is_dir():
        return None

    ts = datetime.now(UTC)
    ts_str = ts.isoformat()
    date_str = ts.strftime("%Y%m%d")

    # Append per-result lines to daily JSONL file
    log_path = logs_dir / SCAN_LOG_PATTERN.format(date=date_str)
    try:
        with open(log_path, "a") as f:
            for result in summary.results:
                entry = _result_to_dict(result)
                entry["ts"] = ts_str
                entry["target"] = summary.target
                f.write(json.dumps(entry) + "\n")
    except OSError:
        return None

    # Write latest summary as a single JSON file
    latest_path = logs_dir / SCAN_LATEST
    try:
        latest_path.write_text(json.dumps(_summary_to_dict(summary), indent=2) + "\n")
    except OSError:
        pass  # Non-critical: daily log is the primary record

    return log_path


def _print_json(summary: ScanSummary) -> None:
    """Print scan summary as JSON to stdout."""
    console.print_json(json.dumps(_summary_to_dict(summary)))


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
# Scanner selection logic
# ---------------------------------------------------------------------------


def _resolve_scanner_list(
    config: PlsecConfig,
    *,
    type_flags: dict[str, bool],
    scanner_names: list[str] | None = None,
    preset_explicit: bool = False,
) -> list[str]:
    """Resolve which scanners to run from config + CLI flags.

    Resolution rules:
    1. No CLI overrides (no type flags, no --scanner):
       Use config.layers.static.scanners (from preset/merge).

    2. --scanner without type flags:
       Use only the named scanners. No type validation.

    3. --scanner with type flags (e.g., --code --scanner bandit):
       Use only the named scanners. Validate each belongs to an active type.

    4. Type flags without --scanner (e.g., --code):
       Select all scanners matching the active type(s).

    5. If preset was explicitly set AND type/scanner flags are also used:
       Union of preset scanners + CLI-selected scanners.

    Args:
        config: Resolved PlsecConfig (preset already applied)
        type_flags: Dict of type flag states {"secrets": bool, "code": bool, ...}
        scanner_names: List of specific scanner IDs from --scanner, or None
        preset_explicit: Whether --preset was explicitly passed on CLI

    Returns:
        Ordered list of scanner IDs to run

    Raises:
        typer.BadParameter: For unknown scanners or type mismatches
    """
    has_type_flags = any(type_flags.values())
    has_scanner_flags = bool(scanner_names)

    # Case 1: No CLI overrides -- use config scanners
    if not has_type_flags and not has_scanner_flags:
        return config.layers.static.scanners

    # Validate --scanner names exist in registry
    if has_scanner_flags:
        for name in scanner_names:  # type: ignore[union-attr]
            if name not in SCANNERS:
                available = sorted(SCANNERS.keys())
                raise typer.BadParameter(f"Unknown scanner: {name!r} (available: {available})")

    # Case 3: --scanner with type flags -- validate types match
    if has_scanner_flags and has_type_flags:
        active_types = {t for t, v in type_flags.items() if v}
        for name in scanner_names:  # type: ignore[union-attr]
            spec = SCANNERS[name]
            if spec.scan_type not in active_types:
                raise typer.BadParameter(
                    f"Scanner '{name}' is type '{spec.scan_type}', "
                    f"not one of: {sorted(active_types)}"
                )
        cli_scanners = list(scanner_names)  # type: ignore[arg-type]

    # Case 2: --scanner without type flags -- use named scanners
    elif has_scanner_flags:
        cli_scanners = list(scanner_names)  # type: ignore[arg-type]

    # Case 4: Type flags without --scanner -- all scanners of active types
    else:
        active_types = {t for t, v in type_flags.items() if v}
        cli_scanners = [sid for sid, spec in SCANNERS.items() if spec.scan_type in active_types]

    # Case 5: If preset was explicit AND CLI flags were used, union them
    if preset_explicit:
        preset_scanners = config.layers.static.scanners
        combined = preset_scanners.copy()
        for s in cli_scanners:
            if s not in combined:
                combined.append(s)
        return combined

    return cli_scanners


# ---------------------------------------------------------------------------
# Config display
# ---------------------------------------------------------------------------


def _print_config_summary(preset: str) -> None:
    """Print brief config line in normal mode."""
    print_info(f"Using preset: {preset}")


def _print_verbose_config(
    config: PlsecConfig,
    scanner_list: list[str],
    preset: str,
) -> None:
    """Print detailed configuration in verbose mode."""
    static = config.layers.static
    console.print(f"  Preset: {preset}")
    console.print(f"  Scanners: {', '.join(scanner_list)}")
    if static.skip_dirs:
        console.print(f"  Skip dirs: {', '.join(static.skip_dirs)}")
    else:
        console.print("  Skip dirs: (none)")
    if static.skip_files:
        console.print(f"  Skip files: {', '.join(static.skip_files)}")
    else:
        console.print("  Skip files: (none)")
    console.print(f"  Severity threshold: {static.severity_threshold}")
    console.print(f"  Timeout: {static.timeout}s")
    if config._provenance:
        console.print("  Config sources:")
        seen_sources = sorted(set(config._provenance.values()))
        for source in seen_sources:
            console.print(f"    {source}")
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
    deps: Annotated[bool, typer.Option("--deps", "-d", help="Run dependency audit.")] = False,
    misconfig: Annotated[
        bool, typer.Option("--misconfig", "-m", help="Run misconfiguration scanning.")
    ] = False,
    scanner: Annotated[
        list[str] | None,
        typer.Option("--scanner", help="Specific scanner to run (repeatable)."),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show configuration details.")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Output results as JSON.")] = False,
) -> None:
    """Run security scanners on the specified path.

    By default, runs all scanners from the active preset (balanced).
    Use --preset to change the security level, or --scanner to select
    specific scanners. Type flags (--code, --secrets, etc.) select all
    scanners of that type.

    Examples:
        plsec scan                              # balanced preset (all scanners)
        plsec scan --preset minimal             # secrets only
        plsec scan --code                       # code scanners only
        plsec scan --scanner bandit             # bandit only
        plsec scan --preset minimal --code      # minimal + all code scanners
        plsec scan --code --scanner bandit      # bandit (validated as code scanner)
    """
    # Inherit verbose from global --verbose if not set locally
    global_obj = ctx.obj or {}
    is_verbose = verbose or global_obj.get("verbose", False)
    global_config_path = global_obj.get("config")

    console.print(f"[bold]plsec scan[/bold] - Scanning {path}\n")

    # 1. Resolve configuration (preset + global + project + CLI merge)
    config, effective_preset = resolve_config(
        cli_preset=preset,
        project_config_path=Path(global_config_path) if global_config_path else None,
    )

    # 2. Resolve scanner list from config + CLI flags
    type_flags = {"secrets": secrets, "code": code, "deps": deps, "misconfig": misconfig}
    try:
        scanner_list = _resolve_scanner_list(
            config,
            type_flags=type_flags,
            scanner_names=scanner,
            preset_explicit=preset is not None,
        )
    except typer.BadParameter as e:
        print_error(str(e))
        raise typer.Exit(1) from e

    # 3. Show config summary
    if is_verbose:
        _print_verbose_config(config, scanner_list, effective_preset)
    else:
        _print_config_summary(effective_preset)

    console.print()

    # 4. Validate path
    path = path.resolve()
    if not path.exists():
        print_error(f"Path not found: {path}")
        raise typer.Exit(1)

    plsec_home = get_plsec_home()
    _check_scanner_prerequisites(plsec_home)

    # 5. Run selected scanners
    summary = ScanSummary(target=str(path))
    ok_count = 0
    warn_count = 0
    error_count = 0
    static_config = config.layers.static

    # Group scanners by scan_type for section headers
    current_section: str | None = None

    for sid in scanner_list:
        if sid not in SCANNERS:
            print_warning(f"Scanner '{sid}' not in registry (skipped)")
            continue

        spec = SCANNERS[sid]

        # Print section header on type change
        if spec.scan_type != current_section:
            current_section = spec.scan_type
            print_header(_SECTION_TITLES.get(current_section, current_section.title()))

        # Run the scanner with config-driven skip dirs/files
        print_info(f"Running {spec.display_name}...")
        result = run_scanner(spec, path, plsec_home, static_config)
        summary.results.append(result)

        if result.passed:
            if result.verdict == "skip":
                print_info(result.message)
            else:
                print_ok(f"{spec.display_name}: {result.message}")
            ok_count += 1
        else:
            # Secrets are errors; code/misconfig are warnings
            if spec.scan_type == "secrets":
                print_error(f"{spec.display_name}: Potential issues found")
                if result.output:
                    console.print(result.output)
                error_count += 1
            else:
                print_warning(f"{spec.display_name}: Issues found")
                if result.output:
                    console.print(result.output)
                warn_count += 1

    # Dependency audit (not yet backed by a scanner registry entry)
    if deps and not scanner:
        print_header("Dependency Audit")
        print_info("Dependency audit not yet implemented")

    summary.passed = error_count == 0

    # Persist scan results to logs
    _write_scan_log(plsec_home, summary)

    # JSON output
    if json_output:
        _print_json(summary)
        raise typer.Exit(1 if error_count > 0 else 0)

    # Summary
    print_summary("Scan complete", ok=ok_count, warnings=warn_count, errors=error_count)

    # Scanner limitations notice
    print()
    print_info("Scanner limitations: docs/scanner-limitations.md")
    print_info("Report issues: https://github.com/peerlabs/plsec/issues")

    if error_count > 0:
        console.print("\n[red]Critical issues found. Review and fix before committing.[/red]")
        raise typer.Exit(1)

    if warn_count > 0:
        console.print("\n[yellow]Warnings found. Review before committing.[/yellow]")
        raise typer.Exit(0)

    console.print("\n[green]All scans passed![/green]")
    raise typer.Exit(0)
