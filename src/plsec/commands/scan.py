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
from typing import Annotated, Literal

import typer

from plsec.core.config import get_plsec_home
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


ScanType = Literal["secrets", "code", "deps", "misconfig", "all"]

# Daily scan log file pattern: scan-YYYYMMDD.jsonl
SCAN_LOG_PATTERN = "scan-{date}.jsonl"
# Symlink/file for quick access to most recent scan results
SCAN_LATEST = "scan-latest.json"


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


@app.callback(invoke_without_command=True)
def scan(
    path: Annotated[Path, typer.Argument(help="Path to scan (default: current directory).")] = Path(
        "."
    ),
    scan_type: Annotated[
        ScanType,
        typer.Option("--type", "-t", help="Type of scan: secrets, code, deps, misconfig, all."),
    ] = "all",
    secrets: Annotated[
        bool, typer.Option("--secrets", "-s", help="Run secret scanning only.")
    ] = False,
    code: Annotated[
        bool, typer.Option("--code", "-c", help="Run code analysis only (Bandit, Semgrep).")
    ] = False,
    deps: Annotated[bool, typer.Option("--deps", "-d", help="Run dependency audit only.")] = False,
    misconfig: Annotated[
        bool, typer.Option("--misconfig", "-m", help="Run misconfiguration scanning only.")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Output results as JSON.")] = False,
) -> None:
    """
    Run security scanners on the specified path.

    By default, runs all applicable scanners. Use flags to run specific scans.
    """
    console.print(f"[bold]plsec scan[/bold] - Scanning {path}\n")

    # Determine which scan types to run
    if secrets:
        scan_type = "secrets"
    elif code:
        scan_type = "code"
    elif deps:
        scan_type = "deps"
    elif misconfig:
        scan_type = "misconfig"

    path = path.resolve()
    if not path.exists():
        print_error(f"Path not found: {path}")
        raise typer.Exit(1)

    plsec_home = get_plsec_home()
    _check_scanner_prerequisites(plsec_home)

    summary = ScanSummary(target=str(path))
    ok_count = 0
    warn_count = 0
    error_count = 0

    # Group scanners by scan_type for section headers
    current_section: str | None = None

    for _sid, spec in SCANNERS.items():
        # Filter by requested scan type
        if scan_type != "all" and spec.scan_type != scan_type:
            continue

        # Print section header on type change
        if spec.scan_type != current_section:
            current_section = spec.scan_type
            section_titles = {
                "secrets": "Secret Scanning",
                "code": "Code Analysis",
                "misconfig": "Misconfiguration Scanning",
            }
            print_header(section_titles.get(current_section, current_section.title()))

        # Run the scanner
        print_info(f"Running {spec.display_name}...")
        result = run_scanner(spec, path, plsec_home)
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
    if scan_type in ("deps", "all"):
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

    if error_count > 0:
        console.print("\n[red]Critical issues found. Review and fix before committing.[/red]")
        raise typer.Exit(1)

    if warn_count > 0:
        console.print("\n[yellow]Warnings found. Review before committing.[/yellow]")
        raise typer.Exit(0)

    console.print("\n[green]All scans passed![/green]")
    raise typer.Exit(0)
