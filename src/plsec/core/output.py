"""
Output formatting utilities.

Provides consistent terminal output using Rich.
"""

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Global console instance
console = Console()


def print_status(
    message: str,
    status: str = "ok",
    *,
    details: str | None = None,
) -> None:
    """
    Print a status message with icon.

    Args:
        message: Main message text.
        status: Status type (ok, warn, error, info, skip).
        details: Optional additional details.
    """
    icons = {
        "ok": "[green][OK][/green]",
        "warn": "[yellow][WARN][/yellow]",
        "error": "[red][ERROR][/red]",
        "info": "[blue][INFO][/blue]",
        "skip": "[dim][SKIP][/dim]",
    }

    icon = icons.get(status, "[dim][--][/dim]")
    console.print(f"{icon} {message}")

    if details:
        console.print(f"      {details}", style="dim")


def print_error(message: str, *, details: str | None = None) -> None:
    """Print an error message."""
    print_status(message, "error", details=details)


def print_warning(message: str, *, details: str | None = None) -> None:
    """Print a warning message."""
    print_status(message, "warn", details=details)


def print_info(message: str, *, details: str | None = None) -> None:
    """Print an info message."""
    print_status(message, "info", details=details)


def print_ok(message: str, *, details: str | None = None) -> None:
    """Print a success message."""
    print_status(message, "ok", details=details)


def print_table(
    title: str,
    columns: list[str],
    rows: list[list[Any]],
    *,
    show_header: bool = True,
) -> None:
    """
    Print a formatted table.

    Args:
        title: Table title.
        columns: Column headers.
        rows: List of row data.
        show_header: Whether to show column headers.
    """
    table = Table(title=title, show_header=show_header)

    for col in columns:
        table.add_column(col)

    for row in rows:
        table.add_row(*[str(cell) for cell in row])

    console.print(table)


def print_panel(
    content: str,
    title: str | None = None,
    *,
    style: str = "blue",
) -> None:
    """
    Print content in a panel.

    Args:
        content: Panel content.
        title: Optional panel title.
        style: Border style color.
    """
    console.print(Panel(content, title=title, border_style=style))


def print_header(text: str) -> None:
    """Print a section header."""
    console.print()
    console.print(f"[bold]{text}[/bold]")
    console.print("-" * len(text))


def print_summary(
    title: str,
    *,
    ok: int = 0,
    warnings: int = 0,
    errors: int = 0,
) -> None:
    """
    Print a summary with counts.

    Args:
        title: Summary title.
        ok: Count of OK items.
        warnings: Count of warnings.
        errors: Count of errors.
    """
    parts = []
    if ok:
        parts.append(f"[green]{ok} OK[/green]")
    if warnings:
        parts.append(f"[yellow]{warnings} warnings[/yellow]")
    if errors:
        parts.append(f"[red]{errors} errors[/red]")

    summary = ", ".join(parts) if parts else "No items"
    console.print(f"\n{title}: {summary}")
