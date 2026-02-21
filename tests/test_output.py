"""Tests for Rich console output helpers (core/output.py).

Covers print_status, the convenience wrappers (print_ok, print_error,
print_warning, print_info), print_summary, print_header, and print_table.

Strategy: monkeypatch the module-level `console` with a Console backed
by a StringIO buffer, then inspect the captured text.  ANSI escape codes
are stripped from the captured output so assertions work against plain text.
"""

import re
from io import StringIO

import pytest
from rich.console import Console

import plsec.core.output as output_mod

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from *text*."""
    return _ANSI_RE.sub("", text)


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> StringIO:
    """Replace the module-level console with a StringIO-backed Console.

    Returns the StringIO buffer for inspection after calling output functions.
    Callers should use ``_strip_ansi(buf.getvalue())`` to obtain plain text.
    """
    buf = StringIO()
    test_console = Console(file=buf, force_terminal=True, no_color=True)
    monkeypatch.setattr(output_mod, "console", test_console)
    return buf


# -----------------------------------------------------------------------
# print_status
# -----------------------------------------------------------------------


class TestPrintStatus:
    """Contract: print_status(message, status) writes '[STATUS] message'
    to the console, with an optional details line indented below."""

    def test_ok_status(self, captured: StringIO):
        output_mod.print_status("all good", "ok")
        text = _strip_ansi(captured.getvalue())
        assert "[OK]" in text
        assert "all good" in text

    def test_warn_status(self, captured: StringIO):
        output_mod.print_status("heads up", "warn")
        text = _strip_ansi(captured.getvalue())
        assert "[WARN]" in text
        assert "heads up" in text

    def test_error_status(self, captured: StringIO):
        output_mod.print_status("broken", "error")
        text = _strip_ansi(captured.getvalue())
        assert "[ERROR]" in text
        assert "broken" in text

    def test_info_status(self, captured: StringIO):
        output_mod.print_status("fyi", "info")
        text = _strip_ansi(captured.getvalue())
        assert "[INFO]" in text
        assert "fyi" in text

    def test_skip_status(self, captured: StringIO):
        output_mod.print_status("skipped", "skip")
        text = _strip_ansi(captured.getvalue())
        assert "[SKIP]" in text
        assert "skipped" in text

    def test_unknown_status_fallback(self, captured: StringIO):
        output_mod.print_status("hmm", "nonexistent")
        text = _strip_ansi(captured.getvalue())
        assert "[--]" in text
        assert "hmm" in text

    def test_details_appear_on_second_line(self, captured: StringIO):
        output_mod.print_status("main msg", "ok", details="extra info")
        text = _strip_ansi(captured.getvalue())
        assert "main msg" in text
        assert "extra info" in text

    def test_no_details_when_none(self, captured: StringIO):
        output_mod.print_status("msg only", "ok")
        text = _strip_ansi(captured.getvalue())
        lines = [line for line in text.strip().split("\n") if line.strip()]
        assert len(lines) == 1


# -----------------------------------------------------------------------
# Convenience wrappers
# -----------------------------------------------------------------------


class TestPrintConvenience:
    """Contract: print_ok/error/warning/info delegate to print_status."""

    def test_print_ok(self, captured: StringIO):
        output_mod.print_ok("success")
        assert "[OK]" in _strip_ansi(captured.getvalue())

    def test_print_error(self, captured: StringIO):
        output_mod.print_error("failure")
        assert "[ERROR]" in _strip_ansi(captured.getvalue())

    def test_print_warning(self, captured: StringIO):
        output_mod.print_warning("caution")
        assert "[WARN]" in _strip_ansi(captured.getvalue())

    def test_print_info(self, captured: StringIO):
        output_mod.print_info("notice")
        assert "[INFO]" in _strip_ansi(captured.getvalue())


# -----------------------------------------------------------------------
# print_summary
# -----------------------------------------------------------------------


class TestPrintSummary:
    """Contract: print_summary renders count-based summaries."""

    def test_all_zero_shows_no_items(self, captured: StringIO):
        output_mod.print_summary("Test")
        text = _strip_ansi(captured.getvalue())
        assert "No items" in text

    def test_ok_only(self, captured: StringIO):
        output_mod.print_summary("Test", ok=5)
        text = _strip_ansi(captured.getvalue())
        assert "5 OK" in text
        assert "warning" not in text.lower()

    def test_mixed_counts(self, captured: StringIO):
        output_mod.print_summary("Test", ok=3, warnings=2, errors=1)
        text = _strip_ansi(captured.getvalue())
        assert "3 OK" in text
        assert "2 warnings" in text
        assert "1 errors" in text

    def test_errors_only(self, captured: StringIO):
        output_mod.print_summary("Test", errors=4)
        text = _strip_ansi(captured.getvalue())
        assert "4 errors" in text
        assert "OK" not in text


# -----------------------------------------------------------------------
# print_header
# -----------------------------------------------------------------------


class TestPrintHeader:
    """Contract: print_header renders bold text with a separator."""

    def test_header_contains_text(self, captured: StringIO):
        output_mod.print_header("Section Title")
        text = _strip_ansi(captured.getvalue())
        assert "Section Title" in text

    def test_header_has_separator(self, captured: StringIO):
        output_mod.print_header("Title")
        text = _strip_ansi(captured.getvalue())
        # Separator should be dashes at least as long as the title
        assert "-----" in text


# -----------------------------------------------------------------------
# print_table
# -----------------------------------------------------------------------


class TestPrintTable:
    """Contract: print_table renders a Rich table with title and data."""

    def test_table_renders_data(self, captured: StringIO):
        output_mod.print_table(
            "My Table",
            ["Name", "Value"],
            [["foo", "bar"], ["baz", "qux"]],
        )
        text = _strip_ansi(captured.getvalue())
        assert "My Table" in text
        assert "foo" in text
        assert "qux" in text
