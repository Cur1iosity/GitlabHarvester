# glh/ui/formatting.py
"""
Text formatting for the console: counts, durations, terminal cell widths.
"""

from __future__ import annotations

import unicodedata

ELLIPSIS = "…"

# --------------------------------------------------------------------------- formatting


def human_int(n: int) -> str:
    """
    Format integer into compact human-readable form.

    Examples:
        532 -> "532"
        1200 -> "1.2K"
        532000 -> "532K"
        1200000 -> "1.2M"
        3400000000 -> "3.4B"
    """
    if n < 1000:
        return str(n)

    for unit, div in (
        ("K", 1_000),
        ("M", 1_000_000),
        ("B", 1_000_000_000),
        ("T", 1_000_000_000_000),
    ):
        if n < div * 1000:
            val = n / div
            return f"{val:.1f}{unit}" if val < 10 else f"{val:.0f}{unit}"

    return f"{n:.0e}"


def plural(n: int, word: str, plural_form: str | None = None) -> str:
    """'1 hit', '2 hits', '1,234 branches' (plural_form overrides the '+s' rule)."""
    form = word if n == 1 else (plural_form or f"{word}s")
    return f"{n:,} {form}"


def format_clock(seconds: float) -> str:
    """Format a duration as a clock: '0:07', '12:34', '1:02:03'."""
    total = max(0, int(seconds))
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes}:{secs:02d}"


def format_duration(seconds: float) -> str:
    """Format a finished phase duration: '0.4s', '12.3s', '1:05', '1:02:03'."""
    if seconds < 60:
        return f"{max(seconds, 0.0):.1f}s"
    return format_clock(seconds)


def _char_width(ch: str) -> int:
    """Terminal cell width of one character (0, 1 or 2)."""
    if unicodedata.category(ch) in ("Mn", "Me", "Cf"):
        return 0  # combining marks, variation selectors, zero-width joiners
    if unicodedata.east_asian_width(ch) in ("W", "F"):
        return 2
    return 1


def display_width(text: str) -> int:
    """Number of terminal cells needed to print ``text``."""
    return sum(_char_width(ch) for ch in text)


def fit_width(text: str, width: int) -> str:
    """Truncate ``text`` to at most ``width`` terminal cells, ending with an ellipsis."""
    if width <= 0:
        return ""
    if display_width(text) <= width:
        return text
    out: list[str] = []
    used = 0
    for ch in text:
        w = _char_width(ch)
        if used + w > width - 1:  # keep one cell for the ellipsis
            break
        out.append(ch)
        used += w
    return "".join(out) + ELLIPSIS


def _single_line(text: str) -> str:
    """Replace control characters (newlines, tabs, ...) so the text stays on one line."""
    return "".join(" " if unicodedata.category(ch) == "Cc" else ch for ch in text)
