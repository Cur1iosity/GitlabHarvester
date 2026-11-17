# glh/cli/report.py
"""
What a run reports at its end: blocks of results (stdout) and their one-line form in the run journal.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from glh.cli.commands.common import UTC
from glh.domain.models import IndexMeta
from glh.engine.harvester import GitlabHarvester
from glh.ui import statusline
from glh.ui.blocks import compact_block, format_block, Row
from glh.ui.formatting import plural
from glh.ui.journal import JOURNAL


def format_age(seconds: float) -> str:
    """'just now', '5 min ago', '3 h ago', '2 days ago'."""
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)} min ago"
    if seconds < 2 * 86400:
        return f"{int(seconds // 3600)} h ago"
    return f"{int(seconds // 86400)} days ago"


def index_rows(path: str | Path, meta: IndexMeta, projects: int,
               now: datetime | None = None) -> list[Row]:
    """The rows of the 'Index' block: which index a search uses and how current it is."""
    built = meta.built_at
    if built is None:
        when = "unknown"
    else:
        built_utc = built.astimezone(UTC)
        age = format_age(((now or datetime.now(UTC)) - built_utc).total_seconds())
        when = f"{built_utc:%Y-%m-%d %H:%M:%S} UTC ({age})"
    window = meta.window
    return [
        ("file", str(path)),
        ("built", when),
        ("projects", f"{projects:,}"),
        ("branches", str(meta.branches) if meta.branches is not None else ""),
        ("active", f"projects active {window.describe()}" if window else ""),
        ("status", f"INCOMPLETE: {meta.incomplete_reason}; rebuild with --dump-projects"
         if meta.incomplete_reason else ""),
    ]


def describe_index(path: str | Path, meta: IndexMeta, projects: int, now: datetime | None = None) -> str:
    """
    One line about the index a search uses, so the user can judge how current it is.

    Example: "Index: idx.jsonl (built 2024-06-01 12:00:00 UTC, 3 h ago; 9 projects, branches: all)".
    """
    built = meta.built_at
    if built is None:
        when = "build time unknown"
    else:
        now = now or datetime.now(UTC)
        built_utc = built.astimezone(UTC)
        when = f"built {built_utc:%Y-%m-%d %H:%M:%S} UTC, {format_age((now - built_utc).total_seconds())}"

    details = [plural(projects, "project")]
    if meta.branches is not None:
        details.append(f"branches: {meta.branches}")
    window = meta.window
    if window:
        details.append(f"projects active {window.describe()}")
    if meta.incomplete_reason:
        details.append(f"INCOMPLETE ({meta.incomplete_reason}; rebuild with --dump-projects)")
    return f"Index: {path} ({when}; {', '.join(details)})"


def report(message: str) -> None:
    """Print a final summary line and add it to the run journal (log file)."""
    print(message)
    JOURNAL.write(message)


def report_block(title: str, rows: list[Row]) -> None:
    """Print a block of results (stdout) after an empty line; the run journal gets it as one line."""
    print()
    for line in format_block(title, rows):
        print(line)
    JOURNAL.write(compact_block(title, rows))


class Summary:
    """The 'Results' block of a run, filled while it goes on and printed at the end."""

    def __init__(self, title: str = "Results") -> None:
        self.title = title
        self.rows: list[Row] = []
        self.notes: list[str] = []  # lines after the block (what to do next)

    def add(self, label: str, value: Any) -> None:
        self.rows.append((label, value))

    def note(self, text: str) -> None:
        self.notes.append(text)

    def report(self) -> None:
        if self.rows:
            report_block(self.title, self.rows)
        for note in self.notes:
            report(note)


def rate_limit_row(glh: GitlabHarvester, summary: Summary) -> None:
    """The HTTP 429 count of the run (counted, not logged one by one), if any; clears the status counter."""
    statusline.STATUS.set_tail(None)
    if (text := glh.rate_limit_summary()) is not None:
        summary.add("rate limit", text.removeprefix("Rate limit: "))
