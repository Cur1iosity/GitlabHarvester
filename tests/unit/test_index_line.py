"""The 'Index: ...' line shown before the search plan (glh.modes.describe_index)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from glh.modes import describe_index

NOW = datetime(2024, 6, 10, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(("age", "text"), [
    (timedelta(seconds=30), "just now"),
    (timedelta(minutes=5), "5 min ago"),
    (timedelta(hours=3, minutes=59), "3 h ago"),
    (timedelta(hours=47), "47 h ago"),
    (timedelta(days=12), "12 days ago"),
])
def test_build_time_and_age(age, text):
    built = NOW - age
    meta = {"timestamp_utc": built.isoformat()}
    line = describe_index("idx.jsonl", meta, 9, now=NOW)
    assert line == f"Index: idx.jsonl (built {built:%Y-%m-%d %H:%M:%S} UTC, {text}; 9 projects)"


def test_build_time_in_another_offset_is_shown_in_utc():
    meta = {"timestamp_utc": "2024-06-10T15:00:00+03:00"}
    assert "built 2024-06-10 12:00:00 UTC, just now" in describe_index("i", meta, 1, now=NOW)


def test_branches_window_and_incomplete_index():
    meta = {
        "timestamp_utc": "2024-06-09T12:00:00+00:00",
        "branches": "all",
        "last_activity_after": "2024-06-01T00:00:00Z",
        "is_completed": False,
    }
    assert describe_index("idx.jsonl", meta, 1, now=NOW) == (
        "Index: idx.jsonl (built 2024-06-09 12:00:00 UTC, 24 h ago; 1 project, branches: all, "
        "projects active since 2024-06-01, INCOMPLETE (listing failed; rebuild with --dump-projects))"
    )


def test_missing_build_time():
    assert describe_index("old.jsonl", {}, 3, now=NOW) == "Index: old.jsonl (build time unknown; 3 projects)"
