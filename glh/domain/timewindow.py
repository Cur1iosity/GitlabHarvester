# glh/domain/timewindow.py
"""
Time windows and the ISO 8601 timestamps of the project index and the GitLab API.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any


@dataclass(frozen=True, slots=True)
class TimeWindow:
    """An optional [after, before] time range (both bounds inclusive, either may be None)."""

    after: datetime | None = None
    before: datetime | None = None

    def __bool__(self) -> bool:
        return self.after is not None or self.before is not None

    def contains(self, moment: datetime) -> bool:
        """True if ``moment`` lies inside the window."""
        return (self.after is None or moment >= self.after) and (self.before is None or moment <= self.before)

    def describe(self) -> str:
        """'since 2024-06-01', 'until 2024-07-01' or '2024-06-01..2024-07-01'."""
        if self.after is not None and self.before is not None:
            return f"{format_bound(self.after)}..{format_bound(self.before)}"
        if self.after is not None:
            return f"since {format_bound(self.after)}"
        if self.before is not None:
            return f"until {format_bound(self.before)}"
        return "any time"


def format_bound(value: datetime | None) -> str:
    """Show midnight UTC as a plain date, anything else as full ISO 8601."""
    if value is None:
        return "?"
    if value.utcoffset() == timedelta(0) and (value.hour, value.minute, value.second) == (0, 0, 0):
        return value.date().isoformat()
    return value.isoformat()


def format_api_time(value: datetime) -> str:
    """ISO 8601 in UTC with a Z suffix, as accepted by GitLab API time parameters."""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timestamp(value: Any) -> datetime | None:
    """
    Parse an ISO 8601 timestamp as stored in the project index.

    Accepts the GitLab form ``2024-06-01T12:00:00.000Z`` on every supported
    Python version (``datetime.fromisoformat`` handles ``Z`` only since 3.11).
    Naive values are interpreted as UTC.

    Returns:
        Timezone-aware datetime, or None if the value is missing or malformed.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
