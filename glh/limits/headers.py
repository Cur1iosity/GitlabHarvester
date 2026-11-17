# glh/limits/headers.py
"""
GitLab's RateLimit-* and Retry-After response headers.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Mapping

# --------------------------------------------------------------------------- headers


def _get(headers: Mapping[str, Any] | None, name: str) -> str | None:
    """Case-insensitive header lookup (plain dicts and requests' CaseInsensitiveDict)."""
    if not headers:
        return None
    value = headers.get(name)
    if value is None:
        lowered = name.lower()
        for key, val in headers.items():
            if str(key).lower() == lowered:
                value = val
                break
    return None if value is None else str(value)


def _number(text: str | None) -> float | None:
    try:
        return None if text is None else float(text.strip())
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class HeaderLimit:
    """What GitLab says about a rate limit in response headers."""

    limit: int | None = None  # RateLimit-Limit: requests per minute
    remaining: int | None = None  # RateLimit-Remaining
    observed: int | None = None  # RateLimit-Observed
    reset_in: float | None = None  # seconds until the window resets (Retry-After / RateLimit-Reset)
    name: str | None = None  # RateLimit-Name, e.g. throttle_authenticated_api


def parse_limit_headers(headers: Mapping[str, Any] | None, *, now: float | None = None) -> HeaderLimit | None:
    """
    Read ``RateLimit-Limit/-Remaining/-Observed/-Reset/-Name`` and ``Retry-After``.

    ``RateLimit-Reset`` is a Unix time (``now`` = time.time() by default).
    Returns None when the response has none of them.
    """
    limit = _number(_get(headers, "RateLimit-Limit"))
    remaining = _number(_get(headers, "RateLimit-Remaining"))
    observed = _number(_get(headers, "RateLimit-Observed"))
    name = _get(headers, "RateLimit-Name")
    reset_in = _number(_get(headers, "Retry-After"))
    if reset_in is None and (reset_at := _number(_get(headers, "RateLimit-Reset"))) is not None:
        reset_in = reset_at - (time.time() if now is None else now)
    if reset_in is not None:
        reset_in = max(reset_in, 0.0)
    if limit is None and remaining is None and observed is None and reset_in is None and not name:
        return None
    return HeaderLimit(
        limit=int(limit) if limit is not None and limit > 0 else None,
        remaining=int(remaining) if remaining is not None else None,
        observed=int(observed) if observed is not None else None,
        reset_in=reset_in,
        name=name or None,
    )
