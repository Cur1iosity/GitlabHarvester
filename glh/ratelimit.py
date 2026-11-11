# glh/ratelimit.py
"""
Client-side request rate limits (--index-rpm, --search-rpm, --rpm).

GitLab rate-limits the search API separately from (and usually much lower
than) the rest of the API, so there are two budgets:

- search requests (``.../search``): ``search_rpm``;
- every other API request (project and branch listing, file-change checks,
  authentication): ``index_rpm``.

Limits apply per python-gitlab client, i.e. per thread: every worker has its
own client (see ``GitlabHarvester._init_worker_client``), so with
``--workers N`` the whole run sends up to N x rpm requests per minute.

Requests are spaced evenly (one every 60/rpm seconds, counted from the start
of the previous one), so there are no bursts at the start of a minute. Retries
of python-gitlab (HTTP 429) go through the same limit.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable
from urllib.parse import urlsplit

from requests.adapters import HTTPAdapter


# Module-level indirections so tests can run the limiter on a virtual clock.
def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def _now() -> float:
    return time.monotonic()


class RateLimiter:
    """At most ``rpm`` request starts per minute, evenly spaced."""

    def __init__(self, rpm: int, *, clock: Callable[[], float] | None = None,
                 sleep: Callable[[float], None] | None = None) -> None:
        if rpm <= 0:
            raise ValueError("rpm must be positive")
        self.rpm = rpm
        self.interval = 60.0 / rpm
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._next_at: float | None = None

    def wait(self) -> float:
        """Block until the next request may start; return the seconds waited."""
        with self._lock:
            now = (self._clock or _now)()
            waited = 0.0
            if self._next_at is not None and now < self._next_at:
                waited = self._next_at - now
                (self._sleep or _sleep)(waited)
                now = self._next_at
            self._next_at = now + self.interval
            return waited


def is_search_request(url: str) -> bool:
    """True for GitLab search API requests (project, group or global ``/search``)."""
    path = urlsplit(url).path.rstrip("/")
    return path.endswith("/search") and "/api/v4/" in path


class ThrottledAdapter(HTTPAdapter):
    """requests transport adapter that waits for the matching :class:`RateLimiter` before each request."""

    def __init__(self, *, index_rpm: int = 0, search_rpm: int = 0, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.index_limiter = RateLimiter(index_rpm) if index_rpm > 0 else None
        self.search_limiter = RateLimiter(search_rpm) if search_rpm > 0 else None

    def send(self, request: Any, *args: Any, **kwargs: Any) -> Any:
        limiter = self.search_limiter if is_search_request(request.url or "") else self.index_limiter
        if limiter is not None:
            limiter.wait()
        return super().send(request, *args, **kwargs)


def limit_session(session: Any, *, index_rpm: int = 0, search_rpm: int = 0) -> None:
    """Mount a fresh :class:`ThrottledAdapter` on ``session`` (no-op without limits)."""
    if index_rpm <= 0 and search_rpm <= 0:
        return
    adapter = ThrottledAdapter(index_rpm=index_rpm, search_rpm=search_rpm)
    session.mount("https://", adapter)
    session.mount("http://", adapter)


def describe(index_rpm: int, search_rpm: int) -> str:
    """'search 30/min, other API 300/min per worker'; '' without limits."""
    parts = []
    if search_rpm > 0:
        parts.append(f"search {search_rpm}/min")
    if index_rpm > 0:
        parts.append(f"other API {index_rpm}/min")
    return f"{', '.join(parts)} per worker" if parts else ""
