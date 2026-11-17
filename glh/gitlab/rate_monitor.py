# glh/gitlab/rate_monitor.py
"""
RateLimitMonitor: the response hook of every paced client.

On HTTP 429 python-gitlab waits (Retry-After) and retries up to 10 times
without any output, which looks like a hung scan. The monitor:

- hands every response to the ``observer`` (``--auto-limits``: the
  :class:`~glh.limits.advisor.LimitAdvisor`);
- reports the wait of the calling thread's task (``on_wait``, the search's
  :class:`~glh.engine.workers.ActiveTasks`);
- warns once, then only counts: ``HTTP 429 xN`` at the end of the status line
  and :meth:`RateLimitMonitor.summary` at the end of the run; with --debug the
  warning repeats at most every ``warn_interval`` seconds.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable
from urllib.parse import urlparse

from glh.ui import statusline
from glh.ui.formatting import format_duration, plural


def retry_after(headers: Any) -> float | None:
    """Seconds python-gitlab waits after a 429 (Retry-After / RateLimit-Reset), if known."""
    try:
        if "Retry-After" in headers:
            return max(float(headers["Retry-After"]), 0.0)
        if "RateLimit-Reset" in headers:
            return max(float(headers["RateLimit-Reset"]) - time.time(), 0.0)
    except (TypeError, ValueError):
        pass
    return None


class RateLimitMonitor:
    """Counts and reports the HTTP 429 responses of a run (see the module doc)."""

    def __init__(self, logger: logging.Logger, *, log_level: int = logging.WARNING) -> None:
        self.logger = logger
        self.log_level = log_level
        # Called with every API response (any thread), e.g. LimitAdvisor.observe.
        self.observer: Callable[[Any], None] | None = None
        # Told what the calling thread waits for ('' when it doesn't wait).
        self.on_wait: Callable[[str], None] | None = None
        self.warn_interval: float = 60.0
        self._lock = threading.Lock()
        self._count = 0
        self._waited = 0.0  # Retry-After seconds, summed over all threads
        self._warned_at: float | None = None

    def _wait(self, text: str) -> None:
        if self.on_wait is not None:
            self.on_wait(text)

    def on_response(self, response: Any, *args: Any, **kwargs: Any) -> None:
        """requests response hook (runs in the thread that made the request)."""
        observer = self.observer
        if observer is not None:
            try:
                observer(response)
            except Exception:  # noqa: BLE001 - advice must never break a request
                self.logger.debug("Limit observer failed", exc_info=True)
        if getattr(response, "status_code", None) != 429:
            self._wait("")
            return None
        wait = retry_after(getattr(response, "headers", None) or {})
        wait_text = format_duration(wait) if wait is not None else "a moment"
        self._wait(f"rate limited (HTTP 429), retry in {wait_text}")
        debug = self.log_level <= logging.DEBUG
        with self._lock:
            self._count += 1
            self._waited += wait or 0.0
            count = self._count
            now = time.monotonic()
            first = self._warned_at is None
            warn = first or (debug and now - self._warned_at >= self.warn_interval)
            if warn:
                self._warned_at = now
        if first:
            statusline.STATUS.set_tail(self.tail)
        if warn:
            path = urlparse(getattr(response, "url", "") or "").path
            advice = ("--auto-limits will suggest new limits." if self.observer is not None
                      else "Fewer --workers or lower --search-rpm/--index-rpm reduce the request rate "
                           "(-m find-limits measures the limits).")
            if debug:
                self.logger.warning(
                    "GitLab rate limit (HTTP 429) on %s: waiting %s before a retry "
                    "(%s so far; python-gitlab retries up to 10 times). %s",
                    path or "a request", wait_text, plural(count, "rate-limited response"), advice,
                )
            else:
                self.logger.warning(
                    "GitLab rate limit (HTTP 429) on %s: waiting %s before a retry (python-gitlab retries "
                    "up to 10 times). Further 429s are only counted: HTTP 429 xN in the status line and a "
                    "summary at the end (--debug repeats this warning). %s",
                    path or "a request", wait_text, advice,
                )
        return None

    def tail(self) -> str:
        """'HTTP 429 x12' for the end of the status line ('' before the first one)."""
        count = self._count
        return f"HTTP 429 x{count:,}" if count else ""

    @property
    def count(self) -> int:
        """HTTP 429 responses so far (all threads)."""
        return self._count

    def summary(self, *, parallel: bool = False) -> str | None:
        """
        'Rate limit: 190 HTTP 429 responses, retried after 12:30 of waits in total (all workers)';
        None without any 429.
        """
        with self._lock:
            count, waited = self._count, self._waited
        if not count:
            return None
        waits = (f", retried after {format_duration(waited)} of waits in total"
                 f"{' (all workers)' if parallel else ''}" if waited else ", retried")
        return f"Rate limit: {plural(count, 'HTTP 429 response')}{waits}"
