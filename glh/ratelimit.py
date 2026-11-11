# glh/ratelimit.py
"""
Client-side request pacing: rate limits (--index-rpm, --search-rpm, --rpm)
and a random delay before every request (--jitter).

GitLab rate-limits the search API separately from (and usually much lower
than) the rest of the API, so there are two budgets:

- search requests (``.../search``): ``search_rpm``;
- every other API request (project and branch listing, file-change checks,
  authentication): ``index_rpm``.

Limits apply per python-gitlab client, i.e. per thread: every worker has its
own client (see ``GitlabHarvester._init_worker_client``), so with
``--workers N`` the whole run sends up to N x rpm requests per minute.

Requests are spaced evenly (one every 60/rpm seconds, counted from the start
of the previous one), so there are no bursts at the start of a minute.

``jitter = (low, high)`` adds a random delay, drawn anew for every request
from ``uniform(low, high)`` seconds, on top of that spacing: the time between
two requests of one thread is at least ``60/rpm + jitter`` (without a limit,
at least the jitter), so jitter never pushes the rate above the limit.

Retries of python-gitlab (HTTP 429) go through the same pacing.
"""

from __future__ import annotations

import random
import re
import threading
import time
from typing import Any, Callable
from urllib.parse import urlsplit

from requests.adapters import HTTPAdapter

Jitter = tuple[float, float]
NO_JITTER: Jitter = (0.0, 0.0)
MAX_JITTER = 3600.0  # seconds; anything longer is a typo, not pacing


# Module-level indirections so tests can run the pacer on a virtual clock.
def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def _now() -> float:
    return time.monotonic()


_JITTER_VALUE = re.compile(r"^\s*(\d+(?:\.\d*)?|\.\d+)\s*(ms|s)?\s*$", re.IGNORECASE)


def _parse_seconds(text: str) -> float:
    m = _JITTER_VALUE.match(text)
    if not m:
        raise ValueError(f"not a duration: {text!r}")
    value = float(m.group(1))
    return value / 1000.0 if (m.group(2) or "s").lower() == "ms" else value


def parse_jitter(value: str) -> Jitter:
    """
    Parse a jitter range: ``MAX`` (= 0-MAX) or ``MIN-MAX``, in seconds, or
    with an ``ms``/``s`` suffix: ``0.03``, ``0.01-0.05``, ``10ms-50ms``.
    ``0`` turns jitter off.

    Raises:
        ValueError: on a malformed value, MIN > MAX, or MAX over MAX_JITTER.
    """
    parts = value.split("-")
    if len(parts) == 1:
        low, high = 0.0, _parse_seconds(parts[0])
    elif len(parts) == 2:
        low, high = _parse_seconds(parts[0]), _parse_seconds(parts[1])
    else:
        raise ValueError(f"not a range: {value!r}")
    if low > high:
        raise ValueError(f"the minimum ({low:g}s) is larger than the maximum ({high:g}s)")
    if high > MAX_JITTER:
        raise ValueError(f"at most {MAX_JITTER:g}s")
    return low, high


def format_jitter(jitter: Jitter) -> str:
    """'0.01-0.05s', '0-0.03s'; '' when off."""
    low, high = jitter
    return f"{low:g}-{high:g}s" if high > 0 else ""


class RateLimiter:
    """
    Paces the requests of one client: at most ``rpm`` request starts per
    minute (0 = no limit), each preceded by a random ``jitter`` delay.
    """

    def __init__(
            self,
            rpm: int = 0,
            *,
            jitter: Jitter = NO_JITTER,
            clock: Callable[[], float] | None = None,
            sleep: Callable[[float], None] | None = None,
            rng: random.Random | None = None,
    ) -> None:
        if rpm < 0 or (rpm == 0 and jitter[1] <= 0):
            raise ValueError("a rate limiter needs a positive rpm or a jitter")
        self.rpm = rpm
        self.interval = 60.0 / rpm if rpm > 0 else 0.0
        self.jitter = jitter
        self._clock = clock
        self._sleep = sleep
        self._rng = rng or random.Random()
        self._lock = threading.Lock()
        self._next_at: float | None = None

    def wait(self) -> float:
        """Block until the next request may start; return the seconds waited."""
        with self._lock:
            now = (self._clock or _now)()
            start = now if self._next_at is None else max(now, self._next_at)
            low, high = self.jitter
            if high > 0:
                start += self._rng.uniform(low, high)
            waited = start - now
            if waited > 0:
                (self._sleep or _sleep)(waited)
            if self.interval:
                self._next_at = start + self.interval
            return waited


def is_search_request(url: str) -> bool:
    """True for GitLab search API requests (project, group or global ``/search``)."""
    path = urlsplit(url).path.rstrip("/")
    return path.endswith("/search") and "/api/v4/" in path


def _limiter(rpm: int, jitter: Jitter) -> RateLimiter | None:
    return RateLimiter(rpm, jitter=jitter) if rpm > 0 or jitter[1] > 0 else None


class ThrottledAdapter(HTTPAdapter):
    """requests transport adapter that waits for the matching :class:`RateLimiter` before each request."""

    def __init__(self, *, index_rpm: int = 0, search_rpm: int = 0, jitter: Jitter = NO_JITTER,
                 **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.index_limiter = _limiter(index_rpm, jitter)
        self.search_limiter = _limiter(search_rpm, jitter)

    def send(self, request: Any, *args: Any, **kwargs: Any) -> Any:
        limiter = self.search_limiter if is_search_request(request.url or "") else self.index_limiter
        if limiter is not None:
            limiter.wait()
        return super().send(request, *args, **kwargs)


def limit_session(session: Any, *, index_rpm: int = 0, search_rpm: int = 0, jitter: Jitter = NO_JITTER) -> None:
    """Mount a fresh :class:`ThrottledAdapter` on ``session`` (no-op without limits or jitter)."""
    if index_rpm <= 0 and search_rpm <= 0 and jitter[1] <= 0:
        return
    adapter = ThrottledAdapter(index_rpm=index_rpm, search_rpm=search_rpm, jitter=jitter)
    session.mount("https://", adapter)
    session.mount("http://", adapter)


def describe(index_rpm: int, search_rpm: int, jitter: Jitter = NO_JITTER) -> str:
    """'search 30/min, other API 300/min per worker, jitter 0.01-0.05s'; '' without pacing."""
    parts = []
    if search_rpm > 0:
        parts.append(f"search {search_rpm}/min")
    if index_rpm > 0:
        parts.append(f"other API {index_rpm}/min")
    text = f"{', '.join(parts)} per worker" if parts else ""
    if jittered := format_jitter(jitter):
        text = f"{text}, jitter {jittered}" if text else f"jitter {jittered}"
    return text
