# glh/autolimit.py
"""
Rate-limit advice while a run goes on (``--auto-limits``). EXPERIMENTAL, like
``glh.limits``.

:class:`LimitAdvisor` sees every API response (``GitlabHarvester.limit_observer``,
called from the worker threads). It counts the successful requests of every
(user, API) pair per second, and when GitLab answers HTTP 429 it estimates the
limit — from ``RateLimit-Limit`` if GitLab sends it, else from the requests of
that user that succeeded in the window before — and proposes a lower
``--search-rpm`` / ``--index-rpm`` per worker (``margin`` below the limit,
split over the user's threads).

:class:`LimiterConsole` asks the user without stopping the run. On a terminal
the question replaces the status line for ``PROMPT_TIMEOUT`` seconds with a
countdown; [Y] applies the new limits at once (``GitlabHarvester.set_rate_limits``),
[N] drops the proposal, no answer keeps it: the status line then starts with
``[Limiter: L]`` and the L key shows the question again. Without a terminal the
proposal is logged as a warning and nothing changes.

Memory stays constant: per (user, API) at most one counter per second of the
last hour.
"""

from __future__ import annotations

import collections
import itertools
import logging
import math
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from glh import ratelimit
from glh.limits import API_NAMES, DEFAULT_MARGIN, INDEX, LONG_WINDOW, SEARCH, WINDOW, parse_limit_headers
from glh.utils import terminal_utils
from glh.utils.keys import KeyReader

if TYPE_CHECKING:
    from glh.harvester import GitlabHarvester

PROMPT_TIMEOUT = 20.0
BADGE = "[Limiter]"
PENDING_BADGE = "[Limiter: L]"
# Keys, with the same keys of a Russian (ЙЦУКЕН) layout.
YES_KEYS = frozenset("yYнН\r\n")
NO_KEYS = frozenset("nNтТ\x1b")
SHOW_KEYS = frozenset("lLдД")
# A new proposal for an API is made at most this often unless it is lower.
_REPEAT_AFTER = 30.0
# 429 despite the current pace: lower it by this factor.
_BACKOFF = 0.75


class _Counter:
    """Successful requests per second over the last ``span`` seconds (constant memory)."""

    def __init__(self, span: float = LONG_WINDOW) -> None:
        self._span = int(span)
        self._buckets: collections.deque[list[int]] = collections.deque()
        self.first_seen: float | None = None

    def add(self, now: float) -> None:
        if self.first_seen is None:
            self.first_seen = now
        second = int(now)
        if self._buckets and self._buckets[-1][0] == second:
            self._buckets[-1][1] += 1
        else:
            self._buckets.append([second, 1])
        while self._buckets and self._buckets[0][0] <= second - self._span:
            self._buckets.popleft()

    def count(self, now: float, span: float) -> int:
        """Requests in the last ``span`` whole seconds up to ``now``."""
        since = int(now) - int(span)
        return sum(n for second, n in self._buckets if second > since)


@dataclass(slots=True)
class Suggestion:
    """New per-worker limits proposed after HTTP 429 responses."""

    number: int
    rpm: dict[str, int] = field(default_factory=dict)  # kind -> proposed rpm per worker
    current: dict[str, int] = field(default_factory=dict)  # kind -> rpm when proposed
    reasons: dict[str, str] = field(default_factory=dict)  # kind -> why

    def flags(self) -> str:
        return " ".join(f"--{kind}-rpm {value}" for kind, value in sorted(self.rpm.items(), reverse=True))

    def describe(self) -> str:
        parts = []
        for kind in (SEARCH, INDEX):
            if kind in self.rpm:
                now = self.current.get(kind, 0)
                parts.append(f"{self.reasons.get(kind, API_NAMES[kind])}: --{kind}-rpm "
                             f"{now or 'no limit'} -> {self.rpm[kind]}")
        return "; ".join(parts)


class LimitAdvisor:
    """Turn HTTP 429 responses of a running scan into proposed --*-rpm values."""

    def __init__(
            self,
            harvester: "GitlabHarvester",
            *,
            margin: float = DEFAULT_MARGIN,
            window: float = WINDOW,
            clock: Callable[[], float] = time.monotonic,
            status: terminal_utils.StatusLine | None = None,
    ) -> None:
        self.harvester = harvester
        self.margin = margin
        self.window = window
        self._clock = clock
        self._status = status if status is not None else terminal_utils.STATUS
        self._lock = threading.Lock()
        self._counters: dict[tuple[Any, str], _Counter] = {}
        self._pending: Suggestion | None = None
        self._numbers = itertools.count(1)
        self._declined: dict[str, int] = {}
        self._last_proposed: dict[str, tuple[float, int]] = {}
        # After new limits are applied, 429s of requests sent before (and their
        # retries) say nothing about the new pace: no proposals for one window.
        self._quiet_until = float("-inf")
        self.limited = {INDEX: 0, SEARCH: 0}
        self.applied: list[str] = []
        # Called (from the thread that saw the 429) when a new proposal is ready.
        self.on_suggestion: Callable[[Suggestion], None] | None = None

    # ------------------------------------------------------------------ wiring

    def attach(self) -> "LimitAdvisor":
        self.harvester.limit_observer = self.observe
        return self

    def detach(self) -> None:
        if self.harvester.limit_observer == self.observe:
            self.harvester.limit_observer = None

    # ---------------------------------------------------------------- observing

    @property
    def pending(self) -> Suggestion | None:
        with self._lock:
            return self._pending

    def observe(self, response: Any) -> None:
        """Count a response; on HTTP 429, maybe propose new limits."""
        status = getattr(response, "status_code", None)
        if status is None:
            return
        request = getattr(response, "request", None)
        url = getattr(response, "url", None) or getattr(request, "url", "") or ""
        kind = SEARCH if ratelimit.is_search_request(url) else INDEX
        headers = getattr(request, "headers", None) or {}
        user = self.harvester.token_user_key(headers.get("PRIVATE-TOKEN"))
        now = self._clock()
        suggestion = None
        with self._lock:
            if 200 <= status < 300:
                self._counters.setdefault((user, kind), _Counter()).add(now)
                return
            if status != 429:
                return
            self.limited[kind] += 1
            suggestion = self._propose(kind, user, getattr(response, "headers", None), now)
        if suggestion is not None and self.on_suggestion is not None:
            self.on_suggestion(suggestion)

    def _threads_of(self, user: Any) -> int:
        tokens = sum(1 for t in self.harvester.tokens if self.harvester.token_user_key(t) == user) or 1
        return max(1, self.harvester.workers) * tokens

    def _propose(self, kind: str, user: Any, headers: Any, now: float) -> Suggestion | None:
        """Lock held. A new or lowered proposal for ``kind``, or None."""
        if now < self._quiet_until:
            return None
        info = parse_limit_headers(headers)
        if info is not None and info.limit is not None:
            limit_rpm = float(info.limit)
            how = f"GitLab allows {info.limit:,} req/min per user"
        else:
            counter = self._counters.get((user, kind))
            if info is not None and info.reset_in is not None and info.reset_in > self.window * 1.5:
                done = counter.count(now, LONG_WINDOW) if counter else 0
                limit_rpm = done / 60.0
                how = f"~{done:,} requests in the hour before HTTP 429"
            else:
                done = counter.count(now, self.window) if counter else 0
                history = now - counter.first_seen if counter and counter.first_seen is not None else 0.0
                reset_in = info.reset_in if info is not None else None
                if history < self.window and reset_in is not None:
                    # Less than a window seen: the window is at least what passed plus
                    # the wait. Preliminary; a full window later refines it (lower only).
                    span = min(max(history + reset_in, 1.0), self.window)
                    limit_rpm = done * 60.0 / span
                    how = f"~{limit_rpm:,.0f} req/min per user before HTTP 429 (preliminary)"
                else:
                    limit_rpm = done * 60.0 / self.window
                    how = f"~{done:,} requests per minute passed before HTTP 429"
            if done <= 0:
                return None
        threads = self._threads_of(user)
        current = self.harvester.search_rpm if kind == SEARCH else self.harvester.index_rpm
        proposed = max(1, math.floor(limit_rpm * self.margin) // threads)
        if current and proposed >= current:
            # Paced below the estimate and still limited: the budget is shared
            # (other clients of the same user, the web UI, CI jobs).
            if current <= 1:
                return None
            proposed = max(1, math.floor(current * _BACKOFF))
            how += " (HTTP 429 even at the current pace: the budget seems shared)"
        declined = self._declined.get(kind)
        if declined is not None and proposed >= declined * 0.8:
            return None
        if self._pending is not None and kind in self._pending.rpm and self._pending.rpm[kind] <= proposed:
            return None
        last = self._last_proposed.get(kind)
        if last is not None and now - last[0] < _REPEAT_AFTER and proposed >= last[1]:
            return None
        self._last_proposed[kind] = (now, proposed)
        pending = self._pending or Suggestion(number=0)
        pending.number = next(self._numbers)
        pending.rpm[kind] = proposed
        pending.current[kind] = current
        pending.reasons[kind] = f"HTTP 429 on {API_NAMES[kind]}: {how}"
        self._pending = pending
        return pending

    # ---------------------------------------------------------------- answers

    def apply(self) -> str | None:
        """Apply the pending proposal to the running scan; return the line printed."""
        with self._lock:
            suggestion, self._pending = self._pending, None
            if suggestion is not None:
                self._quiet_until = self._clock() + self.window
        if suggestion is None:
            return None
        self.harvester.set_rate_limits(index_rpm=suggestion.rpm.get(INDEX), search_rpm=suggestion.rpm.get(SEARCH))
        changes = ", ".join(f"--{kind}-rpm {suggestion.current.get(kind, 0) or 'no limit'} -> {value}"
                            for kind, value in sorted(suggestion.rpm.items(), reverse=True))
        line = f"Limiter: applied {changes} per worker ({suggestion.describe()})"
        self.applied.append(suggestion.flags())
        self._status.write_line(line)
        return line

    def decline(self) -> None:
        """Drop the pending proposal; only a clearly lower one comes back."""
        with self._lock:
            suggestion, self._pending = self._pending, None
            if suggestion is not None:
                self._declined.update(suggestion.rpm)
        if suggestion is not None:
            self._status.write_line(f"Limiter: kept the current limits (declined {suggestion.flags()})")


class LimiterConsole:
    """
    Ask about :class:`LimitAdvisor` proposals without stopping the run.

    A daemon thread reads single keys and drives the status line overlay; the
    scan never waits for it.
    """

    def __init__(
            self,
            advisor: LimitAdvisor,
            *,
            logger: logging.Logger | None = None,
            status: terminal_utils.StatusLine | None = None,
            keys: KeyReader | None = None,
            timeout: float = PROMPT_TIMEOUT,
            clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.advisor = advisor
        self.logger = logger or logging.getLogger("GitlabHarvesterLogger")
        self._status = status if status is not None else terminal_utils.STATUS
        self._keys = keys if keys is not None else KeyReader()
        self.timeout = timeout
        self._clock = clock
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.interactive = False
        # Prompt state (console thread only).
        self._shown: int | None = None  # number of the last proposal shown
        self._deadline: float | None = None  # prompt open until
        self._flash_until = 0.0
        self._flash = ""

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> "LimiterConsole":
        self.interactive = self._status.interactive and self._keys.available()
        if self.interactive:
            self._keys.open()
            self._thread = threading.Thread(target=self._loop, name="glh-limiter", daemon=True)
            self._thread.start()
        else:
            self.advisor.on_suggestion = self._log_suggestion
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        self._keys.close()
        self._status.set_overlay(None)
        if self._status.badge in (BADGE, PENDING_BADGE):
            self._status.set_badge("")
        if self.advisor.on_suggestion == self._log_suggestion:
            self.advisor.on_suggestion = None

    def __enter__(self) -> "LimiterConsole":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # ---------------------------------------------------------------- no terminal

    def _log_suggestion(self, suggestion: Suggestion) -> None:
        self.logger.warning(
            "%s %s. Suggested: %s per worker; not applied (no terminal to ask). "
            "Rerun with these options, or run in a terminal to apply them on the fly.",
            BADGE, suggestion.describe(), suggestion.flags(),
        )

    # ------------------------------------------------------------------- terminal

    def prompt_text(self) -> str:
        """The overlay while a question is open (or a short notice)."""
        now = self._clock()
        if self._deadline is not None:
            suggestion = self.advisor.pending
            left = max(0, math.ceil(self._deadline - now))
            text = suggestion.describe() if suggestion is not None else ""
            return f"{BADGE} {text}. Apply? [Y]es / [N]o / ignore: {left}s"
        return f"{BADGE} {self._flash}"

    def handle(self, key: str | None) -> None:
        """One step of the console: react to ``key`` (None = no key) and the clock."""
        now = self._clock()
        suggestion = self.advisor.pending
        if self._deadline is not None:
            if suggestion is None:
                self._close()
            elif key is not None and key in YES_KEYS:
                self._close()
                self.advisor.apply()
            elif key is not None and key in NO_KEYS:
                self._close()
                self.advisor.decline()
            elif now >= self._deadline:
                self._close()  # no answer: keep running, the proposal stays (L)
        else:
            if suggestion is not None and suggestion.number != self._shown:
                self._open(suggestion.number)
            elif key is not None and key in SHOW_KEYS:
                if suggestion is not None:
                    self._open(suggestion.number)
                else:
                    self._flash = "no proposals: GitLab has not rate-limited this run"
                    self._flash_until = now + 3.0
                    self._status.set_overlay(self.prompt_text)
            elif self._flash and now >= self._flash_until:
                self._flash = ""
                self._status.set_overlay(None)
        pending = self.advisor.pending is not None and self._deadline is None
        self._status.set_badge(PENDING_BADGE if pending else "")

    def _open(self, number: int) -> None:
        self._shown = number
        self._flash = ""
        self._deadline = self._clock() + self.timeout
        self._status.set_overlay(self.prompt_text)

    def _close(self) -> None:
        self._deadline = None
        self._status.set_overlay(None)

    def _loop(self) -> None:
        while not self._stop.is_set():
            key = self._keys.read(0.1)
            try:
                self.handle(key)
            except Exception:  # noqa: BLE001 - the console must never break the run
                self.logger.debug("Limiter console failed", exc_info=True)
