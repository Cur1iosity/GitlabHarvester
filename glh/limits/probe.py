# glh/limits/probe.py
"""
LimitProbe: measures the rate limit of one API by load (see glh.limits).
"""

from __future__ import annotations

import statistics
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from glh.limits.constants import (
    API_NAMES,
    DEFAULT_BUDGET,
    DEFAULT_MAX_REQUESTS,
    LONG_WINDOW,
    MAX_PROBE_CONCURRENCY,
    SEARCH,
    WINDOW,
)
from glh.limits.headers import HeaderLimit, parse_limit_headers
from glh.ui.formatting import format_duration, plural

# More threads must raise the throughput by this much, else the server is saturated.
_GROWTH = 1.15

# Extra wait after Retry-After, so the first request surely falls into the new window.
_RESET_GRACE = 0.5

# Consecutive non-429 failures that end a probe (no access, server errors, network).
_MAX_FAILURES = 5

# --------------------------------------------------------------------------- probe


@dataclass(frozen=True, slots=True)
class ProbeResponse:
    """One probe request: HTTP status (0 = no response), headers, seconds it took."""

    status: int
    headers: Mapping[str, Any] = field(default_factory=dict)
    latency: float = 0.0
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

Sender = Callable[[], ProbeResponse]


@dataclass(slots=True)
class ProbeResult:
    """Outcome of probing one API (search or other) with one token."""

    kind: str
    sent: int = 0
    ok: int = 0
    limited: int = 0  # HTTP 429 responses
    failed: int = 0  # other errors
    # Requests GitLab allows per ``window`` seconds; None = no limit found.
    limit: int | None = None
    window: float = WINDOW
    source: str = "none"  # "headers" | "429" | "none" | "error"
    limit_name: str | None = None
    # Seconds after ``finished_at`` until the budget is back.
    cooldown: float = 0.0
    finished_at: float = 0.0
    peak_rpm: float = 0.0
    peak_concurrency: int = 1
    saturated: bool = False
    deep: bool = False
    budget: int = 0
    # The limit was counted over one full window from its start (else: a lower bound).
    exact: bool = False
    latency: float = 0.0  # median seconds of a successful request
    elapsed: float = 0.0
    error: str = ""

    @property
    def api(self) -> str:
        return API_NAMES.get(self.kind, self.kind)

    @property
    def limit_rpm(self) -> float | None:
        """The limit as requests per minute (None = no limit found)."""
        if self.limit is None:
            return None
        return self.limit * 60.0 / self.window

    def describe(self) -> str:
        """One line: what was found and how."""
        return f"{self.api}: " + "; ".join(self.lines())

    def lines(self) -> list[str]:
        """What was found, then how it was measured."""
        if self.source == "error":
            return [f"probe failed: {self.error}"]
        details = [plural(self.sent, "request")]
        if self.peak_rpm:
            details.append(f"up to {self.peak_concurrency} parallel, peak ~{self.peak_rpm:,.0f} req/min")
        if self.latency:
            details.append(f"latency {self.latency:.2f}s")
        if self.cooldown and self.limited:
            details.append(f"budget back in {format_duration(self.cooldown)}")
        if self.limit is not None:
            if self.window == WINDOW:
                per = "minute"
            elif self.window == LONG_WINDOW:
                per = "hour"
            else:
                per = f"{self.window:g}s (~{self.limit_rpm:,.0f}/min)"
            how = ("GitLab headers" if self.source == "headers"
                   else "HTTP 429, full window counted" if self.exact else "HTTP 429, lower bound")
            name = f", {self.limit_name}" if self.limit_name else ""
            head = f"~{self.limit:,} requests per {per} per user ({how}{name})"
        elif self.source == "429":
            head = "rate limited at once (HTTP 429): the budget was already used up, limit unknown"
        else:
            reach = "server throughput limit" if self.saturated else "not reached"
            head = f"no rate limit found up to ~{self.peak_rpm:,.0f} req/min ({reach})"
        return [head, ", ".join(details)]


class LimitProbe:
    """
    Find the rate limit of one API by sending requests until GitLab answers 429.

    ``sender_factory(kind)`` returns a new sender (own HTTP client) for one
    probe thread; a sender makes one request and returns a :class:`ProbeResponse`.
    It must not retry or wait on 429.
    """

    def __init__(
            self,
            sender_factory: Callable[[str], Sender],
            *,
            max_requests: int = DEFAULT_MAX_REQUESTS,
            budgets: Mapping[str, int] | None = None,
            max_concurrency: int = MAX_PROBE_CONCURRENCY,
            window: float = WINDOW,
            exact: bool = True,
            clock: Callable[[], float] = time.monotonic,
            sleep: Callable[[float], None] = time.sleep,
            on_note: Callable[[str], None] | None = None,
    ) -> None:
        self._factory = sender_factory
        # After a 429 without RateLimit-Limit, wait for the reset and count a full window.
        self.exact = exact
        self._sleep = sleep
        self.max_requests = max(1, int(max_requests))
        self.budgets = dict(DEFAULT_BUDGET if budgets is None else budgets)
        self.max_concurrency = max(1, int(max_concurrency))
        self.window = window
        self._clock = clock
        self._on_note = on_note
        self._lock = threading.Lock()
        # Live counters of the running probe (read by the status line).
        self.sent = 0
        self.ok = 0
        self.limited = 0
        self.concurrency = 0
        self.rpm = 0.0
        self.waiting_until: float | None = None

    def status_text(self) -> str:
        """'4 parallel, ~620 req/min, 1 HTTP 429' for the status line."""
        if (until := self.waiting_until) is not None:
            return f"waiting for the window to reset: {format_duration(max(until - self._clock(), 0.0))} left"
        parts = [f"{self.concurrency} parallel"] if self.concurrency else []
        if self.rpm:
            parts.append(f"~{self.rpm:,.0f} req/min")
        if self.limited:
            parts.append(f"{self.limited} HTTP 429")
        return ", ".join(parts)

    def _note(self, text: str) -> None:
        if self._on_note is not None:
            self._on_note(text)

    def probe(self, kind: str) -> ProbeResult:
        """Probe ``kind`` (INDEX or SEARCH) and return what was found."""
        result = ProbeResult(kind=kind)
        budget = min(self.budgets.get(kind, DEFAULT_BUDGET.get(kind, 60)), self.max_requests)
        result.budget = budget
        records: list[tuple[float, ProbeResponse]] = []
        senders: list[Sender] = []
        stop = threading.Event()
        state = {"failures": 0, "error": ""}
        self.sent = self.ok = self.limited = 0
        self.concurrency = 1
        self.rpm = 0.0
        started = self._clock()

        def run_level(concurrency: int, count: int) -> None:
            while len(senders) < concurrency:
                senders.append(self._factory(kind))
            taken = [0]

            def work(send: Sender) -> None:
                while not stop.is_set():
                    with self._lock:
                        if taken[0] >= count:
                            return
                        taken[0] += 1
                        self.sent += 1
                    response = send()
                    now = self._clock()
                    with self._lock:
                        records.append((now, response))
                        if response.ok:
                            self.ok += 1
                            state["failures"] = 0
                        elif response.status == 429:
                            self.limited += 1
                            stop.set()
                        else:
                            state["failures"] += 1
                            state["error"] = response.error or f"HTTP {response.status}"
                            if state["failures"] >= _MAX_FAILURES:
                                stop.set()

            if concurrency == 1:
                work(senders[0])
                return
            threads = [threading.Thread(target=work, args=(senders[i],), name=f"glh-probe-{i + 1}", daemon=True)
                       for i in range(concurrency)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        # 1. A single request: limits announced in headers need no load at all.
        # Not for search: such headers on a success belong to the general API
        # throttle (search requests count there too), not to the search limit.
        run_level(1, 1)
        first = records[0][1]
        announced = parse_limit_headers(first.headers)
        if kind != SEARCH and first.ok and announced is not None and announced.limit is not None:
            result.limit, result.window, result.source = announced.limit, WINDOW, "headers"
            result.limit_name = announced.name
            return self._finish(result, records, started)

        # 2./3. Levels of growing parallelism until a 429, the budget or saturation.
        concurrency, best_rpm = 1, 0.0
        while not stop.is_set() and self.sent < self.max_requests:
            if self.sent >= budget and not result.deep:
                result.deep = True
                if self.max_requests > budget:
                    self._note(f"{API_NAMES[kind]}: no limit within {plural(budget, 'request')}; "
                               f"probing deeper (up to {self.max_requests:,})")
            cap = self.max_requests if result.deep else budget
            count = min(max(8, 4 * concurrency), cap - self.sent)
            if count <= 0:
                continue
            self.concurrency = concurrency
            level_start, ok_before = self._clock(), self.ok
            run_level(concurrency, count)
            took = self._clock() - level_start
            level_ok = self.ok - ok_before
            if took > 0 and level_ok:
                self.rpm = level_ok * 60.0 / took
                if self.rpm > result.peak_rpm:
                    result.peak_rpm, result.peak_concurrency = self.rpm, concurrency
            if stop.is_set():
                break
            if self._clock() - started >= self.window + 5:
                break  # a whole window without a 429: no per-window limit below this rate
            if best_rpm and self.rpm < best_rpm * _GROWTH:
                result.saturated = True  # more threads don't help: keep the parallelism
            elif concurrency < self.max_concurrency:
                concurrency = min(concurrency * 2, self.max_concurrency)
            best_rpm = max(best_rpm, self.rpm)

        if state["failures"] >= _MAX_FAILURES and not self.limited:
            result.source, result.error = "error", state["error"]
            return self._finish(result, records, started)

        first_429 = next(((t, r) for t, r in records if r.status == 429), None)
        if first_429 is not None:
            at, response = first_429
            info = parse_limit_headers(response.headers) or HeaderLimit()
            result.source = "429"
            result.limit_name = info.name
            result.cooldown = info.reset_in if info.reset_in is not None else self.window
            if info.limit is not None:
                result.limit, result.window, result.source = info.limit, WINDOW, "headers"
            elif info.reset_in is not None and info.reset_in > self.window * 1.5:
                # An hourly (or longer) window: everything sent so far counted.
                result.window = LONG_WINDOW
                result.limit = sum(1 for t, r in records if r.ok and t <= at) or None
            else:
                successes = [t for t, r in records if r.ok and at - result.window <= t <= at]
                result.limit = len(successes) or None
                if info.reset_in is not None and self.exact:
                    self._measure_full_window(kind, result, records, run_level, stop, info.reset_in)
        return self._finish(result, records, started)

    def _measure_full_window(self, kind: str, result: ProbeResult, records: list[tuple[float, ProbeResponse]],
                             run_level: Callable[[int, int], None], stop: threading.Event,
                             reset_in: float) -> None:
        """
        The first 429 came somewhere inside GitLab's window, after an unknown
        part of it was used: a lower bound. Wait for the window to reset and
        count one window from its start: the requests that pass are the limit,
        and the time to the next 429 plus its Retry-After is the window length.
        """
        self._note(f"{API_NAMES[kind]}: HTTP 429 after {plural(result.limit or 0, 'request')}; waiting "
                   f"{format_duration(reset_in)} for the window to reset, then measuring a full window")
        self.waiting_until = self._clock() + reset_in + _RESET_GRACE
        self._sleep(reset_in + _RESET_GRACE)
        self.waiting_until = None
        stop.clear()
        mark = len(records)
        window_start = self._clock()
        cap = min(max(4 * (result.limit or 1) + 8, 40), self.max_requests)
        concurrency = max(1, self.concurrency)
        sent = 0
        while not stop.is_set() and sent < cap and self._clock() - window_start <= self.window * 1.5:
            count = min(max(8, 4 * concurrency), cap - sent)
            run_level(concurrency, count)
            sent += count
        second = records[mark:]
        hit = next(((t, r) for t, r in second if r.status == 429), None)
        if hit is None:
            return  # no 429 this time: keep the lower bound of the first window
        passed = sum(1 for t, r in second if r.ok and t <= hit[0])
        if not passed:
            return
        info = parse_limit_headers(hit[1].headers) or HeaderLimit()
        result.limit = passed
        result.exact = True
        if info.reset_in is not None:
            # The window began about _RESET_GRACE before window_start.
            period = (hit[0] - window_start) + info.reset_in + _RESET_GRACE
            result.window = WINDOW if abs(period - WINDOW) <= 0.1 * WINDOW else float(max(1, round(period)))
            result.cooldown = info.reset_in
        else:
            result.cooldown = result.window

    def _finish(self, result: ProbeResult, records: list[tuple[float, ProbeResponse]],
                started: float) -> ProbeResult:
        result.sent = len(records)
        result.ok = sum(1 for _, r in records if r.ok)
        result.limited = sum(1 for _, r in records if r.status == 429)
        result.failed = result.sent - result.ok - result.limited
        latencies = [r.latency for _, r in records if r.ok and r.latency > 0]
        result.latency = statistics.median(latencies) if latencies else 0.0
        result.finished_at = self._clock()
        result.elapsed = result.finished_at - started
        if not result.peak_rpm and result.ok and result.elapsed > 0:
            result.peak_rpm = result.ok * 60.0 / result.elapsed
        return result
