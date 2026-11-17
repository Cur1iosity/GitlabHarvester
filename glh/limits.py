# glh/limits.py
"""
Empirical detection of GitLab API rate limits (``-m find-limits``, ``--auto-limits``).

EXPERIMENTAL: the probe, the suggestions and the runtime advice
(``glh.autolimit``) may change in behavior, output and options between minor
releases. :data:`EXPERIMENTAL_NOTE` is printed whenever they are used.

GitLab rate-limits the search API separately from (and usually far below) the
rest of the API, and most limits count **per user**, not per token: two tokens
of one user share one budget. The harvester paces the two kinds of requests
with ``--search-rpm`` and ``--index-rpm`` (see ``glh.ratelimit``); this module
finds values for them, and for ``--workers``, by measuring.

How one API is probed (:class:`LimitProbe`):

1. One request. If GitLab announces the limit in ``RateLimit-*`` headers on a
   successful response, that is the answer (no load at all). Not for search:
   such headers belong to the general API throttle, which counts search too.
2. Requests in levels of growing parallelism (1, 2, 4, ... threads) until
   GitLab answers HTTP 429. The successful requests in the window before the
   first 429 are the limit (or ``RateLimit-Limit`` of the 429, if sent);
   ``Retry-After`` / ``RateLimit-Reset`` tell when the budget is back.
3. No 429 within the default budget (search: 60 requests, other API: 300):
   the probe goes on deeper, up to ``max_requests``, to see whether a limit is
   above it and what throughput is really available. It stops early when the
   throughput stops growing with more threads (the server is the bottleneck)
   and a full window passed without a 429 (no per-window limit below it).

Requests of the probe are not paced and not retried (python-gitlab's 429
retries are off), so the probe never waits for GitLab; :meth:`LimitFinder.wait_cooldown`
waits for the window to reset afterwards, before a scan starts.

:func:`recommend` turns the results into ``--workers``, ``--index-rpm`` and
``--search-rpm`` (a ``margin`` below the limit), keeping options the user set
explicitly; :meth:`Recommendation.command` renders the command line to run.
"""

from __future__ import annotations

import json
import math
import secrets
import shlex
import statistics
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterable, Mapping, Sequence

from glh.utils import terminal_utils
from glh.utils.terminal_utils import format_duration, plural

if TYPE_CHECKING:
    from glh.harvester import GitlabHarvester

EXPERIMENTAL_NOTE = ("Rate-limit detection is EXPERIMENTAL: check the suggested values before relying "
                     "on them; behavior and output may change in future releases.")

INDEX = "index"
SEARCH = "search"
KINDS: tuple[str, ...] = (INDEX, SEARCH)
API_NAMES = {INDEX: "other API", SEARCH: "search API"}

# Requests per probed API before the probe decides to go deeper.
DEFAULT_BUDGET = {SEARCH: 60, INDEX: 300}
# Hard cap of requests per probed API (default budget + deep stage): --probe-max.
DEFAULT_MAX_REQUESTS = 600
MAX_REQUESTS_LIMIT = 100_000
MAX_PROBE_CONCURRENCY = 16
# Share of the limit the recommendation uses: --probe-margin.
DEFAULT_MARGIN = 0.85
# Window GitLab counts requests in (Rack::Attack and the application limits: 1 minute).
WINDOW = 60.0
# A Retry-After much longer than WINDOW means a longer (hourly) window.
LONG_WINDOW = 3600.0
# More threads must raise the throughput by this much, else the server is saturated.
_GROWTH = 1.15
# Extra wait after Retry-After, so the first request surely falls into the new window.
_RESET_GRACE = 0.5
# Consecutive non-429 failures that end a probe (no access, server errors, network).
_MAX_FAILURES = 5


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


# --------------------------------------------------------------------------- recommendation


@dataclass(frozen=True, slots=True)
class Settings:
    """Concurrency and pacing of a run: --workers (per token), --index-rpm, --search-rpm (per worker)."""

    workers: int = 1
    index_rpm: int = 0
    search_rpm: int = 0

    def rpm(self, kind: str) -> int:
        return self.index_rpm if kind == INDEX else self.search_rpm


@dataclass(slots=True)
class Recommendation:
    """Suggested --workers / --index-rpm / --search-rpm and why."""

    workers: int
    index_rpm: int
    search_rpm: int
    notes: list[str] = field(default_factory=list)
    kept: tuple[str, ...] = ()  # options set explicitly and left as they are

    @property
    def settings(self) -> Settings:
        return Settings(self.workers, self.index_rpm, self.search_rpm)

    def differs_from(self, current: Settings) -> bool:
        return self.settings != current

    def flags(self) -> list[str]:
        return ["--workers", str(self.workers), "--index-rpm", str(self.index_rpm),
                "--search-rpm", str(self.search_rpm)]

    def describe(self) -> str:
        def rpm(value: int) -> str:
            return str(value) if value else "0 (no limit)"
        kept = f" (kept as set: {', '.join(self.kept)})" if self.kept else ""
        return (f"--workers {self.workers} --index-rpm {rpm(self.index_rpm)} "
                f"--search-rpm {rpm(self.search_rpm)}{kept}")

    def ini(self) -> str:
        return (f"workers = {self.workers}\n"
                f"index-rpm = {self.index_rpm}\n"
                f"search-rpm = {self.search_rpm}")

    def command(self, argv: Sequence[str], *, prog: str = "gitlab-harvester", auto_limits: bool = True) -> str:
        """The command line to run: ``argv`` without its limit options, plus :meth:`flags`."""
        args = strip_limit_options(argv)
        if auto_limits and "--auto-limits" not in args:
            args.append("--auto-limits")
        return shlex.join([prog, *args, *self.flags()])


def recommend(
        results: Mapping[str, ProbeResult],
        *,
        current: Settings,
        explicit: Iterable[str] = (),
        tokens_per_user: int = 1,
        margin: float = DEFAULT_MARGIN,
        max_workers: int = 64,
) -> Recommendation:
    """
    Turn probe results into settings.

    Per probed API the target is ``margin`` x the limit (or x the measured
    throughput when no limit was found) for all threads of one user together:
    ``workers x tokens_per_user`` threads share it. Workers are as many as
    needed to reach the target at the measured latency; options named in
    ``explicit`` (``workers``, ``index_rpm``, ``search_rpm``) are kept.
    """
    explicit = set(explicit)
    tpu = max(1, int(tokens_per_user))
    notes: list[str] = []
    targets: dict[str, int] = {}
    for kind, r in results.items():
        if r.source == "error":
            notes.append(f"{r.api}: not measured ({r.error}); its setting is left as it is.")
            continue
        if r.limit_rpm is not None:
            targets[kind] = max(1, math.floor(r.limit_rpm * margin))
        elif r.peak_rpm > 0:
            targets[kind] = max(1, math.floor(r.peak_rpm * margin))
            notes.append(f"{r.api}: no GitLab limit found; the pace is set to {margin:.0%} of the measured "
                         f"throughput (~{r.peak_rpm:,.0f} req/min) to keep the load reasonable.")
        elif r.source == "429":
            notes.append(f"{r.api}: rate limited before anything could be measured; probe again later "
                         f"(after {format_duration(r.cooldown)}).")

    if "workers" in explicit:
        workers = current.workers
    else:
        needs = []
        for kind, target in targets.items():
            r = results[kind]
            threads = max(1, math.ceil(target * max(r.latency, 0.01) / 60.0))
            if r.saturated:
                threads = min(threads, max(1, r.peak_concurrency))
            needs.append(math.ceil(threads / tpu))
        workers = min(max(needs, default=current.workers), max_workers)
        # Per-worker rpm is an integer: don't spread a small budget over so many
        # threads that rounding down wastes more than a fifth of it.
        for target in targets.values():
            while workers > 1 and (target // (workers * tpu)) * workers * tpu < 0.8 * target:
                workers -= 1
        workers = max(1, workers)

    threads = workers * tpu
    rpm: dict[str, int] = {}
    kept = ["workers"] if "workers" in explicit else []
    for kind in KINDS:
        dest = f"{kind}_rpm"
        value = current.rpm(kind)
        if dest in explicit:
            kept.append(dest.replace("_", "-"))
            rpm[kind] = value
            r = results.get(kind)
            if r is not None and r.limit_rpm is not None and (value == 0 or value * threads > r.limit_rpm):
                total = "no limit" if value == 0 else f"{value * threads:,} req/min"
                notes.append(f"--{kind}-rpm {value} is kept as set, but {threads} threads per user send "
                             f"{total}, above the limit (~{r.limit_rpm:,.0f}/min): expect HTTP 429 waits.")
        elif kind in targets:
            rpm[kind] = max(1, targets[kind] // threads)
        else:
            rpm[kind] = value
    if tpu > 1:
        notes.append(f"{tpu} tokens belong to the same user and share one budget; "
                     f"the per-worker rates account for it ({workers} workers x {tpu} tokens).")
    return Recommendation(workers=workers, index_rpm=rpm[INDEX], search_rpm=rpm[SEARCH],
                          notes=notes, kept=tuple(kept))


# --------------------------------------------------------------------------- command line

# Options (flag -> takes a value) dropped from a command line before the
# recommended ones are added; --mode only when it is find-limits.
_LIMIT_OPTIONS: dict[str, bool] = {
    "-w": True, "--workers": True, "--rpm": True, "--index-rpm": True, "--search-rpm": True,
    "--probe-apis": True, "--probe-max": True, "--probe-margin": True,
}
_TOKEN_OPTIONS = ("-t", "--token")
TOKEN_PLACEHOLDER = "<TOKEN>"


def strip_limit_options(argv: Sequence[str]) -> list[str]:
    """
    ``argv`` without limit/probe options and ``-m find-limits``; tokens are
    replaced by :data:`TOKEN_PLACEHOLDER` (a printed command must not show them).
    """
    out: list[str] = []
    args = list(argv)
    i = 0
    while i < len(args):
        arg = args[i]
        name, eq, value = arg.partition("=")
        nxt = args[i + 1] if i + 1 < len(args) else None
        if name in _LIMIT_OPTIONS:
            i += 1 if eq else 2
            continue
        if name in ("-m", "--mode"):
            mode = value if eq else nxt
            if mode == "find-limits":
                i += 1 if eq else 2
                continue
        if name in _TOKEN_OPTIONS:
            out += [name, TOKEN_PLACEHOLDER]
            i += 1 if eq else 2
            continue
        if arg.startswith("-t") and not arg.startswith("--") and len(arg) > 2:
            out += ["-t", TOKEN_PLACEHOLDER]  # -tTOKEN
            i += 1
            continue
        if arg.startswith("-w") and not arg.startswith("--") and len(arg) > 2 and arg[2:].isdigit():
            i += 1  # -w4
            continue
        out.append(arg)
        i += 1
    return out


# --------------------------------------------------------------------------- harvester binding


def probe_project_from_index(path: str | Path) -> Any | None:
    """Id of the first non-empty project in an index file (streamed), or None."""
    try:
        with open(path, encoding="utf-8") as fp:
            fp.readline()  # meta
            fallback = None
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    project = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(project, dict) or project.get("id") is None:
                    continue
                if not project.get("empty_repo", False):
                    return project["id"]
                fallback = fallback if fallback is not None else project["id"]
            return fallback
    except OSError:
        return None


class LimitFinder:
    """
    Find the API limits of a :class:`~glh.harvester.GitlabHarvester` connection
    and recommend settings for it.

    Probes run with the first token; other tokens of the same user share its
    budget (see ``harvester.tokens_per_user``), tokens of other users get the
    same limits (they are instance settings).
    """

    def __init__(
            self,
            harvester: "GitlabHarvester",
            *,
            max_requests: int = DEFAULT_MAX_REQUESTS,
            margin: float = DEFAULT_MARGIN,
            budgets: Mapping[str, int] | None = None,
            window: float = WINDOW,
            status: terminal_utils.StatusLine | None = None,
            sleep: Callable[[float], None] = time.sleep,
            clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.harvester = harvester
        self.max_requests = max_requests
        self.margin = margin
        self.budgets = budgets
        self.window = window
        self._status = status if status is not None else terminal_utils.STATUS
        self._sleep = sleep
        self._clock = clock
        self.term = f"glhprobe{secrets.token_hex(6)}"

    # ------------------------------------------------------------------ probing

    def project_for_search(self, index_file: str | Path | None = None) -> Any | None:
        """A project to send probe searches to: from the index, else the first page of /projects."""
        if index_file and Path(index_file).is_file():
            found = probe_project_from_index(index_file)
            if found is not None:
                return found
        return self.harvester.first_project_id()

    def sender_factory(self, project_id: Any = None) -> Callable[[str], Sender]:
        """Senders through fresh, unpaced clients of the harvester's first token."""
        harvester = self.harvester
        term = self.term

        def factory(kind: str) -> Sender:
            if kind == SEARCH:
                path = f"/projects/{project_id}/search"
                query = {"scope": "blobs", "search": term, "per_page": 1}
            else:
                path = "/projects"
                query = {"per_page": 1, "simple": "true"}
            return harvester.probe_sender(path, query)

        return factory

    def find(self, kinds: Sequence[str], *, project_id: Any = None) -> dict[str, ProbeResult]:
        """Probe every API in ``kinds`` (in order), waiting for a hit limit to reset in between."""
        results: dict[str, ProbeResult] = {}
        for n, kind in enumerate(kinds):
            if kind == SEARCH and project_id is None:
                results[kind] = ProbeResult(kind=kind, source="error", error="no project to search in")
                continue
            if n:
                self.wait_cooldown(results.values())
            results[kind] = self._probe_one(kind, project_id)
        return results

    def _probe_one(self, kind: str, project_id: Any) -> ProbeResult:
        progress = terminal_utils.Progress(f"Probing {API_NAMES[kind]} limits", unit="requests",
                                           status=self._status)
        probe = LimitProbe(self.sender_factory(project_id), max_requests=self.max_requests,
                           budgets=self.budgets, window=self.window, clock=self._clock, sleep=self._sleep,
                           on_note=progress.note)
        progress.detail_provider = probe.status_text
        base_render = progress.render

        def render() -> str:
            progress.done = probe.sent  # the request counter follows the probe's live counter
            return base_render()

        progress.render = render  # type: ignore[method-assign]
        with progress:
            result = probe.probe(kind)
            limited = f", {plural(result.limited, 'HTTP 429 response')}" if result.limited else ""
            progress.finish(f"Probed {result.api} in {format_duration(result.elapsed)}: "
                            f"{plural(result.sent, 'request')}{limited}")
        return result

    def wait_cooldown(self, results: Iterable[ProbeResult]) -> float:
        """Wait until every rate-limit window the probes ran into has reset; return the seconds waited."""
        until = max((r.finished_at + r.cooldown for r in results if r.limited), default=0.0)
        left = until - self._clock()
        if left <= 0:
            return 0.0
        progress = terminal_utils.Progress("Waiting for the rate-limit window to reset", status=self._status)
        progress.detail_provider = lambda: f"{format_duration(max(until - self._clock(), 0.0))} left"
        with progress:
            while (remaining := until - self._clock()) > 0:
                self._sleep(min(remaining, 0.5))
            progress.finish(f"Rate-limit window reset after {format_duration(left)}")
        return left

    def recommend(self, results: Mapping[str, ProbeResult], *, current: Settings,
                  explicit: Iterable[str] = ()) -> Recommendation:
        from glh.cli import MAX_WORKERS

        return recommend(results, current=current, explicit=explicit,
                         tokens_per_user=self.harvester.tokens_per_user(), margin=self.margin,
                         max_workers=MAX_WORKERS)

    def token_note(self) -> str | None:
        """Which tokens share a user (one budget), for the report; None for a single token."""
        groups = self.harvester.token_user_groups()
        if len(self.harvester.tokens) < 2:
            return None
        shared = [g for g in groups if len(g) > 1]
        users = plural(len(groups), "user")
        if not shared:
            return f"Tokens: {len(self.harvester.tokens)} tokens of {users}: each has its own budget."
        text = "; ".join("tokens " + ", ".join(f"#{i + 1}" for i in g) + " share one user" for g in shared)
        return f"Tokens: {len(self.harvester.tokens)} tokens of {users} ({text}: one budget)."
