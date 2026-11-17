"""Rate-limit detection (glh.limits): header parsing, the probe, recommendations, command lines."""

from __future__ import annotations

import json
import math
import threading

import pytest

from glh import limits
from glh.limits import (
    INDEX,
    LONG_WINDOW,
    SEARCH,
    LimitProbe,
    ProbeResponse,
    ProbeResult,
    Recommendation,
    Settings,
    parse_limit_headers,
    probe_project_from_index,
    recommend,
    strip_limit_options,
)


# --------------------------------------------------------------------------- headers


def test_parse_limit_headers_reads_gitlab_headers_case_insensitively():
    info = parse_limit_headers({"ratelimit-limit": "600", "RateLimit-Remaining": "0", "RateLimit-Observed": "601",
                                "RateLimit-Name": "throttle_authenticated_api", "Retry-After": "42"})
    assert (info.limit, info.remaining, info.observed, info.reset_in, info.name) == (
        600, 0, 601, 42.0, "throttle_authenticated_api")


def test_parse_limit_headers_reset_time_and_nothing():
    assert parse_limit_headers({"RateLimit-Reset": "1030"}, now=1000.0).reset_in == 30.0
    assert parse_limit_headers({"RateLimit-Reset": "900"}, now=1000.0).reset_in == 0.0
    assert parse_limit_headers({"Content-Type": "application/json"}) is None
    assert parse_limit_headers(None) is None
    assert parse_limit_headers({"Retry-After": "soon"}) is None


# --------------------------------------------------------------------------- probe


class VirtualServer:
    """
    A GitLab-like fixed-window limit on a virtual clock. Every request takes
    ``latency`` virtual seconds and requests are served one at a time, so
    more threads don't raise the throughput (a saturated server).
    """

    def __init__(self, *, limit=None, period=60.0, latency=0.01, start=1030.0, used=0, headers="retry-after",
                 announce=False, status=200, retry_after=None):
        self.now = start
        self.limit, self.period, self.latency = limit, period, latency
        self.headers, self.announce, self.status = headers, announce, status
        self.retry_after = retry_after
        self.lock = threading.Lock()
        self.window = int(start // period)
        self.count = used
        self.requests = 0

    def clock(self) -> float:
        with self.lock:
            return self.now

    def sleep(self, seconds: float) -> None:
        with self.lock:
            self.now += seconds

    def send(self) -> ProbeResponse:
        with self.lock:
            self.now += self.latency
            self.requests += 1
            if self.status != 200:
                return ProbeResponse(self.status, {}, self.latency)
            window = int(self.now // self.period)
            if window != self.window:
                self.window, self.count = window, 0
            self.count += 1
            reset_in = math.ceil((window + 1) * self.period - self.now)
            if self.limit is not None and self.count > self.limit:
                headers = {"Retry-After": str(self.retry_after or reset_in)}
                if self.headers == "full":
                    headers.update({"RateLimit-Limit": str(self.limit), "RateLimit-Name": "throttle"})
                return ProbeResponse(429, headers, self.latency)
            headers = {"RateLimit-Limit": str(self.limit)} if self.announce else {}
            return ProbeResponse(200, headers, self.latency)


NOTES: list[str] = []


def probe(server: VirtualServer, kind: str = SEARCH, **kwargs) -> ProbeResult:
    NOTES.clear()
    p = LimitProbe(lambda k: server.send, clock=server.clock, sleep=server.sleep, on_note=NOTES.append, **kwargs)
    return p.probe(kind)


def test_limit_announced_on_success_needs_one_request():
    server = VirtualServer(limit=600, announce=True)
    result = probe(server, kind=INDEX)
    assert (result.source, result.limit, result.sent) == ("headers", 600, 1)
    assert result.limit_rpm == 600


def test_announced_limit_does_not_end_a_search_probe():
    # On a success those headers belong to the general API throttle, not to search.
    server = VirtualServer(limit=10, announce=True)
    result = probe(server, kind=SEARCH)
    assert result.sent > 1 and result.limit == 10 and result.exact


def test_limit_from_429_headers():
    server = VirtualServer(limit=50, headers="full")
    result = probe(server)
    assert (result.source, result.limit, result.limit_name) == ("headers", 50, "throttle")
    assert result.limited == 1 and result.cooldown > 0


def test_retry_after_only_counts_a_full_window_from_its_start():
    # 30 s into the window, 5 requests already used by someone else: the first
    # 429 comes after 15 (a lower bound); the second window counts all 20.
    server = VirtualServer(limit=20, start=1230.0, used=5)
    result = probe(server)
    assert result.source == "429" and result.exact
    assert result.limit == 20 and result.window == 60.0
    assert any("waiting" in n and "full window" in n for n in NOTES)
    assert "full window counted" in result.describe()


def test_short_windows_are_measured_too():
    server = VirtualServer(limit=6, period=10.0, start=1000.0)
    result = probe(server)
    assert result.limit == 6
    assert 9 <= result.window <= 11
    assert 30 <= result.limit_rpm <= 40


def test_long_retry_after_means_an_hourly_window():
    server = VirtualServer(limit=30, retry_after=3000)
    result = probe(server)
    assert result.window == LONG_WINDOW and result.limit == 30
    assert result.limit_rpm == pytest.approx(0.5)
    assert "per hour" in result.describe()


def test_no_limit_goes_deeper_than_the_budget_and_notices_saturation():
    server = VirtualServer(limit=None)
    result = probe(server, kind=INDEX, max_requests=500, budgets={INDEX: 100})
    assert result.source == "none" and result.limit is None
    assert result.deep and result.saturated
    assert result.sent == 500 and server.requests == 500
    assert result.peak_rpm == pytest.approx(6000, rel=0.05)
    assert any("probing deeper" in n for n in NOTES)
    assert "no rate limit found" in result.describe()


def test_probe_max_equal_to_budget_stays_shallow():
    server = VirtualServer(limit=None)
    result = probe(server, max_requests=40)
    assert result.sent == 40 and not NOTES


def test_a_whole_window_without_429_ends_the_probe():
    server = VirtualServer(limit=None, latency=1.0)  # 60 req/min at most
    result = probe(server, max_requests=10_000)
    assert result.source == "none"
    assert 60 <= result.sent <= 80  # ~65 s of virtual time


def test_failures_end_the_probe_with_an_error():
    server = VirtualServer(status=403)
    result = probe(server)
    assert result.source == "error" and "403" in result.error
    assert result.sent == limits._MAX_FAILURES
    assert "probe failed" in result.describe()


def test_rate_limited_from_the_first_request():
    server = VirtualServer(limit=5, used=5)
    result = probe(server)
    assert result.source == "429"
    assert result.limited >= 1


# --------------------------------------------------------------------------- recommendation


def found(kind, limit, latency=0.2, window=60.0, **kw) -> ProbeResult:
    return ProbeResult(kind=kind, limit=limit, window=window, source="429", latency=latency, sent=limit + 1,
                       ok=limit, limited=1, **kw)


def test_search_limit_gives_one_worker_and_the_margin():
    rec = recommend({SEARCH: found(SEARCH, 30, latency=0.5)}, current=Settings())
    assert (rec.workers, rec.search_rpm, rec.index_rpm) == (1, 25, 0)


def test_workers_follow_latency_and_rpm_is_split_over_them():
    results = {INDEX: found(INDEX, 600, latency=0.3), SEARCH: found(SEARCH, 30, latency=0.5)}
    rec = recommend(results, current=Settings())
    # index: 510/min at 0.3 s needs 3 threads; search 25/min over 3 threads = 8 each (24/min).
    assert (rec.workers, rec.index_rpm, rec.search_rpm) == (3, 170, 8)


def test_rounding_never_wastes_more_than_a_fifth_of_a_small_budget():
    results = {INDEX: found(INDEX, 3000, latency=0.5), SEARCH: found(SEARCH, 10, latency=0.5)}
    rec = recommend(results, current=Settings())
    threads = rec.workers
    assert rec.search_rpm * threads >= 0.8 * math.floor(10 * 0.85)


def test_explicit_options_are_kept_and_warned_about():
    rec = recommend({SEARCH: found(SEARCH, 30)}, current=Settings(workers=8, search_rpm=100),
                    explicit={"workers", "search_rpm"})
    assert (rec.workers, rec.search_rpm) == (8, 100)
    assert rec.kept == ("workers", "search-rpm")
    assert any("above the limit" in n for n in rec.notes)
    rec = recommend({SEARCH: found(SEARCH, 30)}, current=Settings(workers=8), explicit={"workers"})
    assert (rec.workers, rec.search_rpm) == (8, 3)


def test_tokens_of_one_user_share_the_budget():
    rec = recommend({SEARCH: found(SEARCH, 60, latency=2.0)}, current=Settings(), tokens_per_user=2)
    # 51/min at 2 s needs 2 threads per user = 1 worker x 2 tokens; 51 // 2 = 25 per worker.
    assert (rec.workers, rec.search_rpm) == (1, 25)
    assert any("same user" in n for n in rec.notes)


def test_no_limit_suggests_a_pace_below_the_measured_throughput():
    result = ProbeResult(kind=INDEX, source="none", peak_rpm=1000.0, peak_concurrency=4, saturated=True,
                         latency=0.1, sent=600, ok=600)
    rec = recommend({INDEX: result}, current=Settings())
    assert rec.index_rpm * rec.workers <= 850
    assert any("no GitLab limit" in n for n in rec.notes)


def test_failed_probe_leaves_the_setting_alone():
    error = ProbeResult(kind=SEARCH, source="error", error="HTTP 403")
    rec = recommend({SEARCH: error}, current=Settings(workers=2, search_rpm=7))
    assert (rec.workers, rec.search_rpm) == (2, 7)
    assert any("not measured" in n for n in rec.notes)


def test_recommendation_renders_flags_and_ini():
    rec = Recommendation(workers=2, index_rpm=100, search_rpm=12)
    assert rec.flags() == ["--workers", "2", "--index-rpm", "100", "--search-rpm", "12"]
    assert rec.ini() == "workers = 2\nindex-rpm = 100\nsearch-rpm = 12"
    assert not rec.differs_from(Settings(2, 100, 12)) and rec.differs_from(Settings(1, 100, 12))


# --------------------------------------------------------------------------- command line


def test_strip_limit_options_drops_limits_and_masks_tokens():
    argv = ["-u", "https://g", "-t", "SECRET", "-w", "4", "--search-rpm=10", "--rpm", "5", "-m", "find-limits",
            "--probe-max", "100", "-s", "pw"]
    assert strip_limit_options(argv) == ["-u", "https://g", "-t", "<TOKEN>", "-s", "pw"]
    assert strip_limit_options(["--token=SECRET", "-tSECRET2", "-w4", "-m", "search"]) == [
        "--token", "<TOKEN>", "-t", "<TOKEN>", "-m", "search"]


def test_command_never_shows_the_token():
    rec = Recommendation(workers=1, index_rpm=0, search_rpm=25)
    cmd = rec.command(["-u", "https://g", "-t", "a;b", "-s", "my pass", "--auto-limits"])
    assert "a;b" not in cmd and "<TOKEN>" in cmd
    assert cmd.count("--auto-limits") == 1 and "'my pass'" in cmd
    assert cmd.endswith("--workers 1 --index-rpm 0 --search-rpm 25")


# --------------------------------------------------------------------------- index


def test_probe_project_comes_from_the_index_without_loading_it(tmp_path):
    path = tmp_path / "idx.jsonl"
    rows = [{"type": "meta"}, {"id": 1, "empty_repo": True}, {"id": 2, "empty_repo": False}]
    path.write_text("".join(json.dumps(r) + "\n" for r in rows) + "not json\n", encoding="utf-8")
    assert probe_project_from_index(path) == 2
    path.write_text(json.dumps({"type": "meta"}) + "\n" + json.dumps({"id": 7, "empty_repo": True}) + "\n",
                    encoding="utf-8")
    assert probe_project_from_index(path) == 7
    assert probe_project_from_index(tmp_path / "missing.jsonl") is None
