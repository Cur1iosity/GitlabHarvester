"""Client-side request rate limits (glh.ratelimit)."""

from __future__ import annotations

import pytest
from requests import Session

from glh import ratelimit
from glh.ratelimit import RateLimiter, ThrottledAdapter, describe, is_search_request, limit_session


class Clock:
    def __init__(self) -> None:
        self.now = 100.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(round(seconds, 6))
        self.now += seconds


def test_requests_are_spaced_evenly():
    clock = Clock()
    limiter = RateLimiter(30, clock=clock, sleep=clock.sleep)  # one request every 2 s
    assert limiter.wait() == 0.0  # the first request goes at once
    assert limiter.wait() == 2.0
    clock.now += 0.5  # the request took 0.5 s: only the rest of the interval is waited
    assert limiter.wait() == 1.5
    clock.now += 10  # a slow request: the next one may start right away
    assert limiter.wait() == 0.0
    assert clock.slept == [2.0, 1.5]


def test_no_burst_after_an_idle_period():
    clock = Clock()
    limiter = RateLimiter(60, clock=clock, sleep=clock.sleep)
    limiter.wait()
    clock.now += 600
    assert [limiter.wait() for _ in range(3)] == [0.0, 1.0, 1.0]


@pytest.mark.parametrize("rpm", [0, -1])
def test_limiter_needs_a_positive_rate(rpm):
    with pytest.raises(ValueError):
        RateLimiter(rpm)


@pytest.mark.parametrize(("url", "search"), [
    ("https://gitlab.test/api/v4/projects/101/search?scope=blobs&search=x", True),
    ("https://gitlab.test/api/v4/projects/acme%2Fapi/search", True),
    ("https://gitlab.test/api/v4/groups/7/search?scope=blobs", True),
    ("https://gitlab.test/api/v4/search?scope=projects", True),
    ("https://gitlab.test/api/v4/projects?page=2", False),
    ("https://gitlab.test/api/v4/projects/101/repository/branches", False),
    ("https://gitlab.test/api/v4/projects/101/repository/commits?path=search", False),
    ("https://gitlab.test/api/v4/user", False),
])
def test_search_requests_are_recognized(url, search):
    assert is_search_request(url) is search


class _Request:
    def __init__(self, url: str) -> None:
        self.url = url


def test_adapter_uses_the_budget_of_the_request_kind(monkeypatch):
    sent: list[str] = []
    monkeypatch.setattr("requests.adapters.HTTPAdapter.send", lambda self, request, *a, **k: sent.append(request.url))
    adapter = ThrottledAdapter(index_rpm=0, search_rpm=60)
    waits: list[str] = []
    monkeypatch.setattr(adapter.search_limiter, "wait", lambda: waits.append("search"))

    adapter.send(_Request("https://g/api/v4/projects/1/search?search=x"))
    adapter.send(_Request("https://g/api/v4/projects?page=1"))

    assert adapter.index_limiter is None
    assert waits == ["search"]
    assert len(sent) == 2


def test_limit_session_mounts_only_with_a_limit():
    session = Session()
    default = session.get_adapter("https://gitlab.test")
    limit_session(session)
    assert session.get_adapter("https://gitlab.test") is default

    limit_session(session, index_rpm=10, search_rpm=2)
    adapter = session.get_adapter("https://gitlab.test")
    assert isinstance(adapter, ThrottledAdapter) and session.get_adapter("http://gitlab.test") is adapter
    assert adapter.index_limiter.rpm == 10 and adapter.search_limiter.rpm == 2


def test_describe():
    assert describe(0, 0) == ""
    assert describe(0, 30) == "search 30/min per worker"
    assert describe(300, 30) == "search 30/min, other API 300/min per worker"


def test_default_sleep_is_patchable(monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr(ratelimit, "_sleep", slept.append)
    clock = Clock()
    limiter = RateLimiter(60, clock=clock)
    limiter.wait()
    limiter.wait()
    assert slept == [1.0]
