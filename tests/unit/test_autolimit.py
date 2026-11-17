"""--auto-limits during a run (glh.limits.advisor, glh.limits.console): proposals after HTTP 429 and the non-blocking prompt."""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from glh.limits.advisor import LimitAdvisor
from glh.limits.console import BADGE, LimiterConsole, PENDING_BADGE
from glh.ui.statusline import StatusLine
from tests.helpers import FakeStream, LogCapture

SEARCH_URL = "https://gitlab.test/api/v4/projects/1/search?scope=blobs&search=x"
INDEX_URL = "https://gitlab.test/api/v4/projects?page=2"


class Clock:
    def __init__(self, now: float = 10_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class StubHarvester:
    """What the advisor uses of GitlabHarvester."""

    def __init__(self, *, tokens=("t1",), users=None, workers=2, search_rpm=0, index_rpm=0):
        self.tokens = tuple(tokens)
        self.users = users or {t: i + 1 for i, t in enumerate(self.tokens)}
        self.workers, self.search_rpm, self.index_rpm = workers, search_rpm, index_rpm
        self.limit_observer = None
        self.changes: list[dict] = []

    def token_user_key(self, token):
        return self.users.get(token)

    def set_rate_limits(self, **kwargs):
        self.changes.append(kwargs)
        for key, value in kwargs.items():
            if value is not None:
                setattr(self, key, value)


def response(status: int, url: str = SEARCH_URL, token: str = "t1", headers: dict | None = None):
    request = SimpleNamespace(url=url, headers={"PRIVATE-TOKEN": token})
    return SimpleNamespace(status_code=status, url=url, request=request, headers=headers or {})


def status_line() -> tuple[StatusLine, FakeStream]:
    stream = FakeStream(tty=True)
    return StatusLine(stream, interactive=True, ticker=False, columns=lambda: 400), stream


@pytest.fixture
def clock() -> Clock:
    return Clock()


def advisor_for(harvester, clock) -> LimitAdvisor:
    status, _ = status_line()
    return LimitAdvisor(harvester, clock=clock, status=status).attach()


def feed(advisor: LimitAdvisor, clock: Clock, n: int, *, every: float, url: str = SEARCH_URL) -> None:
    for _ in range(n):
        clock.now += every
        advisor.observe(response(200, url))


# --------------------------------------------------------------------------- advisor


def test_attach_and_detach_set_the_observer(clock):
    harvester = StubHarvester()
    advisor = advisor_for(harvester, clock)
    assert harvester.limit_observer == advisor.observe
    advisor.detach()
    assert harvester.limit_observer is None


def test_429_after_a_full_window_proposes_the_rate_that_passed(clock):
    harvester = StubHarvester(workers=2)
    advisor = advisor_for(harvester, clock)
    feed(advisor, clock, 120, every=1.0)  # 1 req/s for two minutes: 60 in the last window
    advisor.observe(response(429, headers={"Retry-After": "30"}))
    pending = advisor.pending
    assert pending is not None and pending.rpm == {"search": 51 // 2}
    assert pending.current == {"search": 0}
    assert "60 requests per minute" in pending.describe()
    assert advisor.limited["search"] == 1


def test_ratelimit_limit_header_wins(clock):
    advisor = advisor_for(StubHarvester(workers=2), clock)
    advisor.observe(response(429, INDEX_URL, headers={"RateLimit-Limit": "600", "Retry-After": "5"}))
    assert advisor.pending.rpm == {"index": 255}


def test_less_than_a_window_of_history_gives_a_preliminary_estimate(clock):
    advisor = advisor_for(StubHarvester(workers=2), clock)
    feed(advisor, clock, 6, every=0.1)  # 6 requests, then Retry-After 9: ~6 per 10 s = 36/min
    advisor.observe(response(429, headers={"Retry-After": "9"}))
    assert 14 <= advisor.pending.rpm["search"] <= 16
    assert "preliminary" in advisor.pending.describe()


def test_no_successes_means_no_estimate(clock):
    advisor = advisor_for(StubHarvester(), clock)
    advisor.observe(response(429, headers={"Retry-After": "9"}))
    assert advisor.pending is None and advisor.limited["search"] == 1


def test_already_paced_below_the_estimate_backs_off(clock):
    advisor = advisor_for(StubHarvester(workers=1, search_rpm=8), clock)
    feed(advisor, clock, 70, every=1.0)
    advisor.observe(response(429, headers={"Retry-After": "20"}))
    assert advisor.pending.rpm == {"search": 6}
    assert "shared" in advisor.pending.describe()


def test_users_are_counted_separately(clock):
    harvester = StubHarvester(tokens=("t1", "t2"), users={"t1": 1, "t2": 1}, workers=2)
    advisor = advisor_for(harvester, clock)
    feed(advisor, clock, 70, every=1.0)
    advisor.observe(response(200, token="t2"))
    advisor.observe(response(429, token="t2", headers={"RateLimit-Limit": "40"}))
    # One user, 2 tokens x 2 workers = 4 threads share 34/min.
    assert advisor.pending.rpm == {"search": 8}


def test_apply_changes_the_running_limits_and_quiets_the_advisor(clock):
    harvester = StubHarvester(workers=1)
    advisor = advisor_for(harvester, clock)
    advisor.observe(response(429, headers={"RateLimit-Limit": "30"}))
    line = advisor.apply()
    assert harvester.changes == [{"index_rpm": None, "search_rpm": 25}]
    assert "--search-rpm no limit -> 25" in line and advisor.pending is None
    clock.now += 10
    advisor.observe(response(429, headers={"RateLimit-Limit": "10"}))
    assert advisor.pending is None  # 429s right after a change say nothing about the new pace
    clock.now += 61
    advisor.observe(response(429, headers={"RateLimit-Limit": "10"}))
    assert advisor.pending.rpm == {"search": 8}


def test_declined_proposals_come_back_only_much_lower(clock):
    advisor = advisor_for(StubHarvester(workers=1), clock)
    advisor.observe(response(429, headers={"RateLimit-Limit": "30"}))
    advisor.decline()
    assert advisor.pending is None
    clock.now += 60
    advisor.observe(response(429, headers={"RateLimit-Limit": "28"}))
    assert advisor.pending is None
    advisor.observe(response(429, headers={"RateLimit-Limit": "12"}))
    assert advisor.pending.rpm == {"search": 10}


def test_other_statuses_are_ignored(clock):
    advisor = advisor_for(StubHarvester(), clock)
    advisor.observe(response(500))
    advisor.observe(SimpleNamespace())  # not a response
    assert advisor.pending is None and advisor.limited == {"index": 0, "search": 0}


# --------------------------------------------------------------------------- console


class Keys:
    def __init__(self, available: bool = True) -> None:
        self._available = available
        self.opened = self.closed = False

    def available(self) -> bool:
        return self._available

    def open(self):
        self.opened = True
        return self

    def close(self) -> None:
        self.closed = True

    def read(self, timeout: float):
        return None


def console_for(clock, *, workers=1):
    harvester = StubHarvester(workers=workers)
    status, stream = status_line()
    advisor = LimitAdvisor(harvester, clock=clock, status=status).attach()
    console = LimiterConsole(advisor, status=status, keys=Keys(), clock=clock, timeout=20)
    return harvester, advisor, console, status, stream


def propose(advisor, limit="30"):
    advisor.observe(response(429, headers={"RateLimit-Limit": limit}))


def test_a_new_proposal_opens_the_prompt_and_times_out_without_stopping(clock):
    harvester, advisor, console, status, stream = console_for(clock)
    console.handle(None)
    assert stream.getvalue() == ""  # nothing to say
    propose(advisor)
    console.handle(None)
    assert "Apply? [Y]es / [N]o / ignore: 20s" in stream.getvalue()
    assert console.prompt_text().startswith(BADGE)
    clock.now += 21
    console.handle(None)
    # No answer: nothing changed, the proposal waits behind the badge.
    assert harvester.changes == [] and advisor.pending is not None
    assert status.badge == PENDING_BADGE


@pytest.mark.parametrize("key", ["l", "L", "д", "Д"])
def test_l_shows_the_proposal_again(clock, key):
    _, advisor, console, status, _ = console_for(clock)
    propose(advisor)
    console.handle(None)
    clock.now += 21
    console.handle(None)
    console.handle(key)
    assert console._deadline is not None and status.badge == ""


@pytest.mark.parametrize("key", ["y", "Y", "\r", "н"])
def test_yes_applies(clock, key):
    harvester, advisor, console, status, stream = console_for(clock)
    propose(advisor)
    console.handle(None)
    console.handle(key)
    assert harvester.changes and harvester.search_rpm == 25
    assert advisor.pending is None and status.badge == ""
    assert "Limiter: applied --search-rpm no limit -> 25" in stream.getvalue()


@pytest.mark.parametrize("key", ["n", "N", "\x1b", "т"])
def test_no_declines(clock, key):
    harvester, advisor, console, status, stream = console_for(clock)
    propose(advisor)
    console.handle(None)
    console.handle(key)
    assert harvester.changes == [] and advisor.pending is None
    assert "declined --search-rpm 25" in stream.getvalue()


def test_l_without_proposals_says_so_briefly(clock):
    _, _, console, _, stream = console_for(clock)
    console.handle("l")
    assert "no proposals" in stream.getvalue()
    clock.now += 4
    console.handle(None)
    assert console._flash == ""


def test_start_without_a_terminal_logs_proposals(clock):
    harvester = StubHarvester(workers=1)
    status = StatusLine(FakeStream(tty=False), interactive=False, ticker=False)
    advisor = LimitAdvisor(harvester, clock=clock, status=status).attach()
    logger = logging.getLogger("test-limiter")
    capture = LogCapture()
    logger.addHandler(capture)
    try:
        console = LimiterConsole(advisor, status=status, keys=Keys(available=False), logger=logger).start()
        assert not console.interactive
        propose(advisor)
        console.stop()
    finally:
        logger.removeHandler(capture)
    messages = [r.getMessage() for r in capture.records]
    assert any("--search-rpm 25" in m and "not applied" in m for m in messages)
    assert advisor.on_suggestion is None


def test_console_thread_starts_and_stops(clock):
    harvester = StubHarvester()
    status, _ = status_line()
    advisor = LimitAdvisor(harvester, status=status).attach()
    keys = Keys()
    console = LimiterConsole(advisor, status=status, keys=keys).start()
    assert console.interactive and keys.opened
    console.stop()
    assert keys.closed and status.badge == ""
