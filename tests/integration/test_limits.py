"""Rate-limit detection and runtime advice with real python-gitlab against the Fake GitLab."""

from __future__ import annotations

import io

import pytest

from fakegitlab import FakeGitLab
from glh.domain.planning import ScanOptions
from glh.limits.advisor import LimitAdvisor
from glh.limits.constants import INDEX, SEARCH
from glh.limits.finder import LimitFinder
from glh.limits.recommend import recommend, Settings
from glh.ui.statusline import StatusLine
from tests.helpers import FakeStream, load_index


def quiet_status() -> StatusLine:
    return StatusLine(FakeStream(tty=False), interactive=False, ticker=False)


def finder_for(glh, **kwargs) -> LimitFinder:
    return LimitFinder(glh, status=quiet_status(), **kwargs)


def test_search_limit_is_counted_over_a_full_window(fake_gitlab: FakeGitLab, make_harvester):
    fake_gitlab.set_rate_limits({"search": {"limit": 5, "period": 2}})
    glh = make_harvester()
    finder = finder_for(glh)
    project = finder.project_for_search()
    assert project is not None
    results = finder.find([SEARCH], project_id=project)
    result = results[SEARCH]
    assert result.source == "429" and result.exact and result.limit == 5
    assert 1 <= result.window <= 4
    searches = fake_gitlab.api_requests("project_search")
    assert all(r.arg("search") == finder.term and r.arg("scope") == "blobs" for r in searches)
    assert fake_gitlab.unmatched_requests() == []
    rec = finder.recommend(results, current=Settings(), explicit=())
    assert rec.search_rpm >= 1 and rec.workers >= 1


def test_index_limit_announced_in_headers_costs_one_request(fake_gitlab: FakeGitLab, make_harvester):
    fake_gitlab.set_rate_limits({"api": {"limit": 1000, "period": 60, "on_success": True}})
    glh = make_harvester()
    fake_gitlab.clear_journal()
    results = finder_for(glh).find([INDEX])
    assert results[INDEX].source == "headers" and results[INDEX].limit == 1000
    assert len(fake_gitlab.api_requests("projects")) == 1
    assert fake_gitlab.api_requests("projects")[0].arg("per_page") == "1"


def test_probe_requests_are_not_retried_and_wait_for_the_reset(fake_gitlab: FakeGitLab, make_harvester):
    fake_gitlab.set_rate_limits({"api": {"limit": 8, "period": 2}})
    glh = make_harvester()
    import time

    slept: list[float] = []

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        time.sleep(seconds)

    finder = finder_for(glh, max_requests=60, sleep=sleep)
    result = finder.find([INDEX])[INDEX]
    assert result.source == "headers" and result.limit == 240  # 8 per 2 s, as GitLab's per-minute header
    assert slept == []  # the limit was in the 429's headers: no second window needed
    finder.wait_cooldown([result])
    assert slept and sum(slept) <= 2.6


def test_token_users_group_tokens_of_one_user(fake_gitlab: FakeGitLab, make_harvester):
    glh = make_harvester(tokens=["dev-token", "readonly-token"])
    assert glh.tokens_per_user() == 1 and len(set(glh.token_users)) == 2
    fake_gitlab.reset(scenario={"extends": "default",
                                "users": [{"id": 1, "username": "dev", "name": "Dev", "tokens": ["a", "b"]}]})
    glh = make_harvester(tokens=["a", "b"])
    assert glh.tokens_per_user() == 2 and glh.token_user_groups() == [[0, 1]]
    assert "share one user" in finder_for(glh).token_note()


def test_set_rate_limits_reaches_clients_already_created(make_harvester):
    glh = make_harvester(adjustable_limits=True)
    adapter = glh.connection.gl.session.get_adapter(glh.connection.gl.url)
    assert adapter.search_limiter is None
    glh.set_rate_limits(search_rpm=30, workers=3)
    assert adapter.search_limiter.rpm == 30 and glh.concurrency == 3


def test_advisor_proposes_limits_during_a_rate_limited_search(fake_gitlab: FakeGitLab, make_harvester, tmp_path):
    glh = make_harvester(workers=2, adjustable_limits=True)
    path = tmp_path / "idx.jsonl"
    glh.build_project_index(filename=str(path), per_page=5, branches="all", enforce_dump=True)
    fake_gitlab.set_rate_limits({"search": {"limit": 6, "period": 1}})
    advisor = LimitAdvisor(glh, status=quiet_status()).attach()
    _, hits = glh.search_keywords(load_index(path)[1], ["password"], options=ScanOptions(scan_branches="all"),
                                  session_file=io.StringIO())
    assert hits > 0 and fake_gitlab.api.rate_limits.throttled > 0
    assert advisor.limited[SEARCH] > 0
    pending = advisor.pending
    if pending is not None:  # a 429 right after the first successes can't be estimated
        assert pending.rpm[SEARCH] >= 1
        advisor.apply()
        assert glh.search_rpm == pending.rpm[SEARCH]
    advisor.detach()
    assert glh.limit_observer is None


@pytest.mark.parametrize("kinds", [(SEARCH,), (INDEX, SEARCH)])
def test_find_without_a_project_reports_an_error(make_harvester, kinds):
    results = finder_for(make_harvester(), max_requests=20).find(kinds, project_id=None)
    assert results[SEARCH].source == "error"
    assert recommend(results, current=Settings()).search_rpm == 0
