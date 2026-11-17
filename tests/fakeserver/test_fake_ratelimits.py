"""Per-user rate limits of the Fake GitLab (fakegitlab.ratelimits), WSGI-level, on a virtual clock."""

from __future__ import annotations

import pytest

from fakegitlab import load_scenario
from fakegitlab.api import GitLabApi
from fakegitlab.ratelimits import RateLimits
from tests.fakeserver.test_fake_api import call


class Clock:
    def __init__(self) -> None:
        self.now = 1_699_999_990.0  # 10 s into a minute

    def __call__(self) -> float:
        return self.now


def api_with(spec: dict, clock: Clock) -> GitLabApi:
    api = GitLabApi(load_scenario({"extends": "default", "rate_limits": spec}))
    api.rate_limits = RateLimits(spec, clock=clock)
    return api


def test_scenario_key_and_builtin_scenario():
    assert GitLabApi(load_scenario("ratelimited")).rate_limits
    assert not GitLabApi(load_scenario("default")).rate_limits


def test_api_limit_answers_429_with_gitlab_headers_and_resets_with_the_window():
    clock = Clock()
    api = api_with({"api": {"limit": 3, "period": 60}}, clock)
    for _ in range(3):
        assert call(api, "/api/v4/projects")[0] == 200
    status, body, headers, _ = call(api, "/api/v4/projects")
    assert status == 429 and body == {"message": "Retry later"}
    assert headers["Retry-After"] == "50"
    assert headers["RateLimit-Name"] == "throttle_authenticated_api"
    assert (headers["RateLimit-Limit"], headers["RateLimit-Observed"], headers["RateLimit-Remaining"]) == ("3", "4", "0")
    assert headers["RateLimit-Reset"] == "1700000040" and headers["RateLimit-ResetTime"].endswith("GMT")
    clock.now += 50
    assert call(api, "/api/v4/projects")[0] == 200
    assert api.rate_limits.throttled == 1


def test_search_limit_counts_only_search_and_sends_retry_after_only():
    clock = Clock()
    api = api_with({"search": {"limit": 2, "period": 60}}, clock)
    for _ in range(5):
        assert call(api, "/api/v4/projects")[0] == 200
    query = {"scope": "blobs", "search": "x"}
    assert call(api, "/api/v4/projects/101/search", query)[0] == 200
    assert call(api, "/api/v4/projects/101/search", query)[0] == 200
    status, body, headers, endpoint = call(api, "/api/v4/projects/101/search", query)
    assert (status, endpoint) == (429, "project_search")
    assert "too many times" in body["message"]
    assert headers["Retry-After"] == "50" and "RateLimit-Limit" not in headers


def test_limits_are_per_user_and_headers_on_success_on_request():
    clock = Clock()
    api = api_with({"api": {"limit": 1, "period": 30, "on_success": True}}, clock)
    status, _, headers, _ = call(api, "/api/v4/user")
    assert status == 200 and headers["RateLimit-Limit"] == "2"  # 1 per 30 s, scaled to a minute
    assert headers["RateLimit-Remaining"] == "0"
    assert call(api, "/api/v4/user")[0] == 429
    assert call(api, "/api/v4/user", token="readonly-token")[0] == 200


@pytest.mark.parametrize("spec", [{"other": {"limit": 1}}, {"api": {"limit": 0}}, {"api": {"limit": 1, "headers": "x"}}])
def test_invalid_specs(spec):
    with pytest.raises(ValueError):
        RateLimits(spec)
