"""--index-rpm / --search-rpm against the Fake GitLab: which requests wait, per thread."""

from __future__ import annotations

import io

import pytest

from fakegitlab import FakeGitLab
from glh import ratelimit
from glh.planner import ScanOptions
from tests.helpers import load_index


@pytest.fixture
def waits(monkeypatch) -> list[float]:
    """Run the limiters on a virtual clock (real time + slept time) and record their waits."""
    import threading
    import time

    recorded: list[float] = []
    lock = threading.Lock()
    # Per thread: every client (thread) has its own limiter, as if alone.
    local = threading.local()

    def sleep(seconds: float) -> None:
        with lock:
            recorded.append(seconds)
        local.offset = getattr(local, "offset", 0.0) + seconds

    monkeypatch.setattr(ratelimit, "_sleep", sleep)
    monkeypatch.setattr(ratelimit, "_now", lambda: time.monotonic() + getattr(local, "offset", 0.0))
    return recorded


def index_of(make_harvester, tmp_path) -> list[dict]:
    path = tmp_path / "idx.jsonl"
    make_harvester().build_project_index(filename=str(path), per_page=2, branches="all", enforce_dump=True)
    return load_index(path)[1]


def search(glh, projects, terms=("password", "token")) -> int:
    _, hits = glh.search_keywords(projects, list(terms), options=ScanOptions(scan_branches="all"),
                                  session_file=io.StringIO())
    return hits


def test_search_rpm_spaces_only_search_requests(fake_gitlab: FakeGitLab, make_harvester, tmp_path, waits):
    projects = index_of(make_harvester, tmp_path)
    unlimited = search(make_harvester(), projects)
    fake_gitlab.clear_journal()

    glh = make_harvester(search_rpm=60)
    assert search(glh, projects) == unlimited  # same results
    n_search = len(fake_gitlab.api_requests("project_search"))
    assert n_search > 3
    # One client, one limiter: every search request but the first waits (no time passes: 1 s each).
    assert len(waits) == n_search - 1
    assert all(0.9 < w <= 1.0 for w in waits)


def test_index_rpm_spaces_listing_but_not_search(fake_gitlab: FakeGitLab, make_harvester, tmp_path, waits):
    glh = make_harvester(index_rpm=120)  # the /user request at login is the first one
    path = tmp_path / "idx.jsonl"
    glh.build_project_index(filename=str(path), per_page=2, branches="all", enforce_dump=True)
    n_listing = len(fake_gitlab.requests)
    assert len(waits) == n_listing - 1 and all(0.4 < w <= 0.5 for w in waits)

    waits.clear()
    search(glh, load_index(path)[1])
    assert waits == []


def test_every_worker_has_its_own_budget(fake_gitlab: FakeGitLab, make_harvester, tmp_path, waits):
    projects = index_of(make_harvester, tmp_path)
    fake_gitlab.clear_journal()
    fake_gitlab.add_fault({"match": {"path": "/search$"}, "response": {"delay": 0.05}})

    glh = make_harvester(workers=3, search_rpm=60)
    search(glh, projects)

    n_search = len(fake_gitlab.api_requests("project_search"))
    # The first request of every worker that got work goes at once.
    assert n_search - 3 <= len(waits) < n_search - 1


def test_search_plan_names_the_limits(make_harvester, tmp_path, waits, capsys, monkeypatch):
    from glh.utils import terminal_utils
    from tests.helpers import FakeStream

    projects = index_of(make_harvester, tmp_path)
    err = FakeStream(False)
    monkeypatch.setattr(terminal_utils, "STATUS", terminal_utils.StatusLine(err, ticker=False))
    search(make_harvester(workers=2, index_rpm=300, search_rpm=30), projects, terms=["password"])
    assert "2 workers, rate limit: search 30/min, other API 300/min per worker\n" in err.getvalue()


def test_jitter_delays_every_request(fake_gitlab: FakeGitLab, make_harvester, tmp_path, waits):
    projects = index_of(make_harvester, tmp_path)
    waits.clear()
    fake_gitlab.clear_journal()

    glh = make_harvester(workers=2, jitter=(0.01, 0.05))
    n_before = len(fake_gitlab.requests)  # the login check of the new client
    search(glh, projects)

    n_requests = len(fake_gitlab.requests)
    assert n_requests > 3
    # Every request (login, every search page, in every worker) got its own delay.
    assert len(waits) == n_requests and n_before == 1
    assert all(0.01 <= w <= 0.05 for w in waits)
    assert len(set(waits)) > 1  # random, not a fixed rhythm


def test_search_plan_names_the_jitter(make_harvester, tmp_path, waits, monkeypatch):
    from glh.utils import terminal_utils
    from tests.helpers import FakeStream

    projects = index_of(make_harvester, tmp_path)
    err = FakeStream(False)
    monkeypatch.setattr(terminal_utils, "STATUS", terminal_utils.StatusLine(err, ticker=False))
    search(make_harvester(search_rpm=30, jitter=(0.0, 0.03)), projects, terms=["password"])
    assert ", rate limit: search 30/min per worker, jitter 0-0.03s\n" in err.getvalue()


# --------------------------------------------------------------------------- User-Agent


def user_agents_sent(fake_gitlab: FakeGitLab) -> list[str]:
    return [next(v for k, v in r.headers.items() if k.lower() == "user-agent") for r in fake_gitlab.requests]


def test_fixed_user_agent_on_every_request(fake_gitlab: FakeGitLab, make_harvester, tmp_path):
    projects = index_of(make_harvester, tmp_path)
    assert all(ua.startswith("python-gitlab/") for ua in user_agents_sent(fake_gitlab))  # default
    fake_gitlab.clear_journal()

    search(make_harvester(workers=2, user_agents=["Mozilla/5.0 (X11; Linux x86_64)"]), projects)
    sent = user_agents_sent(fake_gitlab)
    assert len(sent) > 3 and set(sent) == {"Mozilla/5.0 (X11; Linux x86_64)"}  # login check included


def test_random_user_agent_per_request(fake_gitlab: FakeGitLab, make_harvester, tmp_path):
    projects = index_of(make_harvester, tmp_path)
    fake_gitlab.clear_journal()
    agents = [f"agent-{i}/1.0" for i in range(4)]

    search(make_harvester(workers=2, user_agents=agents), projects)
    sent = user_agents_sent(fake_gitlab)
    assert set(sent) <= set(agents)
    assert len(set(sent)) > 1  # chosen per request, not once per run


def test_cli_user_agent_file(fake_gitlab: FakeGitLab, run_cli, tmp_path):
    (tmp_path / "ua.txt").write_text("# test agents\nagent-a/1.0\nagent-b/2.0\n", encoding="utf-8")
    proc = run_cli("-u", fake_gitlab.url, "-t", fake_gitlab.token, "-s", "password", "-b", "all",
                   "--user-agent-file", "ua.txt", check=True)
    assert "random User-Agent of 2" in proc.stderr
    assert set(user_agents_sent(fake_gitlab)) <= {"agent-a/1.0", "agent-b/2.0"}

    bad = run_cli("-u", fake_gitlab.url, "-t", fake_gitlab.token, "-s", "password", "--user-agent-file", "none.txt")
    assert bad.returncode != 0 and "Cannot read the User-Agent file" in bad.stderr
