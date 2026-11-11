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
