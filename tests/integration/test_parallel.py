"""--workers > 1: same results as a sequential run, real concurrency, safe checkpoints."""

from __future__ import annotations

import io
import json
import logging
import re
import threading
from collections import Counter
from pathlib import Path

import pytest

from fakegitlab import FakeGitLab
from glh import GitlabHarvester
from glh.planner import ScanOptions
from tests.helpers import Session, load_index

TERMS = ["password", "api_key", "token", "nothing-matches-this"]


def build_index(make_harvester, path: Path, workers: int) -> list[dict]:
    glh = make_harvester(workers=workers)
    glh.build_project_index(filename=str(path), per_page=2, branches="all", enforce_dump=True)
    return load_index(path)[1]


def run_search(glh: GitlabHarvester, projects, terms=TERMS, **opts):
    fp = io.StringIO()
    results, hits = glh.search_keywords(projects, terms, options=ScanOptions(**opts), session_file=fp)
    return results, hits, Session([json.loads(x) for x in fp.getvalue().splitlines()])


def hit_urls(session: Session) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for h in session.hits():
        out.setdefault(h["term"], []).append(h["url"])
    return {k: sorted(v) for k, v in out.items()}


# --------------------------------------------------------------------------- index


def test_parallel_index_is_identical_to_sequential(fake_gitlab: FakeGitLab, make_harvester, tmp_path):
    sequential = build_index(make_harvester, tmp_path / "seq.jsonl", workers=1)
    fake_gitlab.clear_journal()
    parallel = build_index(make_harvester, tmp_path / "par.jsonl", workers=4)

    assert parallel == sequential  # same projects, same order, same branches
    meta = load_index(tmp_path / "par.jsonl")[0]
    assert meta["is_completed"] is True and meta["projects_count"] == 9
    # Pages are fetched ahead in parallel: a few extra empty pages, never a missing one.
    pages = sorted(int(r.arg("page")) for r in fake_gitlab.api_requests("projects"))
    assert pages[:6] == [1, 2, 3, 4, 5, 6] and len(set(pages)) == len(pages)


def test_parallel_listing_error_keeps_earlier_pages_in_order(fake_gitlab: FakeGitLab, make_harvester, tmp_path):
    sequential = build_index(make_harvester, tmp_path / "seq.jsonl", workers=1)
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/projects$", "query": {"page": "3"}},
                           "response": {"status": 500, "json": {"message": "500 Internal Server Error"}}})
    glh = make_harvester(workers=4)
    glh.fetch_projects(per_page=2, filename=str(tmp_path / "par.jsonl"))

    meta, projects = load_index(tmp_path / "par.jsonl")
    assert meta["is_completed"] is False
    assert [p["id"] for p in projects] == [p["id"] for p in sequential[:4]]  # pages 1-2 only, in order


# --------------------------------------------------------------------------- search


@pytest.fixture
def index(make_harvester, tmp_path) -> list[dict]:
    return build_index(make_harvester, tmp_path / "idx.jsonl", workers=1)


@pytest.mark.parametrize("opts", [
    {"scan_branches": "all", "forks_mode": "branch-diff"},
    {"scan_branches": "default", "forks_mode": "include"},
])
def test_parallel_search_finds_exactly_what_sequential_finds(fake_gitlab: FakeGitLab, make_harvester, index, opts):
    seq_results, seq_hits, seq = run_search(make_harvester(workers=1), index, **opts)
    seq_requests = Counter((r.path, r.arg("ref"), r.arg("search")) for r in fake_gitlab.api_requests("project_search"))
    fake_gitlab.clear_journal()

    par_results, par_hits, par = run_search(make_harvester(workers=6), index, **opts)
    par_requests = Counter((r.path, r.arg("ref"), r.arg("search")) for r in fake_gitlab.api_requests("project_search"))

    assert par_hits == seq_hits > 0
    assert hit_urls(par) == hit_urls(seq)
    assert par_requests == seq_requests
    assert par_results == seq_results  # returned results are sorted back into index order
    assert [r["term"] for r in par.of_type("keyword_done")] == TERMS
    assert [r["hit_counter"] for r in par.of_type("keyword_done")] == \
           [r["hit_counter"] for r in seq.of_type("keyword_done")]


def test_checkpoint_comes_after_every_record_of_its_term(fake_gitlab: FakeGitLab, make_harvester, index):
    # Make the first project's searches slow so later work overtakes it.
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/projects/301/search$"}, "response": {"delay": 0.2}})
    _, _, session = run_search(make_harvester(workers=6), index, scan_branches="all")

    for term in TERMS:
        done_at = next(i for i, r in enumerate(session.records)
                       if r.get("type") == "keyword_done" and r["term"] == term)
        records_at = [i for i, r in enumerate(session.records) if r.get("term") == term and "result" in r]
        assert all(i < done_at for i in records_at), term


def test_workers_run_concurrently_with_their_own_clients(fake_gitlab: FakeGitLab, make_harvester, index,
                                                         monkeypatch):
    fake_gitlab.add_fault({"match": {"path": "/search$"}, "response": {"delay": 0.05}})
    glh = make_harvester(workers=4)
    lock = threading.Lock()
    state = {"now": 0, "peak": 0}
    clients: set[int] = set()
    original = GitlabHarvester._search_branch

    def tracked(self, task):
        with lock:
            state["now"] += 1
            state["peak"] = max(state["peak"], state["now"])
            clients.add(id(self._gl))
        try:
            return original(self, task)
        finally:
            with lock:
                state["now"] -= 1

    monkeypatch.setattr(GitlabHarvester, "_search_branch", tracked)
    fake_gitlab.clear_journal()
    run_search(glh, index, terms=["password"], scan_branches="all")

    assert state["peak"] > 1
    assert len(clients) > 1 and id(glh._gl_main) not in clients  # one python-gitlab client per worker
    assert fake_gitlab.api_requests("user") == []  # workers don't re-authenticate


def test_parallel_progress_counts_planned_projects(fake_gitlab: FakeGitLab, make_harvester, index, monkeypatch):
    import re

    from glh.utils import terminal_utils
    from tests.helpers import FakeStream

    tty = FakeStream(True)
    monkeypatch.setattr(terminal_utils, "STATUS",
                        terminal_utils.StatusLine(tty, columns=lambda: 400, ticker=False, refresh_interval=0))
    run_search(make_harvester(workers=4), index, terms=["password", "token"], scan_branches="all",
               forks_mode="skip")

    out = tty.getvalue()
    assert "Search plan: 2 terms, 5 of 9 projects" in out and ", 4 workers" in out
    counts = {m.group(2) for m in re.finditer(r"(\d+)/(\d+) projects", out)}
    assert counts == {"5"}
    assert "Search finished: 2 terms x 5 projects" in out


# --------------------------------------------------------------------------- slow last task


def test_status_line_shows_the_running_task_not_the_last_finished_one(fake_gitlab: FakeGitLab, make_harvester,
                                                                       index, monkeypatch):
    """Regression: with workers > 1 a slow last project looked hung (status showed a finished project)."""
    from glh.utils import terminal_utils
    from tests.helpers import FakeStream

    tty = FakeStream(True)
    status = terminal_utils.StatusLine(tty, columns=lambda: 400, tick_interval=0.05, refresh_interval=0)
    monkeypatch.setattr(terminal_utils, "STATUS", status)
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/projects/301/search$"}, "response": {"delay": 1.0}})
    glh = make_harvester(workers=4)
    glh.slow_task_report = 0.3

    run_search(glh, index, terms=["password"], scan_branches="default")

    out = tty.getvalue()
    frames = [f for f in out.split("\r") if "projects (" in f]
    slow = "ops/infra/terraform/modules @ main"
    assert any(f" {slow}, 0:00" in f for f in frames), frames  # shown while it runs
    assert re.search(rf"Still searching 'password' in {slow}: running for 0\.\ds\n", out), out
    assert glh._active.snapshot() == []


def test_rate_limit_waits_are_reported(fake_gitlab: FakeGitLab, make_harvester, index, no_retry_sleep):
    from tests.helpers import capture_logs

    fake_gitlab.add_fault({"match": {"path": "/search$"}, "times": 3,
                           "response": {"status": 429, "headers": {"Retry-After": "7"}}})
    glh = make_harvester(workers=4)
    logs = capture_logs(glh)

    _, hits, _ = run_search(glh, index, terms=["password"], scan_branches="default")

    assert hits > 0 and no_retry_sleep == [7.0, 7.0, 7.0]
    warnings = [m for m in logs.messages(logging.WARNING) if "rate limit" in m]
    assert len(warnings) == 1  # throttled
    assert "HTTP 429" in warnings[0] and "/search" in warnings[0] and "7.0s" in warnings[0]
    assert glh._rate_limited == 3
