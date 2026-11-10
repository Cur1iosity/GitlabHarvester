"""Time filters on three levels: index build (API), indexed projects, files with hits (commits API)."""

from __future__ import annotations

import io
import json
import logging
from datetime import datetime, timezone

import pytest

from fakegitlab import FakeGitLab
from glh.planner import ScanOptions
from tests.helpers import Session, capture_logs, load_index


def utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


def run_search(glh, projects, terms, **opts):
    fp = io.StringIO()
    _, hits = glh.search_keywords(projects, terms, options=ScanOptions(**opts), session_file=fp)
    return hits, Session([json.loads(x) for x in fp.getvalue().splitlines()])


def paths(session: Session) -> set[tuple[int, str]]:
    return {(h["project_id"], h["url"].split("/-/tree/", 1)[1].split("#", 1)[0]) for h in session.hits()}


@pytest.fixture
def index(make_harvester, tmp_path):
    glh = make_harvester()
    filename = glh.build_project_index(filename=str(tmp_path / "idx.jsonl"))
    return load_index(filename)[1]


# --------------------------------------------------------------------------- 1. index build


def test_index_window_is_an_api_filter(fake_gitlab: FakeGitLab, make_harvester, tmp_path):
    glh = make_harvester()
    glh.build_project_index(filename=str(tmp_path / "idx.jsonl"),
                            last_activity_after=utc(2024, 6, 1), last_activity_before=utc(2024, 6, 4))

    meta, projects = load_index(tmp_path / "idx.jsonl")
    assert [p["id"] for p in projects] == [202, 201, 101]  # activity 06-03, 06-02, 06-01T12:00
    assert meta["projects_count"] == 3
    assert (meta["last_activity_after"], meta["last_activity_before"]) == ("2024-06-01T00:00:00Z", "2024-06-04T00:00:00Z")
    for r in fake_gitlab.api_requests("projects"):
        assert r.arg("last_activity_after") == "2024-06-01T00:00:00Z"
        assert r.arg("last_activity_before") == "2024-06-04T00:00:00Z"


def test_index_without_window_sends_no_activity_parameters(fake_gitlab: FakeGitLab, make_harvester, tmp_path):
    make_harvester().build_project_index(filename=str(tmp_path / "idx.jsonl"))
    meta, projects = load_index(tmp_path / "idx.jsonl")
    assert len(projects) == 9 and meta["last_activity_after"] is None and meta["last_activity_before"] is None
    assert all(set(r.query) == {"page", "per_page", "order_by", "sort"} for r in fake_gitlab.api_requests("projects"))


def test_reusing_an_index_built_for_another_window_warns(fake_gitlab: FakeGitLab, make_harvester, tmp_path):
    filename = str(tmp_path / "idx.jsonl")
    make_harvester().build_project_index(filename=filename, last_activity_after=utc(2024, 6, 1))
    fake_gitlab.clear_journal()

    glh = make_harvester()
    logs = capture_logs(glh)
    glh.build_project_index(filename=filename)  # no window now: the filtered index is reused
    assert fake_gitlab.api_requests("projects") == []
    warning = " ".join(logs.messages(logging.WARNING))
    assert "was built for projects active since 2024-06-01" in warning and "--dump-projects" in warning

    logs.records.clear()
    glh.build_project_index(filename=filename, last_activity_after=utc(2024, 6, 1))  # same window: silent
    assert logs.messages(logging.WARNING) == []


# --------------------------------------------------------------------------- 2. projects of an existing index


def test_active_window_on_an_existing_index(fake_gitlab: FakeGitLab, make_harvester, index, capsys):
    hits, session = run_search(make_harvester(), index, ["password"],
                               started_from=utc(2024, 5, 1), active_before=utc(2024, 6, 2))
    searched = {int(r.path.split("/")[4]) for r in fake_gitlab.api_requests("project_search")}
    assert searched == {101, 102}  # activity 06-01T12:00 and 05-20: inside the window
    assert set(session.project_ids()) == {101}  # 102 has no "password"
    err = capsys.readouterr().err
    assert "2 of 9 projects" in err
    assert "(skipped: 1 empty, 1 inactive since 2024-05-01, 5 active after 2024-06-02)" in err


def test_active_before_alone(make_harvester, index, capsys):
    run_search(make_harvester(), index, ["token"], active_before=utc(2024, 6, 2))
    err = capsys.readouterr().err
    # 101 (06-01), 102 (05-20), 105 (02-03) remain; 104 is empty.
    assert "Search plan: 1 term, 3 of 9 projects" in err
    assert "5 active after 2024-06-02" in err


# --------------------------------------------------------------------------- 3. files with hits


def test_file_changed_after_drops_hits_in_old_files(fake_gitlab: FakeGitLab, make_harvester, index):
    _, unfiltered = run_search(make_harvester(), index, ["password"])
    fake_gitlab.clear_journal()
    _, filtered = run_search(make_harvester(), index, ["password"], file_changed_after=utc(2024, 3, 1))

    # deploy/env.example last changed 2024-01-20 (also in the fork 201 that inherited it).
    dropped = {(101, "main/deploy/env.example"), (201, "main/deploy/env.example")}
    assert dropped <= paths(unfiltered)
    assert paths(filtered) == paths(unfiltered) - dropped
    assert (101, "main/config/settings.py") in paths(filtered)  # changed 2024-03-15

    checks = fake_gitlab.api_requests("commits")
    assert checks and all(r.arg("since") == "2024-03-01T00:00:00Z" and r.arg("until") is None for r in checks)
    assert all(r.arg("per_page") == "1" for r in checks)


def test_file_changed_before_keeps_only_old_files(make_harvester, index):
    _, session = run_search(make_harvester(), index, ["password"], file_changed_before=utc(2024, 2, 1))
    assert paths(session) == {(101, "main/deploy/env.example"), (201, "main/deploy/env.example")}


def test_file_checks_are_cached_across_terms(fake_gitlab: FakeGitLab, make_harvester, index, capsys):
    # settings.py matches both terms in 101 and 201: still one commits request per (project, branch, file).
    run_search(make_harvester(), index, ["password", "api_key"], file_changed_after=utc(2024, 3, 1))
    keys = [(r.path, r.arg("ref_name"), r.arg("path")) for r in fake_gitlab.api_requests("commits")]
    assert len(keys) == len(set(keys))
    assert ("/api/v4/projects/101/repository/commits", "main", "config/settings.py") in keys
    err = capsys.readouterr().err
    assert "files changed since 2024-03-01" in err and f"{len(keys)} file checks" in err


def test_failed_file_check_keeps_the_hits(fake_gitlab: FakeGitLab, make_harvester, index):
    fake_gitlab.add_fault({"match": {"path": "/repository/commits$"}, "response": {"status": 500, "json": {"message": "500"}}})
    _, unfiltered = run_search(make_harvester(), index, ["password"])
    glh = make_harvester()
    logs = capture_logs(glh)
    _, filtered = run_search(glh, index, ["password"], file_changed_after=utc(2024, 3, 1))
    assert paths(filtered) == paths(unfiltered)
    assert any("keeping its hits" in m for m in logs.messages(logging.WARNING))


def test_file_filter_with_workers_matches_sequential(make_harvester, index):
    window = {"file_changed_after": utc(2024, 3, 1), "file_changed_before": utc(2024, 6, 3)}
    _, sequential = run_search(make_harvester(), index, ["password", "api_key"], scan_branches="all", **window)
    _, parallel = run_search(make_harvester(workers=4), index, ["password", "api_key"], scan_branches="all", **window)
    assert sorted((h["term"], h["url"]) for h in parallel.hits()) == sorted((h["term"], h["url"]) for h in sequential.hits())
