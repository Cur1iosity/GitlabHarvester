"""Instance Project Index building: pagination, branches and failure handling."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import requests

from fakegitlab import FakeGitLab
from tests.helpers import (
    DEFAULT_BRANCH_OF,
    DEFAULT_BRANCHES,
    DEFAULT_PROJECT_IDS_DESC,
    capture_logs,
    load_index,
)


@pytest.mark.parametrize(("per_page", "requests_expected"), [(3, 4), (4, 4), (9, 2), (100, 2)])
def test_project_pagination_until_empty_page(fake_gitlab: FakeGitLab, make_harvester, tmp_path: Path,
                                             per_page, requests_expected):
    out = tmp_path / "idx.jsonl"
    make_harvester().build_project_index(per_page=per_page, filename=str(out))

    meta, projects = load_index(out)
    assert [p["id"] for p in projects] == DEFAULT_PROJECT_IDS_DESC
    assert meta["is_completed"] is True and meta["projects_count"] == 9 and meta["per_page"] == per_page
    pages = [int(r.arg("page")) for r in fake_gitlab.api_requests("projects")]
    assert pages == list(range(1, requests_expected + 1))


def test_index_record_structure(fake_gitlab: FakeGitLab, make_harvester, tmp_path: Path):
    out = tmp_path / "idx.jsonl"
    make_harvester().build_project_index(filename=str(out))
    meta, projects = load_index(out)

    assert set(meta) >= {"type", "source", "timestamp_utc", "projects_count", "elapsed_seconds", "order_by", "sort",
                         "per_page", "is_completed", "branches"}
    assert meta["source"] == fake_gitlab.url.split("://")[1].replace(".", "_").replace(":", "_")
    by_id = {p["id"]: p for p in projects}
    for pid, p in by_id.items():
        assert set(p) == {"id", "web_url", "path_with_namespace", "default_branch", "empty_repo",
                          "forked_from_project", "created_at", "last_activity_at", "branches"}
        assert p["default_branch"] == DEFAULT_BRANCH_OF[pid]
        assert p["branches"] == ([DEFAULT_BRANCH_OF[pid]] if DEFAULT_BRANCH_OF[pid] else [])
    assert by_id[201]["forked_from_project"] == {"id": 101}
    assert by_id[203]["forked_from_project"] == {"id": 999}
    assert by_id[101]["forked_from_project"] is False
    assert by_id[104]["empty_repo"] is True
    # "default" branch mode never calls the branches endpoint.
    assert fake_gitlab.api_requests("branches") == []


def test_index_with_all_branches(fake_gitlab: FakeGitLab, make_harvester, tmp_path: Path):
    out = tmp_path / "idx.jsonl"
    make_harvester().build_project_index(filename=str(out), branches="all", branches_per_page=2)
    meta, projects = load_index(out)

    assert meta["branches"] == "all"
    assert {p["id"]: p["branches"] for p in projects} == DEFAULT_BRANCHES
    # Empty repository is not queried; 4 branches with per_page=2 -> pages 1,2,3(empty).
    assert not fake_gitlab.api_requests(path=r"/projects/104/")
    assert [r.arg("page") for r in fake_gitlab.api_requests("branches", path=r"/projects/101/")] == ["1", "2", "3"]


def test_index_with_branch_limit(fake_gitlab: FakeGitLab, make_harvester, tmp_path: Path):
    out = tmp_path / "idx.jsonl"
    make_harvester().build_project_index(filename=str(out), branches=2)
    _, projects = load_index(out)
    by_id = {p["id"]: p["branches"] for p in projects}
    assert by_id[101] == ["develop", "feature/login-v2"]  # first N in GitLab (name) order
    assert by_id[102] == ["main"]


@pytest.mark.scenario("empty")
def test_empty_instance(fake_gitlab: FakeGitLab, make_harvester, tmp_path: Path):
    out = tmp_path / "idx.jsonl"
    make_harvester().build_project_index(filename=str(out), branches="all")
    meta, projects = load_index(out)
    assert projects == [] and meta["projects_count"] == 0 and meta["is_completed"] is True


def test_existing_index_is_reused_unless_forced(fake_gitlab: FakeGitLab, make_harvester, tmp_path: Path):
    out = tmp_path / "idx.jsonl"
    glh = make_harvester()
    glh.build_project_index(filename=str(out))
    fake_gitlab.clear_journal()

    glh.build_project_index(filename=str(out))
    assert fake_gitlab.api_requests("projects") == []

    glh.build_project_index(filename=str(out), enforce_dump=True)
    assert fake_gitlab.api_requests("projects")


# --------------------------------------------------------------------------- failures


@pytest.mark.parametrize(
    "response",
    [
        {"status": 500, "json": {"message": "500 Internal Server Error"}},
        {"status": 502, "body": "<html>Bad Gateway</html>"},
        {"status": 503, "json": {"message": "503 Service Unavailable"}},
        {"status": 403, "json": {"message": "403 Forbidden"}},
        {"status": 200, "body": "[{\"id\": 1,"},  # malformed JSON -> GitlabParsingError
    ],
    ids=["500", "502", "503", "403", "invalid-json"],
)
def test_error_on_intermediate_page_yields_incomplete_index(fake_gitlab: FakeGitLab, make_harvester, tmp_path: Path,
                                                            response):
    """Regression for the is_completed=True-after-GitlabError defect."""
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/projects$", "query": {"page": "2"}}, "response": response})
    out = tmp_path / "idx.jsonl"
    glh = make_harvester()
    logs = capture_logs(glh)

    glh.build_project_index(per_page=3, filename=str(out), branches="all")

    meta, projects = load_index(out)
    assert meta["is_completed"] is False
    assert meta["projects_count"] == 3
    assert [p["id"] for p in projects] == DEFAULT_PROJECT_IDS_DESC[:3]
    assert all("branches" in p for p in projects)  # enrichment still ran on what was fetched
    assert any("wasn't complete" in m for m in logs.messages(logging.ERROR))


def test_rate_limit_on_intermediate_page_is_retried(fake_gitlab: FakeGitLab, make_harvester, tmp_path: Path,
                                                    no_retry_sleep):
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/projects$", "query": {"page": "2"}}, "times": 1,
                           "response": {"status": 429, "headers": {"Retry-After": "3"}, "json": {"message": "slow"}}})
    out = tmp_path / "idx.jsonl"
    make_harvester().build_project_index(per_page=3, filename=str(out))

    meta, projects = load_index(out)
    assert meta["is_completed"] is True and len(projects) == 9
    assert no_retry_sleep == [3.0]
    assert [(r.arg("page"), r.status) for r in fake_gitlab.api_requests("projects")][:3] == [
        ("1", 200), ("2", 429), ("2", 200)]


def test_persistent_rate_limit_gives_up_after_max_retries(fake_gitlab: FakeGitLab, make_harvester, tmp_path: Path,
                                                          no_retry_sleep):
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/projects$"},
                           "response": {"status": 429, "headers": {"Retry-After": "1"}}})
    out = tmp_path / "idx.jsonl"
    make_harvester().build_project_index(filename=str(out))
    meta, projects = load_index(out)
    assert meta["is_completed"] is False and projects == []
    assert len(no_retry_sleep) == 10  # python-gitlab default max_retries


def test_listing_timeout_aborts_and_marks_index_incomplete(fake_gitlab: FakeGitLab, make_harvester, tmp_path: Path):
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/projects$", "query": {"page": "2"}},
                           "response": {"delay": 3}})
    out = tmp_path / "idx.jsonl"
    with pytest.raises(requests.exceptions.Timeout):
        make_harvester(timeout=1).build_project_index(per_page=3, filename=str(out))
    meta, projects = load_index(out)
    assert meta["is_completed"] is False and len(projects) == 3


def test_branch_listing_errors_are_isolated_per_project(fake_gitlab: FakeGitLab, make_harvester, tmp_path: Path):
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/projects/102/repository/branches$"},
                           "response": {"status": 503, "json": {"message": "503"}}})
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/projects/101/repository/branches$", "query": {"page": "2"}},
                           "response": {"status": 500, "json": {"message": "500"}}})
    out = tmp_path / "idx.jsonl"
    glh = make_harvester()
    logs = capture_logs(glh)
    glh.build_project_index(filename=str(out), branches="all", branches_per_page=2)

    by_id = {p["id"]: p["branches"] for p in load_index(out)[1]}
    assert by_id[102] == []
    assert by_id[101] == ["develop", "feature/login-v2"]  # first page kept
    assert by_id[103] == DEFAULT_BRANCHES[103]
    assert sum("branch list wasn't complete" in m for m in logs.messages(logging.ERROR)) == 2


def test_branch_listing_timeout_does_not_abort_index(fake_gitlab: FakeGitLab, make_harvester, tmp_path: Path):
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/projects/103/repository/branches$"}, "times": 1,
                           "response": {"delay": 3}})
    out = tmp_path / "idx.jsonl"
    make_harvester(timeout=1).build_project_index(filename=str(out), branches="all")
    by_id = {p["id"]: p["branches"] for p in load_index(out)[1]}
    assert by_id[103] == []
    assert by_id[101] == DEFAULT_BRANCHES[101]
