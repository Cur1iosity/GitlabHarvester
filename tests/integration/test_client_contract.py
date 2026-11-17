"""
Wire-level contract between GitlabHarvester/python-gitlab and the GitLab API.

These tests pin down exactly which endpoints, parameters and headers the
current python-gitlab version emits, so changes in either the harvester or the
library surface as explicit test failures.
"""

from __future__ import annotations

import warnings

import gitlab
import gitlab.exceptions
import pytest

from fakegitlab import FakeGitLab
from glh.domain.planning import ScanOptions
from glh.exceptions import GitlabHarvesterError

EXPECTED_ENDPOINTS = {"user", "projects", "branches", "project_search"}


def test_auth_sends_private_token_once(fake_gitlab: FakeGitLab, make_harvester):
    make_harvester()
    reqs = fake_gitlab.requests
    assert [(r.method, r.path) for r in reqs] == [("GET", "/api/v4/user")]
    assert reqs[0].headers["Private-Token"] == fake_gitlab.token
    assert reqs[0].headers["User-Agent"].startswith("python-gitlab/")


def test_no_base_url_warning_from_python_gitlab(fake_gitlab: FakeGitLab):
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        gl = gitlab.Gitlab(fake_gitlab.url, private_token=fake_gitlab.token)
        gl.auth()
        gl.projects.list(get_all=True, per_page=2)  # follows Link headers
    assert gl.user.username == "harvester-bot"


def test_full_workflow_uses_only_known_endpoints_and_parameters(fake_gitlab: FakeGitLab, make_harvester, tmp_path):
    glh = make_harvester()
    index = glh.build_project_index(per_page=4, filename=str(tmp_path / "idx.jsonl"), branches="all",
                                    branches_per_page=50)
    projects = glh.load_projects_from_file(index)["projects"]
    glh.search_keywords(projects, ["password"], options=ScanOptions(scan_branches="default"))

    assert fake_gitlab.unmatched_requests() == []
    assert {r.endpoint for r in fake_gitlab.requests} == EXPECTED_ENDPOINTS
    assert all(r.method == "GET" for r in fake_gitlab.requests)
    assert all(r.headers.get("Private-Token") == fake_gitlab.token for r in fake_gitlab.requests)

    for r in fake_gitlab.api_requests("projects"):
        assert r.query == {"page": [r.arg("page")], "per_page": ["4"], "order_by": ["id"], "sort": ["desc"]}
    for r in fake_gitlab.api_requests("branches"):
        assert set(r.query) == {"page", "per_page"} and r.arg("per_page") == "50"
    for r in fake_gitlab.api_requests("project_search"):
        # Regression: a stray "project=<Project object repr>" parameter used to be sent.
        assert set(r.query) == {"scope", "search", "ref", "page", "per_page"}
        assert (r.arg("scope"), r.arg("search"), r.arg("per_page")) == ("blobs", "password", "100")


def test_special_characters_are_transported_verbatim(fake_gitlab: FakeGitLab, make_harvester):
    glh = make_harvester()
    project = {"id": 103, "web_url": f"{fake_gitlab.url}/acme/frontend/web-app", "default_branch": "master",
               "branches": ["fix/#42-login", "ünïcode-ветка"], "empty_repo": False, "forked_from_project": False}
    glh.search_keywords([project], ['p@ss w0rd!', "$SECRET_VAR"], options=ScanOptions(scan_branches="all"))

    seen = {(r.arg("ref"), r.arg("search")) for r in fake_gitlab.api_requests("project_search")}
    assert ("fix/#42-login", "$SECRET_VAR") in seen
    assert ("ünïcode-ветка", "p@ss w0rd!") in seen


@pytest.mark.parametrize("token", ["wrong-token", ""])
def test_invalid_token_fails_at_construction(fake_gitlab: FakeGitLab, make_harvester, token):
    if not token:
        # Empty token: the harvester skips client creation entirely.
        assert make_harvester(token=token).connection.gl is None
        return
    # python-gitlab raises GitlabAuthenticationError; the harvester turns it into one clear message.
    with pytest.raises(GitlabHarvesterError, match=r"The token failed to authenticate .*HTTP 401 Unauthorized"):
        make_harvester(token=token)


@pytest.mark.parametrize("status", [403, 500])
def test_auth_endpoint_errors_propagate(fake_gitlab: FakeGitLab, make_harvester, status):
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/user$"}, "response": {"status": status, "json": {"message": "x"}}})
    with pytest.raises(GitlabHarvesterError, match=rf"failed to authenticate .*HTTP {status}"):
        make_harvester()


def test_rate_limited_auth_is_retried_with_retry_after(fake_gitlab: FakeGitLab, make_harvester, no_retry_sleep):
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/user$"}, "times": 2,
                           "response": {"status": 429, "headers": {"Retry-After": "7"}}})
    make_harvester()
    assert no_retry_sleep == [7.0, 7.0]
    assert [r.status for r in fake_gitlab.requests] == [429, 429, 200]


def test_oneshot_handlers_override_the_data_driven_api(fake_gitlab: FakeGitLab):
    """Tests can still use the native pytest-httpserver API for ad-hoc responses."""
    fake_gitlab.httpserver.expect_oneshot_request("/api/v4/user").respond_with_json(
        {"id": 42, "username": "override", "web_url": f"{fake_gitlab.url}/override"}
    )
    gl = gitlab.Gitlab(fake_gitlab.url, private_token="anything")
    gl.auth()
    assert gl.user.username == "override"
    with pytest.raises(gitlab.exceptions.GitlabAuthenticationError):
        gl.auth()  # one-shot consumed; the fake rejects the unknown token


def test_file_filters_and_downloads_use_only_known_endpoints_and_parameters(fake_gitlab: FakeGitLab, make_harvester,
                                                                            tmp_path):
    from glh.output.downloads import FileDownloader
    from glh.output.layout import OutputLayout
    from glh.output.sink import SearchOutput

    glh = make_harvester()
    index = glh.build_project_index(filename=str(tmp_path / "idx.jsonl"))
    projects = glh.load_projects_from_file(index)["projects"]
    downloader = FileDownloader(OutputLayout(tmp_path / "s.jsonl", ["password"]), "20260101000000")
    glh.search_keywords(projects, ["password"], options=ScanOptions(filename="settings*", extension=".py"),
                        output=SearchOutput(downloader=downloader))

    assert fake_gitlab.unmatched_requests() == []
    assert {r.endpoint for r in fake_gitlab.requests} == {"user", "projects", "project_search", "file_raw"}
    for r in fake_gitlab.api_requests("project_search"):
        assert set(r.query) == {"scope", "search", "ref", "page", "per_page"}
        assert r.arg("search") == "password filename:settings* extension:py"
    raws = fake_gitlab.api_requests("file_raw")
    assert len(raws) == 2
    for r in raws:
        assert r.method == "GET" and r.query == {"ref": ["main"]}
        assert r.headers.get("Private-Token") == fake_gitlab.token
