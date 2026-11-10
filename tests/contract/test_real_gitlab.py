"""
Optional contract tests against a REAL GitLab instance.

They verify that the response shapes and headers the Fake GitLab emulates are
still what a real GitLab returns. They never run by default:

    GLH_CONTRACT_URL=https://gitlab.example.com \\
    GLH_CONTRACT_TOKEN=<read_api token> \\
    GLH_CONTRACT_PROJECT=<id or group/project with at least one branch> \\
    GLH_CONTRACT_TERM=<term that exists in that project's default branch> \\
    pytest -m contract tests/contract

Only read-only GET requests are issued. Use a dedicated low-privilege token.
"""

from __future__ import annotations

import os
from urllib.parse import quote

import pytest
import requests

from fakegitlab import load_scenario
from fakegitlab.api import GitLabApi

URL = os.environ.get("GLH_CONTRACT_URL", "").rstrip("/")
TOKEN = os.environ.get("GLH_CONTRACT_TOKEN", "")
PROJECT = os.environ.get("GLH_CONTRACT_PROJECT", "")
TERM = os.environ.get("GLH_CONTRACT_TERM", "")

pytestmark = pytest.mark.skipif(not (URL and TOKEN), reason="GLH_CONTRACT_URL / GLH_CONTRACT_TOKEN not set")

# Fields GitlabHarvester reads (glh/harvester.py: reduce_project_fields, scan_branch, get_branches).
HARVESTER_PROJECT_FIELDS = {"id", "web_url", "path_with_namespace", "default_branch", "empty_repo",
                            "created_at", "last_activity_at"}
HARVESTER_BLOB_FIELDS = {"path", "startline", "data"}
PAGINATION_HEADERS = {"X-Page", "X-Per-Page", "X-Next-Page", "X-Prev-Page"}

FAKE = GitLabApi(load_scenario("default"))
FAKE_BASE = "http://gitlab.test"


def get(path: str, **params) -> requests.Response:
    r = requests.get(f"{URL}/api/v4{path}", headers={"PRIVATE-TOKEN": TOKEN}, params=params, timeout=30)
    r.raise_for_status()
    return r


def project_path() -> str:
    if not PROJECT:
        pytest.skip("GLH_CONTRACT_PROJECT not set")
    return PROJECT if PROJECT.isdigit() else quote(PROJECT, safe="")


def assert_fake_fields_exist(real: dict, fake: dict, what: str, ignore: set[str] = frozenset()) -> None:
    """The fake must not invent fields that real GitLab does not return."""
    invented = set(fake) - set(real) - set(ignore)
    assert not invented, f"Fake {what} returns fields unknown to real GitLab: {sorted(invented)}"


def test_current_user():
    user = get("/user").json()
    assert {"id", "username", "web_url"} <= set(user)
    assert user["web_url"].startswith(URL)
    fake = FAKE.serialize_user(load_scenario("default").users[0], FAKE_BASE)
    assert_fake_fields_exist(user, fake, "user", ignore={"is_admin"})  # is_admin only for admins


def test_project_list_shape_and_pagination_headers():
    r = get("/projects", page=1, per_page=2, order_by="id", sort="desc")
    projects = r.json()
    assert isinstance(projects, list)
    assert PAGINATION_HEADERS <= set(r.headers)
    assert r.headers["X-Per-Page"] == "2"
    if projects:
        assert HARVESTER_PROJECT_FIELDS <= set(projects[0])
        fake = FAKE.serialize_project(load_scenario("default").project_by_id(201), FAKE_BASE)
        assert_fake_fields_exist(projects[0], fake, "project",
                                 ignore={"forked_from_project", "_links", "empty_repo", "archived"})
        ids = [p["id"] for p in projects]
        assert ids == sorted(ids, reverse=True)
    if r.headers.get("X-Next-Page"):
        assert 'rel="next"' in r.headers.get("Link", "")


def test_page_past_the_end_is_an_empty_list():
    r = get("/projects", page=100000, per_page=100)
    assert r.json() == []


def test_branches_are_sorted_by_name():
    branches = get(f"/projects/{project_path()}/repository/branches", per_page=100).json()
    names = [b["name"] for b in branches]
    assert names == sorted(names)
    if branches:
        fake = FAKE.serialize_branch(load_scenario("default").project_by_id(101), "main", FAKE_BASE)
        assert_fake_fields_exist(branches[0], fake, "branch")


def test_blob_search_shape():
    if not TERM:
        pytest.skip("GLH_CONTRACT_TERM not set")
    r = get(f"/projects/{project_path()}/search", scope="blobs", search=TERM, page=1, per_page=20)
    blobs = r.json()
    assert blobs, "expected at least one blob hit for GLH_CONTRACT_TERM"
    assert HARVESTER_BLOB_FIELDS <= set(blobs[0])
    assert isinstance(blobs[0]["startline"], int)
    fake = FAKE.search_blobs(load_scenario("default").project_by_id(101), "main",
                             {"a.txt": "password\n"}, "password")[0]
    assert_fake_fields_exist(blobs[0], fake, "blob")


def test_invalid_token_is_401():
    r = requests.get(f"{URL}/api/v4/user", headers={"PRIVATE-TOKEN": "invalid-contract-token"}, timeout=30)
    assert r.status_code == 401
    assert "message" in r.json()
