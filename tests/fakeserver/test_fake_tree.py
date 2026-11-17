"""Fake GitLab repository tree endpoint and filter-only blob searches (WSGI-level)."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from fakegitlab import load_scenario
from fakegitlab.api import GitLabApi
from tests.fakeserver.test_fake_api import call

TREE = "/api/v4/projects/101/repository/tree"


@pytest.fixture(scope="module")
def api() -> GitLabApi:
    return GitLabApi(load_scenario("default"))


def all_paths(api: GitLabApi) -> list[str]:
    return sorted(load_scenario("default").project_by_id(101).branches["main"])


def test_recursive_keyset_pages_follow_the_link_header(api):
    seen, token, pages = [], None, 0
    while True:
        query = {"ref": "main", "recursive": "true", "pagination": "keyset", "per_page": "2"}
        if token:
            query["page_token"] = token
        status, body, headers, endpoint = call(api, TREE, query)
        assert (status, endpoint) == (200, "tree")
        seen += body
        pages += 1
        link = headers.get("Link")
        if not link:
            break
        token = parse_qs(urlsplit(link[1:link.index(">")]).query)["page_token"][0]
    assert pages > 1
    assert sorted(e["path"] for e in seen if e["type"] == "blob") == all_paths(api)
    assert {e["type"] for e in seen} == {"blob", "tree"}  # directories too, as in GitLab


def test_non_recursive_and_offset_pagination(api):
    status, body, headers, _ = call(api, TREE, {"ref": "main"})
    assert status == 200 and all("/" not in e["path"] for e in body)
    assert "X-Page" in headers
    status, body, _, _ = call(api, TREE, {"ref": "main", "path": "config"})
    assert body and all(e["path"].startswith("config/") and e["path"].count("/") == 1 for e in body)
    assert call(api, TREE, {"ref": "no-such-branch"})[0] == 404


@pytest.mark.parametrize(("mode", "status", "found"), [("empty", 200, False), ("error", 400, False),
                                                       ("paths", 200, True)])
def test_filter_only_search_modes(mode, status, found):
    api = GitLabApi(load_scenario({"extends": "default", "instance": {"search_filters_only": mode}}))
    code, body, _, _ = call(api, "/api/v4/projects/101/search", {"scope": "blobs", "search": "extension:py"})
    assert code == status
    if status == 200:
        assert bool(body) is found
        assert all(r["path"].endswith(".py") and r["startline"] == 1 for r in body)
