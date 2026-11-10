"""
Fake GitLab internals: scenario loader, API semantics and fault rules.

Requests are built with Werkzeug's EnvironBuilder and passed straight to
GitLabApi/FaultInjector, so no socket is opened.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request

from fakegitlab import ScenarioError, available_scenarios, load_scenario
from fakegitlab.api import GitLabApi
from fakegitlab.faults import FaultInjector
from fakegitlab.scenario import SCENARIO_PATH_ENV

BASE = "http://gitlab.test"


def req(path: str, query: dict | None = None, token: str | None = "dev-token", method: str = "GET") -> Request:
    headers = {"PRIVATE-TOKEN": token} if token else {}
    env = EnvironBuilder(path=path, query_string=query, headers=headers, method=method, base_url=BASE).get_environ()
    return Request(env)


def call(api: GitLabApi, path: str, query: dict | None = None, **kw):
    result = api.handle(req(path, query, **kw), BASE)
    body = json.loads(result.response.get_data(as_text=True) or "null")
    return result.response.status_code, body, result.response.headers, result.endpoint


@pytest.fixture(scope="module")
def api() -> GitLabApi:
    return GitLabApi(load_scenario("default"))


# --------------------------------------------------------------------------- scenarios


def test_builtin_scenarios_load():
    assert {"default", "empty", "large", "flaky"} <= set(available_scenarios())
    assert len(load_scenario("default").projects) == 9
    assert len(load_scenario("empty").projects) == 0
    assert len(load_scenario("large").projects) == 9 + 250
    assert len(load_scenario("flaky").faults) == 4


def test_branch_inheritance_and_cross_project_inheritance():
    s = load_scenario("default")
    api_service, fork = s.project_by_id(101), s.project_by_id(201)
    assert set(api_service.branches["develop"]) == set(api_service.branches["main"]) | {"scripts/debug.sh"}
    assert fork.branches["main"] == api_service.branches["main"]
    assert "secrets.txt" in fork.branches["alice/experiment"]
    assert s.project_by_id(104).empty_repo and s.project_by_id(104).default_branch is None


def test_generated_projects_are_deterministic():
    a, b = load_scenario("large"), load_scenario("large")
    assert a.projects == b.projects
    p = a.project_by_id(1007)
    assert p.path_with_namespace == "bulk/team-07/service-007"
    assert sorted(p.branches) == ["develop", "main", "release/v7"]
    assert p.branches["develop"]["debug.ini"] == "password = FAKE-bulk-password-007\n"


def test_extends_from_inline_mapping_overrides_projects():
    s = load_scenario({"extends": "default", "name": "x", "remove_projects": [105],
                       "projects": [{"id": 102, "path_with_namespace": "acme/renamed", "branches": {}}]})
    assert s.project_by_id(105) is None
    assert s.project_by_id(102).path_with_namespace == "acme/renamed"
    assert s.project_by_id(101) is not None


def test_custom_scenario_directory_via_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / "mine.json").write_text(json.dumps({
        "users": [{"id": 1, "username": "u", "tokens": ["t"]}],
        "projects": [{"id": 1, "path_with_namespace": "a/b", "branches": {"main": {"files": {"f": "x"}}}}],
    }), encoding="utf-8")
    monkeypatch.setenv(SCENARIO_PATH_ENV, str(tmp_path))
    assert "mine" in available_scenarios()
    s = load_scenario("mine")
    assert s.name == "mine" and s.default_token == "t"
    assert s.project_by_id(1).default_branch == "main"


@pytest.mark.parametrize(
    ("doc", "message"),
    [
        ({"projects": [{"id": 1, "path_with_namespace": "a/b"}, {"id": 1, "path_with_namespace": "a/c"}]}, "Duplicate"),
        ({"projects": [{"id": 1, "path_with_namespace": "a/b", "default_branch": "x",
                        "branches": {"main": {}}}]}, "default_branch"),
        ({"projects": [{"id": 1, "path_with_namespace": "a/b", "forked_from": 5}]}, "forked_from"),
        ({"projects": [{"id": 1, "path_with_namespace": "a/b",
                        "branches": {"a": {"inherit": "b"}, "b": {"inherit": "a"}}}]}, "Circular"),
        ({"projects": [{"id": 1, "path_with_namespace": "a/b", "branches": {"a": {"inherit": "9:main"}}}]}, "unknown"),
        ({"instance": {"nope": 1}}, "Unknown instance"),
    ],
)
def test_invalid_scenarios_are_rejected(doc, message):
    with pytest.raises(ScenarioError, match=message):
        load_scenario(doc)


def test_unknown_scenario_name_lists_available():
    with pytest.raises(ScenarioError, match="Available: .*default"):
        load_scenario("does-not-exist")


# --------------------------------------------------------------------------- auth & routing


@pytest.mark.parametrize("token", [None, "wrong"])
def test_authentication_required(api: GitLabApi, token):
    status, body, _, endpoint = call(api, "/api/v4/user", token=token)
    assert (status, body, endpoint) == (401, {"message": "401 Unauthorized"}, "user")


def test_alternative_token_transports(api: GitLabApi):
    env = EnvironBuilder(path="/api/v4/user", headers={"Authorization": "Bearer readonly-token"},
                         base_url=BASE).get_environ()
    assert api.handle(Request(env), BASE).response.status_code == 200
    assert call(api, "/api/v4/user", {"private_token": "dev-token"}, token=None)[0] == 200


def test_unknown_endpoint_is_404_and_unmatched(api: GitLabApi):
    status, body, _, endpoint = call(api, "/api/v4/groups")
    assert (status, endpoint) == (404, None)


def test_project_lookup_by_encoded_path(api: GitLabApi):
    status, body, _, _ = call(api, "/api/v4/projects/acme%2Fbackend%2Fpayments")
    assert status == 200 and body["id"] == 102
    assert call(api, "/api/v4/projects/999")[0:2] == (404, {"message": "404 Project Not Found"})


# --------------------------------------------------------------------------- projects & pagination


def test_projects_payload_shape(api: GitLabApi):
    _, body, _, _ = call(api, "/api/v4/projects", {"order_by": "id", "sort": "asc", "per_page": "100"})
    by_id = {p["id"]: p for p in body}
    assert by_id[101]["web_url"] == f"{BASE}/acme/backend/api-service"
    assert by_id[101]["namespace"]["full_path"] == "acme/backend"
    assert by_id[101]["name_with_namespace"] == "acme / backend / api-service"
    assert "forked_from_project" not in by_id[101]
    assert by_id[201]["forked_from_project"]["id"] == 101
    assert by_id[201]["forked_from_project"]["path_with_namespace"] == "acme/backend/api-service"
    assert by_id[203]["forked_from_project"] == {"id": 999, "path_with_namespace": "hidden/upstream", "name": "upstream"}
    assert by_id[104]["empty_repo"] is True and by_id[104]["default_branch"] is None
    assert by_id[101]["forks_count"] == 1


def test_pagination_headers_and_links(api: GitLabApi):
    status, body, h, _ = call(api, "/api/v4/projects", {"order_by": "id", "sort": "desc", "per_page": "4", "page": "2"})
    assert status == 200
    assert [p["id"] for p in body] == [105, 104, 103, 102]
    assert (h["X-Page"], h["X-Per-Page"], h["X-Total"], h["X-Total-Pages"]) == ("2", "4", "9", "3")
    assert (h["X-Next-Page"], h["X-Prev-Page"]) == ("3", "1")
    assert 'rel="next"' in h["Link"] and "page=3" in h["Link"] and "order_by=id" in h["Link"]
    assert 'rel="last"' in h["Link"]


def test_page_past_the_end_is_empty(api: GitLabApi):
    _, body, h, _ = call(api, "/api/v4/projects", {"per_page": "5", "page": "3"})
    assert body == [] and h["X-Next-Page"] == ""


def test_per_page_is_capped_and_defaulted(api: GitLabApi):
    assert call(api, "/api/v4/projects", {"per_page": "1000"})[2]["X-Per-Page"] == "100"
    assert call(api, "/api/v4/projects")[2]["X-Per-Page"] == "20"
    assert call(api, "/api/v4/projects", {"page": "abc"})[0] == 400


def test_totals_are_omitted_above_count_limit():
    big = GitLabApi(load_scenario({"extends": "large", "instance": {"count_limit": 100}}))
    _, _, h, _ = call(big, "/api/v4/projects", {"per_page": "10"})
    assert "X-Total" not in h and "X-Total-Pages" not in h
    assert h["X-Next-Page"] == "2" and 'rel="last"' not in h["Link"]


@pytest.mark.parametrize(("order_by", "sort", "first"), [("id", "asc", 101), ("id", "desc", 301),
                                                         ("created_at", "desc", 301), ("name", "asc", 101), ("path", "desc", 202)])
def test_project_ordering(api: GitLabApi, order_by, sort, first):
    _, body, _, _ = call(api, "/api/v4/projects", {"order_by": order_by, "sort": sort})
    assert body[0]["id"] == first


def test_invalid_order_by(api: GitLabApi):
    assert call(api, "/api/v4/projects", {"order_by": "stars"})[0] == 400


# --------------------------------------------------------------------------- branches


def test_branches_sorted_by_name_with_special_characters(api: GitLabApi):
    _, body, _, _ = call(api, "/api/v4/projects/103/repository/branches")
    assert [b["name"] for b in body] == ["fix/#42-login", "master", "ünïcode-ветка"]
    master = body[1]
    assert master["default"] is True and master["protected"] is True
    assert len(master["commit"]["id"]) == 40
    assert body[0]["web_url"].endswith("/-/tree/fix/%2342-login")


def test_branches_of_empty_repo_and_search_filter(api: GitLabApi):
    assert call(api, "/api/v4/projects/104/repository/branches")[1] == []
    _, body, _, _ = call(api, "/api/v4/projects/101/repository/branches", {"search": "^feature"})
    assert [b["name"] for b in body] == ["feature/login-v2"]


# --------------------------------------------------------------------------- search


def test_blob_search_shape_and_context_merging(api: GitLabApi):
    _, body, h, _ = call(api, "/api/v4/projects/301/search", {"scope": "blobs", "search": "PASSWORD", "ref": "main"})
    assert h["X-Total"] == "2"
    assert body[0] == {
        "basename": "variables", "data": 'variable "db_password" {\n  type      = string\n  sensitive = true\n',
        "path": "variables.tf", "filename": "variables.tf", "id": None, "ref": "main",
        "startline": 1, "project_id": 301,
    }
    # Lines 10 and 11 both match: one merged chunk starting two context lines before (Gitaly: 2).
    assert body[1]["startline"] == 8
    assert body[1]["data"].startswith("# filler line 3\n\nvariable \"admin_password\"")
    assert body[1]["data"].count("password") == 2


def test_blob_search_returns_path_matches_first(api: GitLabApi):
    # Like Gitlab::FileFinder: files whose path contains the term come first
    # (startline 1, blob id, first 1024 bytes), then content matches.
    _, body, _, _ = call(api, "/api/v4/projects/201/search", {"scope": "blobs", "search": "SECRET", "ref": "alice/experiment"})
    assert body[0]["path"] == "secrets.txt"
    assert body[0]["startline"] == 1
    content = b"password=FAKE-alice-password-0001\n"
    assert body[0]["data"] == content.decode()
    assert body[0]["id"] == hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()  # git blob id
    assert body[1:] == []  # "secret" does not occur in any file content of this branch


def test_blob_search_path_matches_can_be_disabled():
    api = GitLabApi(load_scenario({"extends": "default", "instance": {"search_path_matches": False}}))
    _, body, _, _ = call(api, "/api/v4/projects/201/search", {"scope": "blobs", "search": "secret", "ref": "alice/experiment"})
    assert body == []


def test_blob_search_path_match_data_is_truncated_to_1024_bytes():
    big = "x" * 3000
    api = GitLabApi(load_scenario({
        "users": [{"id": 1, "username": "u", "tokens": ["t"]}],
        "projects": [{"id": 1, "path_with_namespace": "g/p", "branches": {"main": {"files": {"token.txt": big}}}}],
    }))
    _, body, _, _ = call(api, "/api/v4/projects/1/search", {"scope": "blobs", "search": "token"}, token="t")
    assert [r["startline"] for r in body] == [1]
    assert body[0]["data"] == "x" * 1024


def test_blob_search_defaults_to_default_branch_and_handles_unknown_refs(api: GitLabApi):
    _, body, _, _ = call(api, "/api/v4/projects/103/search", {"scope": "blobs", "search": "password"})
    assert {r["ref"] for r in body} == {"master"}
    assert call(api, "/api/v4/projects/103/search", {"scope": "blobs", "search": "x", "ref": "nope"})[1] == []
    assert call(api, "/api/v4/projects/104/search", {"scope": "blobs", "search": "x"})[1] == []


@pytest.mark.parametrize(
    ("term", "ref", "path"),
    [
        ("p@ss w0rd!", "master", "docs/setup guide.md"),
        ("$SECRET_VAR", "fix/#42-login", "src/login.js"),
        ('"quoted"', "fix/#42-login", "src/login.js"),
        ("КЛЮЧ", "ünïcode-ветка", "i18n/ru.txt"),
    ],
)
def test_blob_search_is_literal_and_case_insensitive(api: GitLabApi, term, ref, path):
    _, body, _, _ = call(api, "/api/v4/projects/103/search", {"scope": "blobs", "search": term, "ref": ref})
    assert [r["path"] for r in body] == [path]


def test_search_parameter_validation(api: GitLabApi):
    assert call(api, "/api/v4/projects/101/search", {"search": "x"})[0] == 400
    assert call(api, "/api/v4/projects/101/search", {"scope": "blobs"})[0] == 400
    assert call(api, "/api/v4/projects/101/search", {"scope": "bogus", "search": "x"})[0] == 400
    assert call(api, "/api/v4/projects/101/search", {"scope": "issues", "search": "x"})[1] == []


# --------------------------------------------------------------------------- faults


def test_fault_rule_matching_after_and_times():
    inj = FaultInjector()
    inj.load([{"name": "r", "match": {"method": "GET", "path": "/projects$", "query": {"page": "2"}},
               "after": 1, "times": 2, "response": {"status": 503}}])

    def status(page: str):
        d = inj.evaluate(req("/api/v4/projects", {"page": page}), "/api/v4/projects")
        return d.response.status_code if d.response else None

    assert status("1") is None
    assert [status("2") for _ in range(4)] == [None, 503, 503, None]
    assert inj.describe()[0]["applied"] == 2


def test_fault_rule_delay_only_and_raw_body():
    inj = FaultInjector()
    inj.add({"match": {"path": "search"}, "response": {"delay": 0.25}})
    inj.add({"match": {"path": "search", "query": {"search": "*"}}, "response": {"body": "{not json"}})
    d = inj.evaluate(req("/api/v4/projects/1/search", {"search": "x"}), "/api/v4/projects/1/search")
    assert d.delay == 0.25
    assert d.response.status_code == 200 and d.response.get_data(as_text=True) == "{not json"
    assert len(d.applied) == 2


# --------------------------------------------------------------------------- time filters


def test_projects_activity_filters_are_strict_like_gitlab(api: GitLabApi):
    def ids(**q):
        status, body, _, _ = call(api, "/api/v4/projects", {"order_by": "id", "sort": "asc", "per_page": 100, **q})
        assert status == 200
        return [p["id"] for p in body]

    assert ids(last_activity_after="2024-06-02T00:00:00Z") == [103, 201, 202, 203, 301]
    assert ids(last_activity_before="2024-02-03T09:00:00Z") == [104]  # 105 is exactly at the bound: excluded
    assert ids(last_activity_after="2024-06-01T00:00:00Z", last_activity_before="2024-06-03T00:00:00Z") == [101, 201]
    assert call(api, "/api/v4/projects", {"last_activity_after": "yesterday"})[0] == 400


def test_commits_endpoint_filters_by_path_and_time(api: GitLabApi):
    def commits(**q):
        status, body, _, endpoint = call(api, "/api/v4/projects/101/repository/commits", q)
        assert status == 200 and endpoint == "commits"
        return [c["committed_date"] for c in body]

    assert commits(ref_name="main", path="config/settings.py") == ["2024-03-15T10:00:00.000Z"]
    assert commits(ref_name="main", path="config/settings.py", since="2024-03-01T00:00:00Z") == \
        ["2024-03-15T10:00:00.000Z"]
    assert commits(ref_name="main", path="config/settings.py", until="2024-03-01T00:00:00Z") == []
    # Files without an explicit date changed at the project's last activity.
    assert commits(ref_name="main", path="README.md") == ["2024-06-01T12:00:00.000Z"]
    assert commits(ref_name="main", path="no/such/file") == []
    # Newest first, one commit per file, when no path is given.
    assert commits(ref_name="main") == sorted(commits(ref_name="main"), reverse=True) and len(commits(ref_name="main")) == 3
    assert call(api, "/api/v4/projects/101/repository/commits", {"ref_name": "nope"})[0] == 404
    assert call(api, "/api/v4/projects/104/repository/commits", {})[1] == []


def test_file_dates_are_inherited_with_the_files(api: GitLabApi):
    # develop inherits main; the fork 201 inherits 101:main.
    for pid, ref in ((101, "develop"), (201, "main")):
        _, body, _, _ = call(api, f"/api/v4/projects/{pid}/repository/commits", {"ref_name": ref, "path": "deploy/env.example"})
        assert [c["committed_date"] for c in body] == ["2024-01-20T10:00:00.000Z"]
    _, body, _, _ = call(api, "/api/v4/projects/101/repository/commits", {"ref_name": "develop", "path": "scripts/debug.sh"})
    assert [c["committed_date"] for c in body] == ["2024-06-01T12:00:00.000Z"]
