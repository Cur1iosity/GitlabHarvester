"""
GitlabHarvester logic with an in-memory stand-in for the python-gitlab client.

These tests do not start an HTTP server; the stub only mimics the handful of
client attributes the harvester touches. Wire-level behavior of the real
python-gitlab client is covered by tests/integration.
"""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import gitlab.exceptions
import pytest
import requests

from glh import GitlabHarvester
from tests.helpers import capture_logs, load_index, write_jsonl


def gl_project(pid: int, *, fork_of: int | None = None, empty: bool = False, default: str | None = "main"):
    return SimpleNamespace(
        id=pid,
        web_url=f"https://gitlab.test/g/p{pid}",
        path_with_namespace=f"g/p{pid}",
        default_branch=None if empty else default,
        empty_repo=empty,
        forked_from_project={"id": fork_of, "name": "up"} if fork_of else None,
        created_at="2024-01-01T00:00:00Z",
        last_activity_at="2024-01-02T00:00:00Z",
    )


class StubProjects:
    """Minimal ``gl.projects`` manager with page-based listing and fault hooks."""

    def __init__(self, pages: list[list[Any]], fail_on_page: int | None = None, exc: BaseException | None = None):
        self.pages = pages
        self.fail_on_page = fail_on_page
        self.exc = exc
        self.calls: list[dict[str, Any]] = []
        self.lazy_projects: dict[int, Any] = {}

    def list(self, **kwargs: Any) -> list[Any]:
        self.calls.append(kwargs)
        page = kwargs["page"]
        if page == self.fail_on_page:
            raise self.exc or gitlab.exceptions.GitlabListError("500 Internal Server Error", 500)
        return self.pages[page - 1] if page <= len(self.pages) else []

    def get(self, pid: int, lazy: bool = False) -> Any:
        if pid not in self.lazy_projects:
            raise AssertionError(f"unexpected projects.get({pid})")
        return self.lazy_projects[pid]


def harvester_with(projects: StubProjects, url: str = "https://gitlab.test") -> GitlabHarvester:
    glh = GitlabHarvester()  # no url/token -> no network
    glh._gl = SimpleNamespace(url=url, projects=projects)  # type: ignore[assignment]
    return glh


# --------------------------------------------------------------------------- client guard


def test_api_methods_require_initialized_client():
    from glh.exceptions import GitlabHarvesterError

    with pytest.raises(GitlabHarvesterError):
        GitlabHarvester().fetch_projects()


# --------------------------------------------------------------------------- error descriptions


@pytest.mark.parametrize(("error", "expected"), [
    (gitlab.exceptions.GitlabError("<html>500 page</html>", response_code=500), "HTTP 500 Internal Server Error"),
    (gitlab.exceptions.GitlabError("nope", response_code=404), "HTTP 404 Not Found"),
    (gitlab.exceptions.GitlabError("teapot", response_code=418), "HTTP 418"),
    (requests.exceptions.ConnectTimeout("timed out"), "ConnectTimeout: timed out"),
])
def test_describe_api_error_is_a_short_line(error, expected):
    from glh.harvester import describe_api_error

    assert describe_api_error(error) == expected


def test_describe_api_error_omits_the_response_body():
    from glh.harvester import describe_api_error

    e = gitlab.exceptions.GitlabError("<html><h1>500</h1><p>Whoops, something went wrong</p></html>",
                                      response_code=500)
    assert describe_api_error(e) == "HTTP 500 Internal Server Error"
    assert "Whoops" not in describe_api_error(e)


# --------------------------------------------------------------------------- tokens & concurrency


@pytest.mark.parametrize(
    ("tokens", "workers", "concurrency", "text"),
    [
        (["a"], 1, 1, ""),
        (["a"], 4, 4, "4 workers"),
        (["a", "b"], 1, 2, "2 tokens x 1 worker = 2 clients"),
        (["a", "b", "c"], 4, 12, "3 tokens x 4 workers = 12 clients"),
    ],
)
def test_concurrency_is_tokens_times_workers(tokens, workers, concurrency, text):
    glh = GitlabHarvester(tokens=tokens, workers=workers)  # no url -> no network
    assert glh.tokens == tuple(tokens)
    assert glh.workers == workers
    assert glh.concurrency == concurrency
    assert glh._concurrency_text() == text


def test_single_token_argument_still_works():
    glh = GitlabHarvester(token="a", workers=2)
    assert glh.tokens == ("a",) and glh.concurrency == 2


def test_worker_threads_cycle_through_tokens():
    glh = GitlabHarvester(tokens=["a", "b", "c"], workers=2)  # concurrency 6
    assigned = [glh._next_worker_token() for _ in range(glh.concurrency)]
    # One client per token per worker: every token used exactly `workers` times.
    assert sorted(assigned) == ["a", "a", "b", "b", "c", "c"]
    # The cycle keeps its phase, so the next phase stays balanced too.
    assert glh._next_worker_token() == "a"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://gitlab.example.com", "gitlab_example_com"),
        ("http://127.0.0.1:8080", "127_0_0_1_8080"),
        ("https://gitlab.example.com/", "gitlab_example_com"),
    ],
)
def test_instance_id_is_filesystem_safe(url, expected):
    glh = harvester_with(StubProjects([]), url=url)
    assert glh.get_instance_id() == expected
    assert glh.get_default_projects_filename() == f"{expected}_projects.jsonl"


# --------------------------------------------------------------------------- fetch_projects


def test_fetch_projects_in_memory_walks_pages_until_empty():
    stub = StubProjects([[gl_project(3), gl_project(2)], [gl_project(1, fork_of=3)]])
    projects = harvester_with(stub).fetch_projects(per_page=2)

    assert [p["id"] for p in projects] == [3, 2, 1]
    assert [c["page"] for c in stub.calls] == [1, 2, 3]
    assert stub.calls[0] == {"page": 1, "per_page": 2, "order_by": "id", "sort": "desc"}
    assert projects[2]["forked_from_project"] == {"id": 3}  # reduced to the id only
    assert projects[0]["forked_from_project"] is False


def test_fetch_projects_to_file_writes_meta_header(tmp_path: Path):
    out = tmp_path / "index.jsonl"
    harvester_with(StubProjects([[gl_project(2), gl_project(1, empty=True)]])).fetch_projects(filename=str(out))

    meta, projects = load_index(out)
    assert meta["is_completed"] is True
    assert meta["projects_count"] == 2
    assert meta["source"] == "gitlab_test"
    assert [p["id"] for p in projects] == [2, 1]
    assert projects[1]["empty_repo"] is True and projects[1]["default_branch"] is None
    assert not (tmp_path / "index.jsonl.tmp").exists()


def test_fetch_projects_api_error_marks_index_incomplete(tmp_path: Path):
    """Regression: a GitlabError mid-listing used to leave is_completed=True."""
    out = tmp_path / "index.jsonl"
    stub = StubProjects([[gl_project(4), gl_project(3)], [gl_project(2)]], fail_on_page=2)
    glh = harvester_with(stub)
    logs = capture_logs(glh)

    glh.fetch_projects(per_page=2, filename=str(out))  # error is logged, not raised

    meta, projects = load_index(out)
    assert meta["is_completed"] is False
    assert meta["projects_count"] == 2
    assert [p["id"] for p in projects] == [4, 3]
    assert any("wasn't complete" in m for m in logs.messages(logging.ERROR))


@pytest.mark.parametrize("exc", [KeyboardInterrupt(), RuntimeError("boom"), requests.exceptions.ReadTimeout("slow")])
def test_fetch_projects_fatal_errors_propagate_and_keep_partial_index(tmp_path: Path, exc):
    out = tmp_path / "index.jsonl"
    stub = StubProjects([[gl_project(2)], [gl_project(1)]], fail_on_page=2, exc=exc)
    with pytest.raises(type(exc)):
        harvester_with(stub).fetch_projects(per_page=1, filename=str(out))

    meta, projects = load_index(out)
    assert meta["is_completed"] is False
    assert [p["id"] for p in projects] == [2]
    assert not (tmp_path / "index.jsonl.tmp").exists()


# --------------------------------------------------------------------------- index files


def test_build_project_index_reuses_existing_file_and_warns_when_incomplete(tmp_path: Path):
    index = write_jsonl(tmp_path / "idx.jsonl", [{"type": "meta", "is_completed": False}, {"id": 1}])
    stub = StubProjects([[gl_project(9)]])
    glh = harvester_with(stub)
    logs = capture_logs(glh)

    assert glh.build_project_index(filename=str(index)) == str(index)
    assert stub.calls == []  # not rebuilt
    assert any("incomplete" in m for m in logs.messages(logging.WARNING))


def test_build_project_index_default_filename_has_no_colon(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(tmp_path)
    glh = harvester_with(StubProjects([[gl_project(1)]]), url="http://127.0.0.1:8080")
    name = glh.build_project_index()
    assert name == "127_0_0_1_8080_project_index.jsonl"
    assert (tmp_path / name).is_file()


def test_enrich_default_mode_makes_no_api_calls(tmp_path: Path):
    index = write_jsonl(
        tmp_path / "idx.jsonl",
        [
            {"type": "meta", "projects_count": 3, "is_completed": True},
            {"id": 1, "default_branch": "main", "empty_repo": False},
            {"id": 2, "default_branch": None, "empty_repo": True},
            {"id": 3, "default_branch": None, "empty_repo": False},
        ],
    )
    stub = StubProjects([])  # projects.get() would raise AssertionError
    harvester_with(stub).enrich_project_index_with_branches(filename=str(index), branches="default")

    meta, projects = load_index(index)
    assert meta["branches"] == "default" and meta["is_completed"] is True
    assert [p["branches"] for p in projects] == [["main"], [], []]
    assert not (tmp_path / "idx.jsonl.branches.tmp").exists()


def test_enrich_rejects_empty_index(tmp_path: Path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(ValueError):
        harvester_with(StubProjects([])).enrich_project_index_with_branches(filename=str(empty), branches="all")


def test_load_projects_from_file_tolerates_broken_lines(tmp_path: Path):
    f = tmp_path / "idx.jsonl"
    f.write_text('{"type": "meta", "timestamp_utc": "2024-01-01T00:00:00+00:00"}\n{"id": 1}\n{broken\n\n{"id": 2}\n',
                 encoding="utf-8")
    glh = GitlabHarvester()
    data = glh.load_projects_from_file(str(f))
    assert data["meta"]["type"] == "meta"
    assert [p["id"] for p in data["projects"]] == [1, 2]
    assert glh.load_projects_from_file(str(tmp_path / "missing.jsonl")) == {}
    assert glh.load_projects_from_file(None) == {}


# --------------------------------------------------------------------------- scan_branch


class StubSearchProject:
    def __init__(self, pages: list[list[dict]], fail_on_page: int | None = None, exc: BaseException | None = None):
        self.id = 7
        self.pages = pages
        self.fail_on_page = fail_on_page
        self.exc = exc
        self.calls: list[dict[str, Any]] = []

    def search(self, scope: str, search: str, **kwargs: Any) -> list[dict]:
        self.calls.append({"scope": scope, "search": search, **kwargs})
        page = kwargs["page"]
        if page == self.fail_on_page:
            raise self.exc or gitlab.exceptions.GitlabSearchError("502 Bad Gateway", 502)
        return self.pages[page - 1] if page <= len(self.pages) else []


def blob(path: str, line: int, data: str = "x") -> dict:
    return {"path": path, "startline": line, "data": data, "ref": "main", "basename": path, "filename": path}


def test_scan_branch_builds_encoded_links_and_counts_hits():
    proj = StubSearchProject([[blob("docs/setup guide.md", 3, "pw"), blob("a/b.txt", 1)]])
    glh = harvester_with(StubProjects([]))

    res, hits = glh.scan_branch(proj, "fix/#42 ünï", "password", "https://gitlab.test/g/p7", hit_counter=10)

    assert hits == 12
    assert res[0] == {
        "url": "https://gitlab.test/g/p7/-/tree/fix/%2342%20%C3%BCn%C3%AF/docs/setup%20guide.md#L3",
        "data": "pw",
    }
    assert res[1]["url"].endswith("/-/tree/fix/%2342%20%C3%BCn%C3%AF/a/b.txt#L1")


def test_scan_branch_sends_only_documented_search_parameters():
    proj = StubSearchProject([[blob("f", 1)]])
    harvester_with(StubProjects([])).scan_branch(proj, "main", "token", "https://gitlab.test/g/p7")
    assert proj.calls == [{"scope": "blobs", "search": "token", "ref": "main", "page": 1, "per_page": 100}]


def test_scan_branch_paginates_while_pages_are_full():
    full = [blob(f"f{i}", i) for i in range(1, 101)]
    proj = StubSearchProject([full, [blob("last", 1)]])
    res, hits = harvester_with(StubProjects([])).scan_branch(proj, "main", "x", "https://g/p")
    assert hits == 101 and len(res) == 101
    assert [c["page"] for c in proj.calls] == [1, 2]


@pytest.mark.parametrize(
    "exc",
    [gitlab.exceptions.GitlabSearchError("500", 500), requests.exceptions.ReadTimeout("timed out"),
     requests.exceptions.ConnectionError("reset")],
)
def test_scan_branch_keeps_results_of_pages_before_an_error(exc):
    full = [blob(f"f{i}", 1) for i in range(100)]
    proj = StubSearchProject([full, full], fail_on_page=2, exc=exc)
    glh = harvester_with(StubProjects([]))
    logs = capture_logs(glh)

    res, hits = glh.scan_branch(proj, "main", "x", "https://g/p")

    assert hits == 100
    assert logs.messages(logging.WARNING)
