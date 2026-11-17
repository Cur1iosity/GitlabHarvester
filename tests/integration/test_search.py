"""Keyword search through python-gitlab: results, links, pagination and failures."""

from __future__ import annotations

import io
import json
import logging
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

from fakegitlab import FakeGitLab
from glh.domain.planning import ScanOptions
from glh.ui import statusline
from glh.ui.statusline import StatusLine
from tests.helpers import capture_logs, PASSWORD_HITS_DEFAULT_BRANCH, PASSWORD_HITS_PER_BRANCH, Session


@pytest.fixture
def indexed(make_harvester, tmp_path: Path):
    """Return (harvester, projects) with an index of all branches."""
    glh = make_harvester()
    index = glh.build_project_index(filename=str(tmp_path / "idx.jsonl"), branches="all")
    return glh, glh.load_projects_from_file(index)["projects"]


def search(glh, projects, terms, **opts):
    fp = io.StringIO()
    results, hits = glh.search_keywords(projects, terms, options=ScanOptions(**opts), session_file=fp)
    return results, hits, Session([json.loads(x) for x in fp.getvalue().splitlines()])


def test_default_branch_search_results(fake_gitlab: FakeGitLab, indexed):
    glh, projects = indexed
    results, hits, session = search(glh, projects, ["password"], scan_branches="default")

    assert hits == sum(PASSWORD_HITS_DEFAULT_BRANCH.values()) == 9
    per_project = {r["project_id"]: sum(len(b["branch_search_result"]) for b in r["project_search_result"])
                   for r in results[0]["result"]}
    assert per_project == PASSWORD_HITS_DEFAULT_BRANCH
    # Regression: "default" must mean the project's default branch, not the
    # alphabetically first indexed branch ("develop" for project 101).
    assert {pid: b for pid, b in session.branches_by_project().items()} == {
        301: ["main"], 203: ["main"], 202: ["master"], 201: ["main"], 103: ["master"], 101: ["main"]}
    assert {r.arg("ref") for r in fake_gitlab.api_requests("project_search", path="/projects/101/")} == {"main"}


def test_all_branches_search_results(indexed):
    glh, projects = indexed
    _, hits, session = search(glh, projects, ["password"], scan_branches="all")
    counts: dict[tuple[int, str], int] = {}
    for h in session.hits():
        counts[(h["project_id"], h["branch"])] = counts.get((h["project_id"], h["branch"]), 0) + 1
    assert counts == PASSWORD_HITS_PER_BRANCH
    assert hits == sum(PASSWORD_HITS_PER_BRANCH.values())


def test_projects_without_matches_and_empty_repos_are_not_reported(fake_gitlab: FakeGitLab, indexed):
    glh, projects = indexed
    results, hits, session = search(glh, projects, ["nothing-matches-this"], scan_branches="all")
    assert hits == 0 and results == [{"term": "nothing-matches-this", "result": []}]
    assert session.hit_records == []
    assert session.of_type("keyword_done")[0]["hit_counter"] == 0
    # Empty repository 104 is skipped without any request.
    assert not fake_gitlab.api_requests(path="/projects/104/")


def test_hit_links_resolve_to_file_and_line(fake_gitlab: FakeGitLab, indexed):
    glh, projects = indexed
    _, _, session = search(glh, projects, ["password", "p@ss w0rd!", "КЛЮЧ"], scan_branches="all")
    scenario = fake_gitlab.scenario
    assert session.hits()

    for h in session.hits():
        project = scenario.project_by_id(h["project_id"])
        prefix = f"{fake_gitlab.url}/{project.path_with_namespace}/-/blob/"
        assert h["url"].startswith(prefix)
        parts = urlsplit(h["url"])
        assert parts.fragment.startswith("L") and not parts.query
        rest = unquote(parts.path)[len(urlsplit(prefix).path):]
        assert rest.startswith(h["branch"] + "/")
        file_path = rest[len(h["branch"]) + 1:]
        content = project.branches[h["branch"]][file_path].splitlines()
        start = int(parts.fragment[1:])
        snippet = content[start - 1:start - 1 + h["data"].count("\n")]
        assert "\n".join(snippet) + "\n" == h["data"]
        assert h["term"].lower() in h["data"].lower()


def test_special_character_links_are_url_encoded(indexed):
    glh, projects = indexed
    _, _, session = search(glh, projects, ["password"], scan_branches="all")
    urls = {h["url"] for h in session.hits() if h["project_id"] == 103}
    assert any("/-/blob/fix/%2342-login/docs/setup%20guide.md#L1" in u for u in urls)
    assert any("/-/blob/%C3%BCn%C3%AFcode-%D0%B2%D0%B5%D1%82%D0%BA%D0%B0/" in u for u in urls)
    assert all(u.count("#") == 1 and " " not in u for u in urls)


@pytest.mark.parametrize(
    ("forks", "scan", "expected"),
    [
        ("include", "all", {101, 103, 201, 202, 203, 301}),
        ("skip", "all", {101, 103, 301}),
    ],
)
def test_fork_modes_select_projects(indexed, forks, scan, expected):
    glh, projects = indexed
    _, _, session = search(glh, projects, ["password"], scan_branches=scan, forks_mode=forks)
    assert set(session.project_ids()) == expected


def test_branch_diff_skips_branches_identical_to_upstream(fake_gitlab: FakeGitLab, indexed):
    glh, projects = indexed
    search(glh, projects, ["password"], scan_branches="all", forks_mode="branch-diff",
           fork_diff_bases=("main", "master", "develop", "dev"))
    refs = lambda pid: sorted(r.arg("ref") for r in fake_gitlab.api_requests("project_search", path=f"/projects/{pid}/"))
    assert refs(201) == ["alice/experiment", "develop", "main"]  # feature/login-v2 equals upstream
    assert refs(202) == ["feature/bob", "master"]
    assert refs(203) == ["carol/wip", "develop", "main"]  # upstream invisible -> regular selection
    assert refs(101) == sorted(["develop", "feature/login-v2", "main", "release/1.0+hotfix"])


def test_branch_diff_searches_a_branch_the_fork_changed(fake_gitlab: FakeGitLab, make_harvester, tmp_path: Path):
    # The same branch name on both sides is not enough: the fork's feature/auth has a commit of its own.
    fake_gitlab.reset(scenario={
        "users": [{"id": 1, "username": "bot", "tokens": ["dev-token"]}],
        "projects": [
            {"id": 1, "path_with_namespace": "acme/app", "default_branch": "main", "branches": {
                "main": {"files": {"README.md": "app\n"}},
                "feature/auth": {"inherit": "main", "files": {"auth.py": "def login(): ...\n"}},
                "feature/ui": {"inherit": "main", "files": {"ui.py": "pass\n"}},
            }},
            {"id": 2, "path_with_namespace": "eve/app", "default_branch": "main", "forked_from": 1, "branches": {
                "main": {"inherit": "1:main"},
                "feature/auth": {"inherit": "1:feature/auth", "files": {"debug.env": "token=FAKE-leak-0001\n"}},
                "feature/ui": {"inherit": "1:feature/ui"},
            }},
        ],
    })
    glh = make_harvester()
    index = glh.build_project_index(filename=str(tmp_path / "idx.jsonl"), branches="all")
    projects = glh.load_projects_from_file(index)["projects"]
    _, hits, session = search(glh, projects, ["token"], scan_branches="all", forks_mode="branch-diff",
                              fork_diff_bases=("main",))
    refs = sorted(r.arg("ref") for r in fake_gitlab.api_requests("project_search", path="/projects/2/"))
    assert refs == ["feature/auth", "main"]  # feature/ui is the upstream's commit: skipped
    assert hits == 1 and session.project_ids() == [2]


def test_without_keep_results_the_hits_only_go_to_the_output(fake_gitlab: FakeGitLab, indexed):
    # The CLI's way: the session file has every hit, so the engine keeps none of them.
    glh, projects = indexed
    fp = io.StringIO()
    results, hits = glh.search_keywords(projects, ["password", "token"], options=ScanOptions(scan_branches="all"),
                                        session_file=fp, keep_results=False)
    assert [r["term"] for r in results] == ["password", "token"] and all(r["result"] == [] for r in results)
    session = Session([json.loads(x) for x in fp.getvalue().splitlines()])
    kept, kept_hits = glh.search_keywords(projects, ["password", "token"], options=ScanOptions(scan_branches="all"))
    assert hits == kept_hits == len(session.hits())
    assert sorted(h["url"] for h in session.hits()) == sorted(
        hit["url"] for r in kept for project in r["result"] for branch in project["project_search_result"]
        for hit in branch["branch_search_result"])


def test_search_pagination_over_100_results(fake_gitlab: FakeGitLab, make_harvester):
    lines = "\n".join(f"secret {i}" if i % 2 == 0 else "filler" for i in range(500)) + "\n"
    fake_gitlab.reset({
        "extends": "default", "instance": {"search_context_lines": 0},
        "projects": [{"id": 105, "path_with_namespace": "sandbox/notes", "branches": {"main": {"files": {"big.txt": lines}}}}],
    })
    glh = make_harvester()
    project = {"id": 105, "web_url": "x", "default_branch": "main", "branches": ["main"], "empty_repo": False}
    _, hits, session = search(glh, [project], ["secret"], scan_branches="default")

    assert hits == 250
    assert [r.arg("page") for r in fake_gitlab.api_requests("project_search")] == ["1", "2", "3"]
    assert [h["url"].rsplit("#L", 1)[1] for h in session.hits()][:3] == ["1", "3", "5"]


def test_search_error_on_intermediate_page_keeps_earlier_pages(fake_gitlab: FakeGitLab, make_harvester):
    lines = "secret\nfiller\n" * 150  # non-adjacent matches -> 150 separate results
    fake_gitlab.reset({
        "extends": "default", "instance": {"search_context_lines": 0},
        "projects": [{"id": 105, "path_with_namespace": "sandbox/notes", "branches": {"main": {"files": {"f": lines}}}}],
        "faults": [{"match": {"path": "/projects/105/search$", "query": {"page": "2"}},
                    "response": {"status": 500, "json": {"message": "500"}}}],
    })
    glh = make_harvester()
    logs = capture_logs(glh)
    project = {"id": 105, "web_url": "x", "default_branch": "main", "branches": ["main"], "empty_repo": False}
    _, hits, _ = search(glh, [project], ["secret"])
    assert hits == 100
    assert any("500" in m for m in logs.messages(logging.WARNING))


@pytest.mark.parametrize(
    "response",
    [
        {"status": 500, "json": {"message": "500 Internal Server Error"}},
        {"status": 502, "body": "<html>bad gateway</html>"},
        {"status": 503, "json": {"message": "503"}},
        {"status": 401, "json": {"message": "401 Unauthorized"}},
        {"status": 403, "json": {"message": "403 Forbidden"}},
        {"status": 404, "json": {"message": "404 Project Not Found"}},
        {"status": 200, "body": "{\"broken\": "},
    ],
    ids=["500", "502", "503", "401", "403", "404", "invalid-json"],
)
def test_partial_success_when_one_project_fails(fake_gitlab: FakeGitLab, indexed, response):
    """One failing project never aborts the scan; whether the term counts as done depends on the error."""
    glh, projects = indexed
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/projects/301/search$"}, "response": response})
    logs = capture_logs(glh)

    _, hits, session = search(glh, projects, ["password"], scan_branches="default")

    assert 301 not in session.project_ids()
    assert hits == sum(PASSWORD_HITS_DEFAULT_BRANCH.values()) - PASSWORD_HITS_DEFAULT_BRANCH[301]
    assert any("ops/infra/terraform/modules" in m for m in logs.messages(logging.WARNING))

    if response["status"] in (403, 404):
        # Permanent: no access / gone. Retrying can't help, so the term is done...
        [done] = session.of_type("keyword_done")
        assert done["hit_counter"] == hits
        assert session.of_type("keyword_incomplete") == [] and glh.incomplete_terms == []
        # ...but not covered: the gap is counted and named.
        kind = "inaccessible" if response["status"] == 403 else "not_found"
        assert (done["inaccessible"], done["not_found"]) == ((1, 0) if kind == "inaccessible" else (0, 1))
        assert done["unsearched"] == [f"ops/infra/terraform/modules @ main: HTTP {response['status']} "
                                      f"{'Forbidden' if kind == 'inaccessible' else 'Not Found'}"]
        assert glh.unsearched == {kind: 1}
    else:
        # Retryable: hits may be missing, so --resume must search the term again.
        assert session.of_type("keyword_done") == []
        incomplete = session.of_type("keyword_incomplete")
        assert [r["term"] for r in incomplete] == ["password"]
        assert incomplete[0]["failed_searches"] == 1 and incomplete[0]["hit_counter"] == hits
        assert incomplete[0]["failures"][0].startswith("ops/infra/terraform/modules @ main: ")
        assert glh.incomplete_terms == ["password"]
        assert "unsearched" not in incomplete[0] and not glh.unsearched


def test_a_search_without_gaps_writes_no_coverage_keys(fake_gitlab: FakeGitLab, indexed):
    glh, projects = indexed
    _, _, session = search(glh, projects, ["password"], scan_branches="default")
    [done] = session.of_type("keyword_done")
    assert set(done) == {"type", "term", "hit_counter", "timestamp_utc"} and not glh.unsearched


def test_error_body_is_hidden_by_default_and_shown_at_debug(fake_gitlab: FakeGitLab, indexed, make_harvester):
    """A 500's HTML body is noise: only a concise line by default, the full body at --debug."""
    glh, projects = indexed
    fake_gitlab.add_fault({
        "match": {"path": "^/api/v4/projects/301/search$"},
        "response": {"status": 500, "body": "<html><h1>500</h1><p>Whoops, something went wrong on our end</p></html>"},
    })

    # Default level (WARNING): a concise one-liner, no response body.
    logs = capture_logs(glh)
    search(glh, projects, ["password"], scan_branches="default")
    warnings = logs.messages(logging.WARNING)
    assert any("HTTP 500 Internal Server Error" in m and "ops/infra/terraform/modules" in m for m in warnings)
    assert all("Whoops" not in m for m in warnings)

    # With --debug the full error (body included) is available for troubleshooting.
    debug_glh = make_harvester(log_level="DEBUG")
    debug_logs = capture_logs(debug_glh)
    search(debug_glh, projects, ["password"], scan_branches="default")
    assert any("Whoops" in m for m in debug_logs.messages(logging.DEBUG))


def test_failed_term_is_not_a_resume_checkpoint(fake_gitlab: FakeGitLab, indexed, tmp_path: Path):
    """Regression: a term whose searches failed used to be marked done, so --resume skipped it."""
    from glh.output.session_reader import load_done_keywords

    glh, projects = indexed
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/projects/301/search$", "query": {"search": "api_key"}},
                           "response": {"status": 502, "body": "bad gateway"}})
    _, _, session = search(glh, projects, ["password", "api_key", "token"], scan_branches="default")

    path = tmp_path / "s.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in session.records), encoding="utf-8")
    assert load_done_keywords(path) == {"password", "token"}  # api_key will be searched again
    # Checkpoints keep the term order; the incomplete term sits in its place.
    assert [(r["type"], r["term"]) for r in session.records if r.get("type", "").startswith("keyword_")] == [
        ("keyword_done", "password"), ("keyword_incomplete", "api_key"), ("keyword_done", "token")]


def test_error_on_a_later_result_page_makes_the_term_incomplete(fake_gitlab: FakeGitLab, make_harvester):
    lines = "secret\nfiller\n" * 150  # 150 separate results -> 2 pages
    fake_gitlab.reset({
        "extends": "default", "instance": {"search_context_lines": 0},
        "projects": [{"id": 105, "path_with_namespace": "sandbox/notes", "branches": {"main": {"files": {"f": lines}}}}],
        "faults": [{"match": {"path": "/projects/105/search$", "query": {"page": "2"}},
                    "response": {"status": 500, "json": {"message": "500"}}}],
    })
    glh = make_harvester()
    project = {"id": 105, "web_url": "x", "default_branch": "main", "branches": ["main"], "empty_repo": False}
    _, hits, session = search(glh, [project], ["secret"])
    assert hits == 100  # page 1 is kept
    assert [r["term"] for r in session.of_type("keyword_incomplete")] == ["secret"]


def test_parallel_failures_are_tracked_too(fake_gitlab: FakeGitLab, indexed, make_harvester):
    _, projects = indexed
    fake_gitlab.add_fault({"match": {"path": "/search$", "query": {"search": "token"}},
                           "response": {"status": 503, "json": {"message": "503"}}})
    glh = make_harvester(workers=4)
    _, _, session = search(glh, projects, ["password", "token"], scan_branches="all")
    assert [r["term"] for r in session.of_type("keyword_done")] == ["password"]
    incomplete = session.of_type("keyword_incomplete")
    assert [r["term"] for r in incomplete] == ["token"] and incomplete[0]["failed_searches"] > 1


def test_search_rate_limit_is_retried(fake_gitlab: FakeGitLab, indexed, no_retry_sleep):
    glh, projects = indexed
    fake_gitlab.add_fault({"match": {"path": "/search$"}, "times": 2,
                           "response": {"status": 429, "headers": {"Retry-After": "2"}}})
    _, hits, _ = search(glh, projects, ["password"], scan_branches="default")
    assert hits == 9
    assert no_retry_sleep == [2.0, 2.0]


def test_search_timeout_skips_branch_and_continues(fake_gitlab: FakeGitLab, make_harvester, tmp_path: Path):
    """Regression: a read timeout used to abort the entire keyword scan."""
    glh = make_harvester(timeout=1)
    projects = glh.load_projects_from_file(glh.build_project_index(filename=str(tmp_path / "i.jsonl")))["projects"]
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/projects/301/search$"}, "times": 1, "response": {"delay": 3}})
    logs = capture_logs(glh)

    _, hits, session = search(glh, projects, ["password"], scan_branches="default")

    assert hits == 9 - PASSWORD_HITS_DEFAULT_BRANCH[301]
    assert 301 not in session.project_ids()
    assert any("timed out" in m.lower() for m in logs.messages(logging.WARNING))
    # The timed-out project may hold hits: the term is not a resume checkpoint.
    assert [r["term"] for r in session.of_type("keyword_incomplete")] == ["password"]


def test_multiple_keywords_session_records(indexed):
    glh, projects = indexed
    results, hits, session = search(glh, projects, ["password", "api_key", "FAKE-token"], scan_branches="default")

    assert [r["term"] for r in results] == ["password", "api_key", "FAKE-token"]
    done = session.of_type("keyword_done")
    assert [d["term"] for d in done] == ["password", "api_key", "FAKE-token"]
    # hit_counter is cumulative across keywords.
    assert done[-1]["hit_counter"] == hits
    assert len(session.hits("password")) == 9
    assert set(session.project_ids("FAKE-token")) == {102}
    # api_key: 101/201 settings.py, 103/202 config.js -> case-insensitive "apiKey" does not match "api_key".
    assert set(session.project_ids("api_key")) == {101, 201}
    # Records of one keyword precede its keyword_done marker.
    order = [r.get("type") or r["term"] for r in session.records]
    assert order.index("keyword_done") > order.index("password")


# --------------------------------------------------------------------------- --started-from


def test_started_from_skips_inactive_projects_without_requests(fake_gitlab: FakeGitLab, indexed):
    from datetime import datetime, timezone

    glh, projects = indexed
    since = datetime(2024, 6, 2, tzinfo=timezone.utc)  # 101 (06-01), 102 (05-20), 105 (02-03) are older
    _, hits, session = search(glh, projects, ["password"], scan_branches="default", started_from=since)

    assert set(session.project_ids()) == {103, 201, 202, 203, 301}
    assert hits == sum(v for k, v in PASSWORD_HITS_DEFAULT_BRANCH.items() if k != 101)
    searched = {int(r.path.split("/")[4]) for r in fake_gitlab.api_requests("project_search")}
    assert searched == {103, 201, 202, 203, 301}
    # Only the documented search parameters are sent (no date parameter exists for blobs).
    assert all(set(r.query) == {"scope", "search", "ref", "page", "per_page"}
               for r in fake_gitlab.api_requests("project_search"))


def test_started_from_keeps_inactive_upstream_for_branch_diff(fake_gitlab: FakeGitLab, indexed):
    from datetime import datetime, timezone

    glh, projects = indexed
    since = datetime(2024, 6, 2, tzinfo=timezone.utc)  # upstream 101 is inactive, fork 201 is active
    search(glh, projects, ["password"], scan_branches="all", forks_mode="branch-diff", started_from=since)
    refs = sorted(r.arg("ref") for r in fake_gitlab.api_requests("project_search", path="/projects/201/"))
    # Still diffed against the (unscanned) upstream: feature/login-v2 equals upstream and is skipped.
    assert refs == ["alice/experiment", "develop", "main"]
    assert not fake_gitlab.api_requests("project_search", path="/projects/101/")


# --------------------------------------------------------------------------- progress counts only planned projects


@pytest.mark.parametrize("ansi", [False, True], ids=["one-line", "panel"])
def test_progress_counts_only_projects_that_are_scanned(fake_gitlab: FakeGitLab, indexed, monkeypatch, ansi):
    """
    With filters, every 'N/M projects' shown on the terminal refers to the scan plan, not the index.

    ``ansi`` is set explicitly: a fake terminal counts as ANSI-capable on POSIX but
    not on Windows, and the status is then a multi-line panel instead of one line.
    """
    import re
    from datetime import datetime, timezone

    from tests.helpers import FakeStream

    glh, projects = indexed
    tty = FakeStream(True)
    status = StatusLine(tty, columns=lambda: 400, ticker=False, refresh_interval=0,  # draw every update
                        ansi=ansi)
    monkeypatch.setattr(statusline, "STATUS", status)

    since = datetime(2024, 6, 2, tzinfo=timezone.utc)
    _, _, session = search(glh, projects, ["password", "token"], scan_branches="all", forks_mode="skip",
                           started_from=since)

    # Forks 201-203 are skipped first, then 101/102/105 as inactive: 103 and 301 remain.
    searched = {int(r.path.split("/")[4]) for r in fake_gitlab.api_requests("project_search")}
    assert searched == {103, 301}
    out = tty.getvalue()
    from tests.helpers import parse_blocks

    plan = parse_blocks(out.replace("\r", "\n"))["Search plan"]
    assert (plan["terms"], plan["projects"], plan["branches"]) == (["2"], ["2 of 9"], ["4"])
    assert plan["skipped"] == ["1 empty", "3 forks", "3 inactive since 2024-06-02"]

    counts = {m.group(2) for m in re.finditer(r"(\d+)/(\d+) projects", out)}
    assert counts == {"2"}, out
    if ansi:
        # The panel: one row per counter, the task below them.
        # (the label column is as wide as the labels shown: "running" comes and goes)
        assert re.search(r"\x1b\[2K  term +2/2 projects \(100%\)", out)
        assert re.search(r"\x1b\[2K  total +3/4 \(75%\)", out)
        assert "ops/infra/terraform/modules @ main" in out
        assert re.search(r"Search finished: 2 terms x 2 projects, \d+ hits? in ", out)
        assert out.endswith("\n")
        return
    frames = [f.strip() for f in out.split("\r") if "projects (" in f]
    assert any(f.startswith("Searching 'token' (2/2) | term 2/2 projects (100%)") for f in frames)
    # Two terms: per-term and overall counters ("total" counts projects x terms).
    assert any(" | total 3/4 (75%) " in f for f in frames)
    assert any("ops/infra/terraform/modules @ main" in f for f in frames)
    assert re.search(r"Search finished: 2 terms x 2 projects, \d+ hits? in ", out)
    assert out.endswith("\n")  # the status line is erased, the summary stays
