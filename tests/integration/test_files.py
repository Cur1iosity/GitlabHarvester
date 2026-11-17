"""
File filters (--filename/--extension) and downloads (--download-files) through
python-gitlab against the Fake GitLab.
"""

from __future__ import annotations

import io
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

import pytest

from fakegitlab import FakeGitLab
from glh.domain.planning import ScanOptions
from glh.output.downloads import FileDownloader
from glh.output.layout import OutputLayout
from glh.output.sink import SearchOutput
from tests.helpers import capture_logs, Session

STAMP = "20261117093000"


@pytest.fixture
def indexed(make_harvester, tmp_path: Path):
    """(harvester, projects) with an index of all branches."""
    glh = make_harvester()
    index = glh.build_project_index(filename=str(tmp_path / "idx.jsonl"), branches="all")
    return glh, glh.load_projects_from_file(index)["projects"]


def search(glh, projects, terms, *, downloader=None, **opts):
    fp = io.StringIO()
    results, hits = glh.search_keywords(projects, terms, options=ScanOptions(**opts),
                                        output=SearchOutput(fp, downloader=downloader))
    return hits, Session([json.loads(x) for x in fp.getvalue().splitlines()])


def file_path(hit: dict) -> str:
    """Repository path of a hit, from its link."""
    tree = unquote(hit["url"].split("/-/tree/", 1)[1].split("#", 1)[0])
    return tree[len(hit["branch"]) + 1:]


def hit_files(session: Session) -> set[tuple[int, str]]:
    return {(h["project_id"], file_path(h)) for h in session.hits()}


def make_downloader(tmp_path: Path, terms, **kw) -> FileDownloader:
    return FileDownloader(OutputLayout(tmp_path / "out" / "audit.jsonl", list(terms)), STAMP, **kw)


def files_under(root: Path) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())


def scenario_file(fake: FakeGitLab, pid: int, branch: str, path: str) -> bytes:
    return fake.scenario.project_by_id(pid).branches[branch][path].encode("utf-8")


# --------------------------------------------------------------------------- filters


def test_extension_filter_is_sent_to_gitlab_and_narrows_the_hits(fake_gitlab: FakeGitLab, indexed):
    glh, projects = indexed
    hits, session = search(glh, projects, ["password"], extension="py")

    assert hit_files(session) == {(101, "config/settings.py"), (201, "config/settings.py")}
    assert hits == 2
    # The term stays as typed in the session; the filter goes only into the request.
    assert {r["term"] for r in session.hit_records} == {"password"}
    assert {r.arg("search") for r in fake_gitlab.api_requests("project_search")} == {"password extension:py"}
    assert session.of_type("keyword_done")[0]["term"] == "password"


@pytest.mark.parametrize(("opts", "expected"), [
    ({"filename": "*.tf"}, {(301, "variables.tf")}),
    ({"filename": "settings.py"}, {(101, "config/settings.py"), (201, "config/settings.py")}),
    ({"filename": "*.md", "extension": "md"}, {(103, "docs/setup guide.md"), (202, "docs/setup guide.md")}),
    ({"filename": "env*"}, {(101, "deploy/env.example"), (201, "deploy/env.example")}),
    ({"filename": "deploy/*"}, {(101, "deploy/env.example"), (201, "deploy/env.example")}),
    ({"extension": "cfg"}, {(203, "app.cfg")}),
    ({"extension": "nothing"}, set()),
])
def test_filename_and_extension_filters(fake_gitlab: FakeGitLab, indexed, opts, expected):
    glh, projects = indexed
    _, session = search(glh, projects, ["password"], **opts)
    assert hit_files(session) == expected


def test_filename_is_rechecked_exactly_on_the_client(fake_gitlab: FakeGitLab, make_harvester):
    # GitLab basic search returns app/myconfig.yml for filename:config.yml too
    # (it matches the end of the path); --filename means the exact file name.
    fake_gitlab.reset({
        "extends": "default",
        "projects": [{"id": 105, "path_with_namespace": "sandbox/notes", "branches": {"main": {"files": {
            "config.yml": "secret: 1\n", "app/myconfig.yml": "secret: 2\n"}}}}],
    })
    glh = make_harvester()
    project = {"id": 105, "web_url": f"{fake_gitlab.url}/sandbox/notes", "default_branch": "main",
               "branches": ["main"], "empty_repo": False, "forked_from_project": False}
    _, session = search(glh, [project], ["secret"], filename="config.yml")
    assert hit_files(session) == {(105, "config.yml")}


def test_results_outside_the_filter_are_dropped_if_gitlab_ignores_it(fake_gitlab: FakeGitLab, indexed):
    glh, projects = indexed
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/projects/102/search$"}, "response": {"status": 200, "json": [
        {"path": "src/client.go", "startline": 1, "data": "token", "ref": "main", "project_id": 102},
        {"path": "src/settings.py", "startline": 3, "data": "token", "ref": "main", "project_id": 102},
    ]}})
    _, session = search(glh, projects, ["token"], extension="py")
    assert hit_files(session) == {(102, "src/settings.py")}


def test_name_filter_runs_before_the_file_time_filter(fake_gitlab: FakeGitLab, indexed):
    """Files dropped by --extension never cost a commits request."""
    glh, projects = indexed
    after = datetime(2024, 3, 1, tzinfo=timezone.utc)
    _, session = search(glh, projects, ["password"], extension="example", file_changed_after=after)
    checked = {r.arg("path") for r in fake_gitlab.api_requests("commits")}
    assert checked == {"deploy/env.example"}
    # env.example last changed on 2024-01-20: dropped by the time filter.
    assert hit_files(session) == set()


# --------------------------------------------------------------------------- downloads


def test_downloads_the_files_with_hits(fake_gitlab: FakeGitLab, indexed, tmp_path: Path):
    glh, projects = indexed
    d = make_downloader(tmp_path, ["password"])
    _, session = search(glh, projects, ["password"], extension="py", downloader=d)

    files = tmp_path / "out" / "password" / "files"
    assert files_under(tmp_path / "out") == [
        f"password/files/acme_backend_api-service_main_{STAMP}_password_config_settings.py",
        f"password/files/alice_api-service_main_{STAMP}_password_config_settings.py",
    ]
    content = scenario_file(fake_gitlab, 101, "main", "config/settings.py")
    for name in files.iterdir():
        assert name.read_bytes() == content
    # Every hit points to its local copy.
    for h in session.hits():
        assert Path(h["file"]).is_file() and Path(h["file"]).parent == files
    assert (d.stats.saved, d.stats.failed, d.stats.bytes) == (2, 0, 2 * len(content))
    # One raw request per file, with only ?ref=<branch>.
    raws = fake_gitlab.api_requests("file_raw")
    assert sorted(r.path for r in raws) == [
        "/api/v4/projects/101/repository/files/config%2Fsettings.py/raw",
        "/api/v4/projects/201/repository/files/config%2Fsettings.py/raw",
    ]
    assert all(r.query == {"ref": ["main"]} for r in raws)
    assert fake_gitlab.unmatched_requests() == []


def test_downloads_special_characters_in_branches_and_paths(fake_gitlab: FakeGitLab, indexed, tmp_path: Path):
    glh, projects = indexed
    d = make_downloader(tmp_path, ["password"])
    target = [p for p in projects if p["id"] == 103]
    _, session = search(glh, target, ["password"], scan_branches="all", downloader=d)

    by_branch = {h["branch"]: Path(h["file"]) for h in session.hits()}
    assert set(by_branch) == {"master", "fix/#42-login", "ünïcode-ветка"}
    for branch, local in by_branch.items():
        assert local.read_bytes() == scenario_file(fake_gitlab, 103, branch, "docs/setup guide.md")
        assert local.name.endswith("_password_docs_setup_guide.md") and local.name.isascii()
    assert {r.arg("ref") for r in fake_gitlab.api_requests("file_raw")} == set(by_branch)


def test_a_file_hit_by_several_terms_is_requested_once(fake_gitlab: FakeGitLab, indexed, tmp_path: Path):
    glh, projects = indexed
    d = make_downloader(tmp_path, ["password", "DB_PASSWORD"])
    search(glh, projects, ["password", "DB_PASSWORD"], extension="py", downloader=d)

    assert len(fake_gitlab.api_requests("file_raw")) == 2  # 101 and 201, not once per term
    assert (d.stats.saved, d.stats.copied) == (2, 2)
    out = tmp_path / "out"
    assert len(files_under(out / "password")) == 2 and len(files_under(out / "DB_PASSWORD")) == 2


def test_a_failed_download_keeps_the_hits_and_the_checkpoint(fake_gitlab: FakeGitLab, indexed, tmp_path: Path):
    glh, projects = indexed
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/projects/201/repository/files/"},
                           "response": {"status": 500, "body": "<html>boom</html>"}})
    logs = capture_logs(glh)
    d = make_downloader(tmp_path, ["password"])
    hits, session = search(glh, projects, ["password"], extension="py", downloader=d)

    assert hits == 2
    files = {h["project_id"]: h.get("file") for h in session.hits()}
    assert files[101] is not None and files[201] is None
    assert d.stats.failed == 1 and d.stats.saved == 1
    warnings = logs.messages(logging.WARNING)
    assert any("Could not download config/settings.py from alice/api-service @ main (HTTP 500 "
               "Internal Server Error)" in m for m in warnings)
    assert not any("<html>" in m for m in warnings)
    # Nothing was missed in the search: the term is still a resume checkpoint.
    assert [r["term"] for r in session.of_type("keyword_done")] == ["password"]
    assert glh.incomplete_terms == []
    assert not [p for p in (tmp_path / "out").rglob("*.part")]


def test_files_over_the_size_limit_are_skipped(fake_gitlab: FakeGitLab, indexed, tmp_path: Path):
    glh, projects = indexed
    d = make_downloader(tmp_path, ["password"], max_size=10)
    hits, session = search(glh, projects, ["password"], extension="py", downloader=d)
    assert hits == 2
    assert all("file" not in h for h in session.hits())
    assert (d.stats.too_large, d.stats.saved) == (2, 0)
    assert not (tmp_path / "out").exists() or files_under(tmp_path / "out") == []


def test_parallel_downloads_match_sequential(fake_gitlab: FakeGitLab, make_harvester, tmp_path: Path):
    def run(workers: int, where: Path) -> list[str]:
        glh = make_harvester(workers=workers)
        where.mkdir()
        index = glh.build_project_index(filename=str(where / "idx.jsonl"), branches="all")
        projects = glh.load_projects_from_file(index)["projects"]
        d = make_downloader(where, ["password", "api_key"])
        search(glh, projects, ["password", "api_key"], scan_branches="all", downloader=d)
        return files_under(where / "out")

    sequential = run(1, tmp_path / "seq")
    parallel = run(4, tmp_path / "par")
    assert sequential == parallel and len(sequential) > 10
