"""Files-only mode (--filename/--extension without a term): search, tree and the auto fallback."""

from __future__ import annotations

import io

import pytest

from fakegitlab import FakeGitLab
from glh.domain.file_filter import FileFilter
from glh.domain.planning import ScanOptions
from tests.helpers import load_index


@pytest.fixture
def index(make_harvester, tmp_path):
    path = tmp_path / "idx.jsonl"
    make_harvester().build_project_index(filename=str(path), per_page=5, branches="default", enforce_dump=True)
    return load_index(path)[1]


def expected_files(fake: FakeGitLab, index, flt: FileFilter) -> set[tuple[int, str]]:
    out = set()
    for p in index:
        if p.get("empty_repo"):
            continue
        project = fake.scenario.project_by_id(p["id"])
        for path in project.branches.get(p["default_branch"], {}):
            if flt.matches(path):
                out.add((p["id"], path))
    return out


def collect(glh, index, listing: str, flt: FileFilter):
    options = ScanOptions(filename=flt.filename, extension=flt.extension, files_only=True, file_listing=listing)
    term = flt.query("").strip()
    results, hits = glh.search_keywords(index, [term], options=options, session_file=io.StringIO())
    found = set()
    for record in results[0]["result"]:
        for branch in record["project_search_result"]:
            for hit in branch["branch_search_result"]:
                assert hit["data"] == "" and "/-/blob/" in hit["url"]
                path = hit["url"].split(f"/-/blob/{branch['branch']}/", 1)[1]
                found.add((record["project_id"], path))
    assert hits == len(found)
    return found


PY = FileFilter(extension="py")


def test_auto_falls_back_to_the_tree_where_filter_only_search_finds_nothing(fake_gitlab: FakeGitLab,
                                                                            make_harvester, index):
    glh = make_harvester()
    fake_gitlab.clear_journal()
    found = collect(glh, index, "auto", PY)
    assert found == expected_files(fake_gitlab, index, PY) and found
    searches = fake_gitlab.api_requests("project_search")
    assert searches and all(r.arg("search") == "extension:py" for r in searches)
    trees = fake_gitlab.api_requests("tree")
    assert trees and all(r.arg("pagination") == "keyset" and r.arg("recursive") == "true" for r in trees)
    assert set(glh.file_listing_counts) == {"tree"}
    assert fake_gitlab.unmatched_requests() == []


def test_auto_trusts_the_search_once_it_found_files(fake_gitlab: FakeGitLab, make_harvester, index):
    fake_gitlab.reset(scenario={"extends": "default", "instance": {"search_filters_only": "paths"}})
    glh = make_harvester()
    fake_gitlab.clear_journal()
    found = collect(glh, index, "auto", PY)
    assert found == expected_files(fake_gitlab, index, PY)
    assert glh.file_listing_counts["search"] > 0
    # Trees only for branches before the search proved itself (workers=1: in order).
    assert len(fake_gitlab.api_requests("tree")) == glh.file_listing_counts["tree"]


def test_auto_stops_searching_when_the_query_is_rejected(fake_gitlab: FakeGitLab, make_harvester, index):
    fake_gitlab.reset(scenario={"extends": "default", "instance": {"search_filters_only": "error"}})
    glh = make_harvester()
    fake_gitlab.clear_journal()
    found = collect(glh, index, "auto", PY)
    assert found == expected_files(fake_gitlab, index, PY)
    assert len(fake_gitlab.api_requests("project_search")) == 1  # rejected once, then only trees
    assert not glh.incomplete_terms


def test_tree_only_never_searches(fake_gitlab: FakeGitLab, make_harvester, index):
    glh = make_harvester(workers=3)
    fake_gitlab.clear_journal()
    flt = FileFilter(filename="settings.py")
    assert collect(glh, index, "tree", flt) == expected_files(fake_gitlab, index, flt)
    assert not fake_gitlab.api_requests("project_search")


def test_search_only_trusts_the_search(fake_gitlab: FakeGitLab, make_harvester, index):
    glh = make_harvester()
    assert collect(glh, index, "search", PY) == set()  # this backend finds nothing without a term
    assert not fake_gitlab.api_requests("tree")


def test_downloads_in_files_only_mode(fake_gitlab: FakeGitLab, make_harvester, index, tmp_path):
    from glh.output.downloads import FileDownloader
    from glh.output.layout import OutputLayout
    from glh.output.sink import SearchOutput

    flt = FileFilter(filename="settings.py")
    term = flt.query("").strip()
    layout = OutputLayout(tmp_path / "s.jsonl", [term])
    output = SearchOutput(io.StringIO(), downloader=FileDownloader(layout, "20261117000000"))
    options = ScanOptions(filename=flt.filename, files_only=True, file_listing="tree")
    results, hits = make_harvester().search_keywords(index, [term], options=options, output=output)
    files = [h["file"] for r in results[0]["result"] for b in r["project_search_result"]
             for h in b["branch_search_result"]]
    assert len(files) == hits == len(expected_files(fake_gitlab, index, flt)) > 0
    assert all((tmp_path / "filename_settings.py" / "files").exists() for _ in files)
