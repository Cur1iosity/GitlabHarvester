"""
End-to-end user scenarios: the real CLI (``python -m gitlab_harvester``) in a
subprocess, talking HTTP to the Fake GitLab.

Assertions cover exit codes, stdout, and the full content of produced files.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fakegitlab import FakeGitLab
from tests.helpers import (
    DEFAULT_BRANCHES,
    DEFAULT_PROJECT_IDS_DESC,
    PASSWORD_HITS_DEFAULT_BRANCH,
    PASSWORD_HITS_PER_BRANCH,
    Session,
    load_index,
    read_jsonl,
)


def gl_args(fake: FakeGitLab) -> list[str]:
    return ["-u", fake.url, "-t", fake.token]


def instance_id(fake: FakeGitLab) -> str:
    return fake.url.split("://", 1)[1].replace(".", "_").replace(":", "_")


# --------------------------------------------------------------------------- 1-2. index


def test_dump_index_with_default_filename(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    proc = run_cli(*gl_args(fake_gitlab), "-m", "dump-index", "-bs", "4", check=True)

    expected = tmp_path / f"{instance_id(fake_gitlab)}_project_index.jsonl"
    assert f"Project index saved to: {expected.name}" in proc.stdout
    assert expected.is_file()
    assert [p.name for p in tmp_path.iterdir()] == [expected.name]  # no tmp leftovers

    meta, projects = load_index(expected)
    assert meta["is_completed"] is True and meta["projects_count"] == 9 and meta["per_page"] == 4
    assert [p["id"] for p in projects] == DEFAULT_PROJECT_IDS_DESC


def test_dump_index_enriched_with_all_branches(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    run_cli(*gl_args(fake_gitlab), "-m", "dump-index", "--index-file", "idx.jsonl", "--index-branches", "all",
            "--branches-per-page", "2", check=True)
    meta, projects = load_index(tmp_path / "idx.jsonl")
    assert meta["branches"] == "all"
    assert {p["id"]: p["branches"] for p in projects} == DEFAULT_BRANCHES


def test_dump_index_with_branch_limit_and_rebuild(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    run_cli(*gl_args(fake_gitlab), "-m", "dump-index", "--index-file", "idx.jsonl", "--index-branches", "1",
            check=True)
    assert {p["id"]: p["branches"] for p in load_index(tmp_path / "idx.jsonl")[1]}[101] == ["develop"]
    # dump-index always rebuilds.
    run_cli(*gl_args(fake_gitlab), "-m", "dump-index", "--index-file", "idx.jsonl", check=True)
    assert {p["id"]: p["branches"] for p in load_index(tmp_path / "idx.jsonl")[1]}[101] == ["main"]


# --------------------------------------------------------------------------- 3-4, 6. search


def test_search_single_keyword(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    proc = run_cli(*gl_args(fake_gitlab), "-s", "password", "--index-file", "idx.jsonl", "--session", "audit",
                   check=True)

    assert "Session saved to: audit.jsonl" in proc.stdout
    assert "Done. Keywords: 1 | Hits: 9" in proc.stdout
    s = Session.load(tmp_path / "audit.jsonl")

    types = [r.get("type", "hit") for r in s.records]
    assert types[0] == "meta" and types[-2:] == ["keyword_done", "summary"]
    meta = s.records[0]
    assert meta["url"] == fake_gitlab.url and meta["keywords_count"] == 1 and meta["forks"] == "include"
    assert meta["index_file"] == "idx.jsonl"
    assert s.of_type("summary")[0]["hits"] == 9
    per_project: dict[int, int] = {}
    for h in s.hits("password"):
        per_project[h["project_id"]] = per_project.get(h["project_id"], 0) + 1
    assert per_project == PASSWORD_HITS_DEFAULT_BRANCH
    for rec in s.hit_records:
        assert set(rec["result"]) == {"project_id", "web_url", "created_at", "last_activity_at",
                                      "project_search_result"}


def test_search_default_session_location(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    run_cli(*gl_args(fake_gitlab), "-s", "FAKE-token", check=True)
    sessions = list((tmp_path / "results").glob("*.jsonl"))
    assert len(sessions) == 1
    assert sessions[0].name.startswith(f"{instance_id(fake_gitlab)}_session_")
    assert Session.load(sessions[0]).project_ids() == [102]
    # Index created next to it with a Windows-safe default name.
    assert (tmp_path / f"{instance_id(fake_gitlab)}_project_index.jsonl").is_file()


def test_search_multiple_keywords_from_file(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    (tmp_path / "terms.txt").write_text(
        "# audit terms\npassword\napi_key\n\nnothing-matches-this\np@ss w0rd!\n$SECRET_VAR\nключ\n", encoding="utf-8")
    proc = run_cli(*gl_args(fake_gitlab), "-f", "terms.txt", "-b", "all", "--session-file", "out/s.jsonl",
                   check=True)

    s = Session.load(tmp_path / "out" / "s.jsonl")
    terms = ["password", "api_key", "nothing-matches-this", "p@ss w0rd!", "$SECRET_VAR", "ключ"]
    assert [d["term"] for d in s.of_type("keyword_done")] == terms
    assert s.records[0]["keywords_count"] == 6
    assert len(s.hits("password")) == sum(PASSWORD_HITS_PER_BRANCH.values())
    assert s.hits("nothing-matches-this") == []
    assert set(s.branches_by_project("$SECRET_VAR")) == {103}
    assert s.branches_by_project("$SECRET_VAR")[103] == ["fix/#42-login"]
    assert s.branches_by_project("ключ") == {103: ["ünïcode-ветка"]}
    # "p@ss w0rd!" lives in web-app master and every branch inheriting it (incl. fork 202).
    assert set(s.project_ids("p@ss w0rd!")) == {103, 202}
    total = len(s.hits())
    assert f"Done. Keywords: 6 | Hits: {total}" in proc.stdout
    assert s.of_type("summary")[0]["hits"] == total


# --------------------------------------------------------------------------- 5. forks


@pytest.mark.parametrize(
    ("args", "expected_hits", "expected_projects"),
    [
        (["--forks", "include", "-b", "all"], 29, {101, 103, 201, 202, 203, 301}),
        (["--forks", "skip", "-b", "all"], 14, {101, 103, 301}),
        (["--forks", "branch-diff", "-b", "all"], 26, {101, 103, 201, 202, 203, 301}),
        (["--forks", "all-branches", "-b", "all"], 29, {101, 103, 201, 202, 203, 301}),
        # Forks scan every indexed branch, regular projects only the default one.
        (["--forks", "all-branches", "--index-branches", "all", "--scan-branches", "default"], 20,
         {101, 103, 201, 202, 203, 301}),
        (["--forks", "branch-diff", "--index-branches", "all", "--scan-branches", "default"], 9,
         {101, 103, 201, 202, 203, 301}),
    ],
    ids=["include", "skip", "branch-diff", "all-branches", "all-branches-forks-only", "branch-diff-default"],
)
def test_fork_modes(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path, args, expected_hits, expected_projects):
    proc = run_cli(*gl_args(fake_gitlab), "-s", "password", "--session-file", "s.jsonl", *args, check=True)
    s = Session.load(tmp_path / "s.jsonl")
    assert len(s.hits()) == expected_hits
    assert f"Hits: {expected_hits}" in proc.stdout
    assert set(s.project_ids()) == expected_projects
    assert s.records[0]["forks"] == args[1]


def test_custom_fork_diff_bases(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    run_cli(*gl_args(fake_gitlab), "-s", "password", "--session-file", "s.jsonl", "-b", "all", "--forks",
            "branch-diff", "--fork-diff-bases", "main", check=True)
    refs = sorted(r.arg("ref") for r in fake_gitlab.api_requests("project_search", path="/projects/201/"))
    # develop is identical to upstream and no longer a base branch -> skipped.
    assert refs == ["alice/experiment", "main"]


# --------------------------------------------------------------------------- 8. dedup & convert


def test_dedup_and_convert_pipeline(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    run_cli(*gl_args(fake_gitlab), "-s", "password", "-b", "all", "--session-file", "s.jsonl", check=True)
    raw = Session.load(tmp_path / "s.jsonl")
    assert len(raw.hits()) == 29

    proc = run_cli("-m", "dedup", "--input-file", "s.jsonl", "--output-file", "clean.jsonl", check=True)
    assert "[dedup] kept records:" in proc.stdout
    clean = Session.load(tmp_path / "clean.jsonl")
    # Same snippet in many branches/forks collapses to one: 8 distinct snippets.
    assert len(clean.hits()) == 8
    assert len({h["data"] for h in clean.hits()}) == 8
    assert [r["type"] for r in clean.records if "type" in r] == ["meta", "keyword_done", "summary"]
    assert (tmp_path / "clean.jsonl.seen.sqlite").exists()

    proc = run_cli("-m", "convert", "--input-file", "clean.jsonl", "--output-file", "clean.json", "--sort-keys",
                   check=True)
    data = json.loads((tmp_path / "clean.json").read_text(encoding="utf-8"))
    assert data == read_jsonl(tmp_path / "clean.jsonl")
    assert f"[convert] objects: {len(data)}" in proc.stdout


def test_dedup_with_hash_algo_and_without_normalization(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    run_cli(*gl_args(fake_gitlab), "-s", "password", "-b", "all", "--session-file", "s.jsonl", check=True)
    run_cli("-m", "dedup", "--input-file", "s.jsonl", "--output-file", "c.jsonl", "--hash-algo", "sha256",
            "--no-normalize-hits", "--sqlite-path", "cache/seen.db", check=True)
    assert len(Session.load(tmp_path / "c.jsonl").hits()) == 8
    assert (tmp_path / "cache" / "seen.db").exists()


# --------------------------------------------------------------------------- --started-from


@pytest.mark.parametrize(
    ("since", "planned", "skipped", "expected_projects", "expected_hits"),
    [
        ("2024-06-02", 5, "1 empty, 3 inactive since 2024-06-02", {103, 201, 202, 203, 301}, 7),
        # 2024-06-03T00:00+03:00 == 2024-06-02T21:00Z -> 201 (06-02 10:00Z) drops out.
        ("2024-06-03T00:00:00+03:00", 4, "1 empty, 4 inactive since 2024-06-03T00:00:00+03:00",
         {103, 202, 203, 301}, 5),
        # The empty repository is never scanned, so it is not counted as planned.
        ("2024-01-01", 8, "1 empty", {101, 103, 201, 202, 203, 301}, 9),
        ("2030-01-01", 0, "1 empty, 8 inactive since 2030-01-01", set(), 0),
    ],
)
def test_search_started_from(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path, since, planned, skipped,
                             expected_projects, expected_hits):
    proc = run_cli(*gl_args(fake_gitlab), "-s", "password", "--index-file", "idx.jsonl", "--session-file", "s.jsonl",
                   "--started-from", since, check=True)

    # Progress output (stderr) counts only the projects that are really scanned.
    assert f"Search plan: 1 term, {planned} of 9 projects, {planned} branch" in proc.stderr
    assert f"(skipped: {skipped})" in proc.stderr
    assert f"Search finished: 1 term x {planned} project" in proc.stderr
    assert f"Hits: {expected_hits}" in proc.stdout
    s = Session.load(tmp_path / "s.jsonl")
    assert set(s.project_ids()) == expected_projects
    assert s.records[0]["started_from"].startswith(since[:10])
    assert s.of_type("summary")[0]["hits"] == expected_hits

    # The index itself is not filtered and is built with the usual requests.
    _, projects = load_index(tmp_path / "idx.jsonl")
    assert len(projects) == 9
    for r in fake_gitlab.api_requests("projects"):
        assert set(r.query) == {"page", "per_page", "order_by", "sort"}


def test_search_started_from_reuses_full_index(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    """An index built without the filter can be searched with different dates."""
    run_cli(*gl_args(fake_gitlab), "-m", "dump-index", "--index-file", "idx.jsonl", check=True)
    fake_gitlab.clear_journal()
    run_cli(*gl_args(fake_gitlab), "-s", "password", "--index-file", "idx.jsonl", "--session-file", "s.jsonl",
            "--started-from", "2024-06-05", check=True)
    assert fake_gitlab.api_requests("projects") == []  # index reused, not rebuilt
    assert Session.load(tmp_path / "s.jsonl").project_ids() == [301, 103]  # index order (id desc)


def test_search_started_from_invalid_value(run_cli):
    proc = run_cli("-u", "http://127.0.0.1:9", "-t", "x", "-s", "password", "--started-from", "last-week")
    assert proc.returncode == 2
    assert "ISO 8601" in proc.stderr


# --------------------------------------------------------------------------- config file (-c/--config)


def _config(fake: FakeGitLab, tmp_path: Path) -> Path:
    cfg = tmp_path / "conf" / "glh.ini"
    cfg.parent.mkdir()
    cfg.write_text(
        f"""
[connection]
url = {fake.url}
token = env:GLH_E2E_TOKEN
[index]
index-file = idx.jsonl
index-branches = all
[search]
scan-branches = all
forks = skip
terms =
    password
    api_key
[session]
session-file = s.jsonl
""",
        encoding="utf-8",
    )
    return cfg


def test_search_from_config_file_only(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("GLH_E2E_TOKEN", fake_gitlab.token)
    cfg = _config(fake_gitlab, tmp_path)
    proc = run_cli("-c", str(cfg), cwd=tmp_path, check=True)

    # Paths are relative to the config file, not to the working directory.
    session = Session.load(tmp_path / "conf" / "s.jsonl")
    assert (tmp_path / "conf" / "idx.jsonl").exists()
    assert [r["term"] for r in session.of_type("keyword_done")] == ["password", "api_key"]
    assert not {201, 202, 203} & set(session.project_ids())  # forks = skip
    assert session.records[0]["config"] == str(cfg)
    assert "Search plan: 2 terms, 5 of 9 projects" in proc.stderr
    assert "Done. Keywords: 2" in proc.stdout


def test_cli_arguments_override_config_file(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("GLH_E2E_TOKEN", fake_gitlab.token)
    cfg = _config(fake_gitlab, tmp_path)
    proc = run_cli("-c", str(cfg), "-s", "token", "--forks", "include", "--session-file", "cli.jsonl",
                   cwd=tmp_path, check=True)

    session = Session.load(tmp_path / "cli.jsonl")  # CLI path: relative to the working directory
    assert [r["term"] for r in session.of_type("keyword_done")] == ["token"]  # -s replaces config terms
    assert "Search plan: 1 term, 8 of 9 projects" in proc.stderr  # forks included again
    searched = {int(r.path.split("/")[4]) for r in fake_gitlab.api_requests("project_search")}
    assert {201, 202, 203} <= searched
    assert not (tmp_path / "conf" / "s.jsonl").exists()


def test_invalid_config_value_fails_before_any_request(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    cfg = tmp_path / "bad.ini"
    cfg.write_text("[search]\nforks = sometimes\n", encoding="utf-8")
    proc = run_cli("-c", str(cfg), *gl_args(fake_gitlab), "-s", "x")
    assert proc.returncode == 2
    assert "forks" in proc.stderr and "choose from" in proc.stderr
    assert fake_gitlab.requests == []


# --------------------------------------------------------------------------- --workers


def test_parallel_cli_run_matches_sequential_run(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    terms = tmp_path / "terms.txt"
    terms.write_text("password\napi_key\ntoken\n", encoding="utf-8")
    common = [*gl_args(fake_gitlab), "-f", str(terms), "-b", "all", "--forks", "branch-diff", "-bs", "3"]

    run_cli(*common, "--index-file", "seq_idx.jsonl", "--session-file", "seq.jsonl", "-w", "1", check=True)
    proc = run_cli(*common, "--index-file", "par_idx.jsonl", "--session-file", "par.jsonl", "-w", "4", check=True)

    def urls(name: str) -> list[tuple[str, str]]:
        return sorted((h["term"], h["url"]) for h in Session.load(tmp_path / name).hits())

    assert urls("par.jsonl") == urls("seq.jsonl") and urls("par.jsonl")
    assert load_index(tmp_path / "par_idx.jsonl")[1] == load_index(tmp_path / "seq_idx.jsonl")[1]
    par = Session.load(tmp_path / "par.jsonl")
    assert [r["term"] for r in par.of_type("keyword_done")] == ["password", "api_key", "token"]
    assert par.records[0]["workers"] == 4
    assert ", 4 workers" in proc.stderr


@pytest.mark.parametrize("value", ["0", "-1", "65", "many"])
def test_invalid_workers_value(run_cli, value):
    proc = run_cli("-u", "http://127.0.0.1:9", "-t", "x", "-s", "password", "-w", value)
    assert proc.returncode == 2
    assert "integer from 1 to 64" in proc.stderr


# --------------------------------------------------------------------------- time filters


def test_dump_index_for_an_activity_window(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    proc = run_cli(*gl_args(fake_gitlab), "-m", "dump-index", "--index-file", "idx.jsonl",
                   "--index-active-after", "2024-06-01", "--index-active-before", "2024-06-04", check=True)
    meta, projects = load_index(tmp_path / "idx.jsonl")
    assert [p["id"] for p in projects] == [202, 201, 101]
    assert meta["last_activity_after"] == "2024-06-01T00:00:00Z"
    assert "Indexed 3 projects (active 2024-06-01..2024-06-04)" in proc.stderr


def test_group_time_options_filter_index_projects_and_files(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    proc = run_cli(*gl_args(fake_gitlab), "-s", "password", "--index-file", "idx.jsonl", "--session-file", "s.jsonl",
                   "--time-after", "2024-03-01", "--time-before", "2024-06-04T00:00:00Z", check=True)

    # Index: only projects active inside the window (API filter): 102 (05-20), 101 (06-01), 201 (06-02), 202 (06-03).
    meta, projects = load_index(tmp_path / "idx.jsonl")
    assert {p["id"] for p in projects} == {101, 102, 201, 202}
    # Files: deploy/env.example (2024-01-20) is dropped, config/settings.py (2024-03-15) kept.
    urls = [h["url"] for h in Session.load(tmp_path / "s.jsonl").hits()]
    assert not any("env.example" in u for u in urls)
    assert any(u.endswith("config/settings.py#L1") for u in urls)
    assert "files changed 2024-03-01..2024-06-04" in proc.stderr
    meta_rec = Session.load(tmp_path / "s.jsonl").records[0]
    assert meta_rec["file_changed_after"].startswith("2024-03-01") and meta_rec["active_before"].startswith("2024-06-04")


def test_done_line_reports_search_time(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    proc = run_cli(*gl_args(fake_gitlab), "-s", "token", "--index-file", "idx.jsonl", "--session-file", "s.jsonl",
                   check=True)
    import re
    assert re.search(r"Done\. Keywords: 1 \| Hits: \d+ \| Search time: \d+\.\ds", proc.stdout), proc.stdout
    summary = Session.load(tmp_path / "s.jsonl").of_type("summary")[0]
    assert summary["elapsed_seconds"] >= 0


# --------------------------------------------------------------------------- --post-process / --final-only


def _search_with(fake: FakeGitLab, run_cli, *extra: str):
    return run_cli(*gl_args(fake), "-s", "password", "-b", "all", "--index-file", "idx.jsonl",
                   "--session-file", "out/audit.jsonl", *extra, check=True)


def test_post_process_keeps_original_and_intermediate_files(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    proc = _search_with(fake_gitlab, run_cli, "--post-process", "dedup,convert")
    out = tmp_path / "out"
    assert sorted(p.name for p in out.iterdir()) == ["audit.deduped.converted.json", "audit.deduped.jsonl", "audit.jsonl"]

    # Same result as running the post-processing modes by hand.
    run_cli("-m", "dedup", "--input-file", "out/audit.jsonl", "--output-file", "manual.jsonl", check=True)
    run_cli("-m", "convert", "--input-file", "manual.jsonl", "--output-file", "manual.json", check=True)
    assert read_jsonl(out / "audit.deduped.jsonl") == read_jsonl(tmp_path / "manual.jsonl")
    assert json.loads((out / "audit.deduped.converted.json").read_text(encoding="utf-8")) == \
        json.loads((tmp_path / "manual.json").read_text(encoding="utf-8"))

    # Dedup really removed the hits repeated across branches and forks.
    assert len(Session.load(out / "audit.deduped.jsonl").hits()) < len(Session.load(out / "audit.jsonl").hits())
    assert "Post-processing: " in proc.stdout and "Final result: " in proc.stdout
    meta = Session.load(out / "audit.jsonl").records[0]
    assert (meta["post_process"], meta["final_only"]) == (["dedup", "convert"], False)


def test_post_process_final_only_leaves_just_the_result(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    proc = _search_with(fake_gitlab, run_cli, "--post-process", "convert,dedup", "--final-only")
    out = tmp_path / "out"
    assert [p.name for p in out.iterdir()] == ["audit.deduped.converted.json"]
    records = json.loads((out / "audit.deduped.converted.json").read_text(encoding="utf-8"))
    assert records[0]["type"] == "meta" and records[-1]["type"] == "summary"
    assert any("term" in r and "result" in r for r in records)
    assert "Removed (--final-only):" in proc.stdout


def test_post_process_from_config_file(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    cfg = tmp_path / "glh.ini"
    cfg.write_text("[postprocess]\npost-process = convert\nfinal-only = true\nsort-keys = true\n", encoding="utf-8")
    _search_with(fake_gitlab, run_cli, "-c", str(cfg))
    assert [p.name for p in (tmp_path / "out").iterdir()] == ["audit.converted.json"]
    assert (tmp_path / "out" / "audit.converted.json").read_text(encoding="utf-8").startswith('[{"active_before"')  # sort-keys


def test_post_process_is_skipped_when_the_search_fails(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/projects$"}, "response": {"status": 403, "json": {"message": "403"}}})
    proc = run_cli(*gl_args(fake_gitlab), "-s", "password", "--index-file", "idx.jsonl", "--session-file", "s.jsonl",
                   "--post-process", "dedup,convert", "--final-only")
    assert proc.returncode != 0
    assert not list(tmp_path.glob("s.*.json*"))


# --------------------------------------------------------------------------- index line before the search plan


def test_index_file_and_build_time_are_shown_before_the_plan(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    import re

    run_cli(*gl_args(fake_gitlab), "-m", "dump-index", "--index-file", "idx.jsonl", check=True)
    built = load_index(tmp_path / "idx.jsonl")[0]["timestamp_utc"][:19].replace("T", " ")
    proc = run_cli(*gl_args(fake_gitlab), "-s", "token", "--index-file", "idx.jsonl", "--session-file", "s.jsonl",
                   check=True)
    lines = proc.stderr.splitlines()
    index_at = next(i for i, line in enumerate(lines) if line.startswith("Index: "))
    assert lines[index_at + 1].startswith("Search plan: ")
    assert re.fullmatch(rf"Index: idx\.jsonl \(built {built} UTC, just now; 9 projects, branches: default\)",
                        lines[index_at])
