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
