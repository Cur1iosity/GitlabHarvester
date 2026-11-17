"""
End-to-end: file filters (--filename, --extension) and downloads (--download-files,
--download-max-size) with the real CLI against the Fake GitLab.
"""

from __future__ import annotations

import re
from pathlib import Path

from fakegitlab import FakeGitLab
from tests.helpers import Session, row


def gl_args(fake: FakeGitLab) -> list[str]:
    return ["-u", fake.url, "-t", fake.token, "--index-file", "idx.jsonl"]


def files_under(root: Path) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())


def settings_py(fake: FakeGitLab) -> bytes:
    return fake.scenario.project_by_id(101).branches["main"]["config/settings.py"].encode("utf-8")


def test_extension_filter_and_downloads(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    proc = run_cli(*gl_args(fake_gitlab), "-s", "password", "--extension", ".py", "--download-files",
                   "--session", "audit", check=True)

    assert (row(proc.stdout, "Results", "terms"), row(proc.stdout, "Results", "hits")) == ("1", "2")
    assert re.fullmatch(r"2 files \(\d+ B\) in .*<term>.files", row(proc.stdout, "Results", "downloaded"))
    assert row(proc.stderr, "Search plan", "files") == "extension py"
    assert row(proc.stderr, "Search plan", "downloads").endswith("files (max 10 MiB each)")

    s = Session.load(tmp_path / "audit.jsonl")
    meta = s.records[0]
    assert (meta["filename"], meta["extension"]) == (None, "py")
    assert meta["download_files"] is True and meta["download_max_size"] == 10 * 1024 ** 2

    stamp = r"\d{14}"
    names = [p.name for p in (tmp_path / "password" / "files").iterdir()]
    assert sorted(re.sub(stamp, "<ts>", n) for n in names) == [
        "acme_backend_api-service_main_<ts>_password_config_settings.py",
        "alice_api-service_main_<ts>_password_config_settings.py",
    ]
    for h in s.hits():
        local = tmp_path / h["file"]
        assert local.read_bytes() == settings_py(fake_gitlab)
    # A single term without --output-separated: no per-term session copy.
    assert files_under(tmp_path / "password") == [f"files/{n}" for n in sorted(names)]


def test_default_location_uses_results_and_the_session_timestamp(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    run_cli(*gl_args(fake_gitlab), "-s", "password", "--filename", "settings.py", "--download-files", check=True)
    results = tmp_path / "results"
    [session] = list(results.glob("*.jsonl"))
    stamp = re.search(r"_session_(\d{14})\.jsonl$", session.name).group(1)
    downloaded = files_under(results / "password" / "files")
    assert downloaded == sorted([
        f"acme_backend_api-service_main_{stamp}_password_config_settings.py",
        f"alice_api-service_main_{stamp}_password_config_settings.py",
    ])


def test_output_separated_and_downloads_share_the_term_directories(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    (tmp_path / "terms.txt").write_text("password\napi_key\nnothing-matches\n", encoding="utf-8")
    proc = run_cli(*gl_args(fake_gitlab), "-f", "terms.txt", "--session-file", "out/audit.jsonl",
                   "--output-separated", "--download-files", check=True)
    out = tmp_path / "out"
    tree = files_under(out)
    assert "audit.jsonl" in tree
    assert "password/audit.jsonl" in tree and "api_key/audit.jsonl" in tree
    assert any(t.startswith("password/files/") for t in tree)
    assert any(t.startswith("api_key/files/") for t in tree)
    assert not (out / "nothing-matches").exists()
    assert row(proc.stdout, "Results", "term files").startswith("2 files in ")
    assert "password/audit.jsonl" in row(proc.stdout, "Results", "term files")

    session = Session.load(out / "audit.jsonl")
    per = Session.load(out / "password" / "audit.jsonl")
    assert per.hits() == session.hits("password")
    for h in session.hits():
        assert (tmp_path / h["file"]).is_file()


def test_size_limit_skips_big_files(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    proc = run_cli(*gl_args(fake_gitlab), "-s", "password", "--extension", "py", "--download-files",
                   "--download-max-size", "10", "--session", "audit", check=True)
    downloaded = row(proc.stdout, "Results", "downloaded")
    assert downloaded.startswith("0 files (0 B) in ") and downloaded.endswith(" | 2 skipped: larger than 10 B")
    assert not (tmp_path / "password").exists() or files_under(tmp_path / "password") == []
    assert all("file" not in h for h in Session.load(tmp_path / "audit.jsonl").hits())


def test_filters_from_config_file(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    (tmp_path / "c.ini").write_text(
        f"[connection]\nurl = {fake_gitlab.url}\ntoken = {fake_gitlab.token}\n"
        "[search]\nsearch = password\nfilename = *.tf\n"
        "[session]\nsession = audit\ndownload-files = true\ndownload-max-size = 1M\n",
        encoding="utf-8",
    )
    run_cli("-c", "c.ini", "--index-file", "idx.jsonl", check=True)
    s = Session.load(tmp_path / "audit.jsonl")
    assert {h["project_id"] for h in s.hits()} == {301}
    assert s.records[0]["download_max_size"] == 1024 ** 2
    [name] = [p.name for p in (tmp_path / "password" / "files").iterdir()]
    assert name.endswith("_password_variables.tf")


def test_invalid_values_fail_before_any_request(fake_gitlab: FakeGitLab, run_cli):
    for args in (["--filename", "my file"], ["--extension", "."], ["--download-max-size", "10X"]):
        proc = run_cli(*gl_args(fake_gitlab), "-s", "password", *args)
        assert proc.returncode == 2, args
        assert args[0] in proc.stderr
    assert fake_gitlab.requests == []


def test_resume_with_other_filters_warns(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    run_cli(*gl_args(fake_gitlab), "-s", "password", "--extension", "py", "--session", "audit", check=True)
    proc = run_cli(*gl_args(fake_gitlab), "-s", "password", "--extension", "md", "--session", "audit",
                   "--resume", check=True)
    # The harvester's console log handler writes to stdout.
    assert "other filters (extension md) than it was started with (extension py)" in proc.stdout + proc.stderr
    proc = run_cli(*gl_args(fake_gitlab), "-s", "password", "--extension", "py", "--session", "audit",
                   "--resume", check=True)
    assert "other filters" not in proc.stdout + proc.stderr


def test_run_journal_records_filters_and_downloads(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    run_cli(*gl_args(fake_gitlab), "-s", "password", "--filename", "*.py", "--download-files",
            "--session", "audit", "--log-file", "run.log", check=True)
    journal = (tmp_path / "run.log").read_text(encoding="utf-8")
    assert "filename=*.py" in journal and "download-files=True" in journal and "download-max-size=10 MiB" in journal
    assert "Search plan: terms 1; files filename *.py; " in journal
    assert "; downloaded 2 files (" in journal
    assert fake_gitlab.token not in journal


# --------------------------------------------------------------------------- --to-zip


def zip_names(path: Path) -> list[str]:
    import zipfile

    with zipfile.ZipFile(path) as zf:
        assert zf.testzip() is None
        return sorted(zf.namelist())


def test_to_zip_packs_session_term_files_and_downloads(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    (tmp_path / "terms.txt").write_text("password\napi_key\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    (out / "older_session.jsonl").write_text("{}\n", encoding="utf-8")  # not this run: left out
    proc = run_cli(*gl_args(fake_gitlab), "-f", "terms.txt", "--session-file", "out/audit.jsonl",
                   "--output-separated", "--download-files", "--post-process", "dedup", "--to-zip",
                   "--log-file", "run.log", check=True)
    assert re.match(r"out[\\/]audit\.zip \(\d+ files, .* -> .*\), packed in ", row(proc.stdout, "Results", "archive"))
    members = zip_names(out / "audit.zip")
    on_disk = [t for t in files_under(out) if t not in ("audit.zip", "older_session.jsonl")]
    assert members == on_disk  # everything this run wrote, in the same layout
    assert {"audit.jsonl", "audit.deduped.jsonl", "password/audit.jsonl", "api_key/audit.jsonl"} <= set(members)
    assert any(m.startswith("password/files/") for m in members)
    assert Session.load(out / "audit.jsonl").records[0]["to_zip"] is True
    assert "; archive out" in (tmp_path / "run.log").read_text(encoding="utf-8")


def test_to_zip_with_final_only_keeps_the_final_file_and_downloads(fake_gitlab: FakeGitLab, run_cli,
                                                                   tmp_path: Path):
    run_cli(*gl_args(fake_gitlab), "-s", "password", "--extension", "py", "--download-files", "--session", "audit",
            "--post-process", "dedup,convert", "--final-only", "--to-zip", check=True)
    members = zip_names(tmp_path / "audit.zip")
    assert "audit.deduped.converted.json" in members
    assert "audit.jsonl" not in members and "audit.deduped.jsonl" not in members
    assert len([m for m in members if m.startswith("password/files/")]) == 2
    assert not any(m.endswith(".sqlite") or m in ("idx.jsonl",) for m in members)


def test_to_zip_from_the_config_file(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    cfg = tmp_path / "glh.ini"
    cfg.write_text("[session]\nsession = audit\n[postprocess]\nto-zip = true\n", encoding="utf-8")
    run_cli("-c", str(cfg), *gl_args(fake_gitlab), "-s", "password", check=True)
    assert zip_names(tmp_path / "audit.zip") == ["audit.jsonl"]
    run_cli("-c", str(cfg), *gl_args(fake_gitlab), "-s", "password", "--session", "again", "--no-to-zip",
            check=True)
    assert not (tmp_path / "again.zip").exists()


# --------------------------------------------------------------------------- --project-filter


def test_project_filter_searches_only_matching_projects_of_the_index(fake_gitlab: FakeGitLab, run_cli,
                                                                     tmp_path: Path):
    run_cli(*gl_args(fake_gitlab), "-m", "dump-index", check=True)
    fake_gitlab.clear_journal()
    proc = run_cli(*gl_args(fake_gitlab), "-s", "password", "--session", "s", "--project-filter", "API-SERVICE",
                   check=True)
    assert "not matching --project-filter API-SERVICE" in proc.stderr
    searched = {r.path.split("/")[4] for r in fake_gitlab.api_requests("project_search")}
    assert searched == {"101", "201"}  # acme/backend/api-service, alice/api-service
    assert not fake_gitlab.api_requests("projects")  # the index was reused, not rebuilt
    s = Session.load(tmp_path / "s.jsonl")
    assert s.records[0]["project_filter"] == ["API-SERVICE"]
    assert {h["project_id"] for h in s.hits()} == {101, 201}


# --------------------------------------------------------------------------- no term: files by name


def test_files_by_name_without_a_term(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    proc = run_cli(*gl_args(fake_gitlab), "--filename", "settings.py", "--download-files", "--session", "s",
                   "--to-zip", check=True)
    assert row(proc.stderr, "Search plan", "files") == "every file matching filename settings.py (no term)"
    assert row(proc.stderr, "Search plan", "listing") == "auto"
    assert "files listed:" in proc.stderr
    s = Session.load(tmp_path / "s.jsonl")
    meta = s.records[0]
    assert meta["files_only"] is True and meta["file_listing"] == "auto"
    hits = s.hits("filename:settings.py")
    assert hits and all(h["data"] == "" and (tmp_path / h["file"]).is_file() for h in hits)
    assert any(t.startswith("filename_settings.py/files/") for t in zip_names(tmp_path / "s.zip"))


def test_no_term_and_no_file_filter_is_still_an_error(fake_gitlab: FakeGitLab, run_cli):
    proc = run_cli(*gl_args(fake_gitlab))
    assert proc.returncode != 0 and "only --filename/--extension to collect files by name" in proc.stderr
