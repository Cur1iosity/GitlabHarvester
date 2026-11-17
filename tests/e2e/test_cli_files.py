"""
End-to-end: file filters (--filename, --extension) and downloads (--download-files,
--download-max-size) with the real CLI against the Fake GitLab.
"""

from __future__ import annotations

import re
from pathlib import Path

from fakegitlab import FakeGitLab
from tests.helpers import Session


def gl_args(fake: FakeGitLab) -> list[str]:
    return ["-u", fake.url, "-t", fake.token, "--index-file", "idx.jsonl"]


def files_under(root: Path) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())


def settings_py(fake: FakeGitLab) -> bytes:
    return fake.scenario.project_by_id(101).branches["main"]["config/settings.py"].encode("utf-8")


def test_extension_filter_and_downloads(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    proc = run_cli(*gl_args(fake_gitlab), "-s", "password", "--extension", ".py", "--download-files",
                   "--session", "audit", check=True)

    assert "Done. Keywords: 1 | Hits: 2" in proc.stdout
    assert re.search(r"Downloaded files: 2 files \(\d+ B\) downloaded to .*<term>.files", proc.stdout)
    assert "files: extension py" in proc.stderr and "download files to" in proc.stderr

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
    assert "Separated output: 2 term files" in proc.stdout and "password/audit.jsonl" in proc.stdout

    session = Session.load(out / "audit.jsonl")
    per = Session.load(out / "password" / "audit.jsonl")
    assert per.hits() == session.hits("password")
    for h in session.hits():
        assert (tmp_path / h["file"]).is_file()


def test_size_limit_skips_big_files(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    proc = run_cli(*gl_args(fake_gitlab), "-s", "password", "--extension", "py", "--download-files",
                   "--download-max-size", "10", "--session", "audit", check=True)
    assert "0 files (0 B) downloaded" in proc.stdout and "2 skipped: larger than 10 B" in proc.stdout
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
    assert "other file filters (extension md) than it was started with (extension py)" in proc.stdout + proc.stderr
    proc = run_cli(*gl_args(fake_gitlab), "-s", "password", "--extension", "py", "--session", "audit",
                   "--resume", check=True)
    assert "other file filters" not in proc.stdout + proc.stderr


def test_run_journal_records_filters_and_downloads(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    run_cli(*gl_args(fake_gitlab), "-s", "password", "--filename", "*.py", "--download-files",
            "--session", "audit", "--log-file", "run.log", check=True)
    journal = (tmp_path / "run.log").read_text(encoding="utf-8")
    assert "filename=*.py" in journal and "download-files=True" in journal and "download-max-size=10 MiB" in journal
    assert "Search plan:" in journal and "files: filename *.py" in journal
    assert "Downloaded files: 2 files" in journal
    assert fake_gitlab.token not in journal
