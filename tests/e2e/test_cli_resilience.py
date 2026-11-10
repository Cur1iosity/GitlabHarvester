"""
End-to-end failure scenarios: interruption + resume, API errors, bad input.

Delays use the Fake GitLab fault injector and are bounded (a reset aborts
pending delays), so no test waits on real timeouts longer than ~1 s.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from fakegitlab import FakeGitLab
from tests.conftest import cli_env, kill_process_tree
from glh.session import load_done_keywords
from tests.helpers import PASSWORD_HITS_DEFAULT_BRANCH, Session, load_index


def gl_args(fake: FakeGitLab) -> list[str]:
    return ["-u", fake.url, "-t", fake.token]


def wait_for(predicate, timeout: float = 30.0, interval: float = 0.05) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise AssertionError("condition not met in time")


class BackgroundCli:
    """
    A CLI process running in the background.

    Output goes to files, not pipes: nobody reads the pipes while the test
    polls, and a full pipe buffer would block the CLI on its progress output.
    """

    def __init__(self, args: list[str], cwd: Path) -> None:
        self._out_path, self._err_path = cwd / ".cli-stdout.log", cwd / ".cli-stderr.log"
        self._out, self._err = self._out_path.open("wb"), self._err_path.open("wb")
        self.proc = subprocess.Popen([sys.executable, "-m", "gitlab_harvester", *args],
                                     cwd=str(cwd), env=cli_env(), stdout=self._out, stderr=self._err)

    def poll(self) -> int | None:
        return self.proc.poll()

    def finish(self, *, kill: bool = False, timeout: float = 30) -> tuple[int, str, str]:
        """Stop (or wait for) the process and return (returncode, stdout, stderr)."""
        if kill:
            kill_process_tree(self.proc)
        self.proc.wait(timeout=timeout)
        self._out.close()
        self._err.close()
        out = self._out_path.read_text(encoding="utf-8", errors="replace")
        err = self._err_path.read_text(encoding="utf-8", errors="replace")
        self._out_path.unlink()
        self._err_path.unlink()
        return self.proc.returncode, out, err


def session_has_done(path: Path, term: str) -> bool:
    """True once the keyword checkpoint is on disk (tolerates a half-written last line)."""
    return term in load_done_keywords(path)


def fault_in_flight(fake: FakeGitLab, name: str) -> bool:
    """
    True once a fault rule has been applied to at least one request.

    The request journal records a request only after its response is sent, so
    a request held by a delay fault is visible through the rule counters only.
    """
    return any(f["name"] == name and f["applied"] > 0 for f in fake.faults)


# --------------------------------------------------------------------------- 7. resume


def test_interrupted_session_resumes_remaining_keywords(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    (tmp_path / "terms.txt").write_text("password\napi_key\nFAKE-token\n", encoding="utf-8")
    session = tmp_path / "audit.jsonl"
    args = [*gl_args(fake_gitlab), "-f", "terms.txt", "--index-file", "idx.jsonl", "--session-file", "audit.jsonl"]

    # Hang the first search request of the second keyword, then kill the process.
    fake_gitlab.add_fault({"name": "hang-api-key", "match": {"path": "/search$", "query": {"search": "api_key"}},
                           "response": {"delay": 60}})
    cli = BackgroundCli(args, tmp_path)
    try:
        wait_for(lambda: fault_in_flight(fake_gitlab, "hang-api-key") or cli.poll() is not None)
        assert cli.poll() is None, "CLI exited before reaching the second keyword"
        # The checkpoint of the finished keyword must already be durable.
        assert session_has_done(session, "password")
    finally:
        cli.finish(kill=True)  # hard kill: no cleanup handlers, no buffer flush

    interrupted = Session.load(session)
    assert [d["term"] for d in interrupted.of_type("keyword_done")] == ["password"]
    assert interrupted.of_type("summary") == []

    # Resume against a healthy server.
    fake_gitlab.reset()
    proc2 = run_cli(*args, "--resume", check=True)

    searched = {r.arg("search") for r in fake_gitlab.api_requests("project_search")}
    assert searched == {"api_key", "FAKE-token"}  # completed keyword is not repeated
    assert fake_gitlab.api_requests("projects") == []  # existing index reused
    assert "Done. Keywords: 2" in proc2.stdout

    s = Session.load(session)
    assert [r.get("type") for r in s.records if r.get("type")] == [
        "meta", "keyword_done", "resume", "keyword_done", "keyword_done", "summary"]
    resume = s.of_type("resume")[0]
    assert (resume["done_keywords"], resume["remaining_keywords"]) == (1, 2)
    assert [d["term"] for d in s.of_type("keyword_done")] == ["password", "api_key", "FAKE-token"]
    assert len(s.hits("password")) == sum(PASSWORD_HITS_DEFAULT_BRANCH.values())
    assert set(s.project_ids("FAKE-token")) == {102}


def test_resume_with_everything_done_is_a_noop(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    args = [*gl_args(fake_gitlab), "-s", "password", "--session-file", "s.jsonl"]
    run_cli(*args, check=True)
    before = (tmp_path / "s.jsonl").read_text(encoding="utf-8")
    fake_gitlab.clear_journal()

    proc = run_cli(*args, "--resume", check=True)
    assert "Nothing to resume" in proc.stdout
    assert (tmp_path / "s.jsonl").read_text(encoding="utf-8") == before
    assert fake_gitlab.api_requests("project_search") == []


def test_resume_without_existing_session_starts_fresh(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    run_cli(*gl_args(fake_gitlab), "-s", "password", "--session-file", "new.jsonl", "--resume", check=True)
    s = Session.load(tmp_path / "new.jsonl")
    assert s.records[0]["type"] == "resume" and s.records[0]["done_keywords"] == 0
    assert len(s.hits()) == 9


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal delivery")
def test_sigint_exits_with_130_and_keeps_partial_session(fake_gitlab: FakeGitLab, tmp_path: Path):
    fake_gitlab.add_fault({"name": "hang", "match": {"path": "/projects/101/search$"}, "response": {"delay": 60}})
    cli = BackgroundCli([*gl_args(fake_gitlab), "-s", "password", "--session-file", "s.jsonl"], tmp_path)
    wait_for(lambda: fault_in_flight(fake_gitlab, "hang") or cli.poll() is not None)
    # The harvester is blocked inside a request; deliver Ctrl+C.
    os.kill(cli.proc.pid, signal.SIGINT)
    fake_gitlab.reset()  # release the delayed request
    code, _, err = cli.finish()
    assert code == 130
    assert "Interrupted" in err
    s = Session.load(tmp_path / "s.jsonl")
    assert s.records[0]["type"] == "meta" and s.of_type("summary") == []


# --------------------------------------------------------------------------- errors


def test_invalid_token_fails_without_output_files(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    proc = run_cli("-u", fake_gitlab.url, "-t", "wrong-token", "-s", "password")
    assert proc.returncode != 0
    assert "401" in proc.stderr
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["-s", "password"], "requires --url and --token"),
        (["-m", "dedup"], "--input-file"),
        (["-m", "convert", "--input-file", "x.jsonl"], "--output-file"),
    ],
)
def test_missing_arguments(run_cli, argv, message):
    proc = run_cli(*argv)
    assert proc.returncode == 1
    assert message in proc.stderr


def test_nothing_to_search(fake_gitlab: FakeGitLab, run_cli):
    proc = run_cli(*gl_args(fake_gitlab))
    assert proc.returncode == 1 and "Nothing to do" in proc.stderr


@pytest.mark.scenario("empty")
def test_empty_instance_reports_empty_index(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    proc = run_cli(*gl_args(fake_gitlab), "-s", "password", "--index-file", "idx.jsonl")
    assert proc.returncode == 1 and "Project index is empty" in proc.stderr
    meta, projects = load_index(tmp_path / "idx.jsonl")
    assert projects == [] and meta["is_completed"] is True


def test_unreachable_server(run_cli, tmp_path: Path):
    import socket

    with socket.socket() as s:  # grab a free port, then close it
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = run_cli("-u", f"http://127.0.0.1:{port}", "-t", "x", "-s", "password", "--timeout", "2")
    assert proc.returncode != 0
    # Linux: "Connection refused"; Windows retries SYNs and reports a connect timeout.
    assert "requests.exceptions.Connect" in proc.stderr


def test_partial_failures_still_produce_a_complete_session(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/projects$", "query": {"page": "2"}}, "times": 1,
                           "response": {"status": 429, "headers": {"Retry-After": "0"}}})
    fake_gitlab.add_fault({"match": {"path": "/projects/301/search$"},
                           "response": {"status": 500, "json": {"message": "500 Internal Server Error"}}})
    fake_gitlab.add_fault({"match": {"path": "/projects/203/search$"}, "response": {"body": "<html>oops"}})
    fake_gitlab.add_fault({"match": {"path": "/projects/202/search$"}, "times": 1, "response": {"delay": 3}})

    proc = run_cli(*gl_args(fake_gitlab), "-s", "password", "-bs", "3", "--timeout", "1", "--index-file",
                   "idx.jsonl", "--session-file", "s.jsonl", "--log-level", "WARN", check=True)

    meta, projects = load_index(tmp_path / "idx.jsonl")
    assert meta["is_completed"] is True and len(projects) == 9  # 429 was retried
    s = Session.load(tmp_path / "s.jsonl")
    expected = {k: v for k, v in PASSWORD_HITS_DEFAULT_BRANCH.items() if k not in {301, 203, 202}}
    assert {pid: sum(1 for h in s.hits() if h["project_id"] == pid) for pid in s.project_ids()} == expected
    assert s.of_type("summary")[0]["hits"] == sum(expected.values())
    assert "ops/infra/terraform/modules" in proc.stdout + proc.stderr  # warnings are visible


def test_failed_project_listing_is_flagged_incomplete(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    fake_gitlab.add_fault({"match": {"path": "^/api/v4/projects$", "query": {"page": "2"}},
                           "response": {"status": 502, "body": "Bad Gateway"}})
    run_cli(*gl_args(fake_gitlab), "-m", "dump-index", "-bs", "4", "--index-file", "idx.jsonl", check=True)
    meta, projects = load_index(tmp_path / "idx.jsonl")
    assert meta["is_completed"] is False and len(projects) == 4

    # A later search reuses the index but warns that it is incomplete.
    fake_gitlab.clear_faults()
    proc = run_cli(*gl_args(fake_gitlab), "-s", "password", "--index-file", "idx.jsonl", "--session-file",
                   "s.jsonl", check=True)
    assert "incomplete" in proc.stdout + proc.stderr


@pytest.mark.scenario("flaky")
def test_flaky_scenario_completes(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    proc = run_cli(*gl_args(fake_gitlab), "-s", "password", "-b", "all", "-bs", "5", "--session-file", "s.jsonl",
                   check=True)
    s = Session.load(tmp_path / "s.jsonl")
    assert s.of_type("summary")
    assert 102 not in s.project_ids()  # branches listing failed -> nothing to scan
    applied = {name for r in fake_gitlab.requests for name in r.faults}
    assert applied == {"projects-rate-limited", "payments-branches-unavailable", "terraform-search-slow",
                       "web-app-search-garbage"}
    assert "Done." in proc.stdout


# --------------------------------------------------------------------------- legacy console encodings (Windows)


def _legacy_console_env(encoding: str) -> dict[str, str]:
    env = cli_env()
    env.pop("PYTHONUTF8", None)
    env["PYTHONIOENCODING"] = encoding  # what a redirected cmd.exe/PowerShell console uses
    return env


@pytest.mark.parametrize("encoding", ["cp1252", "cp866"])
def test_help_works_on_legacy_code_pages(encoding, tmp_path):
    proc = subprocess.run([sys.executable, "-m", "gitlab_harvester", "--help"], cwd=str(tmp_path),
                          env=_legacy_console_env(encoding), capture_output=True)
    assert proc.returncode == 0, proc.stderr.decode(encoding, "replace")
    out = proc.stdout.decode(encoding)
    assert "GitlabHarvester v" in out and "--time-after" in out


@pytest.mark.parametrize("encoding", ["cp1252", "cp866"])
def test_search_output_survives_legacy_code_pages(fake_gitlab, encoding, tmp_path):
    """Banner, progress and log lines with non-encodable branch names must not crash."""
    proc = subprocess.run(
        [sys.executable, "-m", "gitlab_harvester", "-u", fake_gitlab.url, "-t", fake_gitlab.token,
         "-s", "ключ", "-b", "all", "--log-level", "INFO", "--index-file", "idx.jsonl", "--session-file", "s.jsonl"],
        cwd=str(tmp_path), env=_legacy_console_env(encoding), capture_output=True, timeout=90,
    )
    out, err = proc.stdout.decode(encoding, "strict"), proc.stderr.decode(encoding, "strict")
    assert proc.returncode == 0, err
    assert "Logging error" not in out + err and "UnicodeEncodeError" not in out + err
    assert err.lstrip().startswith("GitlabHarvester v")  # plain banner instead of escaped box characters
    assert "Done. Keywords: 1 | Hits: 1" in out
