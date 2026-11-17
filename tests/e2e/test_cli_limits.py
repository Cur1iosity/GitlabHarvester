"""-m find-limits and --auto-limits through the CLI against a rate-limited Fake GitLab."""

from __future__ import annotations

from pathlib import Path

from fakegitlab import FakeGitLab
from tests.helpers import read_jsonl

SHORT_LIMITS = {
    "api": {"limit": 400, "period": 60, "on_success": True},  # announced: no load needed
    "search": {"limit": 4, "period": 2},
}


def test_find_limits_prints_settings_command_and_config(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    fake_gitlab.set_rate_limits(SHORT_LIMITS)
    proc = run_cli("-m", "find-limits", "-u", fake_gitlab.url, "-t", fake_gitlab.token, "--log-file", "run.log",
                   check=True)
    out = proc.stdout
    assert "other API: ~400 requests per minute per user (GitLab headers" in out
    assert "search API: ~4 requests per" in out and "full window counted" in out
    assert "Suggested settings: --workers" in out
    command = next(line for line in out.splitlines() if line.startswith("Command: "))
    assert "-t '<TOKEN>'" in command or "-t <TOKEN>" in command
    assert "--auto-limits --workers" in command and "find-limits" not in command
    assert "workers = " in out and "search-rpm = " in out
    assert fake_gitlab.token not in out + proc.stderr
    assert "Rate-limit detection is EXPERIMENTAL" in proc.stderr
    journal = (tmp_path / "run.log").read_text(encoding="utf-8")
    assert "Suggested settings" in journal and fake_gitlab.token not in journal
    assert "EXPERIMENTAL" in journal
    assert fake_gitlab.unmatched_requests() == []


def test_auto_limits_without_a_terminal_prints_the_command_and_stops(fake_gitlab: FakeGitLab, run_cli,
                                                                   tmp_path: Path):
    fake_gitlab.set_rate_limits(SHORT_LIMITS)
    proc = run_cli("-u", fake_gitlab.url, "-t", fake_gitlab.token, "-s", "password", "--auto-limits",
                   "--probe-apis", "search")
    assert proc.returncode != 0
    assert "no terminal to confirm" in proc.stderr
    assert "Command: " in proc.stdout and "-s password" in proc.stdout
    assert not (tmp_path / "results").exists()  # nothing was searched


def test_auto_limits_with_everything_set_only_watches(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    proc = run_cli("-u", fake_gitlab.url, "-t", fake_gitlab.token, "-s", "password", "--auto-limits",
                   "--workers", "2", "--index-rpm", "0", "--search-rpm", "0", "--session-file", "s.jsonl",
                   check=True)
    assert "nothing to measure; watching the run for HTTP 429" in proc.stderr
    assert "EXPERIMENTAL" in proc.stderr
    meta = read_jsonl(tmp_path / "s.jsonl")[0]
    assert meta["auto_limits"] is True and meta["workers"] == 2
    assert fake_gitlab.api_requests("project_search")  # the search ran


def test_dump_index_with_auto_limits_measures_the_index_api_only(fake_gitlab: FakeGitLab, run_cli):
    fake_gitlab.set_rate_limits(SHORT_LIMITS)
    proc = run_cli("-m", "dump-index", "-u", fake_gitlab.url, "-t", fake_gitlab.token, "--auto-limits",
                   "--workers", "1")
    assert "other API: ~400 requests per minute" in proc.stdout
    assert "search API" not in proc.stdout
