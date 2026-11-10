"""Standalone Fake GitLab (``python -m fakegitlab``) and its diagnostics endpoints."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import requests

from fakegitlab import FakeGitLab
from tests.conftest import REPO_ROOT, cli_env, kill_process_tree


def admin(fake: FakeGitLab, method: str, path: str, **kw) -> requests.Response:
    return requests.request(method, f"{fake.url}/__admin{path}", timeout=5, **kw)


def test_admin_journal_redacts_tokens(fake_gitlab: FakeGitLab):
    requests.get(f"{fake_gitlab.url}/api/v4/user", headers={"PRIVATE-TOKEN": "dev-token"}, timeout=5)
    requests.get(f"{fake_gitlab.url}/api/v4/not-implemented", headers={"PRIVATE-TOKEN": "dev-token"}, timeout=5)

    journal = admin(fake_gitlab, "GET", "/requests").json()
    assert [(r["path"], r["status"], r["endpoint"]) for r in journal] == [
        ("/api/v4/user", 200, "user"), ("/api/v4/not-implemented", 404, None)]
    assert journal[0]["headers"]["Private-Token"] == "<redacted>"
    # Admin calls themselves are not journaled.
    assert len(admin(fake_gitlab, "GET", "/requests").json()) == 2
    admin(fake_gitlab, "DELETE", "/requests")
    assert admin(fake_gitlab, "GET", "/requests").json() == []


def test_admin_faults_and_reset(fake_gitlab: FakeGitLab):
    r = admin(fake_gitlab, "POST", "/faults", json={"name": "boom", "match": {"path": "^/api/v4/user$"},
                                                    "response": {"status": 503}})
    assert r.status_code == 201
    assert requests.get(f"{fake_gitlab.url}/api/v4/user", timeout=5).status_code == 503
    assert admin(fake_gitlab, "GET", "/faults").json()[0]["applied"] == 1

    assert admin(fake_gitlab, "POST", "/faults", json={"match": {"path": "("}}).status_code == 400
    admin(fake_gitlab, "POST", "/reset")
    assert admin(fake_gitlab, "GET", "/faults").json() == []
    assert requests.get(f"{fake_gitlab.url}/api/v4/user", headers={"PRIVATE-TOKEN": "dev-token"},
                        timeout=5).status_code == 200


def test_admin_scenario_switch(fake_gitlab: FakeGitLab):
    info = admin(fake_gitlab, "GET", "/scenario").json()
    assert info["name"] == "default" and info["projects"] == 9 and "flaky" in info["available"]

    switched = admin(fake_gitlab, "POST", "/scenario", json={"name": "empty"}).json()
    assert switched["name"] == "empty" and switched["projects"] == 0
    assert admin(fake_gitlab, "POST", "/scenario", json={"name": "nope"}).status_code == 400
    assert admin(fake_gitlab, "GET", "/health").json() == {"status": "ok", "scenario": "empty"}


def test_standalone_entry_point(tmp_path: Path):
    err_log = (tmp_path / "stderr.log").open("wb")
    proc = subprocess.Popen(
        [sys.executable, "-m", "fakegitlab", "--port", "0", "--scenario", "large"],
        cwd=str(REPO_ROOT), env=cli_env(), stdout=subprocess.PIPE, stderr=err_log, text=True, encoding="utf-8",
    )
    try:
        assert proc.stdout is not None
        first = proc.stdout.readline()
        m = re.search(r"Fake GitLab is up: (http://\S+)", first)
        assert m, first
        url = m.group(1)
        r = requests.get(f"{url}/api/v4/projects", headers={"PRIVATE-TOKEN": "dev-token"},
                         params={"per_page": 100}, timeout=5)
        assert r.status_code == 200 and r.headers["X-Total"] == "259"
        assert requests.get(f"{url}/__admin/health", timeout=5).json()["scenario"] == "large"
    finally:
        kill_process_tree(proc)
        proc.wait(timeout=15)
        err_log.close()
    assert "GET /api/v4/projects" in (tmp_path / "stderr.log").read_text(encoding="utf-8")


def test_list_scenarios_cli():
    out = subprocess.run([sys.executable, "-m", "fakegitlab", "--list-scenarios"], cwd=str(REPO_ROOT),
                         env=cli_env(), capture_output=True, text=True, check=True).stdout.split()
    assert {"default", "empty", "flaky", "large"} <= set(out)
