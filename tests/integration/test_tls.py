"""TLS verification: never disabled silently; --ca-bundle and --insecure are explicit."""

from __future__ import annotations

import ssl
import subprocess
import sys
from pathlib import Path
from typing import Iterator

import pytest

from fakegitlab import FakeGitLab
from glh import GitlabHarvester
from glh.exceptions import GitlabHarvesterError
from glh.planner import ScanOptions
from tests.conftest import cli_env

trustme = pytest.importorskip("trustme")


@pytest.fixture(scope="module")
def ca():
    return trustme.CA()


@pytest.fixture(scope="module")
def https_gitlab(ca) -> Iterator[FakeGitLab]:
    """Fake GitLab over HTTPS with a certificate from a private test CA."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ca.issue_cert("127.0.0.1", "localhost").configure_cert(context)
    server = FakeGitLab("default", ssl_context=context).start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def fake(https_gitlab: FakeGitLab) -> Iterator[FakeGitLab]:
    https_gitlab.reset()
    yield https_gitlab


@pytest.fixture
def ca_file(ca, tmp_path: Path) -> Path:
    path = tmp_path / "private-ca.pem"
    ca.cert_pem.write_to_path(str(path))
    return path


def test_untrusted_certificate_is_an_error_without_silent_fallback(fake: FakeGitLab):
    assert fake.url.startswith("https://")
    with pytest.raises(GitlabHarvesterError) as e:
        GitlabHarvester(url=fake.url, token=fake.token, timeout=5)
    message = str(e.value)
    assert "TLS certificate verification failed" in message
    assert "--ca-bundle" in message and "--insecure" in message
    # The handshake failed, and no unverified retry reached the server.
    assert fake.requests == []


def test_private_ca_bundle(fake: FakeGitLab, ca_file: Path):
    glh = GitlabHarvester(url=fake.url, token=fake.token, timeout=5, ssl_verify=str(ca_file))
    assert [r.endpoint for r in fake.requests] == ["user"]
    projects = glh.fetch_projects(per_page=100)
    assert len(projects) == 9


def test_insecure_is_explicit_and_warned(fake: FakeGitLab, tmp_path: Path):
    log = tmp_path / "glh.log"
    GitlabHarvester(url=fake.url, token=fake.token, timeout=5, ssl_verify=False, log_file=str(log))
    assert [r.endpoint for r in fake.requests] == ["user"]
    assert "TLS certificate verification is DISABLED" in log.read_text(encoding="utf-8")


def test_workers_keep_the_verification_settings(fake: FakeGitLab, ca_file: Path):
    import io

    glh = GitlabHarvester(url=fake.url, token=fake.token, timeout=5, ssl_verify=str(ca_file), workers=4)
    projects = glh.fetch_projects(per_page=2)
    _, hits = glh.search_keywords(projects, ["password"], options=ScanOptions(), session_file=io.StringIO())
    assert hits > 0
    assert all(r.status == 200 for r in fake.requests)


# --------------------------------------------------------------------------- CLI


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-m", "gitlab_harvester", *args], cwd=str(cwd), env=cli_env(),
                          capture_output=True, text=True, encoding="utf-8", timeout=90)


def test_cli_untrusted_certificate_fails_cleanly(fake: FakeGitLab, tmp_path: Path):
    proc = run_cli("-u", fake.url, "-t", fake.token, "-s", "password", cwd=tmp_path)
    assert proc.returncode == 1
    assert "TLS certificate verification failed" in proc.stderr
    assert "Traceback" not in proc.stderr
    assert fake.requests == []


def test_cli_ca_bundle_and_insecure(fake: FakeGitLab, ca_file: Path, tmp_path: Path):
    ok = run_cli("-u", fake.url, "-t", fake.token, "-s", "password", "--ca-bundle", str(ca_file),
                 "--session-file", "a.jsonl", cwd=tmp_path)
    assert ok.returncode == 0, ok.stderr
    assert "Done. Keywords: 1" in ok.stdout

    insecure = run_cli("-u", fake.url, "-t", fake.token, "-s", "password", "--insecure",
                       "--session-file", "b.jsonl", "--index-file", "idx2.jsonl", cwd=tmp_path)
    assert insecure.returncode == 0, insecure.stderr
    assert "TLS certificate verification is DISABLED" in insecure.stdout + insecure.stderr


def test_cli_insecure_and_ca_bundle_exclude_each_other(tmp_path: Path):
    proc = run_cli("-u", "https://127.0.0.1:9", "-t", "x", "-s", "x", "--insecure", "--ca-bundle", "ca.pem",
                   cwd=tmp_path)
    assert proc.returncode == 2
    assert "--insecure and --ca-bundle exclude each other" in proc.stderr
