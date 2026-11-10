"""
Shared pytest fixtures for GitlabHarvester tests.

Layers:
- tests/unit, tests/fakeserver : no HTTP server
- tests/integration            : real python-gitlab -> Fake GitLab (in-process thread)
- tests/e2e                    : CLI subprocess   -> Fake GitLab
- tests/contract               : opt-in, real GitLab (see tests/contract/README)

The Fake GitLab server is started once per session and reset before every
test that requests it, so tests are isolated and order-independent. Select a
scenario per test with ``@pytest.mark.scenario("name")``.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterator

import pytest

from fakegitlab import FakeGitLab

REPO_ROOT = Path(__file__).resolve().parent.parent
_LAYER_MARKERS = {"unit": "unit", "fakeserver": "unit", "integration": "integration", "e2e": "e2e", "contract": "contract"}


# --------------------------------------------------------------------------- collection


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Apply layer markers based on the test directory (tests/<layer>/...)."""
    tests_dir = Path(__file__).resolve().parent
    for item in items:
        try:
            layer = Path(str(item.fspath)).resolve().relative_to(tests_dir).parts[0]
        except ValueError:
            continue
        marker = _LAYER_MARKERS.get(layer)
        if marker:
            item.add_marker(getattr(pytest.mark, marker))


# --------------------------------------------------------------------------- safety net


def _is_local(address: object) -> bool:
    if not isinstance(address, tuple) or not address:
        return True  # AF_UNIX and similar
    host = address[0]
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def _block_external_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Fail fast if an in-process test tries to reach a non-loopback address.

    Guarantees that automated tests never talk to a real GitLab instance.
    Contract tests are exempt by design.
    """
    if request.node.get_closest_marker("contract"):
        return

    original_connect = socket.socket.connect

    def guarded_connect(self: socket.socket, address: object) -> object:
        if not _is_local(address):
            raise RuntimeError(f"Blocked non-local network access in tests: {address!r}")
        return original_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    # Loopback traffic must never be routed through a developer's proxy.
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")


# --------------------------------------------------------------------------- fake gitlab


@pytest.fixture(scope="session")
def fake_gitlab_server() -> Iterator[FakeGitLab]:
    """One Fake GitLab server for the whole session (reset per test)."""
    server = FakeGitLab("default", threaded=True)
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def fake_gitlab(request: pytest.FixtureRequest, fake_gitlab_server: FakeGitLab) -> Iterator[FakeGitLab]:
    """
    A pristine Fake GitLab for this test.

    The scenario comes from ``@pytest.mark.scenario("name")`` (default: "default").
    Handler exceptions inside the fake are surfaced as test failures.
    """
    marker = request.node.get_closest_marker("scenario")
    scenario = marker.args[0] if marker else "default"
    fake_gitlab_server.reset(scenario=scenario)
    yield fake_gitlab_server
    errors = list(fake_gitlab_server.httpserver.handler_errors)
    fake_gitlab_server.reset(scenario="default")
    if errors:
        raise errors[0]


@pytest.fixture
def no_retry_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """
    Make python-gitlab retries instantaneous and record requested wait times.

    python-gitlab sleeps ``Retry-After`` seconds on HTTP 429; tests assert the
    recorded values instead of really waiting.
    """
    import gitlab.utils

    waits: list[float] = []
    monkeypatch.setattr(gitlab.utils.time, "sleep", lambda s: waits.append(float(s)))
    return waits


# --------------------------------------------------------------------------- harvester helpers


@pytest.fixture
def make_harvester(fake_gitlab: FakeGitLab) -> Callable[..., object]:
    """Factory for GitlabHarvester instances connected to the fake."""
    from glh import GitlabHarvester

    def factory(**kwargs: object) -> GitlabHarvester:
        kwargs.setdefault("url", fake_gitlab.url)
        kwargs.setdefault("token", fake_gitlab.token)
        kwargs.setdefault("timeout", 5)
        return GitlabHarvester(**kwargs)  # type: ignore[arg-type]

    return factory


@pytest.fixture(autouse=True)
def _reset_harvester_logger() -> Iterator[None]:
    """Drop handlers added to the shared harvester logger during a test."""
    yield
    logger = logging.getLogger("GitlabHarvesterLogger")
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()


# --------------------------------------------------------------------------- CLI runner


def kill_process_tree(proc: subprocess.Popen) -> None:
    """
    Hard-kill a subprocess including its children.

    On Windows a virtualenv's python.exe is a launcher that runs the real
    interpreter as a child; Popen.kill() alone may leave that child alive for
    a while (still holding files and sockets).
    """
    if proc.poll() is not None:
        return
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, check=False)
    else:
        proc.kill()


def cli_env() -> dict[str, str]:
    """Environment for CLI subprocesses: repo on PYTHONPATH, UTF-8 I/O, no proxies."""
    env = {k: v for k, v in os.environ.items() if k.lower() not in {"http_proxy", "https_proxy", "all_proxy"}}
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(REPO_ROOT), env.get("PYTHONPATH")]))
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["COLUMNS"] = "120"
    return env


@pytest.fixture
def run_cli(tmp_path: Path) -> Callable[..., subprocess.CompletedProcess[str]]:
    """
    Run ``python -m gitlab_harvester`` in a temporary working directory.

    Usage: ``run_cli("-u", url, "-t", token, "-s", "password")``.
    Keyword args: ``cwd`` (default tmp_path), ``timeout`` (seconds), ``check``.
    """

    def runner(*args: str, cwd: Path | None = None, timeout: float = 90, check: bool = False):
        proc = subprocess.run(
            [sys.executable, "-m", "gitlab_harvester", *map(str, args)],
            cwd=str(cwd or tmp_path),
            env=cli_env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        if check and proc.returncode != 0:
            raise AssertionError(
                f"CLI failed with {proc.returncode}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr[-4000:]}"
            )
        return proc

    return runner
