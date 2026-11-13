"""
Several tokens at once (-t "a;b" / --token-file): one pool of workers per token,
each worker bound to one token, every token verified at start-up.

The default scenario has two users with their own tokens (dev-token,
readonly-token) and no permission model, so both see the same projects: perfect
for checking that the work really spreads over every token.
"""

from __future__ import annotations

import io
import json
import threading
from collections import Counter

import pytest

import gitlab.exceptions
from fakegitlab import FakeGitLab
from glh import GitlabHarvester
from glh.exceptions import GitlabHarvesterError
from glh.planner import ScanOptions
from tests.helpers import Session, load_index

TOKENS = ["dev-token", "readonly-token"]
TERMS = ["password", "token"]


def build_index(make_harvester, path) -> list[dict]:
    make_harvester().build_project_index(filename=str(path), per_page=2, branches="all", enforce_dump=True)
    return load_index(path)[1]


def run_search(glh: GitlabHarvester, projects) -> tuple[int, Session]:
    fp = io.StringIO()
    _, hits = glh.search_keywords(projects, TERMS, options=ScanOptions(scan_branches="all"), session_file=fp)
    return hits, Session([json.loads(x) for x in fp.getvalue().splitlines()])


def header(request, name: str) -> str | None:
    """Case-insensitive header lookup on a recorded request."""
    for key, value in request.headers.items():
        if key.lower() == name.lower():
            return value
    return None


def search_tokens(fake: FakeGitLab) -> set[str]:
    """The distinct PRIVATE-TOKEN values seen on blob-search requests."""
    return {t for r in fake.api_requests("project_search") if (t := header(r, "PRIVATE-TOKEN"))}


# --------------------------------------------------------------------------- start-up


def test_every_token_is_authenticated_at_startup(fake_gitlab: FakeGitLab, make_harvester):
    make_harvester(tokens=TOKENS)
    # One /user per token: the main client for the first, a fail-fast check for the rest.
    assert {header(r, "PRIVATE-TOKEN") for r in fake_gitlab.api_requests("user")} == set(TOKENS)


def test_an_invalid_extra_token_fails_fast(fake_gitlab: FakeGitLab, make_harvester):
    with pytest.raises(GitlabHarvesterError, match=r"Token #2 of 2 .*401"):
        make_harvester(tokens=["dev-token", "nope-token"])


def test_an_invalid_first_token_still_fails(fake_gitlab: FakeGitLab, make_harvester):
    with pytest.raises(gitlab.exceptions.GitlabAuthenticationError):
        make_harvester(tokens=["nope-token", "dev-token"])


# --------------------------------------------------------------------------- search


def test_search_spreads_over_every_token(fake_gitlab: FakeGitLab, make_harvester, tmp_path):
    projects = build_index(make_harvester, tmp_path / "idx.jsonl")
    fake_gitlab.clear_journal()

    glh = make_harvester(tokens=TOKENS)  # workers=1 per token -> concurrency 2
    assert glh.concurrency == 2
    run_search(glh, projects)

    assert search_tokens(fake_gitlab) == set(TOKENS)  # both colleagues' tokens did real work


def test_several_workers_per_token_still_use_every_token(fake_gitlab: FakeGitLab, make_harvester, tmp_path):
    # Live threaded run with more than one worker per token: concurrency = tokens x workers.
    projects = build_index(make_harvester, tmp_path / "idx.jsonl")
    fake_gitlab.clear_journal()

    glh = make_harvester(tokens=TOKENS, workers=2)  # 2 tokens x 2 workers = 4 clients
    assert glh.concurrency == 4
    run_search(glh, projects)

    assert search_tokens(fake_gitlab) == set(TOKENS)  # every token carried real requests


def test_token_worker_rpm_wiring(fake_gitlab: FakeGitLab, make_harvester, tmp_path):
    """
    The token -> worker -> rpm chain end to end: M tokens x N workers create
    M*N search clients, N bound to each token, and every client carries its own
    per-worker rpm limiters (so each token's budget is tokens-independent).
    """
    projects = build_index(make_harvester, tmp_path / "idx.jsonl")

    glh = make_harvester(tokens=TOKENS, workers=2, search_rpm=20, index_rpm=300)  # concurrency 4
    assert glh.concurrency == 4

    # Record every worker client built during the search. The main client and the
    # per-token start-up checks ran in __init__, before this spy is installed, so
    # only the pool's worker clients (one per thread) are captured.
    seen: list[tuple[str, int | None, int | None]] = []
    lock = threading.Lock()
    build_client = glh._setup_client

    def spy(gl):
        gl = build_client(gl)
        adapter = gl.session.get_adapter("https://x")  # the mounted ThrottledAdapter
        search_rpm = getattr(getattr(adapter, "search_limiter", None), "rpm", None)
        index_rpm = getattr(getattr(adapter, "index_limiter", None), "rpm", None)
        with lock:
            seen.append((gl.private_token, search_rpm, index_rpm))
        return gl

    glh._setup_client = spy
    run_search(glh, projects)

    assert len(seen) == glh.concurrency                       # one client per (token, worker)
    assert Counter(token for token, _, _ in seen) == {"dev-token": 2, "readonly-token": 2}  # N workers per token
    assert {(s, i) for _, s, i in seen} == {(20, 300)}        # each client paces itself: its own rpm budget


def test_results_match_a_single_token_run(fake_gitlab: FakeGitLab, make_harvester, tmp_path):
    projects = build_index(make_harvester, tmp_path / "idx.jsonl")

    one_hits, one = run_search(make_harvester(), projects)
    many_hits, many = run_search(make_harvester(tokens=TOKENS, workers=2), projects)

    assert many_hits == one_hits
    # Same findings regardless of how many tokens/workers; only the record order differs.
    assert sorted(h["url"] for h in many.hits()) == sorted(h["url"] for h in one.hits())


def test_token_file_runs_like_inline_tokens(fake_gitlab: FakeGitLab, make_harvester, tmp_path):
    # The harvester takes a resolved token list; the CLI resolves -t/--token-file into it.
    from glh import tokens as token_utils

    token_file = tmp_path / "tokens.txt"
    token_file.write_text("# colleagues\ndev-token\nreadonly-token\n", encoding="utf-8")
    assert token_utils.load_tokens(token_file) == TOKENS

    projects = build_index(make_harvester, tmp_path / "idx.jsonl")
    fake_gitlab.clear_journal()
    glh = make_harvester(tokens=token_utils.load_tokens(token_file))
    run_search(glh, projects)
    assert search_tokens(fake_gitlab) == set(TOKENS)
