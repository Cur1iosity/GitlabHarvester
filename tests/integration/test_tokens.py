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
