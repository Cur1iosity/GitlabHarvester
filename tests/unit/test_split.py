"""Per-term output split (glh.postprocess.split, --output-separated)."""

from __future__ import annotations

from pathlib import Path

import pytest

from glh.postprocess.split import (
    MAX_TERM_LEN,
    safe_term_filenames,
    split_session_by_term,
    term_file_paths,
)
from tests.helpers import read_jsonl, write_jsonl


def hit(term: str, project_id: int, url: str) -> dict:
    """A session hit record, as the harvester streams it."""
    return {
        "term": term,
        "result": {
            "project_id": project_id,
            "web_url": f"https://gitlab.test/p{project_id}",
            "project_search_result": [{"branch": "main", "branch_search_result": [{"url": url, "data": "x"}]}],
        },
    }


# --------------------------------------------------------------------------- sanitizing


@pytest.mark.parametrize(("term", "name"), [
    ("password", "password"),
    ("api_key", "api_key"),
    ("api/key", "api_key"),            # path separator -> _
    ("a b:c*?\"<>|", "a_b_c"),         # Windows-forbidden chars -> _ (collapsed, trimmed)
    ("...hidden...", "hidden"),         # leading/trailing dots trimmed
    ("..", "term"),                      # nothing safe left -> fallback
    ("/", "term"),
    ("BEGIN RSA PRIVATE KEY", "BEGIN_RSA_PRIVATE_KEY"),
])
def test_safe_base_names(term, name):
    assert safe_term_filenames([term])[term] == name


def test_long_term_is_truncated():
    assert len(safe_term_filenames(["x" * 200])["x" * 200]) == MAX_TERM_LEN


@pytest.mark.parametrize("reserved", ["CON", "nul", "COM1", "LPT9"])
def test_windows_reserved_names_are_escaped(reserved):
    assert safe_term_filenames([reserved])[reserved] == f"{reserved}_"


def test_colliding_terms_get_distinct_names():
    # Different terms that sanitize to the same base must not share a file.
    m = safe_term_filenames(["api/key", "api_key", "api:key"])
    assert len(set(m.values())) == 3
    assert m["api/key"] == "api_key"
    assert all(v.startswith("api_key") for v in m.values())


def test_case_only_difference_is_a_collision_on_windows():
    # "Token" and "token" differ as terms but share a case-insensitive file name.
    m = safe_term_filenames(["Token", "token"])
    assert len({v.lower() for v in m.values()}) == 2


def test_duplicate_terms_map_to_one_name():
    assert safe_term_filenames(["token", "token"]) == {"token": "token"}


# --------------------------------------------------------------------------- paths


def test_term_file_paths_sit_next_to_the_session():
    session = Path("results/audit.jsonl")
    paths = term_file_paths(session, ["password", "api_key"])
    assert paths["password"] == Path("results/audit.password.jsonl")
    assert paths["api_key"] == Path("results/audit.api_key.jsonl")


def test_term_file_path_never_equals_the_session():
    # A pathological term that would reproduce the session name is pushed aside.
    session = Path("audit.jsonl")
    paths = term_file_paths(session, ["jsonl"])
    assert paths["jsonl"] != session


# --------------------------------------------------------------------------- splitting


def test_split_routes_each_term_and_skips_control_records(tmp_path: Path):
    session = write_jsonl(tmp_path / "audit.jsonl", [
        {"type": "meta", "url": "https://gitlab.test"},
        hit("password", 1, "u1"),
        hit("api_key", 1, "u2"),
        hit("password", 2, "u3"),
        {"type": "keyword_done", "term": "password"},
        hit("api_key", 2, "u4"),
        {"type": "summary", "hits": 4},
    ])

    files = split_session_by_term(session, ["password", "api_key", "nohits"])

    # A file per term that had hits, in the given order; "nohits" gets none.
    assert [p.name for p in files] == ["audit.password.jsonl", "audit.api_key.jsonl"]
    assert not (tmp_path / "audit.nohits.jsonl").exists()

    pwd = read_jsonl(tmp_path / "audit.password.jsonl")
    assert [r["result"]["project_id"] for r in pwd] == [1, 2]
    assert all(r["term"] == "password" and "result" in r for r in pwd)       # only hit records
    assert all(r.get("type") is None for r in pwd)                            # no meta/summary
    assert [r["result"]["project_id"] for r in read_jsonl(tmp_path / "audit.api_key.jsonl")] == [1, 2]


def test_split_writes_all_files_inside_the_session_directory(tmp_path: Path):
    # A path-traversal term must not escape the session's directory.
    session = write_jsonl(tmp_path / "audit.jsonl", [hit("../../evil", 1, "u1")])
    files = split_session_by_term(session, ["../../evil"])
    assert len(files) == 1
    assert files[0].resolve().parent == tmp_path.resolve()


def test_split_of_empty_session_writes_nothing(tmp_path: Path):
    session = write_jsonl(tmp_path / "audit.jsonl", [{"type": "meta"}, {"type": "summary", "hits": 0}])
    assert split_session_by_term(session, ["password", "token"]) == []
