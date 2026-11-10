"""Session resume support (glh.session) and CLI session path resolution."""

from __future__ import annotations

from pathlib import Path

from glh.modes import _load_keywords, _resolve_session_path
from glh.session import load_done_keywords
from tests.helpers import write_jsonl


def test_missing_session_file_means_nothing_done(tmp_path: Path):
    assert load_done_keywords(tmp_path / "absent.jsonl") == set()


def test_reads_keyword_done_records_written_by_harvester(tmp_path: Path):
    # Shape emitted by GitlabHarvester.search_keywords().
    session = write_jsonl(
        tmp_path / "s.jsonl",
        [
            {"type": "meta", "keywords_count": 3},
            {"term": "password", "result": {"project_id": 1, "project_search_result": []}},
            {"type": "keyword_done", "term": "password", "hit_counter": 1, "timestamp_utc": "x"},
            {"type": "keyword_done", "term": "api_key", "hit_counter": 1, "timestamp_utc": "x"},
        ],
    )
    assert load_done_keywords(session) == {"password", "api_key"}


def test_accepts_legacy_keyword_field(tmp_path: Path):
    session = write_jsonl(tmp_path / "s.jsonl", [{"type": "keyword_done", "keyword": "legacy"}])
    assert load_done_keywords(session) == {"legacy"}


def test_ignores_broken_and_truncated_lines(tmp_path: Path):
    session = tmp_path / "s.jsonl"
    session.write_text(
        '{"type": "keyword_done", "term": "ok"}\n'
        "not json at all\n"
        "[1, 2, 3]\n"
        '{"type": "keyword_done", "term": ""}\n'
        '{"type": "keyword_done", "term": "trunc',  # process killed mid-write
        encoding="utf-8",
    )
    assert load_done_keywords(session) == {"ok"}


def test_keywords_file_skips_comments_and_blanks(tmp_path: Path):
    terms = tmp_path / "terms.txt"
    terms.write_text("# comment\npassword\n\n  api_key  \n#x\nключ\n", encoding="utf-8")
    assert _load_keywords(search=None, terms_file=str(terms)) == ["password", "api_key", "ключ"]
    assert _load_keywords(search="  token ", terms_file=None) == ["token"]
    assert _load_keywords(search="   ", terms_file=None) == []


def test_session_path_resolution(tmp_path: Path):
    assert _resolve_session_path("h", None, str(tmp_path / "x.jsonl")) == tmp_path / "x.jsonl"
    assert _resolve_session_path("h", "audit", None) == Path("audit.jsonl")
    default = _resolve_session_path("gitlab_example_com", None, None)
    assert default.parent == Path("results")
    assert default.name.startswith("gitlab_example_com_session_")
    assert ":" not in default.name
