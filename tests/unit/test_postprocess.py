"""Deduplication and conversion of session files (glh.postprocess)."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from glh.postprocess.convert import convert_jsonl_to_json, iter_json_objects
from glh.postprocess.dedup import _content_hash, _normalize_text, dedup_session_file
from tests.helpers import Session, read_jsonl, write_jsonl


def hit_record(term: str, pid: int, branches: dict[str, list[str]]) -> dict:
    return {
        "term": term,
        "result": {
            "project_id": pid,
            "web_url": f"http://gitlab.test/p{pid}",
            "project_search_result": [
                {"branch": b, "branch_search_result": [{"url": f"http://gitlab.test/p{pid}/{b}#L{i}", "data": d}
                                                       for i, d in enumerate(datas, 1)]}
                for b, datas in branches.items()
            ],
        },
    }


@pytest.fixture
def session_file(tmp_path: Path) -> Path:
    return write_jsonl(
        tmp_path / "session.jsonl",
        [
            {"type": "meta", "keywords_count": 2},
            hit_record("password", 1, {"main": ["DB_PASSWORD = x", "unique-1"], "develop": ["DB_PASSWORD   =  x"]}),
            hit_record("password", 2, {"main": ["DB_PASSWORD = x"]}),  # fully duplicated -> record dropped
            {"type": "keyword_done", "term": "password", "hit_counter": 4},
            hit_record("token", 3, {"main": ["token = t", ""]}),  # empty data is skipped
            {"type": "keyword_done", "term": "token", "hit_counter": 2},
            {"type": "summary", "hits": 6},
        ],
    )


def test_normalization_and_hashing():
    assert _normalize_text("  a \n\t b  ") == "a b"
    assert len(_content_hash("x")) == 40
    assert len(_content_hash("x", algo="sha256")) == 64
    assert len(_content_hash("x", algo="sha1")) == 40
    assert _content_hash("x") != _content_hash("y")


def test_dedup_removes_cross_branch_and_cross_project_duplicates(session_file: Path, tmp_path: Path, capsys):
    out = tmp_path / "clean.jsonl"
    dedup_session_file(input_path=session_file, output_path=out)

    records = read_jsonl(out)
    s = Session(records)
    assert [r.get("type") for r in records if "type" in r] == ["meta", "keyword_done", "keyword_done", "summary"]
    assert [h["data"] for h in s.hits()] == ["DB_PASSWORD = x", "unique-1", "token = t"]
    assert s.project_ids() == [1, 3]  # project 2 had only duplicates
    assert s.branches_by_project()[1] == ["main"]  # develop branch collapsed into main's hit
    assert "dropped empty hit-records: 1" in capsys.readouterr().out
    # Default sqlite cache next to the output.
    assert (tmp_path / "clean.jsonl.seen.sqlite").exists()


def test_dedup_without_normalization_keeps_whitespace_variants(session_file: Path, tmp_path: Path):
    out = tmp_path / "clean.jsonl"
    dedup_session_file(input_path=session_file, output_path=out, normalize=False, sqlite_path=tmp_path / "c.db")
    datas = [h["data"] for h in Session.load(out).hits()]
    assert datas.count("DB_PASSWORD = x") == 1
    assert "DB_PASSWORD   =  x" in datas


def test_dedup_runs_are_independent_even_with_the_same_sqlite_path(session_file: Path, tmp_path: Path):
    """
    The seen-hash store is never committed, so every run starts clean.

    This keeps re-running dedup with the default cache path idempotent
    (a persisted cache would make the second run drop every hit).
    """
    db = tmp_path / "seen.sqlite"
    dedup_session_file(input_path=session_file, output_path=tmp_path / "a.jsonl", sqlite_path=db)
    dedup_session_file(input_path=session_file, output_path=tmp_path / "b.jsonl", sqlite_path=db)
    assert read_jsonl(tmp_path / "a.jsonl") == read_jsonl(tmp_path / "b.jsonl")


def test_dedup_passes_through_unknown_records(tmp_path: Path):
    src = write_jsonl(tmp_path / "s.jsonl", [{"term": "x", "result": "not-a-dict"}, {"other": 1}])
    out = tmp_path / "o.jsonl"
    dedup_session_file(input_path=src, output_path=out)
    assert read_jsonl(out) == [{"term": "x", "result": "not-a-dict"}, {"other": 1}]


def test_iter_json_objects_supports_jsonl_and_pretty_json():
    text = '{"a": 1}\n{\n  "b": [1,\n 2]\n}\n\n{"c": "ключ"}\n'
    assert list(iter_json_objects(io.StringIO(text))) == [{"a": 1}, {"b": [1, 2]}, {"c": "ключ"}]


def test_iter_json_objects_rejects_trailing_garbage():
    with pytest.raises(ValueError):
        list(iter_json_objects(io.StringIO('{"a": 1}\n{"b": ')))


def test_convert_jsonl_to_json_array(session_file: Path, tmp_path: Path):
    out = tmp_path / "result.json"
    convert_jsonl_to_json(input_path=session_file, output_path=out, sort_keys=True)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert data == read_jsonl(session_file)
    # sort_keys affects serialization order.
    assert out.read_text(encoding="utf-8").startswith('[{"keywords_count"')
