"""Post-processing chain after a search (glh.postprocess.pipeline, --post-process/--final-only)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from glh.cli import CliParser
from glh.postprocess.convert import convert_jsonl_to_json
from glh.postprocess.dedup import dedup_session_file
from glh.postprocess.pipeline import normalize_steps, run_pipeline
from tests.helpers import Session, read_jsonl, write_jsonl


def hit(term: str, pid: int, branch: str, datas: list[str]) -> dict:
    return {"term": term, "result": {
        "project_id": pid, "web_url": f"http://gitlab.test/p{pid}",
        "project_search_result": [{"branch": branch, "branch_search_result": [
            {"url": f"http://gitlab.test/p{pid}/-/tree/{branch}/f#L{i}", "data": d} for i, d in enumerate(datas, 1)]}],
    }}


@pytest.fixture
def session(tmp_path: Path) -> Path:
    """A finished session where project 2 and branch develop only repeat known hits."""
    return write_jsonl(tmp_path / "audit.jsonl", [
        {"type": "meta", "keywords_count": 2},
        hit("password", 1, "main", ["DB_PASSWORD = x", "token = y"]),
        hit("password", 1, "develop", ["DB_PASSWORD   =  x"]),  # whitespace variant
        hit("password", 2, "main", ["DB_PASSWORD = x"]),
        {"type": "keyword_done", "term": "password", "hit_counter": 4},
        hit("api_key", 3, "main", ["API_KEY = z"]),
        {"type": "keyword_done", "term": "api_key", "hit_counter": 5},
        {"type": "summary", "hits": 5},
    ])


def files(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir())


# --------------------------------------------------------------------------- steps


@pytest.mark.parametrize(("raw", "steps"), [
    ("dedup,convert", ("dedup", "convert")),
    ("convert,dedup", ("dedup", "convert")),  # convert output (JSON array) can't be deduplicated
    (" Dedup , dedup ", ("dedup",)),
    ("convert", ("convert",)),
])
def test_steps_are_normalized_to_run_order(raw, steps):
    assert normalize_steps(raw) == steps
    assert CliParser.parse(["--post-process", raw]).post_process == steps


@pytest.mark.parametrize("raw", ["", " , ", "zip", "dedup,zip"])
def test_invalid_steps_are_a_usage_error(raw, capsys):
    with pytest.raises(SystemExit) as e:
        CliParser.parse(["--post-process", raw])
    assert e.value.code == 2
    assert "dedup, convert or dedup,convert" in capsys.readouterr().err


def test_defaults():
    a = CliParser.parse([])
    assert (a.post_process, a.final_only) == ((), False)


# --------------------------------------------------------------------------- chain


def test_dedup_and_convert_keep_every_file(session: Path, tmp_path: Path):
    result = run_pipeline(session, ("dedup", "convert"))

    assert result.outputs == [tmp_path / "audit.deduped.jsonl", tmp_path / "audit.deduped.converted.json"]
    assert result.removed == [] and result.final == tmp_path / "audit.deduped.converted.json"
    assert files(tmp_path) == ["audit.deduped.converted.json", "audit.deduped.jsonl", "audit.jsonl"]  # no SQLite left

    deduped = Session.load(tmp_path / "audit.deduped.jsonl")
    assert [h["data"] for h in deduped.hits()] == ["DB_PASSWORD = x", "token = y", "API_KEY = z"]
    assert [r["type"] for r in deduped.records if "type" in r] == ["meta", "keyword_done", "keyword_done", "summary"]
    converted = json.loads((tmp_path / "audit.deduped.converted.json").read_text(encoding="utf-8"))
    assert converted == read_jsonl(tmp_path / "audit.deduped.jsonl")
    assert read_jsonl(session)[1]["result"]["project_id"] == 1  # the original is untouched


def test_chain_equals_running_the_modes_by_hand(session: Path, tmp_path: Path):
    manual = tmp_path / "manual"
    manual.mkdir()
    dedup_session_file(input_path=session, output_path=manual / "d.jsonl", sqlite_path=manual / "s.db")
    convert_jsonl_to_json(input_path=manual / "d.jsonl", output_path=manual / "c.json")

    run_pipeline(session, ("dedup", "convert"))
    assert read_jsonl(tmp_path / "audit.deduped.jsonl") == read_jsonl(manual / "d.jsonl")
    assert (tmp_path / "audit.deduped.converted.json").read_text(encoding="utf-8") == \
        (manual / "c.json").read_text(encoding="utf-8")


def test_final_only_keeps_just_the_last_file(session: Path, tmp_path: Path):
    result = run_pipeline(session, ("dedup", "convert"), final_only=True)
    assert files(tmp_path) == ["audit.deduped.converted.json"]
    assert result.removed == [session, tmp_path / "audit.deduped.jsonl"]
    assert len(json.loads(result.final.read_text(encoding="utf-8"))) == 6  # meta, 2 hits, 2 done, summary


@pytest.mark.parametrize(("steps", "final"), [
    (("convert",), "audit.converted.json"),
    (("dedup",), "audit.deduped.jsonl"),
])
def test_single_step(session: Path, tmp_path: Path, steps, final):
    result = run_pipeline(session, steps, final_only=True)
    assert files(tmp_path) == [final] and result.final == tmp_path / final


def test_convert_honors_sort_keys(session: Path, tmp_path: Path):
    run_pipeline(session, ("convert",), sort_keys=True)
    assert (tmp_path / "audit.converted.json").read_text(encoding="utf-8").startswith('[{"keywords_count"')


def test_dedup_options_are_passed_through(session: Path, tmp_path: Path):
    run_pipeline(session, ("dedup",), normalize=False)
    datas = [h["data"] for h in Session.load(tmp_path / "audit.deduped.jsonl").hits()]
    assert "DB_PASSWORD   =  x" in datas  # whitespace variant survives without normalization


def test_custom_sqlite_path_is_kept(session: Path, tmp_path: Path):
    store = tmp_path / "cache" / "seen.db"
    run_pipeline(session, ("dedup",), sqlite_path=store)
    assert store.exists()


def test_failed_step_deletes_nothing(tmp_path: Path):
    broken = tmp_path / "audit.jsonl"
    broken.write_text('{"type": "meta"}\n{"term": "x", "result": ', encoding="utf-8")  # killed mid-write
    with pytest.raises(ValueError):
        run_pipeline(broken, ("dedup", "convert"), final_only=True)
    assert broken.exists()
    assert not (tmp_path / "audit.deduped.jsonl.seen.sqlite").exists()


def test_session_name_without_jsonl_suffix(tmp_path: Path):
    src = write_jsonl(tmp_path / "audit.log", [{"type": "meta"}])
    result = run_pipeline(src, ("dedup", "convert"))
    assert [p.name for p in result.outputs] == ["audit.log.deduped.jsonl", "audit.log.deduped.converted.json"]
