"""Output of a search run (glh.output): layout, the engine's sink, the session file."""

from __future__ import annotations

import io
import json
from pathlib import Path

from glh.output.layout import OutputLayout
from glh.output.session_reader import load_session_meta
from glh.output.sink import SearchOutput, SessionOutput
from tests.helpers import read_jsonl


class FlushCounter(io.StringIO):
    def __init__(self) -> None:
        super().__init__()
        self.flushes = 0

    def flush(self) -> None:
        self.flushes += 1
        super().flush()


# --------------------------------------------------------------------------- layout


def test_layout_paths():
    layout = OutputLayout(Path("results/host_session_1.jsonl"), ["password", "api/key"])
    assert layout.root == Path("results")
    assert layout.term_dir("password") == Path("results/password")
    assert layout.term_results_path("password") == Path("results/password/host_session_1.jsonl")
    assert layout.files_dir("password") == Path("results/password/files")
    assert layout.files_dir("api/key") == Path("results/api_key/files")
    assert layout.describe_files() == str(Path("results/<term>/files"))


def test_layout_names_are_stable_and_distinct():
    layout = OutputLayout(Path("audit.jsonl"), ["Token", "token", "a b"])
    assert [layout.term_name(t) for t in ("Token", "token", "a b")] == ["Token", "token_2", "a_b"]
    # A term outside the list (e.g. from an edited terms file) never clashes.
    assert layout.term_name("a_b") == "a_b_2"
    assert layout.term_name("a_b") == "a_b_2"  # remembered


def test_session_in_the_current_directory():
    layout = OutputLayout(Path("audit.jsonl"), ["password"])
    assert layout.term_results_path("password") == Path("password/audit.jsonl")


# --------------------------------------------------------------------------- engine sink


def test_search_output_writes_jsonl_records_and_flushes_checkpoints():
    stream = FlushCounter()
    out = SearchOutput(stream)
    out.hit("password", {"project_id": 1})
    assert stream.flushes == 0
    out.checkpoint({"type": "keyword_done", "term": "password"})
    assert stream.flushes == 1
    assert [json.loads(x) for x in stream.getvalue().splitlines()] == [
        {"term": "password", "result": {"project_id": 1}},
        {"type": "keyword_done", "term": "password"},
    ]


def test_search_output_without_a_stream_drops_records():
    out = SearchOutput()
    out.hit("t", {"project_id": 1})
    out.checkpoint({"type": "keyword_done"})
    assert out.downloader is None


def test_non_ascii_is_written_as_is():
    stream = io.StringIO()
    SearchOutput(stream).hit("ключ", {"x": "ü"})
    assert "ключ" in stream.getvalue() and "\\u" not in stream.getvalue()


# --------------------------------------------------------------------------- session file


def test_session_output_creates_the_directory_and_writes_control_records(tmp_path: Path):
    layout = OutputLayout(tmp_path / "out" / "audit.jsonl", ["password"])
    with SessionOutput(layout) as out:
        out.meta(url="https://gitlab.test", filename="*.env")
        out.hit("password", {"project_id": 1})
        out.summary(hits=1)
    assert read_jsonl(layout.session_path) == [
        {"type": "meta", "url": "https://gitlab.test", "filename": "*.env"},
        {"term": "password", "result": {"project_id": 1}},
        {"type": "summary", "hits": 1},
    ]
    assert load_session_meta(layout.session_path)["filename"] == "*.env"


def test_session_output_appends_on_resume(tmp_path: Path):
    layout = OutputLayout(tmp_path / "audit.jsonl")
    with SessionOutput(layout) as out:
        out.meta(url="u")
    with SessionOutput(layout, resume=True) as out:
        out.resumed(done_keywords=1)
    assert [r["type"] for r in read_jsonl(layout.session_path)] == ["meta", "resume"]
    # A new (not resumed) run starts the file over.
    with SessionOutput(layout) as out:
        out.meta(url="v")
    assert read_jsonl(layout.session_path) == [{"type": "meta", "url": "v"}]


def test_load_session_meta(tmp_path: Path):
    assert load_session_meta(tmp_path / "missing.jsonl") is None
    (tmp_path / "a.jsonl").write_text('\n{"type": "meta", "x": 1}\n{"type": "summary"}\n', encoding="utf-8")
    assert load_session_meta(tmp_path / "a.jsonl") == {"type": "meta", "x": 1}
    (tmp_path / "b.jsonl").write_text('{"term": "t", "result": {}}\n', encoding="utf-8")
    assert load_session_meta(tmp_path / "b.jsonl") is None
    (tmp_path / "c.jsonl").write_text("{broken\n", encoding="utf-8")
    assert load_session_meta(tmp_path / "c.jsonl") is None
