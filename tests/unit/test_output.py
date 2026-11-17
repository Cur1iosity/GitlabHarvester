"""Output of a search run (glh.output): layout, the engine's sink, the session file."""

from __future__ import annotations

import io
from pathlib import Path

from glh.output.layout import OutputLayout
from glh.output.records import BranchResult, Checkpoint, Hit, ProjectResult, ResumeRecord, SessionMeta, SummaryRecord
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


RESULT = ProjectResult(project_id=1, web_url="https://gitlab.test/g/p", created_at=None, last_activity_at=None,
                       branches=(BranchResult("main", (Hit("https://gitlab.test/g/p/-/tree/main/a.py#L1", "pw"),)),))


def test_search_output_writes_jsonl_records_and_flushes_checkpoints():
    stream = FlushCounter()
    out = SearchOutput(stream)
    out.hit("password", RESULT)
    assert stream.flushes == 0
    out.checkpoint(Checkpoint.for_term("password", 1, "2024-06-10T12:00:00+00:00", []))
    assert stream.flushes == 1
    assert stream.getvalue().splitlines() == [
        '{"term": "password", "result": {"project_id": 1, "web_url": "https://gitlab.test/g/p", "created_at": null, '
        '"last_activity_at": null, "project_search_result": [{"branch": "main", "branch_search_result": '
        '[{"url": "https://gitlab.test/g/p/-/tree/main/a.py#L1", "data": "pw"}]}]}}',
        '{"type": "keyword_done", "term": "password", "hit_counter": 1, "timestamp_utc": "2024-06-10T12:00:00+00:00"}',
    ]


def test_search_output_without_a_stream_drops_records():
    out = SearchOutput()
    out.hit("t", RESULT)
    out.checkpoint(Checkpoint.for_term("t", 0, None, []))
    assert out.downloader is None


def test_non_ascii_is_written_as_is():
    stream = io.StringIO()
    SearchOutput(stream).hit("ключ", ProjectResult(1, "https://gitlab.test/ü", None, None, ()))
    assert "ключ" in stream.getvalue() and "\\u" not in stream.getvalue()


# --------------------------------------------------------------------------- session file


def test_session_output_creates_the_directory_and_writes_control_records(tmp_path: Path):
    layout = OutputLayout(tmp_path / "out" / "audit.jsonl", ["password"])
    with SessionOutput(layout) as out:
        out.meta(SessionMeta(url="https://gitlab.test", filename="*.env", project_filter=("k8s",)))
        out.hit("password", RESULT)
        out.summary(SummaryRecord(hits=1, completed=True))
    meta, hit, summary = read_jsonl(layout.session_path)
    assert meta["type"] == "meta" and meta["url"] == "https://gitlab.test" and meta["project_filter"] == ["k8s"]
    assert list(meta)[:3] == ["type", "timestamp_utc", "url"] and list(meta)[-1] == "final_only"
    assert hit == {"term": "password", "result": RESULT.to_record()}
    assert summary == {"type": "summary", "hits": 1, "completed": True, "incomplete_terms": [],
                       "elapsed_seconds": None, "timestamp_utc": None}
    read_back = load_session_meta(layout.session_path)
    assert read_back is not None and read_back.filename == "*.env" and read_back.project_filter == ("k8s",)


def test_session_output_appends_on_resume(tmp_path: Path):
    layout = OutputLayout(tmp_path / "audit.jsonl")
    with SessionOutput(layout) as out:
        out.meta(SessionMeta(url="u"))
    with SessionOutput(layout, resume=True) as out:
        out.resumed(ResumeRecord(done_keywords=1))
    assert [r["type"] for r in read_jsonl(layout.session_path)] == ["meta", "resume"]
    # A new (not resumed) run starts the file over.
    with SessionOutput(layout) as out:
        out.meta(SessionMeta(url="v"))
    assert [r["url"] for r in read_jsonl(layout.session_path)] == ["v"]


def test_load_session_meta(tmp_path: Path):
    assert load_session_meta(tmp_path / "missing.jsonl") is None
    (tmp_path / "a.jsonl").write_text('\n{"type": "meta", "x": 1, "url": "u"}\n{"type": "summary"}\n',
                                      encoding="utf-8")
    assert load_session_meta(tmp_path / "a.jsonl") == SessionMeta(url="u")
    (tmp_path / "b.jsonl").write_text('{"term": "t", "result": {}}\n', encoding="utf-8")
    assert load_session_meta(tmp_path / "b.jsonl") is None
    (tmp_path / "c.jsonl").write_text("{broken\n", encoding="utf-8")
    assert load_session_meta(tmp_path / "c.jsonl") is None
