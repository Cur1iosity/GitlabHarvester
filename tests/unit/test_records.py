"""The records of a session file as objects (glh.output.records)."""

from __future__ import annotations

import json

import pytest

from glh.domain.models import Project
from glh.output.records import (
    BranchResult,
    Checkpoint,
    Hit,
    HitRecord,
    MAX_FAILURES,
    ProjectResult,
    read_record,
    ResumeRecord,
    SessionMeta,
    SummaryRecord,
)

# Records as the session writer of 1.4.2 wrote them (key order included).
HIT_LINE = {
    "term": "пароль",
    "result": {
        "project_id": 101,
        "web_url": "https://gitlab.test/acme/api",
        "created_at": "2024-01-01T00:00:00.000Z",
        "last_activity_at": None,
        "project_search_result": [
            {"branch": "main", "branch_search_result": [
                {"url": "https://gitlab.test/acme/api/-/blob/main/a.py#L1", "data": "password = 1", "file": "x/a.py"},
                {"url": "https://gitlab.test/acme/api/-/blob/main/b.py#L3", "data": ""},
            ]},
            {"branch": "fix/#42", "branch_search_result": [{"url": "u", "data": "d"}]},
        ],
    },
}
DONE = {"type": "keyword_done", "term": "password", "hit_counter": 29, "timestamp_utc": "2024-06-10T12:00:00+00:00"}
INCOMPLETE = {"type": "keyword_incomplete", "term": "token", "hit_counter": 30, "timestamp_utc": "2024-06-10T12:00:01+00:00",
              "failed_searches": 2, "failures": ["g/p @ main: HTTP 500 Internal Server Error", "g/q @ main: ReadTimeout"]}
META = {"type": "meta", "timestamp_utc": "2024-06-10T12:00:00+00:00", "url": "https://gitlab.test", "config": None,
        "index_file": "idx.jsonl", "batch_size": 100, "tokens": 2, "workers": 3, "index_rpm": 0, "search_rpm": 60,
        "auto_limits": False, "jitter": [0.0, 0.5], "user_agent": None, "user_agent_file": None,
        "branches_per_page": 100, "index_branches": "all", "scan_branches": 5, "forks": "branch-diff",
        "fork_diff_bases": "main,master,develop,dev", "started_from": "2024-01-01T00:00:00+00:00",
        "active_before": None, "file_changed_after": None, "file_changed_before": None, "filename": "*.env",
        "extension": None, "project_filter": ["k8s", "infra/*"], "files_only": False, "file_listing": None,
        "keywords_count": 3, "output_separated": True, "download_files": True, "download_max_size": 10485760,
        "post_process": ["dedup", "convert"], "to_zip": False, "final_only": False}
RESUME = {"type": "resume", "timestamp_utc": "2024-06-10T13:00:00+00:00", "done_keywords": 2, "remaining_keywords": 1}
SUMMARY = {"type": "summary", "hits": 59, "completed": False, "incomplete_terms": ["token"], "elapsed_seconds": 12.5,
           "timestamp_utc": "2024-06-10T12:01:00+00:00"}


@pytest.mark.parametrize("record", [HIT_LINE, DONE, INCOMPLETE, META, RESUME, SUMMARY],
                         ids=["hit", "done", "incomplete", "meta", "resume", "summary"])
def test_records_round_trip_byte_for_byte(record):
    line = json.dumps(record, ensure_ascii=False)
    model = read_record(json.loads(line))
    assert model is not None
    assert json.dumps(model.to_record(), ensure_ascii=False) == line


def test_a_project_result_is_built_from_the_project():
    project = Project.from_record({"id": 101, "web_url": "https://gitlab.test/acme/api",
                                   "created_at": "2024-01-01T00:00:00.000Z"})
    branches = [BranchResult("main", (Hit("u1", "d1", "x/a.py"), Hit("u2"))), BranchResult("dev", (Hit("u3"),))]
    result = ProjectResult.for_project(project, branches)
    assert result.to_record() == {
        "project_id": 101, "web_url": "https://gitlab.test/acme/api", "created_at": "2024-01-01T00:00:00.000Z",
        "last_activity_at": None,
        "project_search_result": [
            {"branch": "main", "branch_search_result": [{"url": "u1", "data": "d1", "file": "x/a.py"},
                                                        {"url": "u2", "data": ""}]},
            {"branch": "dev", "branch_search_result": [{"url": "u3", "data": ""}]},
        ],
    }
    assert result.hit_count == 3 and list(result.files()) == ["x/a.py"]


def test_checkpoints():
    assert Checkpoint.for_term("t", 3, "ts", []).to_record() == {"type": "keyword_done", "term": "t",
                                                                 "hit_counter": 3, "timestamp_utc": "ts"}
    many = [f"p{i} @ main: HTTP 502 Bad Gateway" for i in range(MAX_FAILURES + 5)]
    record = Checkpoint.for_term("t", 3, "ts", many).to_record()
    assert record["type"] == "keyword_incomplete" and record["failed_searches"] == MAX_FAILURES + 5
    assert record["failures"] == many[:MAX_FAILURES]
    # Legacy "keyword"; an incomplete record without its counter is still not done.
    assert Checkpoint.from_record({"type": "keyword_done", "keyword": "old"}) == Checkpoint("old", 0, None)
    assert not Checkpoint.from_record({"type": "keyword_incomplete", "term": "t"}).done
    for other in ({"type": "keyword_done"}, {"type": "keyword_done", "term": ""}, {"type": "summary", "term": "t"},
                  {"term": "t", "result": {}}, ["keyword_done"], None):
        assert Checkpoint.from_record(other) is None


def test_broken_hit_records_are_read_without_raising():
    record = HitRecord.from_record({"term": "t", "result": {"project_search_result": [
        "junk", {"branch": "main", "branch_search_result": [None, {"data": "no url"}, {"url": "u", "file": ""}]},
        {"branch_search_result": "not a list"},
    ]}})
    assert record is not None and record.result.web_url == ""
    assert [len(b.hits) for b in record.result.branches] == [1, 0]
    assert record.result.branches[0].hits[0] == Hit("u")
    assert HitRecord.from_record({"term": "t"}) is None
    assert HitRecord.from_record({"result": {}}) is None
    assert read_record({"type": "unknown"}) is None and read_record("text") is None


def test_session_meta_reads_old_and_new_records():
    old = SessionMeta.from_record({"type": "meta", "url": "u", "removed_option": 1})
    assert old == SessionMeta(url="u")
    assert SessionMeta.from_record({"term": "t"}) is None
    meta = SessionMeta.from_record(META)
    assert meta.project_filter == ("k8s", "infra/*") and meta.jitter == (0.0, 0.5)
    assert list(SessionMeta().to_record()) == list(META)  # every field, in file order
    assert SummaryRecord.from_record(SUMMARY).incomplete_terms == ("token",)
    assert ResumeRecord.from_record(RESUME).remaining_keywords == 1
