"""
The session file written by the real CLI reads back through the record models
(glh.output.records) without losing a byte: one definition of the format for
its writers and readers.
"""

from __future__ import annotations

import json
from pathlib import Path

from fakegitlab import FakeGitLab
from glh.domain.models import IndexMeta, Project
from glh.output.records import Checkpoint, HitRecord, read_record, SessionMeta, SummaryRecord


def test_every_session_record_round_trips_through_the_models(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    (tmp_path / "words.txt").write_text("password\napi_key\n", encoding="utf-8")
    run_cli("-u", fake_gitlab.url, "-t", fake_gitlab.token, "-f", "words.txt", "-b", "all", "--download-files",
            "--project-filter", "acme/*", "--filename", "*.py", "--session-file", "s.jsonl", "--index-file", "i.jsonl",
            check=True)

    kinds = []
    for line in (tmp_path / "s.jsonl").read_text(encoding="utf-8").splitlines():
        record = read_record(json.loads(line))
        assert record is not None, line
        assert json.dumps(record.to_record(), ensure_ascii=False) == line
        kinds.append(type(record))
    assert kinds[0] is SessionMeta and kinds[-1] is SummaryRecord
    assert kinds.count(Checkpoint) == 2 and HitRecord in kinds

    meta_line, *project_lines = (tmp_path / "i.jsonl").read_text(encoding="utf-8").splitlines()
    assert json.dumps(IndexMeta.from_record(json.loads(meta_line)).to_record(), ensure_ascii=False) == meta_line
    for line in project_lines:
        assert json.dumps(Project.from_record(json.loads(line)).to_record(), ensure_ascii=False) == line
