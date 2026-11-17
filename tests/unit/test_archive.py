"""--to-zip (glh.archive): which files of a run go into the archive, and under which names."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from glh import archive


def hit_record(term: str, *files: str | None) -> dict:
    hits = [{"url": f"u{i}", "data": "x", **({"file": f} if f else {})} for i, f in enumerate(files)]
    return {"term": term, "result": {"project_id": 1, "project_search_result": [
        {"branch": "main", "branch_search_result": hits}]}}


def write_session(path: Path, records: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in records) + "broken {\n", encoding="utf-8")
    return path


def names(zip_path: Path) -> list[str]:
    with zipfile.ZipFile(zip_path) as zf:
        return sorted(zf.namelist())


def test_archive_path_is_next_to_the_session(tmp_path):
    assert archive.archive_path(tmp_path / "results" / "x_session_1.jsonl") == tmp_path / "results" / "x_session_1.zip"


def test_downloaded_files_come_from_the_hits_of_the_session(tmp_path):
    session = write_session(tmp_path / "s.jsonl", [
        {"type": "meta"},
        hit_record("password", "pw/files/a.py", None, "pw/files/b.env"),
        {"type": "keyword_done", "term": "password", "file": "not-a-hit"},
        hit_record("token", "pw/files/a.py"),
    ])
    assert list(archive.downloaded_files(session)) == ["pw/files/a.py", "pw/files/b.env", "pw/files/a.py"]
    assert list(archive.downloaded_files(tmp_path / "missing.jsonl")) == []


def test_zip_keeps_the_layout_and_each_file_once(tmp_path):
    root = tmp_path / "results"
    session = write_session(root / "audit.jsonl", [hit_record("password", "x")])
    (root / "password" / "files").mkdir(parents=True)
    (root / "password" / "files" / "a.py").write_text("secret = 1\n", encoding="utf-8")
    (root / "password" / "audit.jsonl").write_text("{}\n", encoding="utf-8")
    (root / "other_session.jsonl").write_text("{}\n", encoding="utf-8")  # another session: not packed
    outside = tmp_path / "elsewhere" / "a.py"
    outside.parent.mkdir()
    outside.write_text("x\n", encoding="utf-8")

    target = archive.archive_path(session)
    result = archive.zip_results(target, root, [
        session, root / "password" / "audit.jsonl", root / "password" / "files" / "a.py",
        root / "password" / "files" / "a.py", outside, target, root / "gone.json",
    ])
    assert names(target) == ["audit.jsonl", "external/a.py", "password/audit.jsonl", "password/files/a.py"]
    assert result.files == 4 and result.missing == [str(root / "gone.json")]
    assert result.size > 0 and result.compressed == target.stat().st_size
    assert "4 files" in result.describe() and "1 missing" in result.describe()
    with zipfile.ZipFile(target) as zf:
        assert zf.read("password/files/a.py") == (root / "password" / "files" / "a.py").read_bytes()
        assert zf.getinfo("audit.jsonl").compress_type == zipfile.ZIP_DEFLATED
    assert not target.with_name(target.name + ".part").exists()


def test_same_name_from_two_places_is_renamed(tmp_path):
    root = tmp_path / "r"
    root.mkdir()
    a, b = tmp_path / "x" / "f.txt", tmp_path / "y" / "f.txt"
    for p in (a, b):
        p.parent.mkdir()
        p.write_text(p.parent.name, encoding="utf-8")
    archive.zip_results(root / "s.zip", root, [a, b])
    assert names(root / "s.zip") == ["external/f.txt", "external/f~2.txt"]


def test_an_existing_archive_is_replaced_and_failures_leave_nothing(tmp_path, monkeypatch):
    root = tmp_path
    f = root / "s.jsonl"
    f.write_text("{}\n", encoding="utf-8")
    target = root / "s.zip"
    target.write_bytes(b"old")
    archive.zip_results(target, root, [f])
    assert names(target) == ["s.jsonl"]

    def broken(self, *args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(zipfile.ZipFile, "write", broken)
    with pytest.raises(OSError):
        archive.zip_results(root / "new.zip", root, [f])
    assert not (root / "new.zip").exists() and not (root / "new.zip.part").exists()
