from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, TextIO


_WS_RE = re.compile(r"\s+")


def _normalize_text(s: str) -> str:
    """
    Normalizes hit text for stable deduplication:
    - strip
    - collapse whitespace to single spaces
    """
    return _WS_RE.sub(" ", s.strip())


def _content_hash(text: str, *, algo: str = "blake2b") -> str:
    """
    Returns a hex digest for dedup key.
    blake2b is fast and has low collision risk.
    """
    b = text.encode("utf-8", errors="replace")
    if algo == "sha1":
        return hashlib.sha1(b).hexdigest()
    if algo == "sha256":
        return hashlib.sha256(b).hexdigest()
    h = hashlib.blake2b(b, digest_size=20)  # 40 hex chars
    return h.hexdigest()


def iter_json_objects(fp: TextIO) -> Iterator[dict[str, Any]]:
    """
    Incremental JSON decoder that supports:
    - JSONL (one JSON object per line)
    - pretty-printed JSON objects spanning multiple lines (indent=2)

    It reads the file progressively and yields JSON objects as soon as they decode.
    """
    decoder = json.JSONDecoder()
    buf = ""
    for chunk in fp:
        buf += chunk
        while True:
            buf = buf.lstrip()
            if not buf:
                break
            try:
                obj, idx = decoder.raw_decode(buf)
            except json.JSONDecodeError:
                # need more data
                break
            yield obj
            buf = buf[idx:]

    # tolerate trailing whitespace
    if buf.strip():
        raise ValueError("Trailing data could not be decoded as JSON.")


@dataclass(slots=True)
class DedupStore:
    db_path: Path
    conn: sqlite3.Connection = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.execute("CREATE TABLE IF NOT EXISTS seen (h TEXT PRIMARY KEY)")
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def add_if_new(self, h: str) -> bool:
        cur = self.conn.execute("INSERT OR IGNORE INTO seen(h) VALUES (?)", (h,))
        return cur.rowcount == 1


def _dedup_record_inplace(
    obj: dict[str, Any],
    *,
    store: DedupStore,
    hash_algo: str = "blake2b",
    normalize: bool = True,
) -> bool:
    """
    Deduplicate content inside a single "hit record".
    Returns True if the record still contains any hits after dedup, else False.
    """
    # Expected shape (your current format):
    # {"term": "...", "result": {"project_id":..., "project_search_result":[
    #    {"branch": "...", "branch_search_result":[{"url": "...", "data": "..."}]}
    # ]}}
    result = obj.get("result")

    if not isinstance(result, dict):
        return True  # unknown payload, keep as-is

    psr = result.get("project_search_result")
    if not isinstance(psr, list):
        return True  # keep as-is

    new_psr: list[dict[str, Any]] = []
    for branch_entry in psr:
        if not isinstance(branch_entry, dict):
            continue
        hits = branch_entry.get("branch_search_result")
        if not isinstance(hits, list):
            continue

        new_hits: list[dict[str, Any]] = []
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            data = hit.get("data", "")
            if not isinstance(data, str):
                data = str(data)

            key_text = _normalize_text(data) if normalize else data
            # If after normalization it's empty — skip (optional behavior)
            if not key_text:
                continue

            h = _content_hash(key_text, algo=hash_algo)
            if store.add_if_new(h):
                new_hits.append(hit)

        if new_hits:
            branch_entry = dict(branch_entry)
            branch_entry["branch_search_result"] = new_hits
            new_psr.append(branch_entry)

    result["project_search_result"] = new_psr
    obj["result"] = result

    # If nothing left — drop this record
    return len(new_psr) > 0


def dedup_session_file(
    *,
    input_path: Path,
    output_path: Path,
    sqlite_path: Path | None = None,
    hash_algo: str = "blake2b",
    normalize: bool = True,
) -> None:
    """
    Streamingly deduplicate identical hit content across the entire session output.

    - Preserves meta/resume/summary/keyword_done records as-is.
    - Deduplicates only "hit" records that look like: {"term": ..., "result": ...}
    - Writes output as strict JSONL (one object per line).
    """
    if sqlite_path is None:
        sqlite_path = output_path.with_suffix(output_path.suffix + ".seen.sqlite")

    store = DedupStore(sqlite_path)
    kept = 0
    dropped = 0

    try:
        with input_path.open("r", encoding="utf-8") as fin, output_path.open("w", encoding="utf-8") as fout:
            for obj in iter_json_objects(fin):
                if not isinstance(obj, dict):
                    continue

                # passthrough control records
                t = obj.get("type")
                if t in {"meta", "resume", "summary", "keyword_done"}:
                    fout.write(json.dumps(obj, ensure_ascii=False) + "\n")
                    kept += 1
                    continue

                # attempt dedup only for hit records
                if "term" in obj and "result" in obj:
                    ok = _dedup_record_inplace(obj, store=store, hash_algo=hash_algo, normalize=normalize)
                    if not ok:
                        dropped += 1
                        continue

                fout.write(json.dumps(obj, ensure_ascii=False) + "\n")
                kept += 1

    finally:
        store.close()

    print(f"[dedup] input:  {input_path}")
    print(f"[dedup] output: {output_path}")
    print(f"[dedup] kept records: {kept}")
    print(f"[dedup] dropped empty hit-records: {dropped}")
    print(f"[dedup] seen-db: {sqlite_path}")
