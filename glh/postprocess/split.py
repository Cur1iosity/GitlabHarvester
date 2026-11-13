"""
Split a finished session file into one file per search term (--output-separated).

When several terms are searched, the session JSONL interleaves the hits of all
terms (in completion order). ``--output-separated`` writes, next to the session,
one file per term that produced hits — ``<session-stem>.<term>.jsonl`` — holding
that term's hit records (the same ``{"term", "result"}`` lines), so each file is
itself a valid session-hit file that ``-m dedup`` / ``-m convert`` can process.

The split runs after the search, streaming the session a line at a time, so the
memory stays bounded; only terms with at least one hit get a file. It works on
the whole session, so with ``--resume`` the files cover every run.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import IO

# Everything except these becomes '_', so the name is safe on Windows, macOS and
# Linux: no path separators (/ \), no Windows-forbidden chars (< > : " | ? *),
# no spaces or control chars. A path separator in a term therefore can't escape
# the session's directory. Dots are kept but trimmed from the ends.
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
# Keep per-term names short; a long term (e.g. "BEGIN RSA PRIVATE KEY") is cut.
MAX_TERM_LEN = 60
# Windows reserved device names (any case); never used as a bare base name.
_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)


def _safe_base(term: str) -> str:
    """Filesystem-safe base name for one term (not yet de-duplicated)."""
    base = _UNSAFE.sub("_", term.strip()).strip("._")[:MAX_TERM_LEN] or "term"
    if base.lower() in _RESERVED:  # CON, NUL, COM1 … are special on Windows
        base = f"{base}_"
    return base


def safe_term_filenames(terms: list[str] | tuple[str, ...]) -> dict[str, str]:
    """
    Map each term to a distinct, filesystem-safe base name.

    The mapping is deterministic in the given order: unsafe characters become
    ``_`` (see ``_UNSAFE``), the name is shortened to ``MAX_TERM_LEN`` and
    de-duplicated case-insensitively (Windows file names are case-insensitive),
    so two terms never share a file. Duplicate terms map to the same name
    (they are searched once).
    """
    mapping: dict[str, str] = {}
    used: set[str] = set()
    for term in terms:
        if term in mapping:
            continue
        base = _safe_base(term)
        candidate, n = base, 1
        while candidate.lower() in used:
            n += 1
            candidate = f"{base}_{n}"
        used.add(candidate.lower())
        mapping[term] = candidate
    return mapping


def term_file_paths(session_path: Path, terms: list[str] | tuple[str, ...]) -> dict[str, Path]:
    """Per-term output paths ``<session-stem>.<term>.jsonl`` next to the session."""
    stem = session_path.with_suffix("")
    suffix = session_path.suffix or ".jsonl"
    paths: dict[str, Path] = {}
    for term, name in safe_term_filenames(terms).items():
        path = Path(f"{stem}.{name}{suffix}")
        if path == session_path:  # never clobber the session itself
            path = Path(f"{stem}.{name}.term{suffix}")
        paths[term] = path
    return paths


def split_session_by_term(session_path: Path, terms: list[str] | tuple[str, ...]) -> list[Path]:
    """
    Write each term's hit records from ``session_path`` to its own file.

    Args:
        session_path: Finished session JSONL.
        terms: The terms the run searched (the full supplied list, so a resumed
            session splits every term). Their order fixes the file names.

    Returns:
        The written paths, in ``terms`` order; only terms with hits get a file.
    """
    paths = term_file_paths(session_path, terms)
    handles: dict[str, IO] = {}
    try:
        with session_path.open("r", encoding="utf-8") as fin:
            for line in fin:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # Only hit records; control records (meta/summary/keyword_*) are skipped.
                if not (isinstance(rec, dict) and "term" in rec and "result" in rec):
                    continue
                term = rec["term"]
                path = paths.get(term)
                if path is None:
                    continue  # a term not in this run's list (e.g. an edited terms file)
                fp = handles.get(term)
                if fp is None:
                    fp = handles[term] = path.open("w", encoding="utf-8")
                fp.write(json.dumps(rec, ensure_ascii=False))
                fp.write("\n")
    finally:
        for fp in handles.values():
            fp.close()

    return [paths[t] for t in paths if t in handles]
