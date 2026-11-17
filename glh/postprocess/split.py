"""
Split a finished session file into one file per search term (--output-separated).

When several terms are searched, the session JSONL interleaves the hits of all
terms (in completion order). ``--output-separated`` writes one file per term
that produced hits into the term's directory next to the session —
``<dir>/<term>/<session>.jsonl`` (``glh.output.OutputLayout``), the same
directory that holds the term's downloaded files — with that term's hit records
(the same ``{"term", "result"}`` lines), so each file is itself a valid
session-hit file that ``-m dedup`` / ``-m convert`` can process.

The split runs after the search, streaming the session a line at a time, so the
memory stays bounded; only terms with at least one hit get a file. It works on
the whole session, so with ``--resume`` the files cover every run.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import IO

# Re-exported: the term names live with the rest of the output layout.
from glh.output import MAX_TERM_LEN, OutputLayout, safe_term_filenames

__all__ = ["MAX_TERM_LEN", "safe_term_filenames", "split_session_by_term", "term_file_paths"]


def term_file_paths(session_path: Path, terms: list[str] | tuple[str, ...],
                    layout: OutputLayout | None = None) -> dict[str, Path]:
    """Per-term output paths ``<dir>/<term>/<session>.jsonl``."""
    layout = layout or OutputLayout(session_path, terms)
    return {term: layout.term_results_path(term) for term in dict.fromkeys(terms)}


def split_session_by_term(session_path: Path, terms: list[str] | tuple[str, ...],
                          layout: OutputLayout | None = None) -> list[Path]:
    """
    Write each term's hit records from ``session_path`` to its own file.

    Args:
        session_path: Finished session JSONL.
        terms: The terms the run searched (the full supplied list, so a resumed
            session splits every term). Their order fixes the directory names.
        layout: The run's output layout (default: one built from the arguments).

    Returns:
        The written paths, in ``terms`` order; only terms with hits get a file.
    """
    paths = term_file_paths(session_path, terms, layout)
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
                    path.parent.mkdir(parents=True, exist_ok=True)
                    fp = handles[term] = path.open("w", encoding="utf-8")
                fp.write(json.dumps(rec, ensure_ascii=False))
                fp.write("\n")
    finally:
        for fp in handles.values():
            fp.close()

    return [paths[t] for t in paths if t in handles]
