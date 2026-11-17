"""Reading a session back: the terms already done (--resume) and the parameters of its first run."""

from __future__ import annotations

import json
from pathlib import Path

from glh.output.records import Checkpoint, SessionMeta


def load_done_keywords(session_path: Path) -> set[str]:
    """
    Read session JSONL and return keywords that were already completed.

    Recognizes records of type="keyword_done". The harvester writes the
    keyword under "term"; "keyword" is accepted for backward compatibility.
    Terms with failed searches get type="keyword_incomplete" instead, so a
    resumed run searches them again.
    """
    done: set[str] = set()

    if not session_path.exists():
        return done

    with session_path.open("r", encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue

            try:
                checkpoint = Checkpoint.from_record(json.loads(line))
            except json.JSONDecodeError:
                continue

            if checkpoint is not None and checkpoint.done:
                done.add(checkpoint.term)

    return done


def load_session_meta(session_path: Path) -> SessionMeta | None:
    """
    Return the first ``meta`` record of a session (the parameters of the run
    that started it), or None if the file is missing or has none.

    Only the beginning of the file is read: the meta record is its first line.
    """
    if not session_path.exists():
        return None
    with session_path.open("r", encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                return SessionMeta.from_record(json.loads(line))
            except json.JSONDecodeError:
                return None
    return None
