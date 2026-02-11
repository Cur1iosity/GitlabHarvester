from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_done_keywords(session_path: Path) -> set[str]:
    """
    Read session JSONL and return keywords that were already completed.

    Recognizes records of type="keyword_done".
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
                rec: dict[str, Any] = json.loads(line)
            except json.JSONDecodeError:
                continue

            if rec.get("type") == "keyword_done":
                kw = rec.get("keyword")
                if isinstance(kw, str) and kw:
                    done.add(kw)

    return done
