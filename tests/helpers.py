"""Small helpers shared by test modules (JSONL parsing, log capture, expectations)."""

from __future__ import annotations

import io
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


def read_jsonl(path: Path | str) -> list[dict[str, Any]]:
    """Parse a strict JSONL file (every non-empty line must be a JSON object)."""
    records: list[dict[str, Any]] = []
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        obj = json.loads(line)
        assert isinstance(obj, dict), f"{path}:{n} is not a JSON object"
        records.append(obj)
    return records


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> Path:
    """Write records as JSONL."""
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records), encoding="utf-8")
    return path


@dataclass(frozen=True)
class Session:
    """Parsed session file with convenience accessors."""

    records: list[dict[str, Any]]

    @classmethod
    def load(cls, path: Path | str) -> "Session":
        return cls(read_jsonl(path))

    def of_type(self, t: str) -> list[dict[str, Any]]:
        return [r for r in self.records if r.get("type") == t]

    @property
    def hit_records(self) -> list[dict[str, Any]]:
        return [r for r in self.records if "term" in r and "result" in r]

    def hits(self, term: str | None = None) -> list[dict[str, Any]]:
        """Flatten hits into {term, project_id, branch, url, data} dicts."""
        out = []
        for r in self.hit_records:
            if term is not None and r["term"] != term:
                continue
            res = r["result"]
            for br in res["project_search_result"]:
                for h in br["branch_search_result"]:
                    out.append({"term": r["term"], "project_id": res["project_id"], "branch": br["branch"], **h})
        return out

    def project_ids(self, term: str | None = None) -> list[int]:
        return [r["result"]["project_id"] for r in self.hit_records if term is None or r["term"] == term]

    def branches_by_project(self, term: str | None = None) -> dict[int, list[str]]:
        out: dict[int, list[str]] = {}
        for r in self.hit_records:
            if term is None or r["term"] == term:
                out.setdefault(r["result"]["project_id"], []).extend(
                    b["branch"] for b in r["result"]["project_search_result"]
                )
        return out


class FakeStream(io.StringIO):
    """In-memory text stream that can pretend to be a terminal (for progress output tests)."""

    def __init__(self, tty: bool) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def load_index(path: Path | str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return (meta, projects) from an Instance Project Index file."""
    records = read_jsonl(path)
    assert records and records[0].get("type") == "meta", "index must start with a meta record"
    return records[0], records[1:]


class LogCapture(logging.Handler):
    """Collects records from the (non-propagating) harvester logger."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def messages(self, level: int = logging.DEBUG) -> list[str]:
        return [r.getMessage() for r in self.records if r.levelno >= level]


def capture_logs(glh: Any) -> LogCapture:
    """Attach a LogCapture to a GitlabHarvester instance logger."""
    cap = LogCapture()
    glh.logger.addHandler(cap)
    return cap


# ---------------------------------------------------------------------------
# Expectations for the "default" scenario (fakegitlab/scenarios/default.yaml).
# Keep in sync with docs/testing.md#default-scenario.
# ---------------------------------------------------------------------------

DEFAULT_PROJECT_IDS_DESC = [301, 203, 202, 201, 105, 104, 103, 102, 101]
DEFAULT_FORK_IDS = {201, 202, 203}

DEFAULT_BRANCHES = {
    101: ["develop", "feature/login-v2", "main", "release/1.0+hotfix"],
    102: ["main"],
    103: ["fix/#42-login", "master", "ünïcode-ветка"],
    104: [],
    105: ["main"],
    201: ["alice/experiment", "develop", "feature/login-v2", "main"],
    202: ["feature/bob", "master"],
    203: ["carol/wip", "develop", "main"],
    301: ["main"],
}

DEFAULT_BRANCH_OF = {101: "main", 102: "main", 103: "master", 104: None, 105: "main",
                     201: "main", 202: "master", 203: "main", 301: "main"}

# "password" hits per project when scanning only default branches.
PASSWORD_HITS_DEFAULT_BRANCH = {301: 2, 203: 1, 202: 1, 201: 2, 103: 1, 101: 2}
# "password" hits per (project, branch) for every branch.
PASSWORD_HITS_PER_BRANCH = {
    (101, "develop"): 2, (101, "feature/login-v2"): 3, (101, "main"): 2, (101, "release/1.0+hotfix"): 2,
    (103, "fix/#42-login"): 1, (103, "master"): 1, (103, "ünïcode-ветка"): 1,
    (201, "alice/experiment"): 3, (201, "develop"): 2, (201, "feature/login-v2"): 3, (201, "main"): 2,
    (202, "feature/bob"): 1, (202, "master"): 1,
    (203, "carol/wip"): 1, (203, "develop"): 1, (203, "main"): 1,
    (301, "main"): 2,
}
