# glh/output/records.py
"""
The records of a session file (JSONL) as objects.

A session holds:

- one ``meta`` record (:class:`SessionMeta`): the parameters of the run that
  started it;
- a ``resume`` record (:class:`ResumeRecord`) at the start of every resumed part;
- hit records (:class:`HitRecord`): a term and its hits in one project
  (:class:`ProjectResult` → :class:`BranchResult` → :class:`Hit`);
- a checkpoint per finished term (:class:`Checkpoint`): ``keyword_done``, or
  ``keyword_incomplete`` when some of its searches failed (not a resume point);
- a ``summary`` record (:class:`SummaryRecord`) at the end of a run.

``to_record()`` gives the record this version writes, keys in file order.
``from_record()`` reads a record of any version and never raises on its shape:
missing values get defaults, malformed parts are skipped, and a record of
another kind gives None.

dedup, convert and the per-term split stream the records as dicts on purpose:
they pass through any record, including ones of other versions, unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any, Iterable, Iterator, Mapping

from glh.domain.models import Project

KEYWORD_DONE = "keyword_done"
KEYWORD_INCOMPLETE = "keyword_incomplete"
# A keyword_incomplete record lists at most this many failed searches.
MAX_FAILURES = 20


def _json(value: Any) -> Any:
    """Tuples are written as JSON lists."""
    return list(value) if isinstance(value, tuple) else value


def _tuple(value: Any) -> Any:
    """JSON lists are read as tuples (records are immutable)."""
    return tuple(value) if isinstance(value, list) else value


def _int(value: Any, default: int = 0) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _typed_record(kind: str, record: Any) -> dict[str, Any]:
    """{"type": kind, <every field in declaration order>} of a dataclass record."""
    return {"type": kind, **{f.name: _json(getattr(record, f.name)) for f in fields(record)}}


def _fields_of(cls: type, record: Mapping[str, Any]) -> dict[str, Any]:
    """The values of ``cls``' fields found in ``record`` (lists as tuples)."""
    return {f.name: _tuple(record[f.name]) for f in fields(cls) if f.name in record}


# --------------------------------------------------------------------------- hits


@dataclass(frozen=True, slots=True)
class Hit:
    """One search result: a link to the file (and line), the snippet, the downloaded copy."""

    url: str
    data: str = ""
    # Local path of the downloaded file (--download-files).
    file: str | None = None

    @classmethod
    def from_record(cls, record: Any) -> "Hit | None":
        if not isinstance(record, Mapping) or not isinstance(record.get("url"), str):
            return None
        file = record.get("file")
        return cls(url=record["url"], data=record.get("data", ""), file=file if isinstance(file, str) and file else None)

    def to_record(self) -> dict[str, Any]:
        record: dict[str, Any] = {"url": self.url, "data": self.data}
        if self.file:
            record["file"] = self.file
        return record


@dataclass(frozen=True, slots=True)
class BranchResult:
    """The hits of a term in one branch."""

    branch: str
    hits: tuple[Hit, ...]

    @classmethod
    def from_record(cls, record: Any) -> "BranchResult | None":
        if not isinstance(record, Mapping):
            return None
        hits = record.get("branch_search_result")
        parsed = (Hit.from_record(h) for h in hits) if isinstance(hits, list) else ()
        return cls(branch=str(record.get("branch", "")), hits=tuple(h for h in parsed if h is not None))

    def to_record(self) -> dict[str, Any]:
        return {"branch": self.branch, "branch_search_result": [h.to_record() for h in self.hits]}


@dataclass(frozen=True, slots=True)
class ProjectResult:
    """The hits of a term in one project, per branch."""

    project_id: Any
    web_url: str
    created_at: str | None
    last_activity_at: str | None
    branches: tuple[BranchResult, ...]

    @classmethod
    def for_project(cls, project: Project, branches: Iterable[BranchResult]) -> "ProjectResult":
        return cls(project_id=project.id, web_url=project.web_url, created_at=project.created_at,
                   last_activity_at=project.last_activity_at, branches=tuple(branches))

    @classmethod
    def from_record(cls, record: Any) -> "ProjectResult | None":
        if not isinstance(record, Mapping):
            return None
        branches = record.get("project_search_result")
        parsed = (BranchResult.from_record(b) for b in branches) if isinstance(branches, list) else ()
        return cls(project_id=record.get("project_id"), web_url=record.get("web_url") or "",
                   created_at=record.get("created_at"), last_activity_at=record.get("last_activity_at"),
                   branches=tuple(b for b in parsed if b is not None))

    def to_record(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "web_url": self.web_url,
            "created_at": self.created_at,
            "last_activity_at": self.last_activity_at,
            "project_search_result": [b.to_record() for b in self.branches],
        }

    @property
    def hit_count(self) -> int:
        return sum(len(b.hits) for b in self.branches)

    def files(self) -> Iterator[str]:
        """Local paths of the downloaded files, one per hit that has one (in order)."""
        for branch in self.branches:
            for hit in branch.hits:
                if hit.file:
                    yield hit.file


@dataclass(frozen=True, slots=True)
class HitRecord:
    """A session line with hits: ``{"term": ..., "result": {...}}``."""

    term: str
    result: ProjectResult

    @classmethod
    def from_record(cls, record: Any) -> "HitRecord | None":
        if not isinstance(record, Mapping) or "term" not in record:
            return None
        result = ProjectResult.from_record(record.get("result"))
        return cls(term=record["term"], result=result) if result is not None else None

    def to_record(self) -> dict[str, Any]:
        return {"term": self.term, "result": self.result.to_record()}


# --------------------------------------------------------------------------- control records


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """
    A term is finished. ``keyword_done`` is the --resume checkpoint; a term with
    failed (retryable) searches gets ``keyword_incomplete`` and is searched again.
    """

    term: str
    hit_counter: int
    timestamp_utc: str | None
    # Number of failed searches (0: done) and the first MAX_FAILURES of them.
    failed_searches: int = 0
    failures: tuple[str, ...] = ()

    @classmethod
    def for_term(cls, term: str, hit_counter: int, timestamp_utc: str, failures: list[str]) -> "Checkpoint":
        return cls(term=term, hit_counter=hit_counter, timestamp_utc=timestamp_utc,
                   failed_searches=len(failures), failures=tuple(failures[:MAX_FAILURES]))

    @property
    def done(self) -> bool:
        return not self.failed_searches

    @classmethod
    def from_record(cls, record: Any) -> "Checkpoint | None":
        """A checkpoint (the legacy ``keyword`` key too); None for other records or without a term."""
        if not isinstance(record, Mapping) or record.get("type") not in (KEYWORD_DONE, KEYWORD_INCOMPLETE):
            return None
        term = record.get("term", record.get("keyword"))
        if not isinstance(term, str) or not term:
            return None
        failures = record.get("failures")
        failures = tuple(f for f in failures if isinstance(f, str)) if isinstance(failures, list) else ()
        failed = _int(record.get("failed_searches"))
        if record["type"] == KEYWORD_INCOMPLETE:
            failed = max(failed, len(failures), 1)
        timestamp = record.get("timestamp_utc")
        return cls(term=term, hit_counter=_int(record.get("hit_counter")),
                   timestamp_utc=timestamp if isinstance(timestamp, str) else None,
                   failed_searches=failed if record["type"] == KEYWORD_INCOMPLETE else 0, failures=failures)

    def to_record(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "type": KEYWORD_DONE if self.done else KEYWORD_INCOMPLETE,
            "term": self.term,
            "hit_counter": self.hit_counter,
            "timestamp_utc": self.timestamp_utc,
        }
        if not self.done:
            record["failed_searches"] = self.failed_searches
            record["failures"] = list(self.failures)
        return record


@dataclass(frozen=True, slots=True)
class SessionMeta:
    """
    The ``meta`` record that starts a session: the parameters of the run, in
    file order. Built from the CLI options by ``glh.cli.factory.session_meta``.
    """

    timestamp_utc: str | None = None
    url: str | None = None
    config: str | None = None
    index_file: str | None = None
    batch_size: int | None = None
    tokens: int | None = None
    workers: int | None = None
    index_rpm: int | None = None
    search_rpm: int | None = None
    auto_limits: bool | None = None
    jitter: tuple[float, ...] | None = None
    user_agent: str | None = None
    user_agent_file: str | None = None
    branches_per_page: int | None = None
    index_branches: str | int | None = None
    scan_branches: str | int | None = None
    forks: str | None = None
    fork_diff_bases: str | None = None
    started_from: str | None = None
    active_before: str | None = None
    file_changed_after: str | None = None
    file_changed_before: str | None = None
    filename: str | None = None
    extension: str | None = None
    project_filter: tuple[str, ...] | None = None
    files_only: bool | None = None
    file_listing: str | None = None
    keywords_count: int | None = None
    output_separated: bool | None = None
    download_files: bool | None = None
    download_max_size: int | None = None
    post_process: tuple[str, ...] | None = None
    to_zip: bool | None = None
    final_only: bool | None = None

    @classmethod
    def from_record(cls, record: Any) -> "SessionMeta | None":
        """The meta of a session (unknown keys ignored); None for any other record."""
        if not isinstance(record, Mapping) or record.get("type") != "meta":
            return None
        return cls(**_fields_of(cls, record))

    def to_record(self) -> dict[str, Any]:
        return _typed_record("meta", self)

    def scope_changes(self, now: "SessionMeta") -> list[tuple[str, Any, Any]]:
        """
        (field, this session's value, ``now``'s value) for every condition of the
        search that differs: what was searched, where and in which files. A
        resumed run must keep them, or one session would mix two different searches.
        Speed, tokens, limits and outputs may change.

        A field missing from an older session's meta: for SCOPE_FILTERS the option
        didn't exist yet (= off, compared as None), for the others unknown (skipped).
        """
        changes: list[tuple[str, Any, Any]] = []
        for name in SCOPE_FIELDS:
            before, after = getattr(self, name), getattr(now, name)
            if before is None and name not in SCOPE_FILTERS:
                continue
            if name == "fork_diff_bases" and not (self.forks == now.forks == "branch-diff"):
                continue  # used by --forks branch-diff only
            if name == "url":
                before, after = before.rstrip("/"), (after or "").rstrip("/")
            if before != after:
                changes.append((name, before, after))
        return changes


# Fields of SessionMeta that decide what a session searched (see SessionMeta.scope_changes), in file order.
SCOPE_FIELDS = ("url", "scan_branches", "forks", "fork_diff_bases", "started_from", "active_before",
                "file_changed_after", "file_changed_before", "filename", "extension", "project_filter",
                "files_only")
# Of these, the filters that are off when an older meta doesn't record them.
SCOPE_FILTERS = frozenset({"started_from", "active_before", "file_changed_after", "file_changed_before",
                           "filename", "extension", "project_filter"})


@dataclass(frozen=True, slots=True)
class ResumeRecord:
    """The ``resume`` record that starts the appended part of a resumed session."""

    timestamp_utc: str | None = None
    done_keywords: int | None = None
    remaining_keywords: int | None = None

    @classmethod
    def from_record(cls, record: Any) -> "ResumeRecord | None":
        if not isinstance(record, Mapping) or record.get("type") != "resume":
            return None
        return cls(**_fields_of(cls, record))

    def to_record(self) -> dict[str, Any]:
        return _typed_record("resume", self)


@dataclass(frozen=True, slots=True)
class SummaryRecord:
    """The ``summary`` record that ends a run."""

    hits: int | None = None
    completed: bool | None = None
    incomplete_terms: tuple[str, ...] = ()
    elapsed_seconds: float | None = None
    timestamp_utc: str | None = None

    @classmethod
    def from_record(cls, record: Any) -> "SummaryRecord | None":
        if not isinstance(record, Mapping) or record.get("type") != "summary":
            return None
        return cls(**_fields_of(cls, record))

    def to_record(self) -> dict[str, Any]:
        return _typed_record("summary", self)


SessionRecord = SessionMeta | ResumeRecord | HitRecord | Checkpoint | SummaryRecord


def read_record(record: Any) -> SessionRecord | None:
    """The object of any session record (None for a record of none of these kinds)."""
    if not isinstance(record, Mapping):
        return None
    kind = record.get("type")
    if kind is None:
        return HitRecord.from_record(record)
    reader = {"meta": SessionMeta, "resume": ResumeRecord, "summary": SummaryRecord}.get(kind, Checkpoint)
    return reader.from_record(record)
