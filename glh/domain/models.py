# glh/domain/models.py
"""
The records of the project index as objects.

The index file (JSONL) is one ``meta`` record (:class:`IndexMeta`), then one
record per project (:class:`Project`):

- ``from_record()`` reads a record of any version: missing keys get defaults,
  and the legacy ``upstream_project_id`` is understood;
- ``to_record()`` gives the record this version writes, keys in file order.

Rewriting an existing index (adding the branches) works on the raw records
instead, so keys this version doesn't know survive: the models are for reading
and for new records. Frozen slots dataclasses also take about half the memory
of the dicts for a large index.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from glh.domain.timewindow import parse_timestamp, TimeWindow


def _int(value: Any) -> int | None:
    """``value`` as an int, or None if it isn't one (bools excluded)."""
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


@dataclass(frozen=True, slots=True)
class Project:
    """
    One project of the index.

    Attributes:
        id: GitLab project id.
        web_url: Project URL (hit links are built from it).
        path_with_namespace: ``group/subgroup/project``.
        default_branch: Default branch name, if the project has one.
        empty_repo: The repository has no commits (never searched).
        is_fork: The project is a fork.
        upstream_id: Id of the project it was forked from, when known.
        created_at / last_activity_at: ISO 8601 timestamps from GitLab.
        branches: Branch names stored in the index; None when the record has
            no ``branches`` key (an index built without branch listing).
    """

    id: int
    web_url: str = ""
    path_with_namespace: str | None = None
    default_branch: str | None = None
    empty_repo: bool = False
    is_fork: bool = False
    upstream_id: int | None = None
    created_at: str | None = None
    last_activity_at: str | None = None
    branches: tuple[str, ...] | None = None

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> "Project":
        """
        A project from an index record of any version.

        Raises:
            ValueError: The record has no usable ``id``.
        """
        pid = _int(record.get("id"))
        if pid is None:
            raise ValueError(f"project record without an id: {record.get('id')!r}")
        legacy_upstream = record.get("upstream_project_id")
        fork = record.get("forked_from_project")
        if legacy_upstream:
            is_fork, upstream = True, _int(legacy_upstream)
        else:
            is_fork = bool(fork)
            upstream = _int(fork.get("id")) if isinstance(fork, Mapping) else None
        branches = record.get("branches")
        return cls(
            id=pid,
            web_url=_str(record.get("web_url")) or "",
            path_with_namespace=_str(record.get("path_with_namespace")),
            default_branch=_str(record.get("default_branch")),
            empty_repo=bool(record.get("empty_repo", False)),
            is_fork=is_fork,
            upstream_id=upstream,
            created_at=_str(record.get("created_at")),
            last_activity_at=_str(record.get("last_activity_at")),
            branches=tuple(b for b in branches if isinstance(b, str)) if isinstance(branches, (list, tuple)) else None,
        )

    def to_record(self) -> dict[str, Any]:
        """The index record of this version (``branches`` only when known)."""
        record: dict[str, Any] = {
            "id": self.id,
            "web_url": self.web_url,
            "path_with_namespace": self.path_with_namespace,
            "default_branch": self.default_branch,
            "empty_repo": self.empty_repo,
            "forked_from_project": {"id": self.upstream_id} if self.is_fork and self.upstream_id is not None
            else False,
            "created_at": self.created_at,
            "last_activity_at": self.last_activity_at,
        }
        if self.branches is not None:
            record["branches"] = list(self.branches)
        return record

    @property
    def name(self) -> str:
        """How the project is shown: its path, else its URL."""
        return self.path_with_namespace or self.web_url

    @property
    def path(self) -> str:
        """``path_with_namespace`` (from ``web_url`` for old records): what --project-filter matches."""
        if self.path_with_namespace:
            return self.path_with_namespace
        return urlsplit(self.web_url).path.strip("/") if self.web_url else ""

    @property
    def branch_names(self) -> tuple[str, ...]:
        """The indexed branches (empty when unknown)."""
        return self.branches or ()

    @property
    def last_activity(self) -> datetime | None:
        """``last_activity_at`` as an aware datetime (None when missing or unparsable)."""
        return parse_timestamp(self.last_activity_at)

    def with_branches(self, branches: Iterable[str]) -> "Project":
        return replace(self, branches=tuple(branches))


def as_project(value: Project | Mapping[str, Any]) -> Project:
    """A Project as is; an index record (dict) through Project.from_record()."""
    return value if isinstance(value, Project) else Project.from_record(value)


@dataclass(frozen=True, slots=True)
class IndexMeta:
    """
    The first record of an index file: how and when it was built.

    Every field is None when an (old or broken) index doesn't have it.
    """

    source: str | None = None
    timestamp_utc: str | None = None
    projects_count: int | None = None
    elapsed_seconds: float | None = None
    order_by: str | None = None
    sort: str | None = None
    per_page: int | None = None
    last_activity_after: str | None = None
    last_activity_before: str | None = None
    is_completed: bool | None = None
    # "default" | "all" | N: added when branches are listed into the index.
    branches: str | int | None = None

    @classmethod
    def from_record(cls, record: Any) -> "IndexMeta":
        """The meta of an index; IndexMeta() for anything that isn't a meta record."""
        if not isinstance(record, Mapping):
            return cls()
        completed = record.get("is_completed")
        branches = record.get("branches")
        return cls(
            source=_str(record.get("source")),
            timestamp_utc=_str(record.get("timestamp_utc")),
            projects_count=_int(record.get("projects_count")),
            elapsed_seconds=record.get("elapsed_seconds") if isinstance(record.get("elapsed_seconds"), (int, float))
            else None,
            order_by=_str(record.get("order_by")),
            sort=_str(record.get("sort")),
            per_page=_int(record.get("per_page")),
            last_activity_after=_str(record.get("last_activity_after")),
            last_activity_before=_str(record.get("last_activity_before")),
            is_completed=completed if isinstance(completed, bool) else None,
            branches=branches if isinstance(branches, (str, int)) and not isinstance(branches, bool) else None,
        )

    def to_record(self) -> dict[str, Any]:
        """The meta record this version writes (``branches`` only when set)."""
        record: dict[str, Any] = {
            "type": "meta",
            "source": self.source,
            "timestamp_utc": self.timestamp_utc,
            "projects_count": self.projects_count,
            "elapsed_seconds": self.elapsed_seconds,
            "order_by": self.order_by,
            "sort": self.sort,
            "per_page": self.per_page,
            "last_activity_after": self.last_activity_after,
            "last_activity_before": self.last_activity_before,
            "is_completed": self.is_completed,
        }
        if self.branches is not None:
            record["branches"] = self.branches
        return record

    @property
    def built_at(self) -> datetime | None:
        return parse_timestamp(self.timestamp_utc)

    @property
    def window(self) -> TimeWindow:
        """The activity window the index was built for (unbounded when not stored)."""
        return TimeWindow(parse_timestamp(self.last_activity_after), parse_timestamp(self.last_activity_before))


@dataclass(slots=True)
class ProjectIndex:
    """A loaded index file."""

    meta: IndexMeta
    projects: list[Project]
