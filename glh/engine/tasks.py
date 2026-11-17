# glh/engine/tasks.py
"""The unit of search work handed to the worker pool."""

from __future__ import annotations

from dataclasses import dataclass

from glh.domain.file_filter import FileFilter
from glh.domain.models import Project
from glh.domain.timewindow import TimeWindow
from glh.gitlab.errors import describe_api_error, is_permanent_error
from glh.output.downloads import FileDownloader
from glh.output.records import Hit, INACCESSIBLE, NOT_FOUND


@dataclass(frozen=True, slots=True)
class BranchTask:
    """A term in one branch of one planned project (with what to do with the files found)."""

    term_no: int
    term: str
    project_no: int
    project: Project
    branches: tuple[str, ...]
    branch_no: int
    file_window: TimeWindow | None = None
    file_filter: FileFilter | None = None
    downloader: FileDownloader | None = None
    # Files-only mode (no term): "auto" | "search" | "tree"; None = term search.
    file_listing: str | None = None

    @property
    def branch(self) -> str:
        return self.branches[self.branch_no]

    @property
    def project_name(self) -> str:
        return self.project.name


@dataclass(frozen=True, slots=True)
class BranchOutcome:
    """
    What searching (or listing the files of) one branch gave.

    Two kinds of trouble, kept apart:

    - ``failure``: a retryable error (5xx, 429 after its retries, 401, a timeout,
      the network, an invalid response) may have hidden hits, so the term is not
      done and --resume searches it again;
    - ``unsearched``: the branch could not be searched at all, no access
      (HTTP 403, INACCESSIBLE) or not found (404, NOT_FOUND). Retrying won't
      change that, so the term is done, but the branch is a gap in the coverage
      and is counted as one (checkpoints, summary, Results block).
    """

    hits: list[Hit]
    failure: str | None = None
    unsearched: str | None = None
    # "group/repo @ main: HTTP 403 Forbidden" for an unsearched branch.
    reason: str = ""

    @classmethod
    def of(cls, task: BranchTask, hits: list[Hit], errors: list[BaseException]) -> "BranchOutcome":
        """The outcome of ``task`` from its hits and the API errors met."""
        where = f"{task.project_name} @ {task.branch}"
        if retryable := [e for e in errors if not is_permanent_error(e)]:
            return cls(hits, failure=f"{where}: {describe_api_error(retryable[0])}")
        if errors:
            kind = INACCESSIBLE if getattr(errors[0], "response_code", None) == 403 else NOT_FOUND
            return cls(hits, unsearched=kind, reason=f"{where}: {describe_api_error(errors[0])}")
        return cls(hits)
