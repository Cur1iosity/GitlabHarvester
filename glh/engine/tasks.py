# glh/engine/tasks.py
"""The unit of search work handed to the worker pool."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from glh.domain.file_filter import FileFilter
from glh.domain.timewindow import TimeWindow
from glh.output.downloads import FileDownloader


@dataclass(frozen=True, slots=True)
class BranchTask:
    """A term in one branch of one planned project (with what to do with the files found)."""

    term_no: int
    term: str
    project_no: int
    project: dict[str, Any]
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
        return self.project.get("path_with_namespace", self.project["web_url"])
