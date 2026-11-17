# glh/engine/file_listing.py
"""
FileLister: the files-only mode (``--filename``/``--extension`` without a term).

Every file of a branch whose name passes the file filters (and
``--file-changed-*``) becomes one hit, downloaded with ``--download-files``.
How the files of a branch are found (``--file-listing``):

- ``search``: the search API with the filters only (``filename:*.env``),
  where the search backend takes such queries (advanced search);
- ``tree``: the repository tree (any GitLab, one request per 100 entries);
- ``auto``: the search first, the tree for a branch with no results or an
  error, until the search has found files once (then it is trusted) or
  rejected the query as invalid (then only the tree is used).
"""

from __future__ import annotations

import logging
import threading
from collections import Counter
from typing import Any
from urllib.parse import quote

import gitlab.exceptions
import requests.exceptions
from gitlab.const import SearchScope
from gitlab.utils import EncodedId

from glh.engine.file_checks import FileChangeChecker, FileFetcher
from glh.engine.tasks import BranchTask
from glh.engine.workers import ActiveTasks
from glh.gitlab.connection import GitLabConnection
from glh.gitlab.errors import describe_api_error, is_permanent_error
from glh.ui import statusline


class FileLister:
    """Finds the matching files of a branch, see the module doc."""

    def __init__(self, connection: GitLabConnection, active: ActiveTasks, changes: FileChangeChecker,
                 fetcher: FileFetcher, logger: logging.Logger) -> None:
        self.connection = connection
        self.active = active
        self.changes = changes
        self.fetcher = fetcher
        self.logger = logger
        self._lock = threading.Lock()
        # --file-listing auto: "unknown" until the instance has shown whether its
        # search takes filter-only queries ("search") or not ("tree").
        self.state = "unknown"
        self.counts: Counter[str] = Counter()  # branches listed per method

    def reset(self) -> None:
        """Forget what the previous search learned (a new search starts)."""
        with self._lock:
            self.state = "unknown"
            self.counts = Counter()

    def collect(self, task: BranchTask) -> tuple[list[dict[str, Any]], str | None]:
        """One hit per matching file of the task's branch; (hits, retryable failure or None)."""
        name = task.project_name
        errors: list[BaseException] = []
        mode = task.file_listing or "auto"
        paths: list[str] | None = None
        how = "tree"
        if mode == "search" or (mode == "auto" and self.state != "tree"):
            paths = self._paths_by_search(task, errors, strict=mode == "search")
            how = "search"
        if paths is None:
            paths = self._paths_by_tree(task, errors)
            how = "tree"
        with self._lock:
            self.counts[how] += 1

        keep: list[str] = []
        for path in dict.fromkeys(paths):
            if task.file_filter and not task.file_filter.matches(path):
                continue
            if task.file_window and not self.changes.changed(task.project["id"], task.branch, path,
                                                             task.file_window):
                continue
            keep.append(path)
        local = self.fetcher.download(task, keep) if task.downloader is not None and keep else {}
        blob_url = f"{task.project['web_url']}/-/blob/{quote(task.branch, safe='/')}"
        hits = []
        for path in keep:
            hit: dict[str, Any] = {"url": f"{blob_url}/{quote(path, safe='/')}", "data": ""}
            if path in local:
                hit["file"] = local[path]
            hits.append(hit)
            self.logger.info("[+] File '%s': %s", task.term, hit["url"])
        retryable = [e for e in errors if not is_permanent_error(e)]
        failure = f"{name} @ {task.branch}: {describe_api_error(retryable[0])}" if retryable else None
        return hits, failure

    def _set_state(self, state: str, message: str) -> None:
        with self._lock:
            if self.state == state:
                return
            self.state = state
        statusline.STATUS.write_line(message)

    def _paths_by_search(self, task: BranchTask, errors: list[BaseException], *, strict: bool) -> list[str] | None:
        """Paths from a filter-only blob search of the branch, or None: let the tree answer for it (auto)."""
        query = task.file_filter.query("").strip() if task.file_filter else ""
        project = self.connection.require().projects.get(task.project["id"], lazy=True)
        found: dict[str, None] = {}
        page, per_page = 1, 100
        try:
            while True:
                if page > 1:
                    self.active.set_step(f"page {page}")
                batch = project.search(scope=SearchScope.BLOBS, ref=task.branch, search=query,
                                       page=page, per_page=per_page)
                for x in batch:
                    if isinstance(x, dict) and x.get("path"):
                        found.setdefault(x["path"])
                page += 1
                if len(batch) < per_page:
                    break
        except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
            if strict or is_permanent_error(e):
                self.logger.warning("Could not search %s @ %s (%s); skipping it, continuing",
                                    task.project_name, task.branch, describe_api_error(e))
                errors.append(e)
                return list(found)
            if getattr(e, "response_code", None) in (400, 422):
                self._set_state(
                    "tree", "File listing: the search API rejects filter-only queries here "
                            f"({describe_api_error(e)}); listing repository trees instead")
            else:
                self.logger.debug("Filter-only search of %s @ %s failed (%s); listing the tree",
                                  task.project_name, task.branch, describe_api_error(e))
            return None
        if found:
            self._set_state("search", "File listing: the search API takes filter-only queries here; using it")
            return list(found)
        if strict or self.state == "search":
            return []
        return None  # nothing found, and the search hasn't proven itself: ask the tree

    def _paths_by_tree(self, task: BranchTask, errors: list[BaseException]) -> list[str]:
        """Every file (blob) path of the branch from the repository tree API (keyset pagination)."""
        paths: list[str] = []
        try:
            entries = self.connection.require().http_list(
                f"/projects/{EncodedId(task.project['id'])}/repository/tree",
                query_data={"ref": task.branch, "recursive": "true", "per_page": 100, "pagination": "keyset"},
                iterator=True,
            )
            for n, entry in enumerate(entries, 1):
                if n % 1000 == 0:
                    self.active.set_step(f"{n:,} tree entries")
                if isinstance(entry, dict) and entry.get("type") == "blob" and entry.get("path"):
                    if not task.file_filter or task.file_filter.matches(entry["path"]):
                        paths.append(entry["path"])
        except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
            self.logger.warning("Could not list the files of %s @ %s (%s); skipping it, continuing",
                                task.project_name, task.branch, describe_api_error(e))
            errors.append(e)
        return paths
