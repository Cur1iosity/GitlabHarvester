# glh/engine/file_checks.py
"""
What a search does with a file it found, besides reporting it:

- :class:`FileChangeChecker` (``--file-changed-*``): was the file changed in
  its branch inside a time window? One commits request per (project, branch,
  file, window), cached across terms and worker threads.
- :class:`FileFetcher` (``--download-files``): download the files with hits
  through the calling thread's client and a :class:`~glh.output.downloads.FileDownloader`.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

import gitlab.exceptions
import requests.exceptions

from glh.domain.timewindow import format_api_time, TimeWindow
from glh.engine.tasks import BranchTask
from glh.engine.workers import ActiveTasks
from glh.gitlab.connection import GitLabConnection
from glh.gitlab.errors import describe_api_error


class FileChangeChecker:
    """Answers 'changed inside the window?' per file, see the module doc."""

    def __init__(self, connection: GitLabConnection, logger: logging.Logger) -> None:
        self.connection = connection
        self.logger = logger
        # (project id, branch, path, after, before) -> changed inside the window; shared by workers.
        self._cache: dict[tuple[Any, ...], bool] = {}
        self._lock = threading.Lock()

    @property
    def checks(self) -> int:
        """Files checked so far (distinct requests)."""
        return len(self._cache)

    def changed(self, project_id: Any, branch: str, path: str, window: TimeWindow) -> bool:
        """
        True if a commit touched ``path`` in ``branch`` inside ``window``.

        Uses GET /projects/:id/repository/commits with ref_name, path, since and
        until. On an API error the hit is kept and a warning is logged.
        """
        key = (project_id, branch, path, window.after, window.before)
        with self._lock:
            if key in self._cache:
                return self._cache[key]

        params: dict[str, Any] = {"ref_name": branch, "path": path}
        if window.after is not None:
            params["since"] = format_api_time(window.after)
        if window.before is not None:
            params["until"] = format_api_time(window.before)
        try:
            # `path` is reserved by python-gitlab's list() (it overrides the URL),
            # so the API filters go through query_parameters.
            commits = self.connection.require().projects.get(project_id, lazy=True).commits.list(
                query_parameters=params, page=1, per_page=1)
            changed = bool(commits)
        except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
            self.logger.warning("Cannot check changes of %s in branch %s of project %s (%s), keeping its hits",
                                path, branch, project_id, describe_api_error(e))
            self.logger.debug("Full error checking changes of %s in branch %s of project %s: %s",
                              path, branch, project_id, e)
            changed = True

        with self._lock:
            self._cache[key] = changed
        return changed


class FileFetcher:
    """Downloads the files with hits of a task, see the module doc."""

    def __init__(self, connection: GitLabConnection, active: ActiveTasks, logger: logging.Logger) -> None:
        self.connection = connection
        self.active = active
        self.logger = logger

    def download(self, task: BranchTask, paths: list[str]) -> dict[str, str]:
        """
        Download ``paths`` of the task's branch (--download-files).

        Returns:
            {repository path: local path} for the saved files. A file that
            can't be downloaded is logged and skipped: its hits are kept, and
            it doesn't make the term incomplete (nothing was missed in the search).
        """
        downloader = task.downloader
        assert downloader is not None
        name = task.project_name
        saved: dict[str, str] = {}
        for path in paths:
            self.active.set_step(f"downloading {path.rsplit('/', 1)[-1]}")
            try:
                local = downloader.save(
                    project_id=task.project.id, project_path=name, branch=task.branch, term=task.term,
                    path=path,
                    fetch=lambda p=path: self.connection.open_raw_file(task.project.id, task.branch, p),
                )
            except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException, OSError) as e:
                downloader.failed()
                self.logger.warning("Could not download %s from %s @ %s (%s); its hits are kept",
                                    path, name, task.branch, describe_api_error(e))
                self.logger.debug("Full error downloading %s from %s @ %s: %s", path, name, task.branch, e)
                continue
            if local is None:
                self.logger.info("Not downloaded (larger than --download-max-size): %s from %s @ %s",
                                 path, name, task.branch)
                continue
            saved[path] = str(local)
        self.active.set_step("")
        return saved
