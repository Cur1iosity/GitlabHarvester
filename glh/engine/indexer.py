# glh/engine/indexer.py
"""
ProjectIndexer: the Instance Project Index of a GitLab connection.

The index is a JSONL file: a ``meta`` record, then one line per project with
the few fields a search needs (id, URLs, default branch, fork origin, empty
repository, activity dates and, on request, its branch names). It is built
once and reused by every later search; pages of projects and branch lists are
fetched by the worker pool, but written in index order.
"""

from __future__ import annotations

import itertools
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Callable, IO, Iterable, Iterator

import gitlab.exceptions
import requests.exceptions
from gitlab.v4.objects import Project as GitlabProject

from glh.domain.models import IndexMeta, Project, ProjectIndex
from glh.domain.timewindow import format_api_time, parse_timestamp, TimeWindow
from glh.engine import workers as pool
from glh.gitlab.connection import GitLabConnection
from glh.gitlab.errors import describe_api_error, is_permanent_error
from glh.ui.formatting import format_duration, plural
from glh.ui.progress import Progress

# datetime.UTC exists only on Python 3.11+, while the package supports 3.10.
UTC = timezone.utc


def _write_jsonl_line(fp: IO, obj: dict[str, Any]) -> None:
    """One JSON object as one line (no ASCII escaping)."""
    fp.write(json.dumps(obj, ensure_ascii=False))
    fp.write("\n")


class ProjectIndexer:
    """Builds, enriches and loads the project index (see the module doc)."""

    def __init__(self, connection: GitLabConnection, logger: logging.Logger) -> None:
        self.connection = connection
        self.logger = logger

    def _imap_ordered(self, fn: Callable[[Any], Any], items: Iterable[Any], *,
                      parallel: bool = True) -> Iterator[pool.Done[Any]]:
        """imap_ordered() with the connection's total concurrency and per-thread clients."""
        return pool.imap_ordered(fn, items, workers=self.connection.concurrency if parallel else 1,
                                 initializer=self.connection.init_worker_client)

    # ------------------------------------------------------------------- names

    def default_index_filename(self) -> str:
        """'<host>_project_index.jsonl' (the default of build_project_index)."""
        return f"{self.connection.instance_id()}_project_index.jsonl"

    def default_projects_filename(self) -> str:
        """'<host>_projects.jsonl' ('undefined_projects.jsonl' without a client)."""
        if not self.connection.gl:
            return "undefined_projects.jsonl"
        return f"{self.connection.instance_id()}_projects.jsonl"

    # ----------------------------------------------------------------- listing

    def fetch_projects(
            self,
            per_page: int = 100,
            filename: str | None = None,
            order_by: str = "id",
            sort: str = "desc",
            last_activity_after: datetime | None = None,
            last_activity_before: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """
        Retrieve projects from the GitLab instance with a reduced set of key fields.

        last_activity_after/last_activity_before are passed to GitLab as API
        filters, so projects outside the window are not even listed.

        Projects can be either collected in memory and returned as a list, or streamed
        directly to a file in NDJSON (JSONL) format to minimize memory usage. When
        streaming is enabled, data is first written to a temporary file and then
        reassembled with a metadata header as the first line.
        """
        gl = self.connection.require()

        def reduce_project_fields(project: GitlabProject) -> dict[str, Any]:
            """The index record of a GitLab project object (the few fields a search needs)."""
            fork_data = getattr(project, "forked_from_project", None)
            return Project(
                id=project.id,
                web_url=project.web_url,
                path_with_namespace=project.path_with_namespace,
                default_branch=getattr(project, "default_branch", None),
                empty_repo=project.empty_repo,
                is_fork=bool(fork_data),
                upstream_id=fork_data["id"] if fork_data else None,
                created_at=project.created_at,
                last_activity_at=project.last_activity_at,
            ).to_record()

        projects: list[dict[str, Any]] = []
        pr_counter = 0
        is_completed: bool = True
        outcome = ""

        start = time.perf_counter()
        tmp_filename = f"{filename}.tmp" if filename else None
        fp = open(tmp_filename, "w", encoding="utf-8") if tmp_filename else None

        host = self.connection.instance_id()
        display_host = self.connection.display_host()

        activity: dict[str, str] = {}
        if last_activity_after is not None:
            activity["last_activity_after"] = format_api_time(last_activity_after)
        if last_activity_before is not None:
            activity["last_activity_before"] = format_api_time(last_activity_before)
        window = TimeWindow(last_activity_after, last_activity_before)
        window_text = f" (active {window.describe()})" if window else ""
        progress = Progress(f"Indexing {display_host}{window_text}", unit="projects").start()

        def fetch_page(number: int) -> list[GitlabProject]:
            client = self.connection.gl or gl
            return client.projects.list(page=number, per_page=per_page, order_by=order_by, sort=sort, **activity)

        try:
            # Pages are fetched up to 2 x workers ahead but processed in order; the
            # first empty page ends the listing (the extra pages are discarded).
            for done in self._imap_ordered(fetch_page, itertools.count(1)):
                batch = done.unwrap()
                if not batch:
                    break
                page = done.item
                if fp is not None:
                    for x in batch:
                        _write_jsonl_line(fp, reduce_project_fields(x))
                else:
                    projects.extend(reduce_project_fields(x) for x in batch)

                batch_size = len(batch)
                pr_counter += batch_size
                progress.advance(batch_size, detail=f"page {page}")

        except gitlab.exceptions.GitlabError as e:
            # The listing stopped early: keep what was fetched, but never
            # mark a partial index as complete.
            is_completed = False
            outcome = " (incomplete: GitLab API error)"
            self.logger.error("Gitlab API error (%s). The project list wasn't complete.",
                              describe_api_error(e))
            self.logger.debug("Full project-listing error: %s", e)

        except KeyboardInterrupt:
            is_completed = False
            outcome = " (interrupted)"
            self.logger.error("Interrupted by user (Ctrl+C).")
            raise

        except Exception:
            is_completed = False
            outcome = " (failed)"
            self.logger.exception("Fatal error while loading projects.")
            raise

        finally:
            elapsed = round(time.perf_counter() - start, 2)
            progress.finish(
                f"Indexed {plural(pr_counter, 'project')}{window_text} from {display_host} in "
                f"{format_duration(elapsed)}{outcome}"
            )

            if fp is not None:
                fp.close()

            if filename:
                meta = IndexMeta(
                    source=host,
                    timestamp_utc=datetime.now(UTC).isoformat(),
                    projects_count=pr_counter,
                    elapsed_seconds=elapsed,
                    order_by=order_by,
                    sort=sort,
                    per_page=per_page,
                    last_activity_after=activity.get("last_activity_after"),
                    last_activity_before=activity.get("last_activity_before"),
                    is_completed=is_completed,
                )
                with open(filename, "w", encoding="utf-8") as out_fp:
                    _write_jsonl_line(out_fp, meta.to_record())
                    with open(tmp_filename, "r", encoding="utf-8") as in_fp:
                        for line in in_fp:
                            out_fp.write(line)

                os.remove(tmp_filename)

        self.logger.info("Loaded %s projects in %s seconds.", pr_counter, elapsed)
        return projects

    def get_branches(self, project_id: int, per_page: int = 100, *, limit: int | None = None) -> list[str]:
        """
        Branch names of a project, in API order (GitLab sorts them by name).

        Stops after ``limit`` branches (None = all). On an API error the
        branches fetched so far are returned and the error is logged;
        list_branches() also tells whether the list is complete.
        """
        return self.list_branches(project_id, per_page, limit=limit)[0]

    def list_branches(self, project_id: int, per_page: int = 100, *,
                      limit: int | None = None) -> tuple[list[str], bool]:
        """
        (branch names, complete): get_branches() plus whether the listing ran to its end.

        A retryable error (5xx, 429 after its retries, timeout, network) cuts the
        list: ``complete`` is False. A permanent one (403/404: no access to the
        repository) leaves nothing to retry, so the list counts as complete.
        """
        gl = self.connection.require()
        branches: list[str] = []
        page = 1
        try:
            while True:
                batch = gl.projects.get(project_id, lazy=True).branches.list(page=page, per_page=per_page)
                if not batch:
                    break

                for b in batch:
                    branches.append(b.name)
                    if limit is not None and len(branches) >= limit:
                        return branches, True

                page += 1

        except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
            self.logger.error(
                "Gitlab API error (%s). The branch list wasn't complete for project with ID: %s.",
                describe_api_error(e), project_id,
            )
            self.logger.debug("Full branch-listing error for project %s: %s", project_id, e)
            return branches, is_permanent_error(e)

        self.logger.debug("Loaded %s branches for project with ID: %s.", len(branches), project_id)
        return branches, True

    def _listed_branches(self, project: Project, per_page: int, limit: int | None) -> tuple[list[str], bool]:
        """
        The branches of a non-empty project for the index, and whether the list is complete.

        A cut list keeps its default branch: without it a failure on the first page
        would leave the project with no branches, and the search would skip it.
        """
        branches, complete = self.list_branches(project.id, per_page, limit=limit)
        if not complete and project.default_branch and project.default_branch not in branches:
            branches.append(project.default_branch)
        return branches, complete

    def _warn_incomplete_branches(self, incomplete: list[str]) -> None:
        """One warning for every project whose branch list an API error cut."""
        if incomplete:
            shown = ", ".join(incomplete[:5]) + (f" and {len(incomplete) - 5} more" if len(incomplete) > 5 else "")
            self.logger.warning(
                "The branch lists of %s are incomplete (GitLab API errors): %s. Their default branch is "
                "kept, other branches may be missing from the search; --dump-projects rebuilds the index.",
                plural(len(incomplete), "project"), shown,
            )

    def first_project_id(self) -> Any | None:
        """Id of a non-empty project from the first page of /projects (for search probes)."""
        gl = self.connection.require()
        try:
            page = gl.http_get("/projects", query_data={"per_page": 20, "order_by": "id", "sort": "desc"})
        except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
            self.logger.warning("Cannot list projects for the limit probe: %s", describe_api_error(e))
            return None
        projects = [p for p in page if isinstance(p, dict) and p.get("id") is not None] if isinstance(page, list) else []
        for project in projects:
            if not project.get("empty_repo", False):
                return project["id"]
        return projects[0]["id"] if projects else None

    # ------------------------------------------------------------------- index

    def build_project_index(
            self,
            *,
            per_page: int = 100,
            filename: str | None = None,
            order_by: str = "id",
            sort: str = "desc",
            enforce_dump: bool = False,
            branches: str | int = "default",  # "default" | "all" | int
            branches_per_page: int = 100,
            last_activity_after: datetime | None = None,
            last_activity_before: datetime | None = None,
    ) -> str:
        """
        Build (or rebuild) the Instance Project Index file (JSONL/NDJSON) and optionally enrich it with branches.

        last_activity_after/last_activity_before limit the index to projects
        active in that window (GitLab API filter). An existing index built
        with a different window is reused with a warning.

        branches:
            - "default": store only default branch (no GitLab branch API calls)
            - "all": fetch all branches for each non-empty project (slow)
            - int: fetch up to N branches for each non-empty project

        Returns:
            Output filename.
        """
        if not filename:
            filename = self.default_index_filename()

        needs_build = enforce_dump or not os.path.exists(filename)
        if needs_build:
            self.logger.info(
                "Building Instance Project Index. Batch size: %s. Output file: %s.",
                per_page,
                filename,
            )
            # Base index (meta + projects without branches)
            self.fetch_projects(per_page=per_page, filename=filename, order_by=order_by, sort=sort,
                                last_activity_after=last_activity_after, last_activity_before=last_activity_before)

            if branches is not None:
                self.enrich_project_index_with_branches(
                    filename=filename,
                    branches=branches,
                    branches_per_page=branches_per_page,
                )
        else:
            self.logger.info("Instance Project Index already exists: %s.", filename)
            try:
                with open(filename, encoding="utf-8") as fp:
                    raw = json.loads(fp.readline() or "{}")
            except (OSError, json.JSONDecodeError):
                raw = None
            meta = IndexMeta.from_record(raw)
            if meta.incomplete_reason:
                self.logger.warning(
                    "Existing project index %s is incomplete (%s). Use --dump-projects to rebuild it.",
                    filename, meta.incomplete_reason,
                )
            if isinstance(raw, dict):
                built = (meta.last_activity_after, meta.last_activity_before)
                wanted = tuple(format_api_time(v) if v is not None else None
                               for v in (last_activity_after, last_activity_before))
                if built != wanted:
                    self.logger.warning(
                        "Existing project index %s was built for projects active %s, this run asks for %s. "
                        "It is reused as is; use --dump-projects to rebuild it.",
                        filename, self._window_text(*built), self._window_text(*wanted),
                    )
        return filename

    def enrich_project_index_with_branches(
            self,
            *,
            filename: str,
            branches: str | int = "default",
            branches_per_page: int = 100,
    ) -> str:
        """Enrich an existing Instance Project Index (JSONL) with branches and rewrite it in-place."""
        if branches == "default":
            self.logger.info("Branches mode: default (no API calls, using default_branch only).")
        elif branches == "all":
            self.logger.info("Branches mode: all (slow).")
        else:
            self.logger.info("Branches mode: limit=%s (slow-ish).", branches)

        tmp_out = f"{filename}.branches.tmp"
        incomplete: list[str] = []  # projects whose branch list an API error cut
        uses_api = branches != "default"
        # Only non-empty repositories cost API calls, so only they are counted.
        to_list = self._count_nonempty_projects(filename) if uses_api else 0
        progress = Progress("Listing branches", total=to_list, unit="projects")
        listed_branches = 0

        with open(filename, "r", encoding="utf-8") as in_fp, open(tmp_out, "w", encoding="utf-8") as out_fp:
            first_line = in_fp.readline()
            if not first_line:
                raise ValueError(f"Project index file is empty: {filename}")

            # The meta is written last: it records whether every branch list is complete.
            meta = json.loads(first_line)
            meta["branches"] = branches
            meta["timestamp_utc"] = datetime.now(UTC).isoformat()

            def index_records():
                for raw in in_fp:
                    raw = raw.strip()
                    if raw:
                        yield json.loads(raw)

            limit = None if branches in ("default", "all") else int(branches)

            def branches_of(record: dict[str, Any]) -> tuple[list[str], bool]:
                project = Project.from_record(record)
                if project.empty_repo:
                    return [], True
                if not uses_api:
                    return ([project.default_branch] if project.default_branch else []), True
                if self.connection.concurrency <= 1:
                    progress.set_detail(project.path_with_namespace or str(project.id))
                return self._listed_branches(project, branches_per_page, limit)

            if uses_api:
                progress.start()
            try:
                # Branch lists are fetched in parallel; the index keeps its order.
                for done in self._imap_ordered(branches_of, index_records(), parallel=uses_api):
                    project = done.item
                    project["branches"], complete = done.unwrap()
                    if not complete:
                        incomplete.append(str(project.get("path_with_namespace") or project["id"]))
                    if uses_api and not project.get("empty_repo", False):
                        listed_branches += len(project["branches"])
                        progress.advance(detail=str(project.get("path_with_namespace") or project["id"]))

                    _write_jsonl_line(out_fp, project)
            except BaseException:
                if uses_api:
                    progress.finish(f"{progress.render()} | stopped")
                raise

        if uses_api:
            progress.finish(
                f"Listed {plural(listed_branches, 'branch', 'branches')} of "
                f"{plural(progress.done, 'project')} in "
                f"{format_duration(progress.elapsed)}"
                + (f" ({len(incomplete)} incomplete)" if incomplete else "")
            )
        self._warn_incomplete_branches(incomplete)
        if incomplete:
            # Not a complete index: reusing it warns, and --dump-projects rebuilds it.
            meta["is_completed"] = False
            meta["branches_incomplete"] = len(incomplete)

        new_file = f"{filename}.new"
        with open(new_file, "w", encoding="utf-8") as out_fp:
            _write_jsonl_line(out_fp, meta)
            with open(tmp_out, "r", encoding="utf-8") as in_fp:
                for line in in_fp:
                    out_fp.write(line)
        os.remove(tmp_out)
        os.replace(new_file, filename)
        if branches != "default":
            self.logger.info("Project index enriched with branches (mode=%s): %s", branches, filename)
        return filename

    @staticmethod
    def _window_text(after: str | None, before: str | None) -> str:
        """Describe an activity window stored as API strings (None = unbounded)."""
        return TimeWindow(parse_timestamp(after), parse_timestamp(before)).describe()

    @staticmethod
    def _count_nonempty_projects(filename: str) -> int:
        """Count non-empty repositories in an index file without loading it into memory."""
        count = 0
        with open(filename, "r", encoding="utf-8") as fp:
            fp.readline()  # meta
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    if not json.loads(line).get("empty_repo", False):
                        count += 1
                except json.JSONDecodeError:
                    continue
        return count

    def download_projects(
            self,
            *,
            per_page: int = 100,
            filename: str | None = None,
            order_by: str = "id",
            sort: str = "desc",
            enforce_dump: bool = False,
            branches: str | int = "default",
            branches_per_page: int = 100,
    ) -> str:
        """Create or update the index, then add branches to it (``branches``: "default", "all" or N)."""
        filename = self.build_project_index(
            per_page=per_page,
            filename=filename,
            order_by=order_by,
            sort=sort,
            enforce_dump=enforce_dump,
        )

        if branches is not None:
            filename = self.enrich_project_index_with_branches(
                filename=filename,
                branches=branches,
                branches_per_page=branches_per_page,
            )

        return filename

    def add_branches_to_projects(self, projects: list[dict], per_page: int = 50) -> list[dict]:
        """
        Add a "branches" list to every project dictionary (in memory).

        Empty repositories get an empty list without API calls and are not counted.
        """
        self.connection.require()
        to_list = sum(1 for p in projects if not p.get("empty_repo", False))
        incomplete: list[str] = []

        def branches_of(project: dict[str, Any]) -> tuple[list[str], bool]:
            if project.get("empty_repo", False):
                return [], True
            return self._listed_branches(Project.from_record(project), per_page, None)

        with Progress("Listing branches", total=to_list, unit="projects") as progress:
            for done in self._imap_ordered(branches_of, projects):
                project = done.item
                project["branches"], complete = done.unwrap()
                if not complete:
                    incomplete.append(str(project.get("path_with_namespace") or project["id"]))
                if not project.get("empty_repo", False):
                    progress.advance(detail=str(project.get("path_with_namespace") or project.get("web_url", "")))

            elapsed = progress.finish(
                f"Listed branches of {plural(progress.done, 'project')} in "
                f"{format_duration(progress.elapsed)}"
            )

        self._warn_incomplete_branches(incomplete)
        self.logger.info("Loaded branches for %s projects in %s seconds.", len(projects), round(elapsed, 2))

        return projects

    def initialize_project_list(
            self,
            per_page: int = 100,
            filename: str | None = None,
            enforce_dump: bool = False,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """
        Make sure the project index exists (fetch it if missing or ``enforce_dump``)
        and load it: (projects, meta). No staleness checks.
        """
        filename = filename or self.default_projects_filename()

        if enforce_dump:
            self.logger.info("Enforce rebuild requested. Building Instance Project Index.")
            self.fetch_projects(per_page=per_page, filename=filename)

        data = self.load_projects_from_file(filename)
        if not data:
            self.logger.info("Instance Project Index was not found or unreadable. Building it now.")
            self.fetch_projects(per_page=per_page, filename=filename)
            data = self.load_projects_from_file(filename)

        meta = (data or {}).get("meta") or {}
        projects = (data or {}).get("projects") or []

        self.logger.info("Instance Project Index initialization completed.")
        return projects, meta

    def load_index(self, filename: str | None) -> ProjectIndex | None:
        """
        Load an index file as objects (about half the memory of
        load_projects_from_file()); None if it is missing or empty.

        Broken lines and records without a project id are skipped with a warning.
        """
        if not filename:
            return None
        try:
            with open(filename, encoding="utf-8") as fp:
                first_line = fp.readline()
                if not first_line:
                    self.logger.warning(f"File '{filename}' is empty.")
                    return None
                meta = IndexMeta.from_record(json.loads(first_line))
                projects: list[Project] = []
                for line in fp:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        projects.append(Project.from_record(json.loads(line)))
                    except (json.JSONDecodeError, ValueError, AttributeError) as e:
                        self.logger.warning(f"Broken JSON line in '{filename}': {e}")
        except FileNotFoundError:
            self.logger.debug(f"File with project data ['{filename}'] was not found.")
            return None
        self._log_loaded(filename, len(projects), meta.timestamp_utc)
        return ProjectIndex(meta=meta, projects=projects)

    def _log_loaded(self, filename: str, count: int, timestamp: Any) -> None:
        ts_str = "unknown"
        if timestamp:
            try:
                ts_str = datetime.fromisoformat(timestamp).strftime("%d-%m-%Y %H:%M:%S")
            except Exception:
                ts_str = timestamp
        self.logger.info(f"Loaded {count} projects from '{filename}'. Collecting time: {ts_str}")

    def load_projects_from_file(self, filename: str | None = None) -> dict[str, Any]:
        """
        Load an index file: {"meta": {...}, "projects": [...]}; {} if it is missing or empty.

        Broken lines are skipped with a warning.
        """
        if not filename:
            return {}

        try:
            projects: list[dict[str, Any]] = []

            with open(filename, encoding="utf-8") as f:
                first_line = f.readline()
                if not first_line:
                    self.logger.warning(f"File '{filename}' is empty.")
                    return {}

                meta: dict[str, Any] = json.loads(first_line)

                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        projects.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        self.logger.warning(f"Broken JSON line in '{filename}': {e}")
                        continue

            self._log_loaded(filename, len(projects), meta.get("timestamp_utc") if isinstance(meta, dict) else None)

            return {
                "meta": meta,
                "projects": projects,
            }

        except FileNotFoundError:
            self.logger.debug(f"File with project data ['{filename}'] was not found.")
            return {}
