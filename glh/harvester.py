# glh/harvester.py
from __future__ import annotations

import itertools
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, IO, Any
from urllib.parse import quote, urlparse

import gitlab.exceptions
import requests.exceptions
from gitlab import Gitlab
from gitlab.const import SearchScope
from gitlab.v4.objects import Project
from requests import Session

from glh.exceptions import GitlabHarvesterError
from glh.planner import (
    ScanOptions,
    ScanPlan,
    TimeWindow,
    branches_to_scan,
    build_scan_plan,
    format_api_time,
    parse_timestamp,
)
from glh import workers as pool
from glh.utils import logging_utils, terminal_utils
from glh.utils.terminal_utils import human_int

# datetime.UTC exists only on Python 3.11+, while the package supports 3.10.
UTC = timezone.utc


def client_required(func: Callable) -> Callable:
    """
    Decorator ensuring that a GitLab client is initialized before method execution.

    The decorator checks whether the GitlabHarvester instance has an active
    GitLab client. If the client is not initialized, a GitlabHarvesterError
    is raised, preventing accidental use of API-dependent methods.

    Args:
        func: Method to be wrapped.

    Returns:
        Wrapped function that performs the client availability check
        before invoking the original method.

    Raises:
        GitlabHarvesterError: If the GitLab client is not initialized.
    """

    def wrapper(*args, **kwargs) -> Callable:
        glh: GitlabHarvester = args[0]
        if not glh._gl:
            raise GitlabHarvesterError("You're trying to use Gitlab client before initialization.")
        return func(*args, **kwargs)

    return wrapper


@dataclass(frozen=True, slots=True)
class _BranchTask:
    """One unit of search work: a term in one branch of one planned project."""

    term_no: int
    term: str
    project_no: int
    project: dict[str, Any]
    branches: tuple[str, ...]
    branch_no: int
    file_window: TimeWindow | None = None

    @property
    def branch(self) -> str:
        return self.branches[self.branch_no]


class GitlabHarvester:
    """High-level GitLab indexing and search engine.

    The harvester manages:
    - GitLab API client initialization
    - Instance Project Index (JSONL) generation/enrichment
    - Term search across projects/branches with progress output
    """

    def __init__(
            self,
            url: str | None = None,
            token: str | None = None,
            search_terms: list | None = None,
            proxy: str | None = None,
            timeout: int = 60,
            *,
            log_level: int | str = logging.WARNING,
            log_file: str | None = None,
            host: str | None = None,  # backward-compat alias for `url`
            workers: int = 1,
    ) -> None:
        self.search_terms: list = search_terms or []
        # Parallel API requests (1 = sequential). See glh/workers.py.
        self.workers: int = max(1, int(workers))
        self._local = threading.local()
        self._gl_main: Gitlab | None = None
        self._client_kwargs: dict[str, Any] | None = None
        # (project id, branch, path, window) -> changed inside the window; shared by workers.
        self._file_change_cache: dict[tuple[Any, ...], bool] = {}
        self._file_change_lock = threading.Lock()

        self.log_level: int = logging_utils.coerce_log_level(log_level)
        self.log_file: str | None = log_file
        self.logger = logging_utils.build_logger(
            name="GitlabHarvesterLogger",
            level=self.log_level,
            log_file=self.log_file,
        )

        url = url or host
        self._gl: Gitlab | None = self._get_gl_client(url=url, token=token, proxy=proxy, timeout=timeout) if url and token else None

    @property
    def _gl(self) -> Gitlab | None:
        """GitLab client of the current thread (worker threads get their own one)."""
        return getattr(self._local, "gl", None) or self._gl_main

    @_gl.setter
    def _gl(self, value: Gitlab | None) -> None:
        self._gl_main = value

    def _init_worker_client(self) -> None:
        """
        Give the calling worker thread its own python-gitlab client.

        requests.Session is not thread-safe, and one shared connection pool
        would be too small for many workers. The token was already verified
        by the main client, so no extra /user request is made.
        """
        if self._client_kwargs is None:
            return  # client not built by _get_gl_client (e.g. a test stub): share it
        kwargs = dict(self._client_kwargs)
        main_session = kwargs.pop("session", None)
        if main_session is not None:
            session = Session()
            session.proxies.update(main_session.proxies)
            kwargs["session"] = session
        self._local.gl = Gitlab(**kwargs)

    def _imap_ordered(self, fn: Callable[[Any], Any], items: Any, *, parallel: bool = True):
        """imap_ordered() with this harvester's worker count and per-thread clients."""
        return pool.imap_ordered(fn, items, workers=self.workers if parallel else 1,
                                 initializer=self._init_worker_client)

    @staticmethod
    def _emit_record(fp: IO, record: dict[str, Any], indent: int | None = None) -> None:
        """
        Serialize and write a single record to an open file in JSON format.

        The record is written as one line (JSONL/NDJSON). Optional indentation
        can be applied for readability when needed.

        Args:
            fp: Open file-like object for writing text data.
            record: Dictionary to serialize.
            indent: Optional JSON indentation level; if None, compact form is used.

        Returns:
            None
        """
        fp.write(json.dumps(record, ensure_ascii=False, indent=indent))
        fp.write("\n")

    @staticmethod
    def _write_jsonl_line(fp: IO, obj: dict[str, Any]) -> None:
        """
        Write a dictionary as a single JSONL (NDJSON) line to the provided file.

        The object is serialized without ASCII escaping and terminated with
        a newline character to maintain one-object-per-line structure.

        Args:
            fp: Open file-like object for writing text data.
            obj: Dictionary to serialize and append.

        Returns:
            None
        """
        fp.write(json.dumps(obj, ensure_ascii=False))
        fp.write("\n")

    def get_instance_id(self) -> str:
        """Return a filesystem-safe identifier for the configured GitLab instance.

        Returns:
            Instance identifier like 'gitlab_example_com' (a port becomes '_8080'),
            or 'undefined' if no client.
        """
        if not self._gl:
            return "undefined"
        parsed = urlparse(self._gl.url)
        host = (parsed.netloc or parsed.path).strip("/")
        # ':' (host:port) is not allowed in Windows file names and would create
        # an NTFS alternate data stream instead of a regular file.
        return host.replace(".", "_").replace(":", "_")

    def get_host(self) -> str:
        """Backward-compatible alias for get_instance_id()."""
        return self.get_instance_id()

    def _display_host(self) -> str:
        """Instance host as shown to the user, e.g. 'gitlab.example.com:8443'."""
        if not self._gl:
            return "undefined"
        parsed = urlparse(self._gl.url)
        return parsed.netloc or self._gl.url

    def _get_default_log_filename(self) -> str:
        """
        Generate the default filename for the log output.

        The name is derived from the normalized GitLab host identifier
        with a ".log" extension.

        Returns:
            Default log filename as a string.
        """
        return f'{self.get_host()}.log'

    def get_default_projects_filename(self) -> str:
        """
        Generate the default filename for the Instance Project Index.

        The name is based on the normalized GitLab host identifier and
        uses a JSONL extension. If the GitLab client is not initialized,
        a generic placeholder name is returned.

        Returns:
            Default project index filename.
        """
        filename: str = 'undefined_projects.jsonl'
        if self._gl:
            filename: str = f'{self.get_host()}_projects.jsonl'
        return filename

    @staticmethod
    def _normalize_proxy(proxy: str) -> str:
        p = proxy.strip()
        if not p:
            return p
        if "://" not in p:
            p = f"http://{p}"
        parsed = urlparse(p)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid proxy URL: {proxy!r}. Example: http://127.0.0.1:8080")
        return p

    def _get_gl_client(
            self,
            url: str,
            token: str,
            timeout: int = 60,
            proxy: str | None = None,
            ssl_verify: bool = True,
            disable_ssl_warnings: bool = True,
            allow_ssl_fallback: bool = True,
    ) -> Gitlab:
        """
        Initialize and authenticate a GitLab API client.

        Args:
            url: GitLab instance URL.
            token: Personal access token for API authentication.
            timeout: Connection timeout in seconds.
            proxy: Optional proxy URL applied to both HTTP and HTTPS.
            ssl_verify: Whether to verify TLS certificates.
            disable_ssl_warnings: Disable urllib3 TLS warnings (only when ssl_verify=False).
            allow_ssl_fallback: If True, retries auth with ssl_verify=False on SSLError.

        Returns:
            Authenticated Gitlab client instance.

        Raises:
            requests.exceptions.SSLError: If TLS fails and fallback is disabled or also fails.
            ValueError: If proxy URL is invalid.
        """
        self.logger.debug("Connecting to GitLab: %s", url)

        kwargs: dict[str, Any] = {
            "url": url,
            "private_token": token,
            "timeout": timeout,
            "ssl_verify": ssl_verify,
        }

        if proxy:
            proxy = self._normalize_proxy(proxy)
            session = Session()
            session.proxies.update({"http": proxy, "https": proxy})
            kwargs["session"] = session

        def _maybe_disable_warnings() -> None:
            if disable_ssl_warnings and kwargs.get("ssl_verify") is False:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        _maybe_disable_warnings()

        gl = Gitlab(**kwargs)

        try:
            gl.auth()
            self.logger.debug("Authenticated to GitLab: %s", url)
            self._client_kwargs = dict(kwargs)
            return gl
        except requests.exceptions.SSLError:
            if not allow_ssl_fallback or kwargs.get("ssl_verify") is False:
                self.logger.exception("TLS handshake failed for %s", url)
                raise

            # Fallback: retry once with ssl verification disabled
            self.logger.info("TLS failed for %s; retrying with ssl_verify=False", url)
            kwargs["ssl_verify"] = False
            _maybe_disable_warnings()

            gl = Gitlab(**kwargs)
            gl.auth()
            self.logger.debug("Authenticated to GitLab (ssl_verify=False): %s", url)
            self._client_kwargs = dict(kwargs)
            return gl

    @client_required
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

        def reduce_project_fields(project: Project) -> dict[str, Any]:
            """Extract a minimal set of relevant fields from a GitLab project object."""
            return {
                "id": project.id,
                "web_url": project.web_url,
                "path_with_namespace": project.path_with_namespace,
                "default_branch": getattr(project, "default_branch", None),
                "empty_repo": project.empty_repo,
                "forked_from_project": {"id": fork_data["id"]}
                if (fork_data := getattr(project, "forked_from_project", None))
                else False,
                "created_at": project.created_at,
                "last_activity_at": project.last_activity_at,
            }

        projects: list[dict[str, Any]] = []
        pr_counter = 0
        is_completed: bool = True
        outcome = ""

        start = time.perf_counter()
        tmp_filename = f"{filename}.tmp" if filename else None
        fp = open(tmp_filename, "w", encoding="utf-8") if tmp_filename else None

        host = self.get_host()

        activity: dict[str, str] = {}
        if last_activity_after is not None:
            activity["last_activity_after"] = format_api_time(last_activity_after)
        if last_activity_before is not None:
            activity["last_activity_before"] = format_api_time(last_activity_before)
        window = TimeWindow(last_activity_after, last_activity_before)
        window_text = f" (active {window.describe()})" if window else ""
        progress = terminal_utils.Progress(f"Indexing {self._display_host()}{window_text}", unit="projects").start()

        def fetch_page(number: int) -> list[Project]:
            return self._gl.projects.list(page=number, per_page=per_page, order_by=order_by, sort=sort, **activity)

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
                        self._emit_record(fp=fp, record=reduce_project_fields(x))
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
            self.logger.error("Gitlab API error. The project list wasn't complete.")
            self.logger.error(e)

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
                f"Indexed {terminal_utils.plural(pr_counter, 'project')}{window_text} from {self._display_host()} in "
                f"{terminal_utils.format_duration(elapsed)}{outcome}"
            )

            if fp is not None:
                fp.close()

            if filename:
                meta = {
                    "type": "meta",
                    "source": host,
                    "timestamp_utc": datetime.now(UTC).isoformat(),
                    "projects_count": pr_counter,
                    "elapsed_seconds": elapsed,
                    "order_by": order_by,
                    "sort": sort,
                    "per_page": per_page,
                    "last_activity_after": activity.get("last_activity_after"),
                    "last_activity_before": activity.get("last_activity_before"),
                    "is_completed": is_completed,
                }
                with open(filename, "w", encoding="utf-8") as out_fp:
                    self._write_jsonl_line(out_fp, meta)
                    with open(tmp_filename, "r", encoding="utf-8") as in_fp:
                        for line in in_fp:
                            out_fp.write(line)

                os.remove(tmp_filename)

        self.logger.info("Loaded %s projects in %s seconds.", pr_counter, elapsed)
        return projects

    @client_required
    def get_branches(
            self,
            project_id: int,
            per_page: int = 100,
            *,
            limit: int | None = None,
    ) -> list[str]:
        """
        Retrieve branch names for a specific GitLab project.

        Args:
            project_id: GitLab project id.
            per_page: Branches API page size.
            limit: Stop after this many branches (None = all).

        Returns:
            Branch names in API order (GitLab sorts them by name). On an API
            error the branches fetched so far are returned and the error is logged.
        """
        branches: list[str] = []
        page = 1
        try:
            while True:
                batch = self._gl.projects.get(project_id, lazy=True).branches.list(page=page, per_page=per_page)
                if not batch:
                    break

                for b in batch:
                    branches.append(b.name)
                    if limit is not None and len(branches) >= limit:
                        return branches

                page += 1

        except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
            self.logger.error(
                "Gitlab API error. The branch list wasn't complete for project with ID: %s.",
                project_id,
            )
            self.logger.error(e)

        self.logger.debug("Loaded %s branches for project with ID: %s.", len(branches), project_id)
        return branches

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
            filename = f"{self.get_instance_id()}_project_index.jsonl"

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
                    meta = json.loads(fp.readline() or "{}")
            except (OSError, json.JSONDecodeError):
                meta = {}
            if isinstance(meta, dict) and meta.get("is_completed") is False:
                self.logger.warning(
                    "Existing project index %s is incomplete (previous build failed). "
                    "Use --dump-projects to rebuild it.",
                    filename,
                )
            if isinstance(meta, dict):
                built = (meta.get("last_activity_after"), meta.get("last_activity_before"))
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
        """
        Enrich an existing Instance Project Index (JSONL) with branches and rewrite it in-place.
        """
        if branches == "default":
            self.logger.info("Branches mode: default (no API calls, using default_branch only).")
        elif branches == "all":
            self.logger.info("Branches mode: all (slow).")
        else:
            self.logger.info("Branches mode: limit=%s (slow-ish).", branches)

        tmp_out = f"{filename}.branches.tmp"
        uses_api = branches != "default"
        # Only non-empty repositories cost API calls, so only they are counted.
        to_list = self._count_nonempty_projects(filename) if uses_api else 0
        progress = terminal_utils.Progress("Listing branches", total=to_list, unit="projects")
        listed_branches = 0

        with open(filename, "r", encoding="utf-8") as in_fp, open(tmp_out, "w", encoding="utf-8") as out_fp:
            first_line = in_fp.readline()
            if not first_line:
                raise ValueError(f"Project index file is empty: {filename}")

            meta = json.loads(first_line)
            meta["branches"] = branches
            meta["timestamp_utc"] = datetime.now(UTC).isoformat()
            self._write_jsonl_line(out_fp, meta)

            def index_records():
                for raw in in_fp:
                    raw = raw.strip()
                    if raw:
                        yield json.loads(raw)

            limit = None if branches in ("default", "all") else int(branches)

            def branches_of(project: dict[str, Any]) -> list[str]:
                if project.get("empty_repo", False):
                    return []
                if not uses_api:
                    default_branch = project.get("default_branch")
                    return [default_branch] if default_branch else []
                if self.workers <= 1:
                    progress.set_detail(str(project.get("path_with_namespace", project["id"])))
                return self.get_branches(project_id=int(project["id"]), per_page=branches_per_page, limit=limit)

            if uses_api:
                progress.start()
            try:
                # Branch lists are fetched in parallel; the index keeps its order.
                for done in self._imap_ordered(branches_of, index_records(), parallel=uses_api):
                    project = done.item
                    project["branches"] = done.unwrap()
                    if uses_api and not project.get("empty_repo", False):
                        listed_branches += len(project["branches"])
                        progress.advance(detail=str(project.get("path_with_namespace", project["id"])))

                    self._emit_record(out_fp, record=project)
            except BaseException:
                if uses_api:
                    progress.finish(f"{progress.render()} | stopped")
                raise

        if uses_api:
            progress.finish(
                f"Listed {terminal_utils.plural(listed_branches, 'branch', 'branches')} of "
                f"{terminal_utils.plural(progress.done, 'project')} in "
                f"{terminal_utils.format_duration(progress.elapsed)}"
            )

        os.replace(tmp_out, filename)
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
        """
        Create or update the Instance Project Index and optionally enrich it with branches.

        This method is a high-level wrapper around index building that:
            1. Generates the base project index using GitLab API.
            2. Optionally augments each project entry with branch information
               according to the selected depth.

        Args:
            per_page: Number of projects requested per API call.
            filename: Optional output path for the index file.
            order_by: Field used for server-side sorting of projects.
            sort: Sorting direction ("asc" or "desc").
            enforce_dump: Force rebuilding the index even if it already exists.
            branches: Branch collection mode:
                - "default" — store only the default branch,
                - "all" — fetch all branches,
                - integer — fetch up to N branches.
            branches_per_page: Number of branches requested per API call.

        Returns:
            Path to the resulting project index file.
        """
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

    @client_required
    def add_branches_to_projects(self, projects: list[dict], per_page: int = 50) -> list[dict]:
        """
        Enrich a list of project dictionaries with branch information.

        Empty repositories get an empty branch list without API calls and are
        not counted in the progress.
        """
        to_list = sum(1 for p in projects if not p.get("empty_repo", False))

        def branches_of(project: dict[str, Any]) -> list[str]:
            if project.get("empty_repo", False):
                return []
            return self.get_branches(project_id=project["id"], per_page=per_page)

        with terminal_utils.Progress("Listing branches", total=to_list, unit="projects") as progress:
            for done in self._imap_ordered(branches_of, projects):
                project = done.item
                project["branches"] = done.unwrap()
                if not project.get("empty_repo", False):
                    progress.advance(detail=str(project.get("path_with_namespace") or project.get("web_url", "")))

            elapsed = progress.finish(
                f"Listed branches of {terminal_utils.plural(progress.done, 'project')} in "
                f"{terminal_utils.format_duration(progress.elapsed)}"
            )

        self.logger.info("Loaded branches for %s projects in %s seconds.", len(projects), round(elapsed, 2))

        return projects

    def initialize_project_list(
            self,
            per_page: int = 100,
            filename: str | None = None,
            enforce_dump: bool = False,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """
        Ensure the Instance Project Index is available and load it.

        The Project Index is a lightweight inventory of all projects within the GitLab
        instance. It is used later as an input index for traversal strategies
        (e.g., processing order, default-branch-only vs all branches, forks inclusion).

        This function does not perform staleness checks or interact with the user.
        Any decisions about refreshing the Project Index should be handled by the caller.

        Args:
            per_page: Batch size for downloading if the Project Index needs to be created.
            filename: Path to the Project Index file (JSONL/NDJSON). If not provided,
                a default instance-specific path is used.
            enforce_dump: If True, rebuild the Project Index file unconditionally.

        Returns:
            A tuple of (projects, meta), where:
                - projects: list of project dictionaries from the Project Index.
                - meta: metadata header (the first JSONL line) describing the index build.

        Raises:
            Any exception raised by the underlying downloader or file reader.
        """
        filename = filename or self.get_default_projects_filename()

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

    def load_projects_from_file(self, filename: str | None = None) -> dict[str, Any]:
        """
        Load the project list from a JSONL/NDJSON file produced by fetch_projects().

        The file format:
          - first line -> metadata object
          - other lines -> individual project objects

        Returns:
            {
                "meta": {...},
                "projects": [...],
            }
        """
        if not filename:
            return {}

        try:
            projects: list[dict[str, Any]] = []

            with open(filename, encoding="utf-8") as f:
                # ---- read meta ----
                first_line = f.readline()
                if not first_line:
                    self.logger.warning(f"File '{filename}' is empty.")
                    return {}

                meta: dict[str, Any] = json.loads(first_line)

                # ---- read projects ----
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        projects.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        self.logger.warning(f"Broken JSON line in '{filename}': {e}")
                        continue

            # ---- logging ----
            ts = meta.get("timestamp_utc")
            ts_str = "unknown"
            if ts:
                try:
                    ts_str = datetime.fromisoformat(ts).strftime("%d-%m-%Y %H:%M:%S")
                except Exception:
                    ts_str = ts

            self.logger.info(
                f"Loaded {len(projects)} projects from '{filename}'. "
                f"Collecting time: {ts_str}"
            )

            return {
                "meta": meta,
                "projects": projects,
            }

        except FileNotFoundError:
            self.logger.debug(f"File with project data ['{filename}'] was not found.")
            return {}

    ##############

    def search_keywords(
            self,
            projects: list[dict[str, Any]],
            keywords: list[str],
            *,
            options: ScanOptions,
            hit_counter: int = 0,
            session_file: IO | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """
        Execute term search across a list of projects.

        The scan plan (which projects and branches pass the filters) is built
        once and printed. Progress counts only planned projects, so projects
        excluded by --forks skip, --started-from or empty repositories never
        inflate the totals. With workers > 1 the (term, project, branch)
        searches run in parallel, see _run_search().

        Args:
            projects: The whole project index.
            keywords: Search terms.
            options: Scan options (branches, forks, activity filter).
            hit_counter: Initial hit counter.
            session_file: Open session JSONL to stream hits and checkpoints to.

        Returns:
            ([{"term", "result"}, ...], total hit counter).
        """
        plan = build_scan_plan(projects, options)
        n_terms = len(keywords)
        terms_text = terminal_utils.plural(n_terms, "term")
        hits_before = hit_counter
        parallel = f", {self.workers} workers" if self.workers > 1 else ""

        files = f", files changed {options.file_window.describe()}" if options.file_window else ""
        terminal_utils.STATUS.write_line(f"Search plan: {terms_text}, {plan.describe()}{files}{parallel}")

        with terminal_utils.Progress(
                "Searching", total=plan.project_count, unit="projects", rounds=n_terms,
        ) as progress:
            res, hit_counter = self._run_search(
                keywords, plan, hit_counter=hit_counter, session_file=session_file,
                progress=progress, checkpoints=True, file_window=options.file_window or None,
            )
            checks = (f", {terminal_utils.plural(len(self._file_change_cache), 'file check')}"
                      if options.file_window else "")
            progress.finish(
                f"Search finished: {terms_text} x {terminal_utils.plural(plan.project_count, 'project')}, "
                f"{terminal_utils.plural(hit_counter - hits_before, 'hit')}{checks} in "
                f"{terminal_utils.format_duration(progress.elapsed)}"
            )

        return res, hit_counter

    def search_keyword(
            self,
            projects: list[dict[str, Any]],
            term: str,
            *,
            options: ScanOptions,
            hit_counter: int = 0,
            session_file: IO | None = None,
            plan: ScanPlan | None = None,
            progress: terminal_utils.Progress | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """
        Search a single term across the planned projects.

        Args:
            projects: The whole project index (used to build the plan if not given).
            term: Search term.
            options: Scan options.
            hit_counter: Initial hit counter.
            session_file: Open session JSONL to stream hits to (no checkpoint record).
            plan: Precomputed scan plan (see build_scan_plan()).
            progress: Progress to update; a standalone one is shown if None.

        Returns:
            (per-project results, updated hit counter).
        """
        plan = plan or build_scan_plan(projects, options)
        own = progress is None
        progress = progress or terminal_utils.Progress(f"Searching '{term}'", total=plan.project_count).start()
        try:
            res, hit_counter = self._run_search([term], plan, hit_counter=hit_counter, session_file=session_file,
                                                progress=progress, checkpoints=False,
                                                file_window=options.file_window or None)
        finally:
            if own:
                progress.finish()
        return res[0]["result"], hit_counter

    def _search_branch(self, task: _BranchTask) -> list[dict[str, Any]]:
        """Worker: search one term in one branch of one project (all result pages)."""
        project_url = task.project["web_url"]
        project_obj: Project = self._gl.projects.get(task.project["id"], lazy=True)
        path_filter = None
        if task.file_window:
            def path_filter(path: str) -> bool:
                return self._file_changed_in_window(task.project["id"], task.branch, path, task.file_window)
        try:
            hits, _ = self.scan_branch(project=project_obj, branch=task.branch, term=task.term,
                                       project_url=project_url, path_filter=path_filter)
        except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
            self.logger.warning("%s | %s Branch: %s", e, project_url, task.branch)
            hits = []
        return hits

    def _file_changed_in_window(self, project_id: Any, branch: str, path: str, window: TimeWindow) -> bool:
        """
        True if a commit touched ``path`` in ``branch`` inside ``window``.

        Uses GET /projects/:id/repository/commits with ref_name, path, since and
        until (one request per file, cached across terms and workers). On an
        API error the hit is kept and a warning is logged.
        """
        key = (project_id, branch, path, window.after, window.before)
        with self._file_change_lock:
            if key in self._file_change_cache:
                return self._file_change_cache[key]

        params: dict[str, Any] = {"ref_name": branch, "path": path}
        if window.after is not None:
            params["since"] = format_api_time(window.after)
        if window.before is not None:
            params["until"] = format_api_time(window.before)
        try:
            # `path` is reserved by python-gitlab's list() (it overrides the URL),
            # so the API filters go through query_parameters.
            commits = self._gl.projects.get(project_id, lazy=True).commits.list(
                query_parameters=params, page=1, per_page=1)
            changed = bool(commits)
        except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
            self.logger.warning("Cannot check changes of %s in branch %s of project %s, keeping its hits: %s",
                                path, branch, project_id, e)
            changed = True

        with self._file_change_lock:
            self._file_change_cache[key] = changed
        return changed

    def _run_search(
            self,
            terms: list[str],
            plan: ScanPlan,
            *,
            hit_counter: int,
            session_file: IO | None,
            progress: terminal_utils.Progress,
            checkpoints: bool,
            file_window: TimeWindow | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """
        Search ``terms`` over ``plan`` with ``self.workers`` threads.

        Work is split into (term, project, branch) tasks taken from one shared
        queue by whichever worker is free, so a few huge repositories don't
        leave other workers idle. Workers only do HTTP; this (main) thread
        merges branch results into one record per (term, project), writes the
        session file and updates progress:

        - a project record is written when all its branches are done
          (with workers > 1, records appear in completion order);
        - ``keyword_done`` is written when every task of the term and of all
          earlier terms is done, so checkpoints keep the term order and
          ``--resume`` stays correct; terms still overlap (no idle barrier).

        With workers == 1 the tasks run inline, in order, exactly as a
        sequential scan.
        """
        n_terms = len(terms)
        hits_before = hit_counter
        term_hits = [0] * n_terms
        projects_left = [plan.project_count] * n_terms
        results: list[list[tuple[int, dict[str, Any]]]] = [[] for _ in terms]
        partial: dict[tuple[int, int], dict[int, list[dict[str, Any]]]] = {}
        state = {"next_term": 0, "term_started": progress.elapsed}
        # When the first task of each term was handed out (feeder thread with workers > 1).
        term_begun: dict[int, float] = {}

        def label(number: int) -> str:
            term = terms[number]
            return f"Searching '{term}'" + (f" ({number + 1}/{n_terms})" if n_terms > 1 else "")

        def close_finished_terms() -> None:
            while state["next_term"] < n_terms and projects_left[state["next_term"]] == 0:
                number = state["next_term"]
                if checkpoints and session_file is not None:
                    self._emit_record(
                        session_file,
                        record={
                            "type": "keyword_done",
                            "term": terms[number],
                            "hit_counter": hits_before + sum(term_hits[:number + 1]),
                            "timestamp_utc": datetime.now(UTC).isoformat(),
                        },
                    )
                    # Resume checkpoint: make it durable even if the process is killed.
                    session_file.flush()
                if checkpoints and n_terms > 1:
                    progress.note(
                        f"Term {number + 1}/{n_terms} '{terms[number]}': "
                        f"{terminal_utils.plural(term_hits[number], 'hit')} in "
                        f"{terminal_utils.format_duration(progress.elapsed - state['term_started'])}"
                    )
                state["term_started"] = progress.elapsed
                state["next_term"] += 1
                if state["next_term"] < n_terms:
                    progress.start_round(state["next_term"] + 1, label(state["next_term"]),
                                         started=term_begun.get(state["next_term"]))
                    progress.done = plan.project_count - projects_left[state["next_term"]]

        def tasks():
            for term_no, term in enumerate(terms):
                term_begun.setdefault(term_no, progress.clock())
                for project_no, (project, branches) in enumerate(plan.targets):
                    for branch_no, branch in enumerate(branches):
                        if self.workers <= 1:
                            info = branch if len(branches) == 1 else f"{branch} [{branch_no + 1}/{len(branches)}]"
                            progress.set_detail(f"{project.get('path_with_namespace', project['web_url'])} @ {info}")
                        yield _BranchTask(term_no, term, project_no, project, branches, branch_no, file_window)

        if n_terms:
            progress.start_round(1, label(0))
        progress.set_info(f"{human_int(hit_counter)} hits")
        close_finished_terms()  # terms without planned projects

        tasks_iter = pool.imap_unordered(self._search_branch, tasks(), workers=self.workers,
                                         initializer=self._init_worker_client)
        for done in tasks_iter:
            task: _BranchTask = done.item
            hits = done.unwrap()
            key = (task.term_no, task.project_no)
            got = partial.setdefault(key, {})
            got[task.branch_no] = hits
            if len(got) < len(task.branches):
                continue

            # All branches of this (term, project) are done: one session record.
            del partial[key]
            project = task.project
            s_res = [{"branch": b, "branch_search_result": got[i]} for i, b in enumerate(task.branches) if got[i]]
            found = sum(len(h) for h in got.values())
            hit_counter += found
            term_hits[task.term_no] += found
            if s_res:
                out = {
                    "project_id": project["id"],
                    "web_url": project["web_url"],
                    "created_at": project.get("created_at"),
                    "last_activity_at": project.get("last_activity_at"),
                    "project_search_result": s_res,
                }
                results[task.term_no].append((task.project_no, out))
                if session_file:
                    self._emit_record(session_file, record={"term": task.term, "result": out})

            projects_left[task.term_no] -= 1
            if task.term_no == state["next_term"]:
                progress.done = plan.project_count - projects_left[task.term_no]
            progress.completed_units = sum(plan.project_count - left for left in projects_left)
            progress.set_info(f"{human_int(hit_counter)} hits")
            if self.workers > 1:
                progress.set_detail(f"{project.get('path_with_namespace', project['web_url'])}")
            progress.advance(0)
            close_finished_terms()

        res = [{"term": term, "result": [out for _, out in sorted(results[i], key=lambda x: x[0])]}
               for i, term in enumerate(terms)]
        return res, hit_counter

    def scan_project(
            self,
            project: dict[str, Any],
            term: str,
            *,
            options: ScanOptions,
            projects_by_id: dict[int, dict[str, Any]] | None = None,
            branches: list[str] | tuple[str, ...] | None = None,
            progress: terminal_utils.Progress | None = None,
            hit_counter: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """
        Scan a single project for a term across the selected branches.

        Args:
            project: Project entry from the index.
            term: Search term.
            options: Scan options (used to select branches when not given).
            projects_by_id: Index lookup for fork upstreams.
            branches: Branches to scan; computed with branches_to_scan() if None.
            progress: Progress whose detail shows the current project and branch.
            hit_counter: Initial hit counter.

        Returns:
            ([{"branch", "branch_search_result"}, ...], updated hit counter).
        """
        res: list[dict[str, Any]] = []

        project_obj: Project = self._gl.projects.get(project["id"], lazy=True)
        project_url: str = project["web_url"]

        if branches is None:
            branches = branches_to_scan(project, options, projects_by_id=projects_by_id)
        if not branches:
            return [], hit_counter

        br_len: int = len(branches)
        name = project.get("path_with_namespace", project_url)

        for num, b in enumerate(branches):
            if progress is not None:
                branch_info = b if br_len == 1 else f"{b} [{num + 1}/{br_len}]"
                progress.set_detail(f"{name} @ {branch_info}")

            try:
                s_res, hit_counter = self.scan_branch(
                    project=project_obj,
                    branch=b,
                    term=term,
                    project_url=project_url,
                    hit_counter=hit_counter,
                )
                if s_res:
                    res.append({"branch": b, "branch_search_result": s_res})
            except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
                self.logger.warning("%s | %s Branch: %s", e, project_url, b)

        return res, hit_counter

    @client_required
    def scan_branch(
            self,
            project: Project,
            branch: str,
            term: str,
            project_url: str,
            hit_counter: int = 0,
            per_page: int = 100,
            path_filter: Callable[[str], bool] | None = None,
            **kwargs,
    ) -> tuple[list[dict], int]:
        """
        Search for a term inside a specific branch using GitLab blob search.

        The method performs a full-text search across repository files within
        the given branch (SearchScope.BLOBS). For each match, a direct URL
        with line reference is generated and logged.

        Args:
            project: GitLab Project object (lazy instance allowed).
            branch: Branch name to scan.
            term: Search term.
            project_url: Base web URL of the project.
            per_page: Number of results per page.
            hit_counter: Global hit counter to be incremented.
            path_filter: Optional predicate on the file path; hits in files for
                which it returns False are dropped (used by the file time filter).
            **kwargs: Additional parameters passed to GitLab search API.

        Returns:
            Tuple containing:
                - List of matches with "url" and optional "data" snippet.
                - Updated hit counter.
        """
        res: list[dict] = []
        page: int = 1

        search_results: list[dict[str, Any]] = []
        try:
            while True:
                batch = project.search(scope=SearchScope.BLOBS,
                                       ref=branch,
                                       search=term,
                                       page=page,
                                       per_page=per_page,
                                       **kwargs,
                                       )

                search_results.extend(batch)
                page += 1

                if len(batch) < per_page:
                    break

        except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
            # Keep results of already fetched pages; a timeout must not abort the whole scan.
            self.logger.warning("[%s] %s: %s", project.id, project_url, e)

        if path_filter is not None and search_results:
            verdict: dict[str, bool] = {}
            search_results = [x for x in search_results
                              if verdict.setdefault(x["path"], path_filter(x["path"]) if x["path"] not in verdict
                                                    else verdict[x["path"]])]

        # Branch names and paths may contain '#', '?', '%', spaces, etc.
        branch_url: str = f"{project_url}/-/tree/{quote(branch, safe='/')}"
        if search_results:
            res = [{'url': f'{branch_url}/{quote(x["path"], safe="/")}#L{x["startline"]}', 'data': x.get('data', '')}
                   for x in search_results]

            for x in res:
                self.logger.info(f"[+] Hitted '{term}': {x['url']}")
            hit_counter += len(res)

        return res, hit_counter
