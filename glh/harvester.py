# glh/harvester.py
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, UTC
from typing import Callable, IO, Any
from urllib.parse import urlparse

import gitlab.exceptions
import requests.exceptions
from gitlab import Gitlab
from gitlab.const import SearchScope
from gitlab.v4.objects import Project
from requests import Session
from tqdm import tqdm

from glh.exceptions import GitlabHarvesterError
from glh.planner import ScanOptions, branches_to_scan, should_scan_project
from glh.utils import logging_utils, terminal_utils


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
            *,
            log_level: int | str = logging.WARNING,
            log_file: str | None = None,
            host: str | None = None,  # backward-compat alias for `url`
    ) -> None:
        self.search_terms: list = search_terms or []

        self.log_level: int = logging_utils.coerce_log_level(log_level)
        self.log_file: str | None = log_file
        self.logger = logging_utils.build_logger(
            name="GitlabHarvesterLogger",
            level=self.log_level,
            log_file=self.log_file,
        )

        url = url or host
        self._gl: Gitlab | None = self._get_gl_client(url=url, token=token, proxy=proxy) if url and token else None

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
            Instance identifier like 'gitlab_example_com', or 'undefined' if no client.
        """
        if not self._gl:
            return "undefined"
        parsed = urlparse(self._gl.url)
        host = (parsed.netloc or parsed.path).strip("/")
        return host.replace(".", "_")

    def get_host(self) -> str:
        """Backward-compatible alias for get_instance_id()."""
        return self.get_instance_id()

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
            return gl
        except requests.exceptions.SSLError:
            if not allow_ssl_fallback or kwargs.get("ssl_verify") is False:
                self.logger.exception("TLS handshake failed for %s", url)
                raise

            # Fallback: retry once with ssl verification disabled
            self.logger.warning("TLS failed for %s; retrying with ssl_verify=False", url)
            kwargs["ssl_verify"] = False
            _maybe_disable_warnings()

            gl = Gitlab(**kwargs)
            gl.auth()
            self.logger.debug("Authenticated to GitLab (ssl_verify=False): %s", url)
            return gl

    @client_required
    def fetch_projects(
            self,
            per_page: int = 100,
            filename: str | None = None,
            order_by: str = "id",
            sort: str = "desc",
    ) -> list[dict[str, Any]]:
        """
        Retrieve projects from the GitLab instance with a reduced set of key fields.

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
        page: int = 1
        is_completed: bool = True

        start = time.perf_counter()
        tmp_filename = f"{filename}.tmp" if filename else None
        fp = open(tmp_filename, "w", encoding="utf-8") if tmp_filename else None

        lay = terminal_utils.layout()

        with terminal_utils.mk_tqdm(
                total=None,
                position=0,
                leave=False,
                layout_=lay,
                unit="projects",
        ) as pbar:
            terminal_utils.set_desc(pbar, f"Listing instance: {self.get_host()}", lay)

            try:
                while batch := self._gl.projects.list(page=page, per_page=per_page, order_by=order_by, sort=sort):
                    if fp is not None:
                        for x in batch:
                            self._emit_record(fp=fp, record=reduce_project_fields(x))
                    else:
                        projects.extend(reduce_project_fields(x) for x in batch)

                    desc = terminal_utils.animate_desc(f"Listing instance: {self.get_host()}",
                                                       terminal_utils.GET_PROJECTS_ANIM_FRAMES, page)
                    terminal_utils.set_desc(pbar, desc, lay)

                    batch_size = len(batch)
                    pbar.update(batch_size)
                    pr_counter += batch_size
                    page += 1

            except gitlab.exceptions.GitlabError as e:
                self.logger.error("Gitlab API error. The project list wasn't complete.")
                self.logger.error(e)

            except KeyboardInterrupt:
                is_completed = False
                self.logger.warning("Interrupted by user (Ctrl+C).")
                raise

            except Exception:
                is_completed = False
                self.logger.exception("Fatal error while loading projects.")
                raise

            finally:
                elapsed = round(time.perf_counter() - start, 2)

                if fp is not None:
                    fp.close()

                if filename:
                    meta = {
                        "type": "meta",
                        "source": self.get_host(),
                        "timestamp_utc": datetime.now(UTC).isoformat(),
                        "projects_count": pr_counter,
                        "elapsed_seconds": elapsed,
                        "order_by": order_by,
                        "sort": sort,
                        "per_page": per_page,
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
            position: int = 1,
            limit: int | None = None,
    ) -> list[str]:
        """
        Retrieve branch names for a specific GitLab project.
        """
        branches: list[str] = []
        lay = terminal_utils.layout()

        with terminal_utils.mk_tqdm(
                total=None,
                position=position,
                leave=False,
                layout_=lay,
                unit="branches",
        ) as pbar:
            terminal_utils.set_desc(pbar, f"Listing branches for ID [{project_id}]", lay)

            page = 1
            try:
                while True:
                    batch = self._gl.projects.get(project_id, lazy=True).branches.list(page=page, per_page=per_page)
                    if not batch:
                        break

                    for b in batch:
                        branches.append(b.name)
                        if limit is not None and len(branches) >= limit:
                            pbar.update(1)
                            return branches

                    pbar.update(len(batch))
                    page += 1

            except gitlab.exceptions.GitlabError as e:
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
    ) -> str:
        """
        Build (or rebuild) the Instance Project Index file (JSONL/NDJSON) and optionally enrich it with branches.

        branches:
            - "default": store only default branch (no GitLab branch API calls)
            - "all": fetch all branches for each non-empty project (slow)
            - int: fetch up to N branches for each non-empty project

        Returns:
            Output filename.
        """
        if not filename:
            host = self._gl.url.split(":", 1)[1].strip("/").replace(".", "_")
            filename = f"{host}_project_index.jsonl"

        needs_build = enforce_dump or not os.path.exists(filename)
        if needs_build:
            self.logger.info(
                "Building Instance Project Index. Batch size: %s. Output file: %s.",
                per_page,
                filename,
            )
            # Base index (meta + projects without branches)
            self.fetch_projects(per_page=per_page, filename=filename, order_by=order_by, sort=sort)

            if branches is not None:
                self.enrich_project_index_with_branches(
                    filename=filename,
                    branches=branches,
                    branches_per_page=branches_per_page,
                )
        else:
            self.logger.info("Instance Project Index already exists: %s.", filename)
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
        lay = terminal_utils.layout()

        with open(filename, "r", encoding="utf-8") as in_fp, open(tmp_out, "w", encoding="utf-8") as out_fp:
            first_line = in_fp.readline()
            if not first_line:
                raise ValueError(f"Project index file is empty: {filename}")

            meta = json.loads(first_line)
            meta["branches"] = branches
            meta["timestamp_utc"] = datetime.now(UTC).isoformat()
            self._write_jsonl_line(out_fp, meta)

            total = meta.get("projects_count")

            with terminal_utils.mk_tqdm(
                    total=total,
                    position=0,
                    leave=False,
                    layout_=lay,
                    unit="projects",
                    delay=2,
            ) as pbar:
                terminal_utils.set_desc(pbar, "Enriching projects with branches", lay)

                for line in in_fp:
                    line = line.strip()
                    if not line:
                        continue

                    project = json.loads(line)

                    if project.get("empty_repo", False):
                        project["branches"] = []
                    else:
                        default_branch = project.get("default_branch")

                        if branches == "default":
                            project["branches"] = [default_branch] if default_branch else []
                        else:
                            limit = None if branches == "all" else int(branches)
                            project["branches"] = self.get_branches(
                                project_id=int(project["id"]),
                                per_page=branches_per_page,
                                limit=limit,
                                position=1,
                            )

                    desc = terminal_utils.animate_desc("Enriching projects with branches",
                                                       terminal_utils.GET_BRANCHES_ANIM_FRAMES, pbar.n)
                    terminal_utils.set_desc(pbar, desc, lay)

                    self._emit_record(out_fp, record=project)
                    pbar.update(1)

        os.replace(tmp_out, filename)
        if branches != "default":
            self.logger.info("Project index enriched with branches (mode=%s): %s", branches, filename)
        return filename

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
        """
        lay = terminal_utils.layout()

        with terminal_utils.mk_tqdm(
                total=len(projects),
                position=0,
                leave=True,
                layout_=lay,
                unit="projects",
                delay=0.5,
        ) as pbar:
            terminal_utils.set_desc(pbar, "Listing branches", lay)

            for project in projects:
                empty = project.get("empty_repo", False)

                terminal_utils.set_desc(pbar, "Loading branches", lay)

                if not empty:
                    project["branches"] = self.get_branches(project_id=project["id"], per_page=per_page)
                    postfix = f'{project["web_url"]}: {len(project["branches"])} branch(es)'
                else:
                    project["branches"] = []
                    postfix = f'{project["web_url"]}: empty'

                terminal_utils.set_postfix(pbar, postfix, lay)
                pbar.update(1)

            self.logger.info(
                "Loaded branches for %s projects in %s seconds.",
                len(projects),
                round(pbar.format_dict.get("elapsed", 0.0), 2),
            )

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
            position: int = 0,
            hit_counter: int = 0,
            session_file: IO | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """
        Execute term search across a list of projects.
        """
        res: list[dict[str, Any]] = []
        lay = terminal_utils.layout()

        if len(keywords) <= 1:
            with terminal_utils.mk_header(position=position, leave=True, layout_=lay) as hdr:
                for term in keywords:
                    # Keep header stable and useful.
                    terminal_utils.set_desc(hdr, f"Searching term: '{term}' | Hit Counter: {hit_counter}", lay)

                    s_res, hit_counter = self.search_keyword(
                        projects=projects,
                        term=term,
                        options=options,
                        ext_pbar=hdr,
                        hit_counter=hit_counter,
                        session_file=session_file,
                        position=position + 1,
                    )
                    res.append({"term": term, "result": s_res})

                    if session_file is not None:
                        self._emit_record(
                            session_file,
                            record={
                                "type": "keyword_done",
                                "term": term,
                                "hit_counter": hit_counter,
                                "timestamp_utc": datetime.now(UTC).isoformat(),
                            },
                        )

                terminal_utils.set_desc(hdr, f"Done | Hit Counter: {hit_counter}", lay)

            return res, hit_counter

        with terminal_utils.mk_tqdm(
                total=len(keywords),
                position=position,
                leave=False,
                layout_=lay,
        ) as pbar:
            for term in keywords:
                s_res, hit_counter = self.search_keyword(
                    projects=projects,
                    term=term,
                    options=options,
                    ext_pbar=pbar,
                    hit_counter=hit_counter,
                    session_file=session_file,
                    position=position + 1,
                )
                res.append({"term": term, "result": s_res})

                if session_file is not None:
                    self._emit_record(
                        session_file,
                        record={
                            "type": "keyword_done",
                            "term": term,
                            "hit_counter": hit_counter,
                            "timestamp_utc": datetime.now(UTC).isoformat(),
                        },
                    )

                pbar.update(1)

        return res, hit_counter

    def search_keyword(
            self,
            projects: list[dict[str, Any]],
            term: str,
            *,
            options: ScanOptions,
            position: int = 1,
            hit_counter: int = 0,
            ext_pbar: tqdm | None = None,
            session_file: IO | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """
        Search a single term across all provided projects.
        """
        projects_by_id = {int(p["id"]): p for p in projects}
        lay = terminal_utils.layout()

        with terminal_utils.mk_tqdm(
                total=len(projects),
                position=position,
                leave=False,
                layout_=lay,
                delay=2,
        ) as pbar:
            terminal_utils.set_desc(pbar, term, lay)
            res: list[dict[str, Any]] = []

            for pr in projects:
                raw_desc = pr.get("path_with_namespace", "unknown")
                terminal_utils.set_desc(pbar, raw_desc, lay)

                if ext_pbar is not None:
                    terminal_utils.set_desc(ext_pbar, f"Searching term: '{term}' | Hit Counter: {hit_counter}", lay)

                if not should_scan_project(pr, options):
                    pbar.update(1)
                    continue

                s_res, hit_counter = self.scan_project(
                    project=pr,
                    term=term,
                    options=options,
                    projects_by_id=projects_by_id,
                    ext_pbar=pbar,
                    hit_counter=hit_counter,
                )

                if s_res:
                    out = {
                        "project_id": pr["id"],
                        "web_url": pr["web_url"],
                        "created_at": pr.get("created_at"),
                        "last_activity_at": pr.get("last_activity_at"),
                        "project_search_result": s_res,
                    }
                    res.append(out)

                    if session_file:
                        self._emit_record(session_file, record={"term": term, "result": out})

                pbar.update(1)

        return res, hit_counter

    def scan_project(
            self,
            project: dict[str, Any],
            term: str,
            *,
            options: ScanOptions,
            projects_by_id: dict[int, dict[str, Any]] | None = None,
            ext_pbar: tqdm | None = None,
            hit_counter: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """
        Scan a single project for a term across the selected branches.
        """
        res: list[dict[str, Any]] = []

        project_obj: Project = self._gl.projects.get(project["id"], lazy=True)
        project_url: str = project["web_url"]

        branches = branches_to_scan(project, options, projects_by_id=projects_by_id)
        if not branches:
            return [], hit_counter

        br_len: int = len(branches)
        lay = terminal_utils.layout()

        for num, b in enumerate(branches):
            if ext_pbar is not None:
                postfix = b if br_len == 1 else f"{b} [{num + 1}/{br_len}]"
                terminal_utils.set_postfix(ext_pbar, postfix, lay)

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
            except gitlab.exceptions.GitlabError as e:
                self.logger.error("%s | %s Branch: %s", e, project_url, b, exc_info=True)

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
                                       project=project,
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

        except gitlab.exceptions.GitlabError as e:
            self.logger.error(e)

        branch_url: str = f"{project_url}/-/tree/{branch}"
        if search_results:
            res = [{'url': f'{branch_url}/{x["path"]}#L{x["startline"]}', 'data': x.get('data', '')} for x in
                   search_results]

            for x in res:
                self.logger.info(f"[+] Hitted '{term}': {x['url']}")
            hit_counter += len(res)

        return res, hit_counter
