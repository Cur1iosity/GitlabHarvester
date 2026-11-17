# glh/engine/harvester.py
"""
GitlabHarvester: the facade of the engine (the public API of the package).

It holds the parts built by :class:`~glh.engine.factory.HarvesterFactory` and
delegates to them:

- ``connection`` (:class:`~glh.gitlab.connection.GitLabConnection`): clients, tokens, workers;
- ``clients`` (:class:`~glh.gitlab.factory.ClientFactory`): client settings and pacing;
- ``monitor`` (:class:`~glh.gitlab.rate_monitor.RateLimitMonitor`): HTTP 429 accounting;
- ``indexer`` (:class:`~glh.engine.indexer.ProjectIndexer`): the project index;
- ``search`` (:class:`~glh.engine.search.SearchEngine`): term search and files-only mode.

::

    harvester = GitlabHarvester(url="https://gitlab.example.com", token="...")
    # or: GitlabHarvester.from_settings(HarvesterSettings(url=..., tokens=(...,), workers=4))
    index_file = harvester.build_project_index()
    index = harvester.load_index(index_file)
    results, hits = harvester.search_keywords(index.projects, ["password"], options=ScanOptions())
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime
from typing import Any, Callable, IO, Iterable, Mapping

from gitlab import Gitlab
from gitlab.v4.objects import Project as GitlabProject

from glh.domain.models import as_project, Project, ProjectIndex
from glh.domain.planning import ScanOptions, ScanPlan
from glh.engine.factory import HarvesterFactory, HarvesterParts, HarvesterSettings
from glh.gitlab.throttling import Jitter, NO_JITTER
from glh.output.sink import SearchOutput
from glh.ui.progress import Progress


class GitlabHarvester:
    """Builds the project index of a GitLab instance and searches it (see the module doc)."""

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
            ssl_verify: bool | str = True,
            index_rpm: int = 0,
            search_rpm: int = 0,
            jitter: Jitter = NO_JITTER,
            user_agents: list[str] | tuple[str, ...] = (),
            tokens: list[str] | tuple[str, ...] | None = None,
            adjustable_limits: bool = False,
    ) -> None:
        # A single ``token`` (string) is the one-token case of ``tokens``.
        resolved_tokens = tuple(tokens) if tokens else ((token,) if token else ())
        settings = HarvesterSettings(
            url=url or host, tokens=resolved_tokens, proxy=proxy, timeout=timeout, ssl_verify=ssl_verify,
            workers=workers, index_rpm=index_rpm, search_rpm=search_rpm, jitter=jitter,
            user_agents=tuple(user_agents), adjustable_limits=adjustable_limits, log_level=log_level,
            log_file=log_file,
        )
        self._attach(HarvesterFactory(settings).build())
        self.search_terms: list = search_terms or []

    @classmethod
    def from_settings(cls, settings: HarvesterSettings, *, connect: bool = True) -> "GitlabHarvester":
        """A harvester built by :class:`HarvesterFactory` from ``settings``."""
        harvester = cls.__new__(cls)
        harvester._attach(HarvesterFactory(settings).build(connect=connect))
        harvester.search_terms = []
        return harvester

    def _attach(self, parts: HarvesterParts) -> None:
        self.parts = parts
        self.settings = parts.settings
        self.logger = parts.logger
        self.log_level = parts.log_level
        self.log_file = parts.settings.log_file
        self.monitor = parts.monitor
        self.clients = parts.clients
        self.connection = parts.connection
        self.active = parts.active
        self.indexer = parts.indexer
        self.search = parts.search

    # ------------------------------------------------------------- run state

    @property
    def tokens(self) -> tuple[str, ...]:
        return self.connection.tokens

    @property
    def token_users(self) -> list[Any]:
        return self.connection.token_users

    @property
    def workers(self) -> int:
        """Parallel API requests per token."""
        return self.connection.workers

    @property
    def concurrency(self) -> int:
        """Total concurrent clients: tokens x workers."""
        return self.connection.concurrency

    @property
    def index_rpm(self) -> int:
        return self.clients.pacing.index_rpm

    @property
    def search_rpm(self) -> int:
        return self.clients.pacing.search_rpm

    @property
    def jitter(self) -> Jitter:
        return self.clients.pacing.jitter

    @property
    def user_agents(self) -> tuple[str, ...]:
        return self.clients.settings.user_agents

    @property
    def adjustable_limits(self) -> bool:
        return self.clients.adjustable

    @property
    def limit_observer(self) -> Callable[[Any], None] | None:
        """Called with every API response (--auto-limits: the LimitAdvisor)."""
        return self.monitor.observer

    @limit_observer.setter
    def limit_observer(self, observer: Callable[[Any], None] | None) -> None:
        self.monitor.observer = observer

    @property
    def rate_limit_warn_interval(self) -> float:
        return self.monitor.warn_interval

    @rate_limit_warn_interval.setter
    def rate_limit_warn_interval(self, seconds: float) -> None:
        self.monitor.warn_interval = seconds

    @property
    def slow_task_report(self) -> float:
        return self.search.slow_task_report

    @slow_task_report.setter
    def slow_task_report(self, seconds: float) -> None:
        self.search.slow_task_report = seconds

    @property
    def incomplete_terms(self) -> list[str]:
        """Terms of the last search that had failed (retryable) searches."""
        return self.search.incomplete_terms

    @property
    def file_listing_counts(self) -> Counter[str]:
        """Files-only mode: branches listed per method ('search', 'tree')."""
        return self.search.lister.counts

    # ---------------------------------------------------------------- limits

    def set_rate_limits(self, *, index_rpm: int | None = None, search_rpm: int | None = None,
                        workers: int | None = None) -> None:
        """
        Change the pace of every client at once (needs ``adjustable_limits`` for
        clients made without limits) and, for pools started later, the workers.
        """
        self.clients.set_pacing(index_rpm=index_rpm, search_rpm=search_rpm)
        if workers is not None:
            self.connection.set_workers(workers)

    @property
    def rate_limited(self) -> int:
        """HTTP 429 responses so far (all threads)."""
        return self.monitor.count

    def rate_limit_summary(self) -> str | None:
        """'Rate limit: N HTTP 429 responses, retried after … of waits in total'; None without any."""
        return self.monitor.summary(parallel=self.concurrency > 1)

    def token_user_groups(self) -> list[list[int]]:
        return self.connection.token_user_groups()

    def tokens_per_user(self) -> int:
        return self.connection.tokens_per_user()

    def token_user_key(self, token: str | None) -> Any:
        return self.connection.token_user_key(token)

    def unpaced_client(self, token: str | None = None) -> Gitlab:
        """A client that is neither paced nor counted (the rate-limit probe)."""
        return self.connection.unpaced_client(token)

    # ------------------------------------------------------------------ index

    def get_instance_id(self) -> str:
        """'gitlab_example_com' (host:port -> host_port), 'undefined' without a client."""
        return self.connection.instance_id()

    def get_host(self) -> str:
        """Backward-compatible alias for get_instance_id()."""
        return self.connection.instance_id()

    def get_default_projects_filename(self) -> str:
        return self.indexer.default_projects_filename()

    def first_project_id(self) -> Any | None:
        return self.indexer.first_project_id()

    def fetch_projects(self, per_page: int = 100, filename: str | None = None, order_by: str = "id",
                       sort: str = "desc", last_activity_after: datetime | None = None,
                       last_activity_before: datetime | None = None) -> list[dict[str, Any]]:
        return self.indexer.fetch_projects(per_page=per_page, filename=filename, order_by=order_by, sort=sort,
                                           last_activity_after=last_activity_after,
                                           last_activity_before=last_activity_before)

    def get_branches(self, project_id: int, per_page: int = 100, *, limit: int | None = None) -> list[str]:
        return self.indexer.get_branches(project_id, per_page, limit=limit)

    def build_project_index(self, **kwargs: Any) -> str:
        """See ProjectIndexer.build_project_index (per_page, filename, enforce_dump, branches, …)."""
        return self.indexer.build_project_index(**kwargs)

    def enrich_project_index_with_branches(self, **kwargs: Any) -> str:
        return self.indexer.enrich_project_index_with_branches(**kwargs)

    def download_projects(self, **kwargs: Any) -> str:
        return self.indexer.download_projects(**kwargs)

    def add_branches_to_projects(self, projects: list[dict], per_page: int = 50) -> list[dict]:
        return self.indexer.add_branches_to_projects(projects, per_page)

    def initialize_project_list(self, per_page: int = 100, filename: str | None = None,
                                enforce_dump: bool = False) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        return self.indexer.initialize_project_list(per_page, filename, enforce_dump)

    def load_projects_from_file(self, filename: str | None = None) -> dict[str, Any]:
        """{"meta": {...}, "projects": [{...}, ...]} as dicts; {} if missing or empty (see load_index)."""
        return self.indexer.load_projects_from_file(filename)

    def load_index(self, filename: str | None) -> ProjectIndex | None:
        """The index file as objects (IndexMeta, Project); None if missing or empty."""
        return self.indexer.load_index(filename)

    # ----------------------------------------------------------------- search

    def search_keywords(self, projects: Iterable[Project | Mapping[str, Any]], keywords: list[str], *,
                        options: ScanOptions,
                        hit_counter: int = 0, session_file: IO | None = None,
                        output: SearchOutput | None = None) -> tuple[list[dict[str, Any]], int]:
        """See SearchEngine.search_keywords."""
        return self.search.search_keywords(projects, keywords, options=options, hit_counter=hit_counter,
                                           session_file=session_file, output=output)

    def search_keyword(self, projects: Iterable[Project | Mapping[str, Any]], term: str, *, options: ScanOptions,
                       hit_counter: int = 0, session_file: IO | None = None, plan: ScanPlan | None = None,
                       progress: Progress | None = None,
                       output: SearchOutput | None = None) -> tuple[list[dict[str, Any]], int]:
        return self.search.search_keyword(projects, term, options=options, hit_counter=hit_counter,
                                          session_file=session_file, plan=plan, progress=progress, output=output)

    def scan_project(self, project: Project | Mapping[str, Any], term: str, *, options: ScanOptions,
                     projects_by_id: Mapping[int, Project | Mapping[str, Any]] | None = None,
                     **kwargs: Any) -> tuple[list[dict[str, Any]], int]:
        """Search one project (a Project or an index record) for a term; see SearchEngine.scan_project."""
        by_id = {k: as_project(v) for k, v in projects_by_id.items()} if projects_by_id else None
        found, hits = self.search.scan_project(as_project(project), term, options=options, projects_by_id=by_id,
                                               **kwargs)
        return [b.to_record() for b in found], hits

    def scan_branch(self, project: GitlabProject, branch: str, term: str, project_url: str,
                    **kwargs: Any) -> tuple[list[dict], int]:
        """Search one branch; the hits as session dicts ({"url", "data"[, "file"]})."""
        found, hits = self.search.scan_branch(project, branch, term, project_url, **kwargs)
        return [h.to_record() for h in found], hits
