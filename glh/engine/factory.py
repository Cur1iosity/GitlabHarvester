# glh/engine/factory.py
"""
HarvesterFactory: builds the objects of a harvester and wires them together.

One :class:`HarvesterSettings` describes a run; :meth:`HarvesterFactory.build`
turns it into :class:`HarvesterParts`::

    logger
    RateLimitMonitor ──on_response──┐
    ClientFactory  ◄────────────────┘   (settings, pacing, hook)
    GitLabConnection(ClientFactory)     (tokens, workers; connect() authenticates)
    ActiveTasks  ◄──on_wait── RateLimitMonitor
    FileChangeChecker, FileFetcher, FileLister
    ProjectIndexer(connection)
    SearchEngine(connection, active, checks, fetcher, lister)

:class:`~glh.engine.harvester.GitlabHarvester` is the facade over these parts;
nothing else creates them.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from glh.engine.file_checks import FileChangeChecker, FileFetcher
from glh.engine.file_listing import FileLister
from glh.engine.indexer import ProjectIndexer
from glh.engine.search import SearchEngine
from glh.engine.workers import ActiveTasks
from glh.gitlab.connection import GitLabConnection
from glh.gitlab.factory import ClientFactory
from glh.gitlab.rate_monitor import RateLimitMonitor
from glh.gitlab.settings import ClientSettings, Pacing
from glh.gitlab.throttling import Jitter, NO_JITTER
from glh.ui.logs import build_logger, coerce_log_level

LOGGER_NAME = "GitlabHarvesterLogger"


@dataclass(frozen=True, slots=True)
class HarvesterSettings:
    """Everything that shapes a harvester (the CLI builds it from its options)."""

    url: str | None = None
    tokens: tuple[str, ...] = ()
    proxy: str | None = None
    timeout: int = 60
    ssl_verify: bool | str = True
    # Parallel API requests per token (1 = sequential).
    workers: int = 1
    # Requests per minute per client (thread); 0 = no limit.
    index_rpm: int = 0
    search_rpm: int = 0
    jitter: Jitter = field(default=NO_JITTER)
    user_agents: tuple[str, ...] = ()
    # --auto-limits: clients get a pacing adapter even without limits, so the pace can change on the fly.
    adjustable_limits: bool = False
    log_level: int | str = logging.WARNING
    log_file: str | None = None

    @property
    def client(self) -> ClientSettings:
        return ClientSettings(url=self.url, proxy=self.proxy, timeout=self.timeout, ssl_verify=self.ssl_verify,
                              user_agents=tuple(self.user_agents))

    @property
    def pacing(self) -> Pacing:
        return Pacing(index_rpm=self.index_rpm, search_rpm=self.search_rpm, jitter=self.jitter)


@dataclass(slots=True)
class HarvesterParts:
    """The wired objects of one harvester."""

    settings: HarvesterSettings
    logger: logging.Logger
    log_level: int
    monitor: RateLimitMonitor
    clients: ClientFactory
    connection: GitLabConnection
    active: ActiveTasks
    file_checks: FileChangeChecker
    fetcher: FileFetcher
    lister: FileLister
    indexer: ProjectIndexer
    search: SearchEngine


class HarvesterFactory:
    """Builds :class:`HarvesterParts` from :class:`HarvesterSettings` (see the module doc)."""

    def __init__(self, settings: HarvesterSettings) -> None:
        self.settings = settings

    def build(self, *, connect: bool = True) -> HarvesterParts:
        """
        Create and wire every part; with ``connect`` (and a URL and a token)
        authenticate every token before returning (GitlabHarvesterError on failure).
        """
        s = self.settings
        level = coerce_log_level(s.log_level)
        logger = build_logger(name=LOGGER_NAME, level=level, log_file=s.log_file)
        monitor = RateLimitMonitor(logger, log_level=level)
        clients = ClientFactory(s.client, s.pacing, adjustable=s.adjustable_limits,
                                on_response=monitor.on_response, logger=logger)
        connection = GitLabConnection(clients, s.tokens, workers=s.workers, logger=logger)
        active = ActiveTasks()
        monitor.on_wait = active.set_waiting
        file_checks = FileChangeChecker(connection, logger)
        fetcher = FileFetcher(connection, active, logger)
        lister = FileLister(connection, active, file_checks, fetcher, logger)
        indexer = ProjectIndexer(connection, logger)
        search = SearchEngine(connection, active, file_checks, fetcher, lister, logger)
        if connect:
            connection.connect()
        return HarvesterParts(settings=s, logger=logger, log_level=level, monitor=monitor, clients=clients,
                              connection=connection, active=active, file_checks=file_checks, fetcher=fetcher,
                              lister=lister, indexer=indexer, search=search)
