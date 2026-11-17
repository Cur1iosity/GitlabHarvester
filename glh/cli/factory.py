# glh/cli/factory.py
"""
The composition root of a CLI run: every object a command needs is made here
from the parsed options (:class:`~glh.cli.args.CliArgs`), so the commands only
use objects and never assemble them.

- :func:`create_harvester` — the GitlabHarvester of the run (tokens,
  User-Agents, TLS, proxy, workers, pacing), via the engine's HarvesterFactory;
- :func:`scan_options` — what a search scans (branches, forks, time and file
  filters, project filter, files-only mode);
- :func:`create_run_output` / :func:`open_session` — where a search writes
  (layout, session file, downloaded files);
- :func:`create_limit_finder`, :func:`create_limit_watch` — the experimental
  rate-limit detection (probe, then the advisor and its console during the run).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from glh.cli import tokens
from glh.cli.args import CliArgs
from glh.domain.planning import ScanOptions
from glh.engine.factory import HarvesterSettings
from glh.engine.harvester import GitlabHarvester
from glh.exceptions import GitlabHarvesterError
from glh.gitlab import user_agents
from glh.limits.advisor import LimitAdvisor
from glh.limits.console import LimiterConsole
from glh.limits.finder import LimitFinder
from glh.output.downloads import FileDownloader
from glh.output.layout import OutputLayout
from glh.output.sink import SessionOutput

# --------------------------------------------------------------------------- harvester


def require_gitlab(args: CliArgs) -> str:
    """The URL of a GitLab-dependent mode; SystemExit without a URL or a token."""
    if not args.url or not (args.token or args.token_file):
        raise SystemExit("This mode requires --url and --token.")
    return args.url


def resolve_tokens(args: CliArgs) -> tuple[str, ...]:
    """-t/--token (';'-separated) or --token-file as a token list; SystemExit on a bad file."""
    try:
        if args.token_file:
            return tuple(tokens.load_tokens(args.token_file))
        if args.token:
            return tuple(tokens.parse_tokens(args.token))
    except tokens.TokenError as e:
        raise SystemExit(str(e)) from None
    return ()


def resolve_user_agents(args: CliArgs) -> tuple[str, ...]:
    """-A (one fixed) or --user-agent-file (random per request); () = python-gitlab's."""
    if args.user_agent_file:
        try:
            return tuple(user_agents.load_user_agents(args.user_agent_file))
        except user_agents.UserAgentError as e:
            raise SystemExit(str(e)) from None
    return (args.user_agent,) if args.user_agent else ()


def harvester_settings(args: CliArgs) -> HarvesterSettings:
    """The HarvesterSettings of a run from its options."""
    url = require_gitlab(args)
    token_list = resolve_tokens(args)
    if not token_list:
        raise SystemExit("This mode requires --url and --token.")
    return HarvesterSettings(
        url=url,
        tokens=token_list,
        proxy=args.proxy or None,
        timeout=args.timeout,
        ssl_verify=False if args.insecure else (args.ca_bundle or True),
        workers=args.workers,
        index_rpm=args.index_rpm,
        search_rpm=args.search_rpm,
        jitter=args.jitter,
        user_agents=resolve_user_agents(args),
        adjustable_limits=args.auto_limits,
        log_level=args.log_level,
        log_file=args.log_file,
    )


def create_harvester(args: CliArgs) -> GitlabHarvester:
    """The connected harvester of a run; SystemExit with one clear line if connecting fails."""
    try:
        return GitlabHarvester.from_settings(harvester_settings(args))
    except (GitlabHarvesterError, ValueError) as e:  # ValueError: an invalid --proxy
        raise SystemExit(str(e)) from None


# --------------------------------------------------------------------------- search


def scan_options(args: CliArgs, *, files_only: bool = False) -> ScanOptions:
    """What a search scans, from its options."""
    return ScanOptions(
        scan_branches=args.scan_branches,
        forks_mode=args.forks,
        fork_diff_bases=tuple(x.strip() for x in args.fork_diff_bases.split(",") if x.strip()),
        started_from=args.started_from,
        active_before=args.active_before,
        file_changed_after=args.file_changed_after,
        file_changed_before=args.file_changed_before,
        filename=args.filename,
        extension=args.extension,
        project_filter=args.project_filter,
        files_only=files_only,
        file_listing=args.file_listing,
    )


@dataclass(frozen=True, slots=True)
class RunOutput:
    """Where a search writes: the layout of its files and the downloader (--download-files)."""

    layout: OutputLayout
    downloader: FileDownloader | None

    @property
    def session_path(self) -> Path:
        return self.layout.session_path


def create_run_output(args: CliArgs, session_path: Path, terms: list[str], stamp: str) -> RunOutput:
    """The output of a search: ``terms`` is the full supplied list (fixes the term directory names)."""
    layout = OutputLayout(session_path, terms)
    downloader = FileDownloader(layout, stamp, max_size=args.download_max_size) if args.download_files else None
    return RunOutput(layout=layout, downloader=downloader)


def open_session(run: RunOutput, *, resume: bool) -> SessionOutput:
    """The session sink of the run (a context manager; appends on --resume)."""
    return SessionOutput(run.layout, resume=resume, downloader=run.downloader)


# --------------------------------------------------------------------------- rate limits (experimental)


def create_limit_finder(args: CliArgs, harvester: GitlabHarvester) -> LimitFinder:
    """The probe of -m find-limits / --auto-limits (--probe-max, --probe-margin)."""
    return LimitFinder(harvester, max_requests=args.probe_max, margin=args.probe_margin)


def create_limit_watch(args: CliArgs, harvester: GitlabHarvester) -> LimiterConsole:
    """--auto-limits during a run: the advisor on every response and its (started) console."""
    advisor = LimitAdvisor(harvester, margin=args.probe_margin).attach()
    return LimiterConsole(advisor, logger=harvester.logger).start()
