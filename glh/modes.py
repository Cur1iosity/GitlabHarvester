# glh/modes.py
"""
Mode dispatcher for GitlabHarvester.

This module maps CLI arguments to concrete workflows:
- search: ensure index, scan terms, write session JSONL
- dump-index: rebuild index JSONL
- find-limits: measure the API rate limits and print settings for them
- dedup: remove duplicates from session output
- convert: convert JSONL -> JSON

The dispatcher is intentionally thin; core logic lives in GitlabHarvester and postprocess modules.
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from glh import GitlabHarvester, archive, limits, ratelimit, tokens, user_agents
from glh.autolimit import LimitAdvisor, LimiterConsole
from glh.exceptions import GitlabHarvesterError
from glh.cli import CliArgs, _get_version
from glh.downloads import FileDownloader, format_size
from glh.output import OutputLayout, SessionOutput
from glh.planner import ScanOptions, TimeWindow, parse_timestamp
from glh.postprocess.convert import convert_jsonl_to_json
from glh.postprocess.dedup import dedup_session_file
from glh.postprocess.pipeline import run_pipeline
from glh.postprocess.split import split_session_by_term
from glh.session import load_done_keywords, load_session_meta
from glh.utils import terminal_utils
from glh.utils.logging_utils import JOURNAL
from glh.utils.terminal_utils import format_duration

# datetime.UTC exists only on Python 3.11+, while the package supports 3.10.
UTC = timezone.utc


def _require_gitlab(args: CliArgs) -> str:
    """Ensure a URL and at least one token are present for GitLab-dependent modes."""
    if not args.url or not (args.token or args.token_file):
        raise SystemExit("This mode requires --url and --token.")
    return args.url


def _resolve_tokens(args: CliArgs) -> list[str]:
    """Resolve -t/--token (';'-separated) or --token-file into a list of tokens."""
    try:
        if args.token_file:
            return tokens.load_tokens(args.token_file)
        if args.token:
            return tokens.parse_tokens(args.token)
    except tokens.TokenError as e:
        raise SystemExit(str(e)) from None
    return []


def _load_keywords(*, search: str | None, terms_file: str | None, terms: tuple[str, ...] = ()) -> list[str]:
    """Load keywords from --search, --terms-file or the config file `terms` list (in that order)."""
    if search:
        s = search.strip()
        return [s] if s else []

    if terms_file:
        p = Path(terms_file)
        keywords: list[str] = []
        for line in p.read_text(encoding="utf-8").splitlines():
            t = line.strip()
            if t and not t.startswith("#"):
                keywords.append(t)
        return keywords

    return [t.strip() for t in terms if t.strip()]


def _run_stamp() -> str:
    """UTC timestamp of a run, as used in default session and downloaded file names."""
    return datetime.now(UTC).strftime("%Y%m%d%H%M%S")


def _default_session_name(url: str, stamp: str | None = None) -> str:
    """Build a stable session name prefix from the GitLab URL."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.netloc or parsed.path).replace(".", "_").strip("_") or "gitlab"
    return f"{host}_session_{stamp or _run_stamp()}"


def _resolve_session_path(url: str, session: str | None, session_file: str | None,
                          stamp: str | None = None) -> Path:
    """Resolve session JSONL path from CLI args."""
    if session_file:
        return Path(session_file)
    if session:
        return Path(f"{session}.jsonl")
    return Path(f"results{os.sep}{_default_session_name(url, stamp)}.jsonl")


def _format_age(seconds: float) -> str:
    """'just now', '5 min ago', '3 h ago', '2 days ago'."""
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)} min ago"
    if seconds < 2 * 86400:
        return f"{int(seconds // 3600)} h ago"
    return f"{int(seconds // 86400)} days ago"


def describe_index(path: str | Path, meta: dict[str, Any], projects: int, now: datetime | None = None) -> str:
    """
    One line about the index a search uses, so the user can judge how current it is.

    Example: "Index: idx.jsonl (built 2024-06-01 12:00:00 UTC, 3 h ago; 9 projects, branches: all)".
    """
    built = parse_timestamp(meta.get("timestamp_utc"))
    if built is None:
        when = "build time unknown"
    else:
        now = now or datetime.now(UTC)
        built_utc = built.astimezone(UTC)
        when = f"built {built_utc:%Y-%m-%d %H:%M:%S} UTC, {_format_age((now - built_utc).total_seconds())}"

    details = [terminal_utils.plural(projects, "project")]
    if meta.get("branches") is not None:
        details.append(f"branches: {meta['branches']}")
    window = TimeWindow(parse_timestamp(meta.get("last_activity_after")),
                        parse_timestamp(meta.get("last_activity_before")))
    if window:
        details.append(f"projects active {window.describe()}")
    if meta.get("is_completed") is False:
        details.append("INCOMPLETE (listing failed; rebuild with --dump-projects)")
    return f"Index: {path} ({when}; {', '.join(details)})"


def _report(message: str) -> None:
    """Print a final summary line and add it to the run journal (log file)."""
    print(message)
    JOURNAL.write(message)


def _when(after: datetime | None, before: datetime | None) -> str | None:
    window = TimeWindow(after, before)
    return window.describe() if window else None


def _describe_token_source(args: CliArgs) -> str | None:
    """How many tokens and from where, for the run journal — never the values."""
    if args.token_file:
        return f"file {args.token_file}"
    if args.token:
        n = len([t for t in args.token.split(tokens.SEPARATOR) if t.strip()])
        return f"{n} inline"
    return None


def _describe_options(args: CliArgs) -> str:
    """The settings that shape a run, for the run journal (never the token)."""
    opts: dict[str, Any] = {}
    if args.mode in ("search", "dump-index", "find-limits"):
        opts.update({
            "tls": "UNVERIFIED (--insecure)" if args.insecure else (f"ca-bundle {args.ca_bundle}" if args.ca_bundle else "verified"),
            "index-file": args.index_file or "(default)",
            "index-branches": args.index_branches,
            "batch-size": args.batch_size,
            "tokens": _describe_token_source(args),
            "workers": args.workers,
            "index-rpm": args.index_rpm or "no limit",
            "search-rpm": args.search_rpm or "no limit",
            "jitter": ratelimit.format_jitter(args.jitter) or "off",
            "user-agent": (f"file {args.user_agent_file}" if args.user_agent_file
                           else (repr(args.user_agent) if args.user_agent else "python-gitlab")),
            "index-active": _when(args.index_active_after, args.index_active_before),
            "auto-limits": args.auto_limits or None,
        })
    if args.mode == "find-limits" or args.auto_limits:
        opts.update({
            "probe-apis": ",".join(args.probe_apis) or "(auto)",
            "probe-max": args.probe_max,
            "probe-margin": args.probe_margin,
        })
    if args.mode == "search":
        if args.search:
            terms = f"search {args.search!r}"
        elif args.terms_file:
            terms = f"terms-file {args.terms_file}"
        else:
            terms = f"{len(args.terms)} from the config file"
        opts.update({
            "dump-projects": args.dump_projects,
            "scan-branches": args.scan_branches,
            "forks": args.forks,
            "fork-diff-bases": args.fork_diff_bases if args.forks == "branch-diff" else None,
            "terms": terms,
            "active": _when(args.started_from, args.active_before),
            "file-changed": _when(args.file_changed_after, args.file_changed_before),
            "filename": args.filename,
            "extension": args.extension,
            "download-files": args.download_files or None,
            "download-max-size": (format_size(args.download_max_size) if args.download_max_size else "no limit")
            if args.download_files else None,
            "session": args.session_file or args.session or "(default)",
            "resume": args.resume,
            "output-separated": args.output_separated or None,
            "post-process": ",".join(args.post_process) or None,
            "final-only": args.final_only if args.post_process else None,
        })
    if args.mode in ("dedup", "convert"):
        opts.update({"input-file": args.input_file, "output-file": args.output_file})
    return "Options: " + ", ".join(f"{k}={v}" for k, v in opts.items() if v is not None)


def run_mode(args: CliArgs) -> None:
    """
    Dispatch execution based on args.mode.

    With --log-file, a summary of the run (options, index, search plan, per-term
    results, output files, duration, outcome) is appended to the log file
    whatever the log level, see logging_utils.RunJournal.
    """
    started = time.perf_counter()
    if args.log_file:
        JOURNAL.open(args.log_file)
        url = f", url={args.url}" if args.url and args.mode in ("search", "dump-index", "find-limits") else ""
        config = f", config={args.config}" if args.config else ""
        JOURNAL.write(f"Run started: gitlab-harvester {_get_version()}, mode={args.mode}{url}{config}, "
                      f"cwd={Path.cwd()}")
        options = _describe_options(args)
        if options != "Options: ":
            JOURNAL.write(options)
    try:
        match args.mode:
            case "search":
                _run_search(args)
            case "dump-index":
                _run_dump_index(args)
            case "find-limits":
                _run_find_limits(args)
            case "dedup":
                _run_dedup(args)
            case "convert":
                _run_convert(args)
            case _:
                raise SystemExit(f"Unknown mode: {args.mode}")
    except SystemExit as e:
        if e.code not in (None, 0):
            reason = f"exit code {e.code}" if isinstance(e.code, int) else str(e.code)
            JOURNAL.write(f"Run failed after {format_duration(time.perf_counter() - started)}: {reason}")
        else:
            JOURNAL.write(f"Run finished in {format_duration(time.perf_counter() - started)}")
        raise
    except BaseException as e:
        reason = "interrupted" if isinstance(e, KeyboardInterrupt) else f"{type(e).__name__}: {e}"
        JOURNAL.write(f"Run failed after {format_duration(time.perf_counter() - started)}: {reason}")
        raise
    else:
        JOURNAL.write(f"Run finished in {format_duration(time.perf_counter() - started)}")
    finally:
        JOURNAL.close()


def _mk_harvester(args: CliArgs) -> GitlabHarvester:
    """Create a GitlabHarvester instance from CLI args."""
    url = _require_gitlab(args)
    token_list = _resolve_tokens(args)
    if not token_list:
        raise SystemExit("This mode requires --url and --token.")

    agents: list[str] = []
    if args.user_agent_file:
        try:
            agents = user_agents.load_user_agents(args.user_agent_file)
        except user_agents.UserAgentError as e:
            raise SystemExit(str(e)) from None
    elif args.user_agent:
        agents = [args.user_agent]

    kwargs: dict[str, Any] = {
        "url": url,
        "tokens": token_list,
        "timeout": args.timeout,
        "workers": args.workers,
        "index_rpm": args.index_rpm,
        "search_rpm": args.search_rpm,
        "jitter": args.jitter,
        "user_agents": agents,
        "log_level": args.log_level,
        "log_file": args.log_file,
        "ssl_verify": False if args.insecure else (args.ca_bundle or True),
        "adjustable_limits": args.auto_limits,
    }
    if args.proxy:
        kwargs["proxy"] = args.proxy

    try:
        return GitlabHarvester(**kwargs)
    except GitlabHarvesterError as e:
        raise SystemExit(str(e)) from None


def _run_dump_index(args: CliArgs) -> None:
    """Rebuild the Instance Project Index and write to disk."""
    glh = _mk_harvester(args)
    console = _start_auto_limits(args, glh, (limits.INDEX,)) if args.auto_limits else None
    try:
        index_file = glh.build_project_index(
            per_page=args.batch_size,
            filename=args.index_file,
            enforce_dump=True,
            branches=args.index_branches,
            branches_per_page=args.branches_per_page,
            last_activity_after=args.index_active_after,
            last_activity_before=args.index_active_before,
        )
    finally:
        _stop_auto_limits(console)
    _report(f"Project index saved to: {index_file}")
# --------------------------------------------------------------------------- rate limits


def _index_path(args: CliArgs, glh: GitlabHarvester) -> str:
    """The index file a search would use (same default name as build_project_index)."""
    return args.index_file or f"{glh.get_instance_id()}_project_index.jsonl"


def _current_settings(args: CliArgs) -> limits.Settings:
    return limits.Settings(workers=args.workers, index_rpm=args.index_rpm, search_rpm=args.search_rpm)


def _measure(args: CliArgs, glh: GitlabHarvester, kinds: tuple[str, ...]
             ) -> tuple[limits.LimitFinder, dict[str, limits.ProbeResult], limits.Recommendation]:
    """Probe ``kinds``, print what was found and the recommended settings."""
    terminal_utils.STATUS.write_line(limits.EXPERIMENTAL_NOTE)
    finder = limits.LimitFinder(glh, max_requests=args.probe_max, margin=args.probe_margin)
    project = finder.project_for_search(_index_path(args, glh)) if limits.SEARCH in kinds else None
    terminal_utils.STATUS.write_line(
        f"Measuring rate limits of {', '.join(limits.API_NAMES[k] for k in kinds)} "
        f"(up to {args.probe_max:,} requests each; this provokes HTTP 429 on purpose)")
    results = finder.find(kinds, project_id=project)
    recommendation = finder.recommend(results, current=_current_settings(args), explicit=args.explicit_limits)

    _report(f"Rate limits found at {args.url} (token #1):")
    for kind in kinds:
        _report(f"  {results[kind].describe()}")
    if note := finder.token_note():
        _report(f"  {note}")
    _report(f"Suggested settings: {recommendation.describe()}")
    for note in recommendation.notes:
        _report(f"  - {note}")
    return finder, results, recommendation


def _confirm(question: str) -> bool:
    """Ask a yes/no question on the terminal (Enter = yes)."""
    sys.stderr.write(question)
    sys.stderr.flush()
    try:
        answer = sys.stdin.readline()
    except (OSError, ValueError):
        return False
    if not answer:
        return False
    return answer.strip().lower() in ("", "y", "yes", "д", "да", "н")


def _start_auto_limits(args: CliArgs, glh: GitlabHarvester, kinds: tuple[str, ...]) -> LimiterConsole:
    """
    --auto-limits before a run: measure ``kinds`` (unless every option they
    need was set explicitly), offer the settings, wait for the probed windows to
    reset, then watch the run for HTTP 429 (returned console; stop it after the run).
    """
    kinds = tuple(k for k in kinds if k in (args.probe_apis or kinds))
    needed = {"workers", *(f"{k}_rpm" for k in kinds)}
    if not kinds or needed <= args.explicit_limits:
        terminal_utils.STATUS.write_line(limits.EXPERIMENTAL_NOTE)
        terminal_utils.STATUS.write_line(
            "Auto limits: --workers and the rpm options are set, nothing to measure; "
            "watching the run for HTTP 429.")
    else:
        finder, results, recommendation = _measure(args, glh, kinds)
        current = _current_settings(args)
        if recommendation.differs_from(current):
            if not (sys.stdin.isatty() and sys.stderr.isatty()):
                _report(f"Command: {recommendation.command(sys.argv[1:])}")
                raise SystemExit("--auto-limits: no terminal to confirm the settings. "
                                 "Run the command above (or add the suggested options) to start.")
            if _confirm(f"Apply {recommendation.describe()} to this run? [Y/n] "):
                glh.set_rate_limits(workers=recommendation.workers, index_rpm=recommendation.index_rpm,
                                    search_rpm=recommendation.search_rpm)
                terminal_utils.STATUS.write_line(f"Auto limits: applied {recommendation.describe()}")
            else:
                terminal_utils.STATUS.write_line(
                    f"Auto limits: kept --workers {current.workers} --index-rpm {current.index_rpm} "
                    f"--search-rpm {current.search_rpm}; next time: {' '.join(recommendation.flags())}")
        finder.wait_cooldown(results.values())
    advisor = LimitAdvisor(glh, margin=args.probe_margin).attach()
    return LimiterConsole(advisor, logger=glh.logger).start()


def _stop_auto_limits(console: LimiterConsole | None) -> None:
    """End the run's limit watch and report what it did."""
    if console is None:
        return
    console.stop()
    advisor = console.advisor
    advisor.detach()
    harvester = advisor.harvester
    if advisor.applied:
        _report(f"Limiter: limits changed during the run; start the next run with --workers "
                f"{harvester.workers} --index-rpm {harvester.index_rpm} --search-rpm {harvester.search_rpm}")
    if (pending := advisor.pending) is not None:
        _report(f"Limiter: proposal not applied: {pending.describe()} ({pending.flags()})")


def _run_find_limits(args: CliArgs) -> None:
    """Measure the rate limits (-m find-limits) and print the settings to use; no search."""
    glh = _mk_harvester(args)
    kinds = args.probe_apis or limits.KINDS
    _, results, recommendation = _measure(args, glh, kinds)
    _report(f"Command: {recommendation.command(sys.argv[1:])}")
    _report("Config file:\n  " + recommendation.ini().replace("\n", "\n  "))
    reset = max((r.finished_at + r.cooldown - time.monotonic() for r in results.values() if r.limited),
                default=0.0)
    if reset > 0:
        _report(f"The probed rate-limit budget is back in about {format_duration(reset)}.")


def _run_search(args: CliArgs) -> None:
    """Run term search workflow and write a session JSONL file."""
    glh = _mk_harvester(args)
    keywords = _load_keywords(search=args.search, terms_file=args.terms_file, terms=args.terms)
    if not keywords:
        raise SystemExit("Nothing to do: provide --search, --terms-file or `terms` in the config file.")

    console = None
    if args.auto_limits:
        # The index API is measured only when the index is going to be built.
        build_index = args.dump_projects or not os.path.exists(_index_path(args, glh))
        console = _start_auto_limits(args, glh, limits.KINDS if build_index else (limits.SEARCH,))
    try:
        _search(args, glh, keywords)
    finally:
        _stop_auto_limits(console)


def _search(args: CliArgs, glh: GitlabHarvester, keywords: list[str]) -> None:
    """The search workflow proper (see _run_search)."""
    stamp = _run_stamp()
    # The full supplied list (before --resume drops already-done terms): the
    # --output-separated split names and covers files for every term.
    all_keywords = list(keywords)

    index_file = glh.build_project_index(
        per_page=args.batch_size,
        filename=args.index_file,
        enforce_dump=args.dump_projects,
        branches=args.index_branches,
        branches_per_page=args.branches_per_page,
        last_activity_after=args.index_active_after,
        last_activity_before=args.index_active_before,
    )

    data = glh.load_projects_from_file(index_file)
    projects = data.get("projects", [])
    terminal_utils.STATUS.write_line(describe_index(index_file, data.get("meta") or {}, len(projects)))
    if not projects:
        raise SystemExit(f"Project index is empty: {index_file}")

    options = ScanOptions(
        scan_branches=args.scan_branches,
        forks_mode=args.forks,
        fork_diff_bases=tuple(x.strip() for x in args.fork_diff_bases.split(",") if x.strip()),
        started_from=args.started_from,
        active_before=args.active_before,
        file_changed_after=args.file_changed_after,
        file_changed_before=args.file_changed_before,
        filename=args.filename,
        extension=args.extension,
    )

    session_path = _resolve_session_path(glh.get_instance_id(), args.session, args.session_file, stamp)
    layout = OutputLayout(session_path, all_keywords)
    downloader = (FileDownloader(layout, stamp, max_size=args.download_max_size)
                  if args.download_files else None)

    done_keywords: set[str] = set()
    if args.resume:
        _warn_changed_file_filter(glh, session_path, options)
        done_keywords = load_done_keywords(session_path)
        if done_keywords:
            keywords = [k for k in keywords if k not in done_keywords]
        if not keywords:
            _report(f"Nothing to resume: all keywords already completed in {session_path}")
            return

    with SessionOutput(layout, resume=args.resume, downloader=downloader) as output:
        if args.resume:
            output.resumed(
                timestamp_utc=datetime.now(UTC).isoformat(),
                done_keywords=len(done_keywords),
                remaining_keywords=len(keywords),
            )
        else:
            output.meta(
                timestamp_utc=datetime.now(UTC).isoformat(),
                url=args.url,
                config=args.config,
                index_file=str(index_file),
                batch_size=args.batch_size,
                tokens=len(glh.tokens),
                workers=glh.workers,
                index_rpm=glh.index_rpm,
                search_rpm=glh.search_rpm,
                auto_limits=args.auto_limits,
                jitter=list(args.jitter),
                user_agent=args.user_agent,
                user_agent_file=args.user_agent_file,
                branches_per_page=args.branches_per_page,
                index_branches=args.index_branches,
                scan_branches=args.scan_branches,
                forks=args.forks,
                fork_diff_bases=args.fork_diff_bases,
                started_from=args.started_from.isoformat() if args.started_from else None,
                active_before=args.active_before.isoformat() if args.active_before else None,
                file_changed_after=args.file_changed_after.isoformat() if args.file_changed_after else None,
                file_changed_before=args.file_changed_before.isoformat() if args.file_changed_before else None,
                **options.file_filter.to_meta(),
                keywords_count=len(keywords),
                output_separated=args.output_separated,
                download_files=args.download_files,
                download_max_size=args.download_max_size if args.download_files else None,
                post_process=list(args.post_process),
                final_only=args.final_only,
            )

        search_started = time.perf_counter()
        _, hits = glh.search_keywords(
            projects=projects,
            keywords=keywords,
            options=options,
            output=output,
        )
        search_elapsed = time.perf_counter() - search_started
        incomplete = list(glh.incomplete_terms)

        output.summary(
            hits=hits,
            completed=not incomplete,
            incomplete_terms=incomplete,
            elapsed_seconds=round(search_elapsed, 2),
            timestamp_utc=datetime.now(UTC).isoformat(),
        )

    _report(f"Session saved to: {session_path}")
    _report(f"Done. Keywords: {len(keywords)} | Hits: {hits} | Search time: {format_duration(search_elapsed)}")
    if downloader is not None:
        _report(f"Downloaded files: {downloader.summary()}")
    if incomplete:
        _report(
            f"INCOMPLETE: searches failed for {len(incomplete)} of {len(keywords)} terms "
            f"({', '.join(repr(t) for t in incomplete)}); they are not marked done. "
            f"Repeat the command with --resume to search them again."
        )

    # Split before post-processing: --final-only there may delete the session.
    if args.output_separated:
        _separate_output(all_keywords, layout)

    if args.post_process:
        _post_process(args, session_path, keep_session=bool(incomplete))


def _warn_changed_file_filter(glh: GitlabHarvester, session_path: Path, options: ScanOptions) -> None:
    """
    --resume with other --filename/--extension than the session's first run:
    the completed terms were searched in other files, so say so.
    """
    meta = load_session_meta(session_path)
    if meta is None:
        return
    before = {key: meta.get(key) for key in ("filename", "extension")}
    now = options.file_filter.to_meta()
    if before != now:
        def show(values: dict[str, Any]) -> str:
            return ", ".join(f"{k} {v}" for k, v in values.items() if v) or "none"
        glh.logger.warning(
            "Resuming %s with other file filters (%s) than it was started with (%s): "
            "terms already completed were searched with the old filters.",
            session_path, show(now), show(before),
        )


def _separate_output(terms: list[str], layout: OutputLayout) -> None:
    """Write each term's hits to <dir>/<term>/<session>.jsonl (--output-separated); needs several terms."""
    if len(terms) < 2:
        _report("--output-separated ignored: it needs several search terms.")
        return
    files = split_session_by_term(layout.session_path, terms, layout)
    if not files:
        _report("Separated output: no hits, no per-term files written.")
        return
    shown = (", ".join(f.relative_to(layout.root).as_posix() for f in files) if len(files) <= 10
             else f"{len(files)} files")
    _report(f"Separated output: {terminal_utils.plural(len(files), 'term file')} "
            f"in {layout.root} ({shown})")


def _post_process(args: CliArgs, session_path: Path, keep_session: bool = False) -> None:
    """Run --post-process steps on a finished session (files are deleted only if all steps succeed)."""
    final_only = args.final_only and not keep_session
    if args.final_only and keep_session:
        _report("--final-only ignored: the search is incomplete, the session is kept for --resume.")
    result = run_pipeline(
        session_path,
        args.post_process,
        final_only=final_only,
        sqlite_path=Path(args.sqlite_path) if args.sqlite_path else None,
        hash_algo=args.hash_algo,
        normalize=args.normalize_hits,
        sort_keys=args.sort_keys,
    )
    for note in result.notes:
        JOURNAL.write(f"Post-processing {note}")
    _report(f"Post-processing: {' -> '.join(str(p) for p in [session_path, *result.outputs])}")
    if result.removed:
        _report(f"Removed (--final-only): {', '.join(str(p) for p in result.removed)}")
    _report(f"Final result: {result.final}")


def _require_path(value: str | None, *, name: str) -> Path:
    """Require a CLI path argument in postprocess modes."""
    if not value:
        raise SystemExit(f"Missing required argument for this mode: {name}")
    return Path(value)


def _run_dedup(args: CliArgs) -> None:
    """Run deduplication over a session file."""
    input_path = _require_path(args.input_file, name="--input-file")
    output_path = _require_path(args.output_file, name="--output-file")

    sqlite_path = Path(args.sqlite_path) if args.sqlite_path else None

    stats = dedup_session_file(
        input_path=input_path,
        output_path=output_path,
        sqlite_path=sqlite_path,
        hash_algo=args.hash_algo,
        normalize=args.normalize_hits,
    )
    JOURNAL.write(f"Dedup: {input_path} -> {output_path} (kept {stats['kept']} records, "
                  f"dropped {stats['dropped']} duplicate-only hit records)")


def _run_convert(args: CliArgs) -> None:
    """Convert JSONL session file to JSON."""
    input_path = _require_path(args.input_file, name="--input-file")
    output_path = _require_path(args.output_file, name="--output-file")

    count = convert_jsonl_to_json(
        input_path=input_path,
        output_path=output_path,
        sort_keys=args.sort_keys,
    )
    JOURNAL.write(f"Convert: {input_path} -> {output_path} ({count} objects)")
