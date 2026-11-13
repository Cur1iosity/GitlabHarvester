# glh/modes.py
"""
Mode dispatcher for GitlabHarvester.

This module maps CLI arguments to concrete workflows:
- search: ensure index, scan terms, write session JSONL
- dump-index: rebuild index JSONL
- dedup: remove duplicates from session output
- convert: convert JSONL -> JSON

The dispatcher is intentionally thin; core logic lives in GitlabHarvester and postprocess modules.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, IO
from urllib.parse import urlparse

from glh import GitlabHarvester, ratelimit, tokens, user_agents
from glh.exceptions import GitlabHarvesterError
from glh.cli import CliArgs, _get_version
from glh.planner import ScanOptions, TimeWindow, parse_timestamp
from glh.postprocess.convert import convert_jsonl_to_json
from glh.postprocess.dedup import dedup_session_file
from glh.postprocess.pipeline import run_pipeline
from glh.postprocess.split import split_session_by_term
from glh.session import load_done_keywords
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


def _default_session_name(url: str) -> str:
    """Build a stable session name prefix from the GitLab URL."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.netloc or parsed.path).replace(".", "_").strip("_") or "gitlab"
    ts = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    return f"{host}_session_{ts}"


def _resolve_session_path(url: str, session: str | None, session_file: str | None) -> Path:
    """Resolve session JSONL path from CLI args."""
    if session_file:
        return Path(session_file)
    if session:
        return Path(f"{session}.jsonl")
    return Path(f"results{os.sep}{_default_session_name(url)}.jsonl")


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


def _write_jsonl_line(fp: IO[str], record: dict[str, Any]) -> None:
    """Write a JSONL record to an open file."""
    fp.write(json.dumps(record, ensure_ascii=False) + "\n")


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
    if args.mode in ("search", "dump-index"):
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
        url = f", url={args.url}" if args.url and args.mode in ("search", "dump-index") else ""
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

    index_file = glh.build_project_index(
        per_page=args.batch_size,
        filename=args.index_file,
        enforce_dump=True,
        branches=args.index_branches,
        branches_per_page=args.branches_per_page,
        last_activity_after=args.index_active_after,
        last_activity_before=args.index_active_before,
    )
    _report(f"Project index saved to: {index_file}")


def _run_search(args: CliArgs) -> None:
    """Run term search workflow and write a session JSONL file."""
    glh = _mk_harvester(args)

    keywords = _load_keywords(search=args.search, terms_file=args.terms_file, terms=args.terms)
    if not keywords:
        raise SystemExit("Nothing to do: provide --search, --terms-file or `terms` in the config file.")
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
    )

    session_path = _resolve_session_path(glh.get_instance_id(), args.session, args.session_file)
    session_path.parent.mkdir(parents=True, exist_ok=True)

    done_keywords: set[str] = set()
    if args.resume:
        done_keywords = load_done_keywords(session_path)
        if done_keywords:
            keywords = [k for k in keywords if k not in done_keywords]
        if not keywords:
            _report(f"Nothing to resume: all keywords already completed in {session_path}")
            return

    mode = "a" if args.resume else "w"
    with session_path.open(mode, encoding="utf-8") as sess_fp:
        if args.resume:
            _write_jsonl_line(
                sess_fp,
                {
                    "type": "resume",
                    "timestamp_utc": datetime.now(UTC).isoformat(),
                    "done_keywords": len(done_keywords),
                    "remaining_keywords": len(keywords),
                },
            )
        else:
            _write_jsonl_line(
                sess_fp,
                {
                    "type": "meta",
                    "timestamp_utc": datetime.now(UTC).isoformat(),
                    "url": args.url,
                    "config": args.config,
                    "index_file": str(index_file),
                    "batch_size": args.batch_size,
                    "tokens": len(glh.tokens),
                    "workers": args.workers,
                    "index_rpm": args.index_rpm,
                    "search_rpm": args.search_rpm,
                    "jitter": list(args.jitter),
                    "user_agent": args.user_agent,
                    "user_agent_file": args.user_agent_file,
                    "branches_per_page": args.branches_per_page,
                    "index_branches": args.index_branches,
                    "scan_branches": args.scan_branches,
                    "forks": args.forks,
                    "fork_diff_bases": args.fork_diff_bases,
                    "started_from": args.started_from.isoformat() if args.started_from else None,
                    "active_before": args.active_before.isoformat() if args.active_before else None,
                    "file_changed_after": args.file_changed_after.isoformat() if args.file_changed_after else None,
                    "file_changed_before": args.file_changed_before.isoformat() if args.file_changed_before else None,
                    "keywords_count": len(keywords),
                    "output_separated": args.output_separated,
                    "post_process": list(args.post_process),
                    "final_only": args.final_only,
                },
            )

        search_started = time.perf_counter()
        _, hits = glh.search_keywords(
            projects=projects,
            keywords=keywords,
            options=options,
            session_file=sess_fp,
        )
        search_elapsed = time.perf_counter() - search_started
        incomplete = list(glh.incomplete_terms)

        _write_jsonl_line(
            sess_fp,
            {
                "type": "summary",
                "hits": hits,
                "completed": not incomplete,
                "incomplete_terms": incomplete,
                "elapsed_seconds": round(search_elapsed, 2),
                "timestamp_utc": datetime.now(UTC).isoformat(),
            },
        )

    _report(f"Session saved to: {session_path}")
    _report(f"Done. Keywords: {len(keywords)} | Hits: {hits} | Search time: {format_duration(search_elapsed)}")
    if incomplete:
        _report(
            f"INCOMPLETE: searches failed for {len(incomplete)} of {len(keywords)} terms "
            f"({', '.join(repr(t) for t in incomplete)}); they are not marked done. "
            f"Repeat the command with --resume to search them again."
        )

    # Split before post-processing: --final-only there may delete the session.
    if args.output_separated:
        _separate_output(all_keywords, session_path)

    if args.post_process:
        _post_process(args, session_path, keep_session=bool(incomplete))


def _separate_output(terms: list[str], session_path: Path) -> None:
    """Write each term's hits to its own file (--output-separated); needs several terms."""
    if len(terms) < 2:
        _report("--output-separated ignored: it needs several search terms.")
        return
    files = split_session_by_term(session_path, terms)
    if not files:
        _report("Separated output: no hits, no per-term files written.")
        return
    shown = ", ".join(f.name for f in files) if len(files) <= 10 else f"{len(files)} files"
    _report(f"Separated output: {terminal_utils.plural(len(files), 'term file')} "
            f"in {session_path.parent} ({shown})")


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
