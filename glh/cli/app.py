# glh/cli/app.py
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

import time
from datetime import datetime
from pathlib import Path
from typing import Any

from glh.cli import tokens
from glh.cli.args import CliArgs
from glh.cli.commands.dump_index import run_dump_index
from glh.cli.commands.find_limits import run_find_limits
from glh.cli.commands.postprocess import run_convert, run_dedup
from glh.cli.commands.search import run_search
from glh.domain.timewindow import TimeWindow
from glh.gitlab import throttling
from glh.output.downloads import format_size
from glh.ui.formatting import format_duration
from glh.ui.journal import JOURNAL
from glh.version import get_version


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
            "jitter": throttling.format_jitter(args.jitter) or "off",
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
            "project-filter": ",".join(args.project_filter) or None,
            "file-listing": args.file_listing if not (args.search or args.terms_file or args.terms) else None,
            "download-files": args.download_files or None,
            "download-max-size": (format_size(args.download_max_size) if args.download_max_size else "no limit")
            if args.download_files else None,
            "session": args.session_file or args.session or "(default)",
            "resume": args.resume,
            "output-separated": args.output_separated or None,
            "post-process": ",".join(args.post_process) or None,
            "final-only": args.final_only if args.post_process else None,
            "to-zip": args.to_zip or None,
        })
    if args.mode in ("dedup", "convert"):
        opts.update({"input-file": args.input_file, "output-file": args.output_file})
    return "Options: " + ", ".join(f"{k}={v}" for k, v in opts.items() if v is not None)


def run_mode(args: CliArgs, argv: list[str] | None = None) -> None:
    """
    Dispatch execution based on args.mode.

    With --log-file, a summary of the run (options, index, search plan, per-term
    results, output files, duration, outcome) is appended to the log file
    whatever the log level, see glh.ui.journal.RunJournal.
    """
    started = time.perf_counter()
    if args.log_file:
        JOURNAL.open(args.log_file)
        url = f", url={args.url}" if args.url and args.mode in ("search", "dump-index", "find-limits") else ""
        config = f", config={args.config}" if args.config else ""
        JOURNAL.write(f"Run started: gitlab-harvester {get_version()}, mode={args.mode}{url}{config}, "
                      f"cwd={Path.cwd()}")
        if argv is not None:
            JOURNAL.write("Command: " + " ".join(["gitlab-harvester", *tokens.mask_argv(argv)]))
        options = _describe_options(args)
        if options != "Options: ":
            JOURNAL.write(options)
    try:
        match args.mode:
            case "search":
                run_search(args)
            case "dump-index":
                run_dump_index(args)
            case "find-limits":
                run_find_limits(args)
            case "dedup":
                run_dedup(args)
            case "convert":
                run_convert(args)
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
