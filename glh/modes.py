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

from glh import GitlabHarvester
from glh.cli import CliArgs
from glh.planner import ScanOptions, TimeWindow, parse_timestamp
from glh.postprocess.convert import convert_jsonl_to_json
from glh.postprocess.dedup import dedup_session_file
from glh.postprocess.pipeline import run_pipeline
from glh.session import load_done_keywords
from glh.utils import terminal_utils
from glh.utils.terminal_utils import format_duration

# datetime.UTC exists only on Python 3.11+, while the package supports 3.10.
UTC = timezone.utc


def _require_gitlab(args: CliArgs) -> tuple[str, str]:
    """Ensure URL and token are present for GitLab-dependent modes."""
    if not args.url or not args.token:
        raise SystemExit("This mode requires --url and --token.")
    return args.url, args.token


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


def run_mode(args: CliArgs) -> None:
    """Dispatch execution based on args.mode."""
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


def _mk_harvester(args: CliArgs) -> GitlabHarvester:
    """Create a GitlabHarvester instance from CLI args."""
    url, token = _require_gitlab(args)

    kwargs: dict[str, Any] = {
        "url": url,
        "token": token,
        "timeout": args.timeout,
        "workers": args.workers,
        "log_level": args.log_level,
        "log_file": args.log_file,
    }
    if args.proxy:
        kwargs["proxy"] = args.proxy

    return GitlabHarvester(**kwargs)


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
    print(f"Project index saved to: {index_file}")


def _run_search(args: CliArgs) -> None:
    """Run term search workflow and write a session JSONL file."""
    glh = _mk_harvester(args)

    keywords = _load_keywords(search=args.search, terms_file=args.terms_file, terms=args.terms)
    if not keywords:
        raise SystemExit("Nothing to do: provide --search, --terms-file or `terms` in the config file.")

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
            print(f"Nothing to resume: all keywords already completed in {session_path}")
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
                    "workers": args.workers,
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

        _write_jsonl_line(
            sess_fp,
            {
                "type": "summary",
                "hits": hits,
                "elapsed_seconds": round(search_elapsed, 2),
                "timestamp_utc": datetime.now(UTC).isoformat(),
            },
        )

    print(f"Session saved to: {session_path}")
    print(f"Done. Keywords: {len(keywords)} | Hits: {hits} | Search time: {format_duration(search_elapsed)}")

    if args.post_process:
        _post_process(args, session_path)


def _post_process(args: CliArgs, session_path: Path) -> None:
    """Run --post-process steps on a finished session (files are deleted only if all steps succeed)."""
    result = run_pipeline(
        session_path,
        args.post_process,
        final_only=args.final_only,
        sqlite_path=Path(args.sqlite_path) if args.sqlite_path else None,
        hash_algo=args.hash_algo,
        normalize=args.normalize_hits,
        sort_keys=args.sort_keys,
    )
    print(f"Post-processing: {' -> '.join(str(p) for p in [session_path, *result.outputs])}")
    if result.removed:
        print(f"Removed (--final-only): {', '.join(str(p) for p in result.removed)}")
    print(f"Final result: {result.final}")


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

    dedup_session_file(
        input_path=input_path,
        output_path=output_path,
        sqlite_path=sqlite_path,
        hash_algo=args.hash_algo,
        normalize=args.normalize_hits,
    )


def _run_convert(args: CliArgs) -> None:
    """Convert JSONL session file to JSON."""
    input_path = _require_path(args.input_file, name="--input-file")
    output_path = _require_path(args.output_file, name="--output-file")

    convert_jsonl_to_json(
        input_path=input_path,
        output_path=output_path,
        sort_keys=args.sort_keys,
    )
