# glh/cli/commands/search.py
"""
-m search: search the terms (or collect files by name) and write the session and its results.
"""

from __future__ import annotations

import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from glh.cli.args import CliArgs
from glh.cli.commands.auto_limits import start_auto_limits, stop_auto_limits
from glh.cli.commands.common import building_index, index_path, load_keywords, resolve_session_path, run_stamp, UTC
from glh.cli.factory import create_harvester, create_run_output, open_session, scan_options, session_meta
from glh.cli.report import index_rows, rate_limit_row, report, Summary
from glh.domain.file_filter import FileFilter
from glh.domain.models import IndexMeta, ProjectIndex
from glh.engine.harvester import GitlabHarvester
from glh.limits.constants import KINDS, SEARCH
from glh.output import archive
from glh.output.layout import OutputLayout
from glh.output.records import INACCESSIBLE, NOT_FOUND, ResumeRecord, SessionMeta, SummaryRecord
from glh.output.session_reader import load_done_keywords, load_session_meta
from glh.postprocess.pipeline import run_pipeline
from glh.postprocess.split import split_session_by_term
from glh.ui import statusline
from glh.ui.formatting import format_duration, plural
from glh.ui.journal import JOURNAL


def run_search(args: CliArgs) -> None:
    """Run term search workflow and write a session JSONL file."""
    glh = create_harvester(args)
    keywords = load_keywords(search=args.search, terms_file=args.terms_file, terms=args.terms)
    files_only = False
    if not keywords and (args.filename or args.extension):
        # No term: collect the files by name. The filter string is the session term.
        keywords = [FileFilter(args.filename, args.extension).query("").strip()]
        files_only = True
    if not keywords:
        raise SystemExit("Nothing to do: provide --search, --terms-file or `terms` in the config file "
                         "(or only --filename/--extension to collect files by name).")

    console = None
    if args.auto_limits:
        # The index API is measured only when the index is going to be built.
        build_index = args.dump_projects or not os.path.exists(index_path(args, glh))
        console = start_auto_limits(args, glh, KINDS if build_index else (SEARCH,))
    summary = Summary()
    try:
        _search(args, glh, keywords, summary, files_only=files_only)
    finally:
        limiter = stop_auto_limits(console)
    summary.rows += limiter
    summary.report()


def _search(args: CliArgs, glh: GitlabHarvester, keywords: list[str], summary: Summary, *,
            files_only: bool = False) -> None:
    """The search workflow proper (see run_search)."""
    stamp = run_stamp()
    # The full supplied list (before --resume drops already-done terms): the
    # --output-separated split names and covers files for every term.
    all_keywords = list(keywords)

    with building_index(args, glh, mode="search"):
        index_file = glh.build_project_index(
            per_page=args.batch_size,
            filename=args.index_file,
            enforce_dump=args.dump_projects,
            branches=args.index_branches,
            branches_per_page=args.branches_per_page,
            last_activity_after=args.index_active_after,
            last_activity_before=args.index_active_before,
        )

    index = glh.load_index(index_file) or ProjectIndex(IndexMeta(), [])
    projects = index.projects
    statusline.STATUS.write_block("Index", index_rows(index_file, index.meta, len(projects)))
    if not projects:
        raise SystemExit(f"Project index is empty: {index_file}")

    options = scan_options(args, files_only=files_only)

    session_path = resolve_session_path(glh.get_instance_id(), args.session, args.session_file, stamp)
    run = create_run_output(args, session_path, all_keywords, stamp)
    layout, downloader = run.layout, run.downloader

    done_keywords: set[str] = set()
    if args.resume:
        _check_resume_scope(session_path, session_meta(
            args, glh, options, index_file=index_file, keywords_count=len(keywords), files_only=files_only,
            timestamp_utc=""))
        done_keywords = load_done_keywords(session_path)
        if done_keywords:
            keywords = [k for k in keywords if k not in done_keywords]
        if not keywords:
            report(f"Nothing to resume: all keywords already completed in {session_path}")
            return

    with open_session(run, resume=args.resume) as output:
        if args.resume:
            output.resumed(ResumeRecord(
                timestamp_utc=datetime.now(UTC).isoformat(),
                done_keywords=len(done_keywords),
                remaining_keywords=len(keywords),
            ))
        else:
            output.meta(session_meta(args, glh, options, index_file=index_file, keywords_count=len(keywords),
                                     files_only=files_only, timestamp_utc=datetime.now(UTC).isoformat()))

        search_started = time.perf_counter()
        _, hits = glh.search_keywords(
            projects=projects,
            keywords=keywords,
            options=options,
            output=output,
            keep_results=False,  # the session file has every hit: memory doesn't grow with them
        )
        search_elapsed = time.perf_counter() - search_started
        incomplete = list(glh.incomplete_terms)
        unsearched = glh.unsearched

        output.summary(SummaryRecord(
            hits=hits,
            completed=not incomplete,
            incomplete_terms=tuple(incomplete),
            elapsed_seconds=round(search_elapsed, 2),
            timestamp_utc=datetime.now(UTC).isoformat(),
            inaccessible=unsearched[INACCESSIBLE],
            not_found=unsearched[NOT_FOUND],
        ))

    summary.add("hits", f"{hits:,}")
    summary.add("files" if files_only else "terms", keywords[0] if files_only else f"{len(keywords):,}")
    summary.add("search time", format_duration(search_elapsed))
    summary.add("session", str(session_path))
    if downloader is not None:
        summary.add("downloaded", downloader.summary_lines())
    rate_limit_row(glh, summary)
    if incomplete:
        summary.add("INCOMPLETE", [f"searches failed for {len(incomplete)} of {len(keywords)} terms: "
                                   f"{', '.join(repr(t) for t in incomplete)}", "not marked done"])
        summary.note("Repeat the command with --resume to search the incomplete terms again.")
    if unsearched_total := unsearched[INACCESSIBLE] + unsearched[NOT_FOUND]:
        # Done (retrying won't help), but not covered: never let it pass as a complete search.
        kinds = [f"{unsearched[INACCESSIBLE]:,} no access (HTTP 403)" if unsearched[INACCESSIBLE] else "",
                 f"{unsearched[NOT_FOUND]:,} not found (HTTP 404)" if unsearched[NOT_FOUND] else ""]
        summary.add("NOT SEARCHED", [f"{plural(unsearched_total, 'search', 'searches')}: "
                                     f"{', '.join(k for k in kinds if k)}",
                                     "the session lists them (\"unsearched\" of each term)"])

    # Files with hits for --to-zip: read from the session before --final-only may delete it.
    downloaded = list(dict.fromkeys(archive.downloaded_files(session_path))) if args.to_zip else []

    # Split before post-processing: --final-only there may delete the session.
    separated = _separate_output(all_keywords, layout, summary) if args.output_separated else []

    processed: list[Path] = []
    if args.post_process:
        processed = _post_process(args, session_path, summary, keep_session=bool(incomplete))

    if args.to_zip:
        _zip_results(layout, [session_path, *processed, *separated, *downloaded], summary)


def _zip_results(layout: OutputLayout, paths: list[Path | str], summary: Summary) -> None:
    """--to-zip: pack this run's results into <dir>/<session>.zip, keeping their layout."""
    target = archive.archive_path(layout.session_path)
    statusline.STATUS.write_line(f"Packing the results into {target} ...")
    started = time.perf_counter()
    existing = [p for p in paths if Path(p).exists()]  # --final-only removed some on purpose
    try:
        result = archive.zip_results(target, layout.root, existing)
    except OSError as e:
        raise SystemExit(f"--to-zip failed: {e}. The results are unchanged in {layout.root}.") from None
    summary.add("archive", f"{result.describe()}, packed in {format_duration(time.perf_counter() - started)}")
    for path in result.missing:
        JOURNAL.write(f"Archive: missing, not archived: {path}")


# How a search condition is named when --resume refuses (SessionMeta.scope_changes).
_SCOPE_NAMES = {"url": "--url", "files_only": "files by name without a term"}


def _check_resume_scope(session_path: Path, now: SessionMeta) -> None:
    """
    Refuse --resume when the search conditions differ from the ones the session
    was started with: its completed terms were searched under the old ones, and
    one session would mix the results of two different searches. Speed, tokens,
    limits and outputs may change. A session without a meta record is resumed.
    """
    meta = load_session_meta(session_path)
    if meta is None or not (changes := meta.scope_changes(now)):
        return

    def show(value: Any) -> str:
        if value is None or value is False:
            return "none" if value is None else "no"
        if value is True:
            return "yes"
        return ",".join(map(str, value)) if isinstance(value, (list, tuple)) else str(value)

    rows = [(_SCOPE_NAMES.get(name, "--" + name.replace("_", "-")), f"{show(before)} -> {show(after)}")
            for name, before, after in changes]
    width = max(len(label) for label, _ in rows)
    raise SystemExit(
        f"Cannot resume {session_path}: it was started with other search conditions:\n"
        + "".join(f"  {label.ljust(width)}  {change}\n" for label, change in rows)
        + "Its completed terms were searched under the old ones, so the session would mix two different "
          "searches. Resume with the original options, or start a new session (another --session, or "
          "without --resume)."
    )


def _separate_output(terms: list[str], layout: OutputLayout, summary: Summary) -> list[Path]:
    """Write each term's hits to <dir>/<term>/<session>.jsonl (--output-separated); needs several terms."""
    if len(terms) < 2:
        summary.add("term files", "none: --output-separated needs several terms")
        return []
    files = split_session_by_term(layout.session_path, terms, layout)
    if not files:
        summary.add("term files", "none: no hits")
        return []
    shown = ([f.relative_to(layout.root).as_posix() for f in files] if len(files) <= 10 else [])
    summary.add("term files", [f"{plural(len(files), 'file')} in {layout.root}", *shown])
    return files


def _post_process(args: CliArgs, session_path: Path, summary: Summary, keep_session: bool = False) -> list[Path]:
    """Run --post-process steps on a finished session (files are deleted only if all steps succeed)."""
    final_only = args.final_only and not keep_session
    if args.final_only and keep_session:
        summary.note("--final-only ignored: the search is incomplete, the session is kept for --resume.")
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
    summary.add("post-process", result.details)
    summary.add("removed", [str(p) for p in result.removed])
    summary.add("final result", str(result.final))
    return [p for p in result.outputs if p not in result.removed]
