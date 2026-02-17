from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, IO

from glh import GitlabHarvester
from glh.planner import ScanOptions
from glh.postprocess.convert import convert_jsonl_to_json
from glh.postprocess.dedup import dedup_session_file
from glh.session import load_done_keywords

from glh.cli import CliArgs


def _load_keywords(*, search: str | None, terms_file: str | None) -> list[str]:
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

    return []


def _default_session_name(host: str) -> str:
    safe = host.replace(".", "_")
    ts = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    return f"{safe}_session_{ts}"


def _resolve_session_path(host: str, session: str | None, session_file: str | None) -> Path:
    if session_file:
        return Path(session_file)
    if session:
        return Path(f"{session}.jsonl")
    return Path(f"results{os.sep}{_default_session_name(host)}.jsonl")


def _write_jsonl_line(fp: IO[str], record: dict[str, Any]) -> None:
    fp.write(json.dumps(record, ensure_ascii=False) + "\n")


def run_mode(args: CliArgs) -> None:
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
    harvester_kwargs: dict[str, Any] = {"host": args.host, "token": args.token}
    if args.proxy:
        harvester_kwargs["proxy"] = args.proxy
    return GitlabHarvester(**harvester_kwargs)


def _run_dump_index(args: CliArgs) -> None:
    glh = _mk_harvester(args)

    index_file = glh.build_project_index(
        per_page=args.batch_size,
        filename=args.index_file,
        enforce_dump=True,  # dump-index is always "rebuild"
        branches=args.index_branches,
        branches_per_page=args.branches_per_page,
    )
    print(f"Project index saved to: {index_file}")


def _run_search(args: CliArgs) -> None:
    glh = _mk_harvester(args)

    keywords = _load_keywords(search=args.search, terms_file=args.terms_file)
    if not keywords:
        raise SystemExit("Nothing to do: provide --search or --terms-file.")

    # Ensure/build index for search run (optionally rebuild)
    index_file = glh.build_project_index(
        per_page=args.batch_size,
        filename=args.index_file,
        enforce_dump=args.dump_projects,
        branches=args.index_branches,
        branches_per_page=args.branches_per_page,
    )

    data = glh.load_projects_from_file(index_file)
    projects = data.get("projects", [])
    if not projects:
        raise SystemExit(f"Project index is empty: {index_file}")

    options = ScanOptions(
        scan_branches=args.scan_branches,
        forks_mode=args.forks,
        fork_diff_bases=tuple(x.strip() for x in args.fork_diff_bases.split(",") if x.strip()),
    )

    session_path = _resolve_session_path(glh.get_host(), args.session, args.session_file)
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
                    "host": args.host,
                    "index_file": str(index_file),
                    "batch_size": args.batch_size,
                    "branches_per_page": args.branches_per_page,
                    "index_branches": args.index_branches,
                    "scan_branches": args.scan_branches,
                    "forks": args.forks,
                    "fork_diff_bases": args.fork_diff_bases,
                    "keywords_count": len(keywords),
                },
            )

        _, hits = glh.search_keywords(
            projects=projects,
            keywords=keywords,
            options=options,
            session_file=sess_fp,
        )

        _write_jsonl_line(
            sess_fp,
            {"type": "summary", "hits": hits, "timestamp_utc": datetime.now(UTC).isoformat()},
        )

    print(f"Session saved to: {session_path}")
    print(f"Done. Keywords: {len(keywords)} | Hits: {hits}")


def _require_path(value: str | None, *, name: str) -> Path:
    if not value:
        raise SystemExit(f"Missing required argument for this mode: {name}")
    return Path(value)


def _run_dedup(args: CliArgs) -> None:
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
    input_path = _require_path(args.input_file, name="--input-file")
    output_path = _require_path(args.output_file, name="--output-file")

    convert_jsonl_to_json(
        input_path=input_path,
        output_path=output_path,
        sort_keys=args.sort_keys,
    )
