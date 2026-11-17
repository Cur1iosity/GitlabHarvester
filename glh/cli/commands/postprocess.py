# glh/cli/commands/postprocess.py
"""
-m dedup and -m convert on an existing session file.
"""

from __future__ import annotations

from pathlib import Path

from glh.cli.args import CliArgs
from glh.cli.commands.common import require_path
from glh.cli.report import report_block
from glh.postprocess.convert import convert_jsonl_to_json
from glh.postprocess.dedup import dedup_session_file


def run_dedup(args: CliArgs) -> None:
    """Run deduplication over a session file."""
    input_path = require_path(args.input_file, name="--input-file")
    output_path = require_path(args.output_file, name="--output-file")

    sqlite_path = Path(args.sqlite_path) if args.sqlite_path else None

    stats = dedup_session_file(
        input_path=input_path,
        output_path=output_path,
        sqlite_path=sqlite_path,
        hash_algo=args.hash_algo,
        normalize=args.normalize_hits,
    )
    report_block("Dedup", [
        ("input", str(input_path)),
        ("output", str(output_path)),
        ("kept", f"{stats['kept']:,} records"),
        ("dropped", f"{stats['dropped']:,} duplicate-only hit records"),
        ("seen-db", stats.get("seen_db") or ""),
    ])


def run_convert(args: CliArgs) -> None:
    """Convert JSONL session file to JSON."""
    input_path = require_path(args.input_file, name="--input-file")
    output_path = require_path(args.output_file, name="--output-file")

    count = convert_jsonl_to_json(
        input_path=input_path,
        output_path=output_path,
        sort_keys=args.sort_keys,
    )
    report_block("Convert", [
        ("input", str(input_path)),
        ("output", str(output_path)),
        ("objects", f"{count:,}"),
    ])
