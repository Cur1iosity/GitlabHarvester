# glh/cli/commands/dump_index.py
"""
-m dump-index: (re)build the project index.
"""

from __future__ import annotations

from glh.cli.args import CliArgs
from glh.cli.commands.auto_limits import start_auto_limits, stop_auto_limits
from glh.cli.commands.common import building_index
from glh.cli.factory import create_harvester
from glh.cli.report import rate_limit_row, Summary
from glh.limits.constants import INDEX


def run_dump_index(args: CliArgs) -> None:
    """Rebuild the Instance Project Index and write to disk."""
    glh = create_harvester(args)
    console = start_auto_limits(args, glh, (INDEX,)) if args.auto_limits else None
    try:
        with building_index(args, glh, mode="dump-index"):
            index_file = glh.build_project_index(
                per_page=args.batch_size,
                filename=args.index_file,
                enforce_dump=True,
                branches=args.index_branches,
                branches_per_page=args.branches_per_page,
                last_activity_after=args.index_active_after,
                last_activity_before=args.index_active_before,
            )
        summary = Summary()
        summary.add("index", str(index_file))
        rate_limit_row(glh, summary)
    finally:
        limiter = stop_auto_limits(console)
    summary.rows += limiter
    summary.report()
