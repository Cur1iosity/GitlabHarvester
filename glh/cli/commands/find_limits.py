# glh/cli/commands/find_limits.py
"""
-m find-limits: measure the API rate limits (experimental).
"""

from __future__ import annotations

import sys
import time

from glh.cli.args import CliArgs
from glh.cli.commands.auto_limits import measure
from glh.cli.commands.common import connect_harvester
from glh.cli.report import report_block
from glh.limits.constants import KINDS
from glh.ui.formatting import format_duration


def run_find_limits(args: CliArgs) -> None:
    """Measure the rate limits (-m find-limits) and print the settings to use; no search."""
    glh = connect_harvester(args)
    kinds = args.probe_apis or KINDS
    _, results, recommendation = measure(args, glh, kinds)
    reset = max((r.finished_at + r.cooldown - time.monotonic() for r in results.values() if r.limited),
                default=0.0)
    report_block("Next run", [
        ("command", recommendation.command(sys.argv[1:])),
        ("config file", recommendation.ini().split("\n")),
        ("budget back", f"in about {format_duration(reset)} (the probe used it up)" if reset > 0 else ""),
    ])
