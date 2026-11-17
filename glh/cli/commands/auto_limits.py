# glh/cli/commands/auto_limits.py
"""
--auto-limits around a run (experimental): measure, offer the settings, watch the run.
"""

from __future__ import annotations

import sys

from glh.cli.args import CliArgs
from glh.cli.commands.common import index_path
from glh.cli.report import report_block
from glh.engine.harvester import GitlabHarvester
from glh.limits.advisor import LimitAdvisor
from glh.limits.console import LimiterConsole
from glh.limits.constants import API_NAMES, EXPERIMENTAL_NOTE, SEARCH
from glh.limits.finder import LimitFinder
from glh.limits.probe import ProbeResult
from glh.limits.recommend import Recommendation, Settings
from glh.ui import statusline
from glh.ui.blocks import Row


def current_settings(args: CliArgs) -> Settings:
    return Settings(workers=args.workers, index_rpm=args.index_rpm, search_rpm=args.search_rpm)


def measure(args: CliArgs, glh: GitlabHarvester, kinds: tuple[str, ...]
             ) -> tuple[LimitFinder, dict[str, ProbeResult], Recommendation]:
    """Probe ``kinds``, print what was found and the recommended settings."""
    statusline.STATUS.write_line(EXPERIMENTAL_NOTE)
    finder = LimitFinder(glh, max_requests=args.probe_max, margin=args.probe_margin)
    project = finder.project_for_search(index_path(args, glh)) if SEARCH in kinds else None
    statusline.STATUS.write_line(
        f"Measuring rate limits of {', '.join(API_NAMES[k] for k in kinds)} "
        f"(up to {args.probe_max:,} requests each; this provokes HTTP 429 on purpose)")
    results = finder.find(kinds, project_id=project)
    recommendation = finder.recommend(results, current=current_settings(args), explicit=args.explicit_limits)

    rows: list[Row] = [(results[kind].api, results[kind].lines()) for kind in kinds]
    if note := finder.token_note():
        rows.append(("tokens", note.removeprefix("Tokens: ")))
    report_block(f"Rate limits at {args.url} (token #1)", rows)

    def rpm(value: int) -> str:
        return f"{value} per worker" if value else "0 (no limit)"

    kept = set(recommendation.kept)
    report_block("Suggested settings", [
        ("workers", f"{recommendation.workers}" + (" (kept as set)" if "workers" in kept else "")),
        ("index-rpm", rpm(recommendation.index_rpm) + (" (kept as set)" if "index-rpm" in kept else "")),
        ("search-rpm", rpm(recommendation.search_rpm) + (" (kept as set)" if "search-rpm" in kept else "")),
        ("notes", list(recommendation.notes)),
    ])
    return finder, results, recommendation


def confirm(question: str) -> bool:
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


def start_auto_limits(args: CliArgs, glh: GitlabHarvester, kinds: tuple[str, ...]) -> LimiterConsole:
    """
    --auto-limits before a run: measure ``kinds`` (unless every option they
    need was set explicitly), offer the settings, wait for the probed windows to
    reset, then watch the run for HTTP 429 (returned console; stop it after the run).
    """
    kinds = tuple(k for k in kinds if k in (args.probe_apis or kinds))
    needed = {"workers", *(f"{k}_rpm" for k in kinds)}
    if not kinds or needed <= args.explicit_limits:
        statusline.STATUS.write_line(EXPERIMENTAL_NOTE)
        statusline.STATUS.write_line(
            "Auto limits: --workers and the rpm options are set, nothing to measure; "
            "watching the run for HTTP 429.")
    else:
        finder, results, recommendation = measure(args, glh, kinds)
        current = current_settings(args)
        if recommendation.differs_from(current):
            if not (sys.stdin.isatty() and sys.stderr.isatty()):
                report_block("Next run", [("command", recommendation.command(sys.argv[1:]))])
                raise SystemExit("--auto-limits: no terminal to confirm the settings. "
                                 "Run the command above (or add the suggested options) to start.")
            if confirm(f"Apply {recommendation.describe()} to this run? [Y/n] "):
                glh.set_rate_limits(workers=recommendation.workers, index_rpm=recommendation.index_rpm,
                                    search_rpm=recommendation.search_rpm)
                statusline.STATUS.write_line(f"Auto limits: applied {recommendation.describe()}")
            else:
                statusline.STATUS.write_line(
                    f"Auto limits: kept --workers {current.workers} --index-rpm {current.index_rpm} "
                    f"--search-rpm {current.search_rpm}; next time: {' '.join(recommendation.flags())}")
        finder.wait_cooldown(results.values())
    advisor = LimitAdvisor(glh, margin=args.probe_margin).attach()
    return LimiterConsole(advisor, logger=glh.logger).start()


def stop_auto_limits(console: LimiterConsole | None) -> list[Row]:
    """End the run's limit watch; rows about what it did, for the 'Results' block."""
    if console is None:
        return []
    console.stop()
    advisor = console.advisor
    advisor.detach()
    harvester = advisor.harvester
    lines = []
    if advisor.applied:
        lines.append(f"limits changed during the run; next run: --workers {harvester.workers} "
                     f"--index-rpm {harvester.index_rpm} --search-rpm {harvester.search_rpm}")
    if (pending := advisor.pending) is not None:
        lines.append(f"proposal not applied: {pending.flags()} ({pending.describe()})")
    return [("limiter", lines)] if lines else []
