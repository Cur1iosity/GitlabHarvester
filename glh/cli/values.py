# glh/cli/values.py
"""
Converters of command-line values (argparse ``type=`` functions); the config file uses them too.
"""

from __future__ import annotations

import argparse
from datetime import datetime

from glh.cli.args import BranchesMode
from glh.domain import file_filter, project_filter
from glh.domain.timewindow import parse_timestamp
from glh.engine.workers import MAX_WORKERS
from glh.gitlab import throttling, user_agents
from glh.limits.constants import KINDS, MAX_REQUESTS_LIMIT
from glh.output import downloads
from glh.postprocess.pipeline import normalize_steps


def parse_branches(value: str) -> BranchesMode:
    """Parse branches mode argument.

    Allowed values:
      - 'default'
      - 'all'
      - positive integer (e.g. '10')

    Args:
        value: Raw CLI value.

    Returns:
        Parsed branches mode.

    Raises:
        argparse.ArgumentTypeError: If value is invalid.
    """
    v = value.strip().lower()
    if v in {"default", "all"}:
        return v
    if v.isdigit() and int(v) > 0:
        return int(v)
    raise argparse.ArgumentTypeError("Use 'default', 'all', or a positive integer (e.g., 10).")


def parse_post_process(value: str) -> tuple[str, ...]:
    """Parse --post-process: comma-separated steps (dedup, convert), returned in run order."""
    try:
        return normalize_steps(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"{e}. Use dedup, convert or dedup,convert.") from None


def parse_workers(value: str) -> int:
    """Parse --workers: an integer from 1 to MAX_WORKERS."""
    v = value.strip()
    if v.isdigit() and 1 <= int(v) <= MAX_WORKERS:
        return int(v)
    raise argparse.ArgumentTypeError(f"Use an integer from 1 to {MAX_WORKERS}.")


def parse_rpm(value: str) -> int:
    """Parse --rpm/--index-rpm/--search-rpm: a non-negative integer (0 = no limit)."""
    v = value.strip()
    if v.isdigit():
        return int(v)
    raise argparse.ArgumentTypeError("Use a non-negative integer (requests per minute, 0 = no limit).")


def parse_probe_apis(value: str) -> tuple[str, ...]:
    """Parse --probe-apis: comma-separated index, search (in probe order: index first)."""
    names = {x.strip().lower() for x in value.split(",") if x.strip()}
    if not names or names - set(KINDS):
        raise argparse.ArgumentTypeError("Use index, search or index,search.")
    return tuple(k for k in KINDS if k in names)


def parse_probe_max(value: str) -> int:
    """Parse --probe-max: requests per probed API, 1..MAX_REQUESTS_LIMIT."""
    v = value.strip()
    if v.isdigit() and 1 <= int(v) <= MAX_REQUESTS_LIMIT:
        return int(v)
    raise argparse.ArgumentTypeError(f"Use an integer from 1 to {MAX_REQUESTS_LIMIT}.")


def parse_probe_margin(value: str) -> float:
    """Parse --probe-margin: share of the found limit to use, 0.1..1 (or 10%..100%)."""
    v = value.strip()
    try:
        margin = float(v[:-1]) / 100 if v.endswith("%") else float(v)
    except ValueError:
        margin = -1.0
    if 0.1 <= margin <= 1.0:
        return margin
    raise argparse.ArgumentTypeError("Use a number from 0.1 to 1 (or 10% to 100%), e.g. 0.85.")


def parse_jitter(value: str) -> tuple[float, float]:
    """Parse --jitter: MAX or MIN-MAX seconds, optionally with ms/s (0.03, 0.01-0.05, 10ms-50ms)."""
    try:
        return throttling.parse_jitter(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(
            f"{e}. Use MAX or MIN-MAX in seconds, e.g. 0.03, 0.01-0.05 or 10ms-50ms (0 = off).") from None


def parse_user_agent(value: str) -> str:
    """Parse -A/--user-agent: a User-Agent that can be sent as an HTTP header."""
    try:
        return user_agents.check_user_agent(value)
    except user_agents.UserAgentError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def parse_filename(value: str) -> str:
    """Parse --filename: a file name or a mask with '*' (no spaces)."""
    try:
        return file_filter.normalize_filename(value)
    except file_filter.FileFilterError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def parse_extension(value: str) -> str:
    """Parse --extension: 'py', '.py' and '*.py' all mean 'py'."""
    try:
        return file_filter.normalize_extension(value)
    except file_filter.FileFilterError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def parse_project_filter(value: str) -> tuple[str, ...]:
    """Parse --project-filter: comma-separated project path patterns (k8s, infra/*)."""
    try:
        return project_filter.parse_patterns(value)
    except project_filter.ProjectFilterError as e:
        raise argparse.ArgumentTypeError(f"{e}. Use e.g. k8s, infra/* or k8s,*-deploy.") from None


def parse_size(value: str) -> int:
    """Parse --download-max-size: bytes or with k/M/G (500k, 10M, 1G); 0 = no limit."""
    try:
        return downloads.parse_size(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "Use bytes or a size with k, M or G, e.g. 500k, 10M or 1G (0 = no limit).") from None


def parse_started_from(value: str) -> datetime:
    """Parse a time filter value (e.g. --started-from) into a timezone-aware datetime.

    Allowed values:
      - date: '2024-06-01' (midnight UTC)
      - date and time: '2024-06-01T12:30', '2024-06-01 12:30:00'
      - with offset: '2024-06-01T12:30:00+03:00', '2024-06-01T09:30:00Z'

    Raises:
        argparse.ArgumentTypeError: If value is not an ISO 8601 date/datetime.
    """
    dt = parse_timestamp(value)
    if dt is None:
        raise argparse.ArgumentTypeError(
            "Use an ISO 8601 date or datetime, e.g. 2024-06-01 or 2024-06-01T12:00:00+00:00."
        )
    return dt
