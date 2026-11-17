# glh/cli/args.py
"""
CliArgs: the parsed and resolved command-line options of a run.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

BranchesMode = str | int  # "default" | "all" | int

DEFAULT_INDEX_BRANCHES: BranchesMode = "default"

DEFAULT_SCAN_BRANCHES: BranchesMode = "default"

DEFAULT_DOWNLOAD_MAX_SIZE = 10 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class CliArgs:
    """Typed container for parsed CLI arguments."""

    config: str | None
    url: str | None
    token: str | None
    token_file: str | None
    proxy: str | None
    timeout: int
    insecure: bool
    ca_bundle: str | None
    workers: int
    index_rpm: int
    search_rpm: int
    jitter: tuple[float, float]
    user_agent: str | None
    user_agent_file: str | None

    auto_limits: bool
    probe_apis: tuple[str, ...]
    probe_max: int
    probe_margin: float
    # Which of workers, index_rpm, search_rpm were set on the command line or in
    # the config file (--auto-limits keeps them).
    explicit_limits: frozenset[str]

    log_file: str | None
    log_level: str
    debug: bool

    mode: str

    batch_size: int
    dump_projects: bool
    index_file: str | None
    index_branches: BranchesMode
    branches_per_page: int

    scan_branches: BranchesMode
    forks: str
    fork_diff_bases: str
    started_from: datetime | None
    active_before: datetime | None
    index_active_after: datetime | None
    index_active_before: datetime | None
    file_changed_after: datetime | None
    file_changed_before: datetime | None
    search: str | None
    terms_file: str | None
    terms: tuple[str, ...]
    filename: str | None
    extension: str | None
    project_filter: tuple[str, ...]
    file_listing: str
    session: str | None
    session_file: str | None
    resume: bool
    output_separated: bool
    download_files: bool
    download_max_size: int

    input_file: str | None
    output_file: str | None
    post_process: tuple[str, ...]
    final_only: bool
    to_zip: bool

    sqlite_path: str | None
    hash_algo: str
    normalize_hits: bool

    sort_keys: bool
