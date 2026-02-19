# glh/cli.py
"""
Command-line interface parsing for GitlabHarvester.

This module provides:
- Version resolution via importlib.metadata
- Branches mode parsing helpers
- A typed CliArgs container
- Argparse builder and parser
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from importlib.metadata import version, PackageNotFoundError


BranchesMode = str | int  # "default" | "all" | int

DEFAULT_INDEX_BRANCHES: BranchesMode = "default"
DEFAULT_SCAN_BRANCHES: BranchesMode = "default"
_BANNER = r"""
┏┓• ┓  ┓ ┓┏
┃┓┓╋┃┏┓┣┓┣┫┏┓┏┓┓┏┏┓┏╋┏┓┏┓
┗┛┗┗┗┗┻┗┛┛┗┗┻┛ ┗┛┗ ┛┗┗ ┛
""".rstrip()


def _get_version() -> str:
    """Return installed package version (or 'unknown' if not installed)."""
    try:
        return version("gitlab-harvester")
    except PackageNotFoundError:
        return "unknown"


def get_banner() -> str:
    """Return the CLI banner with version suffix."""
    return f"{_BANNER} v{_get_version()}"


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


@dataclass(frozen=True, slots=True)
class CliArgs:
    """Typed container for parsed CLI arguments."""

    url: str | None
    token: str | None
    proxy: str | None
    timeout: int

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
    search: str | None
    terms_file: str | None
    session: str | None
    session_file: str | None
    resume: bool

    input_file: str | None
    output_file: str | None

    sqlite_path: str | None
    hash_algo: str
    normalize_hits: bool

    sort_keys: bool


class CliParser:
    """Argparse wrapper for building and parsing GitlabHarvester CLI."""

    @staticmethod
    def build() -> argparse.ArgumentParser:
        """Build and return the configured ArgumentParser."""
        parser = argparse.ArgumentParser(
            prog="gitlab-harvester",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=f"{get_banner()}\nSearch GitLab instances for sensitive data, secrets, and patterns "
                        f"across projects and branches using a local project index.",
        )

        # Core connectivity
        # NOTE: -H/--host is kept for backward compatibility and maps to --url.
        parser.add_argument(
            "-u", "--url", "-H", "--host",
            dest="url",
            default=None,
            help="GitLab base URL (e.g., https://gitlab.example.com). Alias: -H/--host (deprecated).",
        )
        parser.add_argument("-t", "--token", default=None, help="GitLab token (required for search/dump-index).",)
        parser.add_argument("-p", "--proxy", default=None, help="HTTP(S) proxy URL for GitLab API traffic.",)
        parser.add_argument("--timeout", default=60, type=int, help="Timeout in seconds for GitLab API request.",)

        # Logging
        parser.add_argument("--log-file", default=None, help="Write logs to a file (in addition to stderr).")
        parser.add_argument("--log-level", choices=("ERROR", "WARN", "INFO"), default="WARN", help="Console log level.")
        parser.add_argument("--debug", action="store_true", help="Enable debug logging (overrides --log-level).")

        # Mode
        parser.add_argument(
            "-m",
            "--mode",
            choices=("search", "dump-index", "dedup", "convert"),
            default="search",
            help="Execution mode.",
        )

        # Index
        parser.add_argument("-bs", "--batch-size", type=int, default=100, help="API pagination batch size.")
        parser.add_argument("--index-file", default=None, help="Path to the Instance Project Index file (JSONL).")
        parser.add_argument("--dump-projects", action="store_true", help="Force rebuilding the project index.")

        # Branches
        parser.add_argument(
            "-b",
            "--branches",
            dest="branches",
            type=parse_branches,
            default=None,
            help="Convenience: set both --index-branches and --scan-branches.",
        )
        parser.add_argument("--index-branches", type=parse_branches, default=None, help="Branches mode for index build.")
        parser.add_argument("--scan-branches", type=parse_branches, default=None, help="Branches mode for scanning.")
        parser.add_argument("--branches-per-page", type=int, default=100, help="Branches API pagination size.")

        # Forks
        parser.add_argument(
            "--forks",
            choices=("skip", "include", "branch-diff", "all-branches"),
            default="include",
            help="Fork handling strategy.",
        )
        parser.add_argument("--fork-diff-bases", default="main,master,develop,dev", help="Comma-separated base branches.")

        # Search
        group = parser.add_mutually_exclusive_group()
        group.add_argument("-s", "--search", default=None, help="Single search term.")
        group.add_argument("-f", "--terms-file", default=None, help="Path to file with one term per line.")

        sess = parser.add_mutually_exclusive_group()
        sess.add_argument("--session", default=None, help="Session name (creates results/<name>.jsonl).")
        sess.add_argument("--session-file", default=None, help="Explicit session file path (JSONL).")

        parser.add_argument("--resume", action="store_true", help="Resume from existing session file.")

        # Postprocess
        parser.add_argument("--input-file", default=None, help="Input file for postprocess modes.")
        parser.add_argument("--output-file", default=None, help="Output file for postprocess modes.")

        # Dedup
        parser.add_argument("--sqlite-path", default=None, help="Optional sqlite cache path for dedup.")
        parser.add_argument(
            "--hash-algo",
            choices=("blake2b", "sha1", "sha256"),
            default="blake2b",
            help="Hash algorithm for deduplication.",
        )
        parser.add_argument("--no-normalize-hits", action="store_true", help="Disable hit normalization.")

        # Convert
        parser.add_argument("--sort-keys", action="store_true", help="Sort JSON keys in convert mode output.")

        parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {_get_version()}")

        return parser

    @classmethod
    def parse(cls, argv: list[str] | None = None) -> CliArgs:
        """Parse argv into CliArgs."""
        ns = cls.build().parse_args(argv)

        if ns.debug:
            ns.log_level = "DEBUG"

        if ns.index_branches is None and ns.branches is not None:
            ns.index_branches = ns.branches
        if ns.scan_branches is None and ns.branches is not None:
            ns.scan_branches = ns.branches

        if ns.index_branches is None:
            ns.index_branches = DEFAULT_INDEX_BRANCHES
        if ns.scan_branches is None:
            ns.scan_branches = DEFAULT_SCAN_BRANCHES

        return CliArgs(
            url=ns.url,
            token=ns.token,
            proxy=ns.proxy,
            timeout=ns.timeout,
            log_file=ns.log_file,
            log_level=ns.log_level,
            debug=ns.debug,
            mode=ns.mode,
            batch_size=ns.batch_size,
            dump_projects=ns.dump_projects,
            index_file=ns.index_file,
            index_branches=ns.index_branches,
            branches_per_page=ns.branches_per_page,
            scan_branches=ns.scan_branches,
            forks=ns.forks,
            fork_diff_bases=ns.fork_diff_bases,
            search=ns.search,
            terms_file=ns.terms_file,
            session=ns.session,
            session_file=ns.session_file,
            resume=ns.resume,
            input_file=ns.input_file,
            output_file=ns.output_file,
            sqlite_path=ns.sqlite_path,
            hash_algo=ns.hash_algo,
            normalize_hits=not ns.no_normalize_hits,
            sort_keys=ns.sort_keys,
        )
