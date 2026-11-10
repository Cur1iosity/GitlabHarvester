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
import sys
from dataclasses import dataclass
from datetime import datetime
from importlib.metadata import version, PackageNotFoundError

from glh.config import TERMS_DEST, ConfigError, load_config
from glh.planner import parse_timestamp
from glh.postprocess.pipeline import normalize_steps


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


def _can_encode(text: str, stream: object) -> bool:
    """True if ``stream``'s encoding can represent ``text`` (no encoding attribute = assume UTF-8)."""
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        text.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def get_banner(stream: object | None = None) -> str:
    """
    Return the CLI banner with version suffix.

    The box-drawing banner needs a Unicode-capable stream. If ``stream`` uses
    an encoding without those characters (e.g. cp1252 or cp866 in a redirected
    Windows console), a plain-text banner is returned instead.
    """
    if stream is not None and not _can_encode(_BANNER, stream):
        return f"GitlabHarvester v{_get_version()}"
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


MAX_WORKERS = 64


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


# (specific dest, group dest) for every time bound; see CliParser.parse().
TIME_BOUNDS: tuple[tuple[str, str], ...] = (
    ("index_active_after", "time_after"),
    ("index_active_before", "time_before"),
    ("started_from", "time_after"),
    ("active_before", "time_before"),
    ("file_changed_after", "time_after"),
    ("file_changed_before", "time_before"),
)
TIME_WINDOWS: tuple[tuple[str, str, str], ...] = (
    ("index_active_after", "index_active_before", "--index-active-after/--index-active-before"),
    ("started_from", "active_before", "--active-after/--active-before"),
    ("file_changed_after", "file_changed_before", "--file-changed-after/--file-changed-before"),
)


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


@dataclass(frozen=True, slots=True)
class CliArgs:
    """Typed container for parsed CLI arguments."""

    config: str | None
    url: str | None
    token: str | None
    proxy: str | None
    timeout: int
    insecure: bool
    ca_bundle: str | None
    workers: int

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
    session: str | None
    session_file: str | None
    resume: bool

    input_file: str | None
    output_file: str | None
    post_process: tuple[str, ...]
    final_only: bool

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
            # Help goes to stdout: the banner must be encodable there.
            description=f"{get_banner(sys.stdout)}\nSearch GitLab instances for sensitive data, secrets, and patterns "
                        f"across projects and branches using a local project index.",
        )

        parser.add_argument(
            "-c", "--config",
            default=None,
            metavar="FILE",
            help="INI config file with any of these options (see config.example.ini). "
                 "Command-line arguments override values from the file.",
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
        parser.add_argument(
            "--ca-bundle",
            default=None,
            metavar="FILE",
            help="CA bundle (PEM) to verify the GitLab TLS certificate, e.g. for a private CA.",
        )
        parser.add_argument(
            "--insecure",
            action=argparse.BooleanOptionalAction,
            default=False,
            help="Disable TLS certificate verification (not recommended: the token is sent to an "
                 "unverified server). Verification is never disabled automatically.",
        )
        parser.add_argument(
            "-w", "--workers",
            type=parse_workers,
            default=1,
            metavar="N",
            help=f"Parallel API requests (1-{MAX_WORKERS}, default 1 = sequential). Speeds up project listing, "
                 "branch listing and search; use more than 1 only if the instance has no API rate limits.",
        )

        # Logging
        parser.add_argument("--log-file", default=None, help="Write logs to a file (in addition to stderr).")
        parser.add_argument("--log-level", choices=("ERROR", "WARN", "INFO"), default="WARN", help="Console log level.")
        parser.add_argument("--debug", action=argparse.BooleanOptionalAction, default=False,
                            help="Enable debug logging (overrides --log-level).")

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
        parser.add_argument("--dump-projects", action=argparse.BooleanOptionalAction, default=False,
                            help="Force rebuilding the project index.")

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

        # Time filters
        tf = parser.add_argument_group(
            "time filters",
            "DATE is ISO 8601: 2024-06-01, 2024-06-01T12:00, 2024-06-01T12:00:00+03:00 (no offset = UTC). "
            "A specific option overrides --time-after/--time-before.",
        )

        def time_option(*flags: str, dest: str | None = None, help_text: str) -> None:
            kwargs: dict[str, object] = {"type": parse_started_from, "default": None, "metavar": "DATE", "help": help_text}
            if dest:
                kwargs["dest"] = dest
            tf.add_argument(*flags, **kwargs)

        time_option("--time-after", help_text="Shortcut for --index-active-after, --active-after and --file-changed-after.")
        time_option("--time-before", help_text="Shortcut for --index-active-before, --active-before and --file-changed-before.")
        time_option("--index-active-after",
                    help_text="Index only projects with activity after DATE (GitLab API filter: fewer pages to list).")
        time_option("--index-active-before", help_text="Index only projects with activity before DATE (GitLab API filter).")
        time_option("--active-after", "--started-from", dest="started_from",
                    help_text="Search only indexed projects with activity (last_activity_at) on or after DATE; "
                              "others are skipped without API calls. Secrets committed earlier but still present "
                              "in skipped projects are not reported.")
        time_option("--active-before", help_text="Search only indexed projects with activity on or before DATE.")
        time_option("--file-changed-after",
                    help_text="Keep only hits in files changed (by a commit in that branch) on or after DATE. "
                              "Costs one commits API request per file with hits.")
        time_option("--file-changed-before", help_text="Keep only hits in files changed on or before DATE.")

        # Search
        group = parser.add_mutually_exclusive_group()
        group.add_argument("-s", "--search", default=None, help="Single search term.")
        group.add_argument("-f", "--terms-file", default=None, help="Path to file with one term per line.")

        sess = parser.add_mutually_exclusive_group()
        sess.add_argument("--session", default=None, help="Session name (creates <name>.jsonl in the current directory).")
        sess.add_argument("--session-file", default=None, help="Explicit session file path (JSONL).")

        parser.add_argument("--resume", action=argparse.BooleanOptionalAction, default=False,
                            help="Resume from existing session file.")

        # Postprocess
        parser.add_argument(
            "--post-process",
            type=parse_post_process,
            default=(),
            metavar="STEPS",
            help="After a finished search, run these steps on the session file: dedup, convert or "
                 "dedup,convert (always in this order). Writes <session>.deduped.jsonl and "
                 "<session>[.deduped].converted.json; the dedup/convert options below apply.",
        )
        parser.add_argument(
            "--final-only",
            action=argparse.BooleanOptionalAction,
            default=False,
            help="With --post-process: keep only the last file and delete the session JSONL and "
                 "intermediate files (saves space; the session can't be resumed afterwards).",
        )
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
        parser.add_argument("--normalize-hits", action=argparse.BooleanOptionalAction, default=True,
                            help="Normalize whitespace before comparing hits in dedup.")

        # Convert
        parser.add_argument("--sort-keys", action=argparse.BooleanOptionalAction, default=False,
                            help="Sort JSON keys in convert mode output.")

        parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {_get_version()}")

        return parser

    @classmethod
    def _given_dests(cls, argv: list[str] | None) -> set[str]:
        """Return the argparse dests that were set explicitly on the command line."""
        probe = cls.build()
        for action in probe._actions:  # noqa: SLF001 - argparse exposes no public accessor
            action.default = argparse.SUPPRESS
        return set(vars(probe.parse_args(argv)))

    @staticmethod
    def _resolve_time_bounds(ns: argparse.Namespace, given: set[str], config: dict) -> None:
        """
        Resolve every time bound in place and drop time keys from ``config``.

        Order: specific option on the CLI > --time-after/--time-before on the CLI >
        specific key in the config file > time-after/time-before in the config file.
        """
        resolved: dict[str, object] = {}
        for specific, group in TIME_BOUNDS:
            if specific in given:
                resolved[specific] = getattr(ns, specific)
            elif group in given:
                resolved[specific] = getattr(ns, group)
            elif specific in config:
                resolved[specific] = config[specific]
            elif group in config:
                resolved[specific] = config[group]
            else:
                resolved[specific] = None
        for dest in {d for pair in TIME_BOUNDS for d in pair}:
            config.pop(dest, None)
        for dest, value in resolved.items():
            setattr(ns, dest, value)

    @classmethod
    def parse(cls, argv: list[str] | None = None) -> CliArgs:
        """
        Parse argv into CliArgs.

        Precedence: command-line argument > config file (-c/--config) > built-in default.
        A search source (-s/-f) or session option given on the command line replaces
        the alternatives from the config file, and -b on the command line overrides
        index-branches/scan-branches from the config file.
        """
        parser = cls.build()
        ns = parser.parse_args(argv)
        ns.terms = ()

        if ns.config:
            try:
                config = load_config(ns.config, parser)
            except ConfigError as e:
                parser.error(str(e))
            given = cls._given_dests(argv)

            exclusive = (("search", "terms_file", TERMS_DEST), ("session", "session_file"))
            for group in exclusive:
                if given & set(group):
                    for dest in group:
                        config.pop(dest, None)

            # -b on the command line beats branch modes from the file.
            if "branches" in given:
                for dest in ("index_branches", "scan_branches"):
                    if dest not in given:
                        config.pop(dest, None)

            cls._resolve_time_bounds(ns, given, config)

            for dest, value in config.items():
                if dest not in given:
                    setattr(ns, dest, value)
        else:
            cls._resolve_time_bounds(ns, {d for d, _ in TIME_BOUNDS + (("time_after", ""), ("time_before", ""))
                                          if getattr(ns, d) is not None}, {})

        if ns.insecure and ns.ca_bundle:
            parser.error("--insecure and --ca-bundle exclude each other.")

        for after, before, names in TIME_WINDOWS:
            low, high = getattr(ns, after), getattr(ns, before)
            if low is not None and high is not None and low > high:
                parser.error(f"{names}: the start ({low.isoformat()}) is later than the end ({high.isoformat()}).")

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
            config=ns.config,
            url=ns.url,
            token=ns.token,
            proxy=ns.proxy,
            timeout=ns.timeout,
            insecure=ns.insecure,
            ca_bundle=ns.ca_bundle,
            workers=ns.workers,
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
            started_from=ns.started_from,
            active_before=ns.active_before,
            index_active_after=ns.index_active_after,
            index_active_before=ns.index_active_before,
            file_changed_after=ns.file_changed_after,
            file_changed_before=ns.file_changed_before,
            search=ns.search,
            terms_file=ns.terms_file,
            terms=tuple(ns.terms),
            session=ns.session,
            session_file=ns.session_file,
            resume=ns.resume,
            input_file=ns.input_file,
            output_file=ns.output_file,
            post_process=tuple(ns.post_process),
            final_only=ns.final_only,
            sqlite_path=ns.sqlite_path,
            hash_algo=ns.hash_algo,
            normalize_hits=ns.normalize_hits,
            sort_keys=ns.sort_keys,
        )
