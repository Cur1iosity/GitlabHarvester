from __future__ import annotations

import argparse
from dataclasses import dataclass

BranchesMode = str | int  # "default" | "all" | int

DEFAULT_INDEX_BRANCHES: BranchesMode = "default"
DEFAULT_SCAN_BRANCHES: BranchesMode = "default"


def parse_branches(value: str) -> BranchesMode:
    v = value.strip().lower()
    if v in {"default", "all"}:
        return v
    if v.isdigit() and int(v) > 0:
        return int(v)
    raise argparse.ArgumentTypeError("Use 'default', 'all', or a positive integer (e.g., 10).")


@dataclass(frozen=True, slots=True)
class CliArgs:
    # Core connectivity
    host: str
    token: str
    proxy: str | None

    # Logging (parsed here; wiring handlers happens elsewhere)
    log_file: str | None
    log_level: str
    debug: bool

    # Mode
    mode: str  # search|dump-index|dedup|convert

    # Index build
    batch_size: int
    dump_projects: bool
    index_file: str | None
    index_branches: BranchesMode
    branches_per_page: int

    # Search scan
    scan_branches: BranchesMode
    forks: str
    fork_diff_bases: str
    search: str | None
    terms_file: str | None
    session: str | None
    session_file: str | None
    resume: bool

    # Postprocess
    input_file: str | None
    output_file: str | None

    # Dedup options
    sqlite_path: str | None
    hash_algo: str
    normalize_hits: bool

    # Convert options
    sort_keys: bool


class CliParser:
    @staticmethod
    def build() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="gitlab-harvester",
            description="Collect and use an Instance Project Index from a GitLab instance.",
        )

        # Core connectivity
        parser.add_argument("-H", "--host", required=True, help="GitLab host (e.g., gitlab.example.com).")
        parser.add_argument("-t", "--token", required=True, help="GitLab token with read_api permissions.")
        parser.add_argument(
            "-p",
            "--proxy",
            default=None,
            help=(
                "HTTP(S) proxy URL for GitLab API traffic (e.g., http://127.0.0.1:8080). "
                "Useful for Burp/ZAP or corporate proxies."
            ),
        )

        # Logging
        parser.add_argument("--log-file", default=None, help="Optional path to log file.")
        parser.add_argument(
            "--log-level",
            choices=("ERROR", "WARN", "INFO"),
            default="WARN",
            help="Base logging level (default: WARN).",
        )
        parser.add_argument("--debug", action="store_true", help="Enable debug logging (overrides --log-level).")

        # Mode
        parser.add_argument(
            "-m",
            "--mode",
            choices=("search", "dump-index", "dedup", "convert"),
            default="search",
            help="Operation mode (default: search).",
        )

        # Index build options
        parser.add_argument(
            "-bs",
            "--batch-size",
            type=int,
            default=100,
            help="Projects per page for GitLab API requests (default: 100).",
        )
        parser.add_argument("--index-file", default=None, help="Path to Instance Project Index file (JSONL/NDJSON).")
        parser.add_argument(
            "--dump-projects",
            action="store_true",
            help="Rebuild the Instance Project Index even if it already exists (used in search mode).",
        )

        # Unified shorthand alias (applies to both index + scan if used alone)
        parser.add_argument(
            "-b",
            "--branches",
            dest="branches",
            type=parse_branches,
            default=None,
            help="Shorthand for setting both --index-branches and --scan-branches.",
        )

        parser.add_argument(
            "--index-branches",
            dest="index_branches",
            type=parse_branches,
            default=None,
            help="Branch depth for building the Project Index: 'default', 'all', or N.",
        )

        parser.add_argument(
            "--scan-branches",
            dest="scan_branches",
            type=parse_branches,
            default=None,
            help="Branch scope for scanning: omit/default, 'all', or N.",
        )

        parser.add_argument(
            "--branches-per-page",
            type=int,
            default=100,
            help="Branches per page for GitLab API requests (default: 100).",
        )

        # Fork strategy (search)
        parser.add_argument(
            "--forks",
            choices=("skip", "include", "branch-diff", "all-branches"),
            default="include",
            help="How to handle forked projects during search.",
        )
        parser.add_argument(
            "--fork-diff-bases",
            default="main,master,develop,dev",
            help="Comma-separated list of base branches for --forks=branch-diff.",
        )

        # Search terms
        group = parser.add_mutually_exclusive_group()
        group.add_argument("-s", "--search", default=None, help="Single search term.")
        group.add_argument("-f", "--terms-file", default=None, help="File with search terms (one per line).")

        sess = parser.add_mutually_exclusive_group()
        sess.add_argument("--session", default=None, help="Session name for results output (writes .jsonl).")
        sess.add_argument("--session-file", default=None, help="Explicit path for session results file (JSONL).")

        parser.add_argument("--resume", action="store_true", help="Resume search using existing session file.")

        # Postprocess IO (dedup/convert)
        parser.add_argument("--input-file", default=None, help="Input file for postprocess modes (dedup/convert).")
        parser.add_argument("--output-file", default=None, help="Output file for postprocess modes (dedup/convert).")

        # Dedup options
        parser.add_argument(
            "--sqlite-path",
            default=None,
            help="Optional path to sqlite seen-db for dedup mode (defaults to <output>.seen.sqlite).",
        )
        parser.add_argument(
            "--hash-algo",
            choices=("blake2b", "sha1", "sha256"),
            default="blake2b",
            help="Hash algorithm for dedup keys (default: blake2b).",
        )
        parser.add_argument(
            "--no-normalize-hits",
            action="store_true",
            help="Disable hit text normalization (whitespace collapse/strip) in dedup mode.",
        )

        # Convert options
        parser.add_argument("--sort-keys", action="store_true", help="Sort keys in JSON output for convert mode.")

        return parser

    @classmethod
    def parse(cls, argv: list[str] | None = None) -> CliArgs:
        ns = cls.build().parse_args(argv)

        # logging override
        if ns.debug:
            ns.log_level = "DEBUG"

        # shorthand branches
        if ns.index_branches is None and ns.branches is not None:
            ns.index_branches = ns.branches
        if ns.scan_branches is None and ns.branches is not None:
            ns.scan_branches = ns.branches

        # defaults
        if ns.index_branches is None:
            ns.index_branches = DEFAULT_INDEX_BRANCHES
        if ns.scan_branches is None:
            ns.scan_branches = DEFAULT_SCAN_BRANCHES

        return CliArgs(
            host=ns.host,
            token=ns.token,
            proxy=ns.proxy,
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
