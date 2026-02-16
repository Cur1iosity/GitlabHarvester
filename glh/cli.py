from __future__ import annotations

import argparse
from dataclasses import dataclass

BranchesMode = str | int  # "default" | "all" | int

DEFAULT_INDEX_BRANCHES: BranchesMode = "default"
DEFAULT_SCAN_BRANCHES: BranchesMode = "default"


def parse_branches(value: str) -> BranchesMode:
    """
    Parse a CLI argument that specifies branch depth or mode.

    Supported values:
        - "default" — use only the default branch.
        - "all" — process all available branches.
        - positive integer — limit the number of branches to the given value.

    Args:
        value: Raw string value received from the command line.

    Returns:
        Either a string ("default" or "all") or an integer representing
        the maximum number of branches.

    Raises:
        argparse.ArgumentTypeError: If the value does not match any of the
            supported formats.
    """
    v = value.strip().lower()
    if v in {"default", "all"}:
        return v
    if v.isdigit() and int(v) > 0:
        return int(v)
    raise argparse.ArgumentTypeError(
        "Use 'default', 'all', or a positive integer (e.g., 10)."
    )


@dataclass(frozen=True, slots=True)
class CliArgs:
    host: str
    token: str
    proxy: str | None

    batch_size: int
    dump_only: bool
    dump_projects: bool

    index_file: str | None

    index_branches: BranchesMode
    scan_branches: BranchesMode
    branches_per_page: int

    forks: str
    fork_diff_bases: str

    search: str | None
    terms_file: str | None
    output: str | None

    session: str | None
    session_file: str | None
    resume: bool


class CliParser:
    """Argument parser builder for the GitLab harvester CLI."""

    @staticmethod
    def build() -> argparse.ArgumentParser:
        """
        Construct and configure the argument parser for the GitLab Harvester CLI.

        The parser defines options for:
            - GitLab connectivity (host and token).
            - Building and managing the Instance Project Index.
            - Controlling branch collection and scan depth.
            - Fork handling strategies.
            - Specifying search terms.
            - Session management and resume capability.
            - Output redirection.

        Returns:
            A fully configured ArgumentParser instance ready to parse CLI arguments.
        """

        parser = argparse.ArgumentParser(
            prog="gl-harvester",
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

        # Index build options
        parser.add_argument(
            "-bs",
            "--batch-size",
            type=int,
            default=100,
            help="Projects per page for GitLab API requests (default: 100).",
        )

        parser.add_argument(
            "--index-file",
            default=None,
            help="Path to Instance Project Index file (JSONL/NDJSON). Defaults to instance-specific name.",
        )

        parser.add_argument(
            "--dump-projects",
            action="store_true",
            help="Rebuild the Instance Project Index even if it already exists.",
        )

        parser.add_argument(
            "--dump-only",
            action="store_true",
            help="Only build the Instance Project Index and exit.",
        )

        # Unified shorthand alias (applies to both index + scan if used alone)
        parser.add_argument(
            "-b", "--branches",
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
            help=(
                "Branch depth for building the Project Index: "
                "'default' (store only default branch), 'all' (store all), or N limit."
            ),
        )

        parser.add_argument(
            "--scan-branches",
            dest="scan_branches",
            type=parse_branches,
            default=None,
            help=(
                "Branch scope for scanning: "
                "omit -> scan default only; "
                "'all' -> scan all branches from index; "
                "N -> scan up to N branches (default + N-1)."
            ),
        )

        parser.add_argument(
            "--branches-per-page",
            type=int,
            default=100,
            help="Branches per page for GitLab API requests (default: 100).",
        )

        # ---- Fork handling strategy ----
        parser.add_argument(
            "--forks",
            choices=("skip", "include", "branch-diff", "all-branches"),
            default="include",
            help=(
                "How to handle forked projects during search: "
                "skip (ignore forks), "
                "include (treat as regular projects), "
                "branch-diff (scan only base + unique branches vs upstream), "
                "all-branches (scan every branch of forks)."
            ),
        )

        parser.add_argument(
            "--fork-diff-bases",
            default="main,master,develop,dev",
            help=(
                "Comma-separated list of branch names always scanned in forks "
                "when --forks=branch-diff (default: main,master,develop,dev)."
            ),
        )

        # Work mode: search terms
        group = parser.add_mutually_exclusive_group()
        group.add_argument("-s", "--search", default=None, help="Single search term.")
        group.add_argument("-f", "--terms-file", default=None, help="File with search terms (one per line).")

        sess = parser.add_mutually_exclusive_group()
        sess.add_argument(
            "--session",
            default=None,
            help="Session name for results output (writes <name>.jsonl).",
        )
        sess.add_argument(
            "--session-file",
            default=None,
            help="Explicit path for session results file (JSONL).",
        )

        # Output
        parser.add_argument("-o", "--output", default=None, help="Output file for results (optional).")
        parser.add_argument(
            "--resume",
            action="store_true",
            help="Resume search using an existing session file (if supported).",
        )

        return parser

    @classmethod
    def parse(cls, argv: list[str] | None = None) -> CliArgs:
        """
        Parse CLI arguments and normalize interdependent options.

        This method performs additional post-processing on raw argparse output:
            - Propagates shorthand --branches to both index and scan modes.
            - Applies default branch modes when not explicitly provided.
            - Resolves --output alias depending on execution mode:
                * In dump-only mode: --output maps to --index-file.
                * In search mode: --output maps to --session-file if no session target
                  was explicitly specified.

        Args:
            argv: Optional list of command-line arguments. If None, sys.argv is used.

        Returns:
            CliArgs dataclass instance containing validated and normalized parameters.
        """
        ns = cls.build().parse_args(argv)

        # ---- NORMALIZATION LOGIC ----

        # 1) shorthand fills gaps
        if ns.index_branches is None and ns.branches is not None:
            ns.index_branches = ns.branches

        if ns.scan_branches is None and ns.branches is not None:
            ns.scan_branches = ns.branches

        # 2) hard defaults
        if ns.index_branches is None:
            ns.index_branches = DEFAULT_INDEX_BRANCHES

        if ns.scan_branches is None:
            ns.scan_branches = DEFAULT_SCAN_BRANCHES

        # 3) output aliasing by mode
        # dump-only: --output aliases --index-file (if index_file not explicitly set)
        if ns.dump_only:
            if ns.index_file is None and ns.output is not None:
                ns.index_file = ns.output

        # search mode: --output aliases --session-file (if session not set)
        is_search_mode = bool(ns.search or ns.terms_file)
        if is_search_mode:
            if ns.session is None and ns.session_file is None and ns.output is not None:
                ns.session_file = ns.output


        # ---- CREATE FINAL CONFIG ----

        return CliArgs(
            host=ns.host,
            token=ns.token,

            proxy=ns.proxy,

            batch_size=ns.batch_size,
            dump_only=ns.dump_only,
            dump_projects=ns.dump_projects,

            index_file=ns.index_file,

            index_branches=ns.index_branches,
            scan_branches=ns.scan_branches,
            branches_per_page=ns.branches_per_page,

            forks=ns.forks,
            fork_diff_bases=ns.fork_diff_bases,

            search=ns.search,
            terms_file=ns.terms_file,
            output=ns.output,

            session=ns.session,
            session_file=ns.session_file,
            resume=ns.resume,
        )
