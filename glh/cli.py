from __future__ import annotations

import argparse
from dataclasses import dataclass
from importlib.metadata import version, PackageNotFoundError

BranchesMode = str | int  # "default" | "all" | int

DEFAULT_INDEX_BRANCHES: BranchesMode = "default"
DEFAULT_SCAN_BRANCHES: BranchesMode = "default"


def _get_version() -> str:
    try:
        return version("gitlab-harvester")
    except PackageNotFoundError:
        return "unknown"


def parse_branches(value: str) -> BranchesMode:
    v = value.strip().lower()
    if v in {"default", "all"}:
        return v
    if v.isdigit() and int(v) > 0:
        return int(v)
    raise argparse.ArgumentTypeError("Use 'default', 'all', or a positive integer (e.g., 10).")


@dataclass(frozen=True, slots=True)
class CliArgs:
    host: str | None
    token: str | None
    proxy: str | None

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
    @staticmethod
    def build() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="gitlab-harvester",
            description="Collect and use an Instance Project Index from a GitLab instance.",
        )

        # Core connectivity (NOW OPTIONAL)
        parser.add_argument("-H", "--host", default=None, help="GitLab host (required for search/dump-index).")
        parser.add_argument("-t", "--token", default=None, help="GitLab token (required for search/dump-index).")

        parser.add_argument(
            "-p",
            "--proxy",
            default=None,
            help="HTTP(S) proxy URL for GitLab API traffic.",
        )

        # Logging
        parser.add_argument("--log-file", default=None)
        parser.add_argument("--log-level", choices=("ERROR", "WARN", "INFO"), default="WARN")
        parser.add_argument("--debug", action="store_true")

        # Mode
        parser.add_argument(
            "-m",
            "--mode",
            choices=("search", "dump-index", "dedup", "convert"),
            default="search",
        )

        # Index
        parser.add_argument("-bs", "--batch-size", type=int, default=100)
        parser.add_argument("--index-file", default=None)
        parser.add_argument("--dump-projects", action="store_true")

        # Branches
        parser.add_argument("-b", "--branches", dest="branches", type=parse_branches, default=None)
        parser.add_argument("--index-branches", type=parse_branches, default=None)
        parser.add_argument("--scan-branches", type=parse_branches, default=None)
        parser.add_argument("--branches-per-page", type=int, default=100)

        # Forks
        parser.add_argument("--forks", choices=("skip", "include", "branch-diff", "all-branches"), default="include")
        parser.add_argument("--fork-diff-bases", default="main,master,develop,dev")

        # Search
        group = parser.add_mutually_exclusive_group()
        group.add_argument("-s", "--search", default=None)
        group.add_argument("-f", "--terms-file", default=None)

        sess = parser.add_mutually_exclusive_group()
        sess.add_argument("--session", default=None)
        sess.add_argument("--session-file", default=None)

        parser.add_argument("--resume", action="store_true")

        # Postprocess
        parser.add_argument("--input-file", default=None)
        parser.add_argument("--output-file", default=None)

        # Dedup
        parser.add_argument("--sqlite-path", default=None)
        parser.add_argument("--hash-algo", choices=("blake2b", "sha1", "sha256"), default="blake2b")
        parser.add_argument("--no-normalize-hits", action="store_true")

        # Convert
        parser.add_argument("--sort-keys", action="store_true")

        parser.add_argument(
            "-V",
            "--version",
            action="version",
            version=f"%(prog)s {_get_version()}",
        )

        return parser

    @classmethod
    def parse(cls, argv: list[str] | None = None) -> CliArgs:
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
