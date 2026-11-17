# glh/cli/parser.py
"""
The argparse parser of the CLI and the resolution of its options (config file, group shortcuts, defaults).
"""

from __future__ import annotations

import argparse
import sys

from glh.cli.args import CliArgs, DEFAULT_DOWNLOAD_MAX_SIZE, DEFAULT_INDEX_BRANCHES, DEFAULT_SCAN_BRANCHES
from glh.cli.banner import get_banner
from glh.cli.config import ConfigError, load_config, TERMS_DEST
from glh.cli.values import (
    parse_branches,
    parse_extension,
    parse_filename,
    parse_jitter,
    parse_post_process,
    parse_probe_apis,
    parse_probe_margin,
    parse_probe_max,
    parse_project_filter,
    parse_rpm,
    parse_size,
    parse_started_from,
    parse_user_agent,
    parse_workers,
)
from glh.engine.workers import MAX_WORKERS
from glh.gitlab import throttling
from glh.limits.constants import DEFAULT_BUDGET, DEFAULT_MARGIN, DEFAULT_MAX_REQUESTS, INDEX, SEARCH
from glh.version import get_version

# (specific dest, group dest) for every request rate limit; resolved like TIME_BOUNDS.
RATE_LIMITS: tuple[tuple[str, str], ...] = (
    ("index_rpm", "rpm"),
    ("search_rpm", "rpm"),
)

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
        tok = parser.add_mutually_exclusive_group()
        tok.add_argument(
            "-t", "--token", default=None,
            help="GitLab token(s), required for search/dump-index. Several tokens separated by ';' run in "
                 "parallel, each with its own --workers clients and its own rate-limit budget.",
        )
        tok.add_argument(
            "--token-file", default=None, metavar="FILE",
            help="File with one GitLab token per line (# comments allowed); each token runs in parallel, "
                 "like several tokens in -t.",
        )
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
            default=None,
            metavar="N",
            help=f"Parallel API requests (1-{MAX_WORKERS}, default 1 = sequential). Speeds up project listing, "
                 "branch listing and search; use more than 1 only if the instance has no API rate limits "
                 "(--auto-limits or -m find-limits measure them).",
        )
        parser.add_argument(
            "--rpm", type=parse_rpm, default=None, metavar="N",
            help="Shortcut for --index-rpm and --search-rpm (a specific option overrides it).",
        )
        parser.add_argument(
            "--index-rpm", type=parse_rpm, default=None, metavar="N",
            help="Max API requests per minute per worker, except search requests: project and branch "
                 "listing, file-change checks, file downloads (default 0 = no limit).",
        )
        parser.add_argument(
            "--search-rpm", type=parse_rpm, default=None, metavar="N",
            help="Max search API requests per minute per worker; GitLab rate-limits search separately "
                 "(default 0 = no limit).",
        )
        parser.add_argument(
            "--jitter", type=parse_jitter, default=None, metavar="RANGE",
            help="Random delay before every API request, drawn anew for each one: MAX or MIN-MAX seconds, "
                 "e.g. 0.03, 0.01-0.05 or 10ms-50ms (default: off). Adds to the --*-rpm spacing.",
        )
        lim = parser.add_argument_group(
            "rate-limit detection (EXPERIMENTAL)",
            "Experimental: behavior, output and options may change in future releases.\n"
            "-m find-limits measures the GitLab API rate limits of the token and prints the --workers,\n"
            "--index-rpm and --search-rpm to use. --auto-limits does it before a search (only the\n"
            "search API when the project index already exists) and watches the run for HTTP 429.",
        )
        lim.add_argument(
            "--auto-limits", action=argparse.BooleanOptionalAction, default=False,
            help="[experimental] Before a search, measure the rate limits and offer settings for them (asks on a terminal; "
                 "elsewhere prints the command and exits). During the search, propose lower limits after "
                 "HTTP 429 without stopping (L shows the proposal again). Options set explicitly are kept; "
                 "with all of them set, nothing is measured.",
        )
        lim.add_argument(
            "--probe-apis", type=parse_probe_apis, default=None, metavar="APIS",
            help="[experimental] APIs to measure: index, search or index,search. Default: both with -m find-limits; "
                 "with --auto-limits search, plus index when the project index has to be built.",
        )
        lim.add_argument(
            "--probe-max", type=parse_probe_max, default=DEFAULT_MAX_REQUESTS, metavar="N",
            help=f"[experimental] Most requests to send per measured API (default {DEFAULT_MAX_REQUESTS}). The probe "
                 f"first sends a default budget (search {DEFAULT_BUDGET[SEARCH]}, other API "
                 f"{DEFAULT_BUDGET[INDEX]}); without HTTP 429 it goes deeper up to N to find "
                 "a higher limit or the real throughput.",
        )
        lim.add_argument(
            "--probe-margin", type=parse_probe_margin, default=DEFAULT_MARGIN, metavar="SHARE",
            help=f"[experimental] Share of a found limit the suggested settings use, 0.1-1 (default {DEFAULT_MARGIN}).",
        )

        ua = parser.add_mutually_exclusive_group()
        ua.add_argument("-A", "--user-agent", type=parse_user_agent, default=None, metavar="STRING",
                        help="User-Agent of every API request (default: python-gitlab's).")
        ua.add_argument("--user-agent-file", default=None, metavar="FILE",
                        help="File with one User-Agent per line (# comments allowed): every API request "
                             "gets one chosen at random.")

        # Logging
        parser.add_argument("--log-file", default=None, help="Write logs to a file (in addition to stderr).")
        parser.add_argument("--log-level", choices=("ERROR", "WARN", "INFO"), default="WARN", help="Console log level.")
        parser.add_argument("--debug", action=argparse.BooleanOptionalAction, default=False,
                            help="Enable debug logging (overrides --log-level).")

        # Mode
        parser.add_argument(
            "-m",
            "--mode",
            choices=("search", "dump-index", "find-limits", "dedup", "convert"),
            default="search",
            help="Execution mode (find-limits is experimental).",
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

        ff = parser.add_argument_group(
            "file filters",
            "Search the terms only in some files (case-insensitive; together, a file must match both).\n"
            "GitLab applies them on its side (filename:/extension: in the search string) and the\n"
            "harvester re-checks every result. Without a term (-s/-f) they collect every matching\n"
            "file instead (one hit per file; with --download-files, the files): see --file-listing.",
        )
        ff.add_argument(
            "--filename", type=parse_filename, default=None, metavar="PATTERN",
            help="Only files with this name. PATTERN is an exact name, which may include the extension "
                 "(settings.py, .env, Dockerfile), or a mask where * matches any characters (*.env, "
                 "config*, docker-compose*.yml, *secret*). A PATTERN with / matches the end of the "
                 "path (config/*.yml).",
        )
        pf = parser.add_argument_group(
            "project filter",
            "Search only some projects of the index (it stays complete; filtered projects cost no requests).",
        )
        pf.add_argument(
            "--project-filter", type=parse_project_filter, default=(), metavar="PATTERNS",
            help="Search only indexed projects whose path (group/subgroup/project) matches one of these "
                 "comma-separated patterns, case-insensitive: without * a substring (k8s), with * the "
                 "whole path (infra/*, *-k8s). Applied to the existing index, no extra API requests; "
                 "the index itself stays complete.",
        )
        ff.add_argument(
            "--file-listing", choices=("auto", "search", "tree"), default="auto",
            help="Without a term: how the files of a branch are found. search: the search API with the "
                 "filters only (works where the search backend takes such queries, e.g. advanced search); "
                 "tree: the repository tree, any GitLab, one request per 100 entries; auto (default): "
                 "search, falling back to the tree.",
        )
        ff.add_argument(
            "--extension", type=parse_extension, default=None, metavar="EXT",
            help="Only files with this extension; the dot is optional: py, .py and *.py are the same.",
        )

        sess = parser.add_mutually_exclusive_group()
        sess.add_argument("--session", default=None, help="Session name (creates <name>.jsonl in the current directory).")
        sess.add_argument("--session-file", default=None, help="Explicit session file path (JSONL).")

        parser.add_argument("--resume", action=argparse.BooleanOptionalAction, default=False,
                            help="Resume from existing session file.")

        parser.add_argument(
            "--output-separated",
            action=argparse.BooleanOptionalAction,
            default=False,
            help="With several search terms, also write each term's hits to its own file "
                 "<session>.<term>.jsonl next to the session (ignored for a single term).",
        )
        parser.add_argument(
            "--download-files",
            action=argparse.BooleanOptionalAction,
            default=False,
            help="Download every file with hits into a 'files' directory next to the session "
                 "(results/files by default), one sub-directory per term: "
                 "files/<term>/<project>_<branch>_<timestamp>_<path>.",
        )
        parser.add_argument(
            "--download-max-size",
            type=parse_size,
            default=DEFAULT_DOWNLOAD_MAX_SIZE,
            metavar="SIZE",
            help="With --download-files: skip files larger than SIZE: bytes or with k, M, G "
                 "(500k, 10M, 1G; 0 = no limit). Default: 10M.",
        )

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
        parser.add_argument(
            "--to-zip",
            action=argparse.BooleanOptionalAction,
            default=False,
            help="After the search (and --post-process), pack the run's results into <session>.zip next to "
                 "the session, in the same layout: the session, --post-process outputs, the "
                 "--output-separated term files and the --download-files files of the session's hits. "
                 "The original files are kept.",
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

        parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {get_version()}")

        return parser

    @classmethod
    def _given_dests(cls, argv: list[str] | None) -> set[str]:
        """Return the argparse dests that were set explicitly on the command line."""
        probe = cls.build()
        for action in probe._actions:  # noqa: SLF001 - argparse exposes no public accessor
            action.default = argparse.SUPPRESS
        return set(vars(probe.parse_args(argv)))

    @staticmethod
    def _resolve_group_options(ns: argparse.Namespace, given: set[str], config: dict) -> None:
        """
        Resolve every option that has a group shortcut (time bounds, rate limits)
        in place and drop their keys from ``config``.

        Order: specific option on the CLI > group option (--time-after, --rpm, ...)
        on the CLI > specific key in the config file > group key in the config file.
        """
        resolved: dict[str, object] = {}
        for specific, group in TIME_BOUNDS + RATE_LIMITS:
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
        for dest in {d for pair in TIME_BOUNDS + RATE_LIMITS for d in pair}:
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

            exclusive = (("search", "terms_file", TERMS_DEST), ("session", "session_file"),
                         ("user_agent", "user_agent_file"), ("token", "token_file"))
            for group in exclusive:
                if given & set(group):
                    for dest in group:
                        config.pop(dest, None)

            # -b on the command line beats branch modes from the file.
            if "branches" in given:
                for dest in ("index_branches", "scan_branches"):
                    if dest not in given:
                        config.pop(dest, None)

            cls._resolve_group_options(ns, given, config)

            for dest, value in config.items():
                if dest not in given:
                    setattr(ns, dest, value)
        else:
            grouped = TIME_BOUNDS + RATE_LIMITS + (("time_after", ""), ("time_before", ""), ("rpm", ""))
            cls._resolve_group_options(ns, {d for d, _ in grouped if getattr(ns, d) is not None}, {})

        explicit_limits = frozenset(d for d in ("workers", *(dest for dest, _ in RATE_LIMITS))
                                    if getattr(ns, d) is not None)
        if ns.workers is None:
            ns.workers = 1
        for dest, _ in RATE_LIMITS:
            if getattr(ns, dest) is None:
                setattr(ns, dest, 0)

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
            token_file=ns.token_file,
            proxy=ns.proxy,
            timeout=ns.timeout,
            insecure=ns.insecure,
            ca_bundle=ns.ca_bundle,
            workers=ns.workers,
            index_rpm=ns.index_rpm,
            search_rpm=ns.search_rpm,
            jitter=ns.jitter or throttling.NO_JITTER,
            user_agent=ns.user_agent,
            user_agent_file=ns.user_agent_file,
            auto_limits=ns.auto_limits,
            probe_apis=tuple(ns.probe_apis or ()),
            probe_max=ns.probe_max,
            probe_margin=ns.probe_margin,
            explicit_limits=explicit_limits,
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
            filename=ns.filename,
            extension=ns.extension,
            project_filter=tuple(ns.project_filter),
            file_listing=ns.file_listing,
            session=ns.session,
            session_file=ns.session_file,
            resume=ns.resume,
            output_separated=ns.output_separated,
            download_files=ns.download_files,
            download_max_size=ns.download_max_size,
            input_file=ns.input_file,
            output_file=ns.output_file,
            post_process=tuple(ns.post_process),
            final_only=ns.final_only,
            to_zip=ns.to_zip,
            sqlite_path=ns.sqlite_path,
            hash_algo=ns.hash_algo,
            normalize_hits=ns.normalize_hits,
            sort_keys=ns.sort_keys,
        )
