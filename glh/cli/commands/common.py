# glh/cli/commands/common.py
"""
Helpers shared by the commands: the harvester of a run, tokens, terms, session and index paths.
"""

from __future__ import annotations

import contextlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlparse

from glh.cli import tokens
from glh.cli.args import CliArgs
from glh.engine.harvester import GitlabHarvester
from glh.exceptions import GitlabHarvesterError
from glh.gitlab import user_agents
from glh.ui import statusline

# datetime.UTC exists only on Python 3.11+, while the package supports 3.10.
UTC = timezone.utc


def require_gitlab(args: CliArgs) -> str:
    """Ensure a URL and at least one token are present for GitLab-dependent modes."""
    if not args.url or not (args.token or args.token_file):
        raise SystemExit("This mode requires --url and --token.")
    return args.url


def resolve_tokens(args: CliArgs) -> list[str]:
    """Resolve -t/--token (';'-separated) or --token-file into a list of tokens."""
    try:
        if args.token_file:
            return tokens.load_tokens(args.token_file)
        if args.token:
            return tokens.parse_tokens(args.token)
    except tokens.TokenError as e:
        raise SystemExit(str(e)) from None
    return []


def load_keywords(*, search: str | None, terms_file: str | None, terms: tuple[str, ...] = ()) -> list[str]:
    """Load keywords from --search, --terms-file or the config file `terms` list (in that order)."""
    if search:
        s = search.strip()
        return [s] if s else []

    if terms_file:
        p = Path(terms_file)
        keywords: list[str] = []
        for line in p.read_text(encoding="utf-8").splitlines():
            t = line.strip()
            if t and not t.startswith("#"):
                keywords.append(t)
        return keywords

    return [t.strip() for t in terms if t.strip()]


def run_stamp() -> str:
    """UTC timestamp of a run, as used in default session and downloaded file names."""
    return datetime.now(UTC).strftime("%Y%m%d%H%M%S")


def default_session_name(url: str, stamp: str | None = None) -> str:
    """Build a stable session name prefix from the GitLab URL."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.netloc or parsed.path).replace(".", "_").strip("_") or "gitlab"
    return f"{host}_session_{stamp or run_stamp()}"


def resolve_session_path(url: str, session: str | None, session_file: str | None,
                          stamp: str | None = None) -> Path:
    """Resolve session JSONL path from CLI args."""
    if session_file:
        return Path(session_file)
    if session:
        return Path(f"{session}.jsonl")
    return Path(f"results{os.sep}{default_session_name(url, stamp)}.jsonl")


def connect_harvester(args: CliArgs) -> GitlabHarvester:
    """Create a GitlabHarvester instance from CLI args."""
    url = require_gitlab(args)
    token_list = resolve_tokens(args)
    if not token_list:
        raise SystemExit("This mode requires --url and --token.")

    agents: list[str] = []
    if args.user_agent_file:
        try:
            agents = user_agents.load_user_agents(args.user_agent_file)
        except user_agents.UserAgentError as e:
            raise SystemExit(str(e)) from None
    elif args.user_agent:
        agents = [args.user_agent]

    kwargs: dict[str, Any] = {
        "url": url,
        "tokens": token_list,
        "timeout": args.timeout,
        "workers": args.workers,
        "index_rpm": args.index_rpm,
        "search_rpm": args.search_rpm,
        "jitter": args.jitter,
        "user_agents": agents,
        "log_level": args.log_level,
        "log_file": args.log_file,
        "ssl_verify": False if args.insecure else (args.ca_bundle or True),
        "adjustable_limits": args.auto_limits,
    }
    if args.proxy:
        kwargs["proxy"] = args.proxy

    try:
        return GitlabHarvester(**kwargs)
    except GitlabHarvesterError as e:
        raise SystemExit(str(e)) from None


def index_hint(index_file: str, *, mode: str, rebuild: bool) -> str:
    """The tip shown while the project index is built (see building_index)."""
    if mode == "dump-index":
        return (f"Tip: searches reuse this index: run them from this directory, or pass "
                f"--index-file {index_file} (no --dump-projects).")
    if rebuild:
        return (f"Tip: --dump-projects rebuilds {index_file}; without it, the next searches reuse "
                f"the index (--index-file FILE picks another one).")
    return (f"Tip: next time this index is reused: --index-file {index_file} (found automatically "
            f"from this directory; --dump-projects rebuilds it).")


@contextlib.contextmanager
def building_index(args: CliArgs, glh: GitlabHarvester, *, mode: str) -> Iterator[None]:
    """While the index is built (not when an existing one is reused): the reuse tip above the status line."""
    index_file = index_path(args, glh)
    rebuild = mode == "dump-index" or args.dump_projects
    if not (rebuild or not os.path.exists(index_file)):
        yield
        return
    statusline.STATUS.set_hint(index_hint(index_file, mode=mode, rebuild=rebuild and mode != "dump-index"))
    try:
        yield
    finally:
        statusline.STATUS.set_hint(None)

# --------------------------------------------------------------------------- rate limits


def index_path(args: CliArgs, glh: GitlabHarvester) -> str:
    """The index file a search would use (same default name as build_project_index)."""
    return args.index_file or f"{glh.get_instance_id()}_project_index.jsonl"


def require_path(value: str | None, *, name: str) -> Path:
    """Require a CLI path argument in postprocess modes."""
    if not value:
        raise SystemExit(f"Missing required argument for this mode: {name}")
    return Path(value)
