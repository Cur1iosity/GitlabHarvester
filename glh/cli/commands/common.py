# glh/cli/commands/common.py
"""
Helpers shared by the commands: terms, session and index paths, the index tip.
"""

from __future__ import annotations

import contextlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from urllib.parse import urlparse

from glh.cli.args import CliArgs
from glh.engine.harvester import GitlabHarvester
from glh.ui import statusline

# datetime.UTC exists only on Python 3.11+, while the package supports 3.10.
UTC = timezone.utc


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
