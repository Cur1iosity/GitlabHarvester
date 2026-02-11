"""
glh — GitLab Harvester package
==============================

High-level toolkit for building a **GitLab Instance Project Index** and performing
keyword search across repositories and branches using the GitLab API.

The package provides:

- Fast collection of minimal project metadata into a JSONL index.
- Optional enrichment with branch lists.
- Flexible scanning strategies for branches and forks.
- Session-based result recording with resume capability.
- CLI interface for everyday usage.

Modules
-------

cli
    Argument parser and normalization logic for the CLI tool.

harvester
    Core GitlabHarvester class implementing index building, branch collection,
    and keyword scanning.

planner
    Strategy helpers for deciding which projects and branches to scan
    (fork handling, diff-based branch selection, limits).

session
    Utilities for session file handling and resume support.

Typical usage
-------------

As a library:

    from glh import GitlabHarvester

    glh = GitlabHarvester(host="gitlab.example.com", token="...")
    index = glh.build_project_index()
    results, hits = glh.search_keywords(projects, ["password"])

As a CLI:

    glh-harvest --host gitlab.example.com --token XXX \
        --search "password" --scan-branches all

"""

from .harvester import GitlabHarvester
from .cli import CliParser

__all__ = [
    "GitlabHarvester",
    "CliParser",
]
