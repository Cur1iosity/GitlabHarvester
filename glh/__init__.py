"""
glh — GitLab Harvester
======================

Builds an index of the projects of a GitLab instance and searches their
repositories and branches for terms through the GitLab API (no cloning).

The package is layered (see docs/architecture.md):

``glh.cli``          command line: options, config file, commands, reports
``glh.limits``       experimental rate-limit detection and runtime advice
``glh.engine``       the work: GitlabHarvester (facade) and HarvesterFactory, index, search, workers
``glh.gitlab``       talking to GitLab: client factory, connection, pacing, HTTP 429, errors
``glh.output``       where results go: session files, downloads, archives
``glh.postprocess``  dedup and convert of session files
``glh.domain``       pure rules: scan planning, time windows, filters
``glh.ui``           console output: status line, progress, blocks, logs

Library use::

    from glh import GitlabHarvester
    from glh.domain import ScanOptions

    harvester = GitlabHarvester(url="https://gitlab.example.com", token="...")
    index_file = harvester.build_project_index()
    projects = harvester.load_projects_from_file(index_file)["projects"]
    results, hits = harvester.search_keywords(projects, ["password"], options=ScanOptions())

    # or with every setting in one object:
    from glh.engine.factory import HarvesterSettings
    harvester = GitlabHarvester.from_settings(HarvesterSettings(url=..., tokens=("...",), workers=4))

Only ``GitlabHarvester``, ``CliParser`` and ``__version__`` are guaranteed
between releases; the modules below them may move.
"""

from glh.cli.parser import CliParser
from glh.engine.harvester import GitlabHarvester
from glh.version import __version__

__all__ = ["GitlabHarvester", "CliParser", "__version__"]
