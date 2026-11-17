# glh/domain/project_filter.py
"""
Search only some projects of the index (``--project-filter``).

The filter works on the project index a search reads, not on the index build:
the index stays complete, and every search picks its own projects from it
without any API request. A project is matched by its ``path_with_namespace``
(``group/subgroup/project``; the path of ``web_url`` for old index files),
case-insensitively, against a comma-separated list of patterns — any one
matching is enough:

- without ``*`` or ``?`` a pattern is a substring: ``k8s`` matches
  ``infra/k8s-deploy``, ``k8s/charts`` and ``team/my-k8s``;
- with them it must match the whole path: ``*`` is any characters (``/``
  included), ``?`` one character: ``infra/*``, ``*/k8s-*``, ``*-k8s``.

Other characters are literal (``[`` is not a character class).
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from glh.domain.models import as_project, Project


class ProjectFilterError(ValueError):
    """A malformed --project-filter value."""


def _compile(pattern: str) -> re.Pattern[str]:
    if "*" not in pattern and "?" not in pattern:
        return re.compile(re.escape(pattern), re.IGNORECASE)
    parts = []
    for ch in pattern:
        parts.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
    return re.compile("^" + "".join(parts) + "$", re.IGNORECASE | re.DOTALL)


def parse_patterns(value: str) -> tuple[str, ...]:
    """'k8s, infra/*' -> ('k8s', 'infra/*'); duplicates dropped, order kept."""
    patterns = tuple(dict.fromkeys(p.strip().strip("/") for p in (value or "").split(",") if p.strip().strip("/")))
    if not patterns:
        raise ProjectFilterError("empty project filter")
    for p in patterns:
        if any(ch.isspace() for ch in p):
            raise ProjectFilterError(f"no spaces in a project pattern: {p!r} (GitLab paths have none)")
    return patterns


def project_path(project: Project | Mapping[str, Any]) -> str:
    """``path_with_namespace`` of a project (from ``web_url`` for old records)."""
    return as_project(project).path


class ProjectFilter:
    """Patterns of --project-filter; falsy when there are none (every project passes)."""

    __slots__ = ("patterns", "_compiled")

    def __init__(self, patterns: tuple[str, ...] | list[str] = ()) -> None:
        self.patterns: tuple[str, ...] = tuple(patterns)
        self._compiled = tuple(_compile(p) for p in self.patterns)

    def __bool__(self) -> bool:
        return bool(self.patterns)

    def matches(self, project: Project) -> bool:
        if not self.patterns:
            return True
        path = project.path
        return any(rx.search(path) for rx in self._compiled)

    def describe(self) -> str:
        """'k8s, infra/*' for messages."""
        return ", ".join(self.patterns)
