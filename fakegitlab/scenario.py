"""
Declarative scenario loading for the Fake GitLab API.

A *scenario* is a YAML/JSON document describing a virtual GitLab instance:
users and tokens, projects, branches, repository files and optional fault rules.
The loader resolves inheritance (``extends``), deterministic bulk generation
(``generate``) and branch file inheritance (``inherit``), and produces an
immutable in-memory model consumed by :mod:`fakegitlab.api`.

Scenario lookup order for a bare name (e.g. ``"default"``):

1. Directories listed in the ``FAKE_GITLAB_SCENARIO_PATH`` environment variable
   (``os.pathsep``-separated).
2. The built-in ``fakegitlab/scenarios`` directory.

A value containing a path separator or ending with ``.yaml``/``.yml``/``.json``
is treated as a file path.
"""

from __future__ import annotations

import copy
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BUILTIN_SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"
SCENARIO_PATH_ENV = "FAKE_GITLAB_SCENARIO_PATH"
_SUFFIXES = (".yaml", ".yml", ".json")

DEFAULT_TIMESTAMP = "2024-01-01T00:00:00.000Z"


class ScenarioError(ValueError):
    """Raised when a scenario file is missing or inconsistent."""


@dataclass(frozen=True, slots=True)
class User:
    """A GitLab user that can authenticate with one of its tokens."""

    id: int
    username: str
    name: str
    tokens: tuple[str, ...]
    is_admin: bool = False


@dataclass(frozen=True, slots=True)
class Project:
    """A virtual GitLab project with fully resolved branch contents."""

    id: int
    path_with_namespace: str
    name: str
    description: str | None
    default_branch: str | None
    visibility: str
    archived: bool
    created_at: str
    last_activity_at: str
    # Upstream reference for forks: either an int (project present in the
    # scenario) or a dict with at least "id" (upstream not visible / external).
    forked_from: int | dict[str, Any] | None
    # branch name -> {file path -> file content}; insertion order is preserved.
    branches: dict[str, dict[str, str]] = field(default_factory=dict)

    @property
    def path(self) -> str:
        """Last path segment (project slug)."""
        return self.path_with_namespace.rsplit("/", 1)[-1]

    @property
    def namespace_path(self) -> str:
        """Full namespace path (everything except the project slug)."""
        return self.path_with_namespace.rsplit("/", 1)[0] if "/" in self.path_with_namespace else ""

    @property
    def empty_repo(self) -> bool:
        """A repository without branches is reported as empty by GitLab."""
        return not self.branches


@dataclass(frozen=True, slots=True)
class Instance:
    """Instance-wide behavior knobs."""

    # Base URL used in generated web_url fields and Link headers.
    # None means "derive from the incoming request" (matches any client URL).
    external_url: str | None = None
    default_per_page: int = 20
    max_per_page: int = 100
    # GitLab omits X-Total / X-Total-Pages when the count exceeds this value.
    count_limit: int = 10_000
    # Lines of context before/after each blob search match. GitLab basic search
    # gets it from Gitaly (surroundContext = 2 in search_files.go).
    search_context_lines: int = 2
    # Also return files whose path contains the term (Gitlab::FileFinder#find_by_path).
    search_path_matches: bool = True
    version: str = "17.5.0-fake"


@dataclass(frozen=True, slots=True)
class Scenario:
    """Resolved, ready-to-serve scenario."""

    name: str
    description: str
    instance: Instance
    users: tuple[User, ...]
    projects: tuple[Project, ...]
    faults: tuple[dict[str, Any], ...]
    source: str | None = None

    def project_by_id(self, project_id: int) -> Project | None:
        """Return a project by numeric id."""
        for p in self.projects:
            if p.id == project_id:
                return p
        return None

    def project_by_path(self, path_with_namespace: str) -> Project | None:
        """Return a project by its full path (case-insensitive, like GitLab)."""
        needle = path_with_namespace.lower()
        for p in self.projects:
            if p.path_with_namespace.lower() == needle:
                return p
        return None

    def user_for_token(self, token: str | None) -> User | None:
        """Return the user owning the token, if any."""
        if not token:
            return None
        for u in self.users:
            if token in u.tokens:
                return u
        return None

    @property
    def default_token(self) -> str:
        """First token of the first user; convenient for tests and docs."""
        for u in self.users:
            if u.tokens:
                return u.tokens[0]
        raise ScenarioError(f"Scenario {self.name!r} defines no tokens.")


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def scenario_dirs() -> list[Path]:
    """Return scenario lookup directories in priority order."""
    dirs: list[Path] = []
    extra = os.environ.get(SCENARIO_PATH_ENV, "")
    for chunk in extra.split(os.pathsep):
        if chunk.strip():
            dirs.append(Path(chunk.strip()))
    dirs.append(BUILTIN_SCENARIO_DIR)
    return dirs


def available_scenarios() -> list[str]:
    """List scenario names discoverable in lookup directories."""
    names: set[str] = set()
    for d in scenario_dirs():
        if d.is_dir():
            for f in d.iterdir():
                if f.suffix in _SUFFIXES and not f.name.startswith("_"):
                    names.add(f.stem)
    return sorted(names)


def resolve_scenario_path(name_or_path: str | os.PathLike[str]) -> Path:
    """Resolve a scenario name or path to an existing file."""
    raw = str(name_or_path)
    looks_like_path = any(sep in raw for sep in ("/", "\\")) or raw.endswith(_SUFFIXES)
    if looks_like_path:
        p = Path(raw)
        if not p.is_file():
            raise ScenarioError(f"Scenario file not found: {p}")
        return p

    for d in scenario_dirs():
        for suffix in _SUFFIXES:
            candidate = d / f"{raw}{suffix}"
            if candidate.is_file():
                return candidate

    raise ScenarioError(
        f"Unknown scenario {raw!r}. Available: {', '.join(available_scenarios()) or '(none)'}"
    )


def _read_document(path: Path) -> dict[str, Any]:
    """Read a YAML or JSON document into a dict."""
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        data = json.loads(text)
    else:
        try:
            import yaml
        except ImportError as e:  # pragma: no cover - environment issue
            raise ScenarioError("PyYAML is required to load YAML scenarios (pip install pyyaml).") from e
        data = yaml.safe_load(text)

    if not isinstance(data, dict):
        raise ScenarioError(f"Scenario root must be a mapping: {path}")
    return data


def _merge_documents(base: dict[str, Any], child: dict[str, Any]) -> dict[str, Any]:
    """
    Merge a child scenario document onto its ``extends`` base.

    - ``instance``: shallow dict merge.
    - ``users``: replaced when the child defines them.
    - ``projects``: merged by ``id`` (child entries replace base entries,
      new ids are appended); ``remove_projects`` drops base ids.
    - ``generate`` and ``faults``: concatenated.
    """
    out = copy.deepcopy(base)
    for key in ("name", "description"):
        if key in child:
            out[key] = child[key]

    out["instance"] = {**(base.get("instance") or {}), **(child.get("instance") or {})}

    if "users" in child:
        out["users"] = copy.deepcopy(child["users"])

    removed = {int(x) for x in child.get("remove_projects") or []}
    projects = [p for p in (base.get("projects") or []) if int(p["id"]) not in removed]
    by_id = {int(p["id"]): i for i, p in enumerate(projects)}
    for p in child.get("projects") or []:
        pid = int(p["id"])
        if pid in by_id:
            projects[by_id[pid]] = copy.deepcopy(p)
        else:
            by_id[pid] = len(projects)
            projects.append(copy.deepcopy(p))
    out["projects"] = projects

    out["generate"] = list(base.get("generate") or []) + list(child.get("generate") or [])
    out["faults"] = list(base.get("faults") or []) + list(child.get("faults") or [])
    return out


def _load_document(path: Path, _seen: tuple[Path, ...] = ()) -> dict[str, Any]:
    """Load a document and recursively apply ``extends``."""
    resolved = path.resolve()
    if resolved in _seen:
        chain = " -> ".join(str(p) for p in (*_seen, resolved))
        raise ScenarioError(f"Circular scenario 'extends': {chain}")

    doc = _read_document(path)
    parent = doc.get("extends")
    if not parent:
        return doc

    # Relative names are looked up next to the child file first.
    parent_path: Path | None = None
    for suffix in ("", *_SUFFIXES):
        candidate = path.parent / f"{parent}{suffix}"
        if candidate.is_file():
            parent_path = candidate
            break
    if parent_path is None:
        parent_path = resolve_scenario_path(parent)

    base = _load_document(parent_path, (*_seen, resolved))
    return _merge_documents(base, doc)


def _expand_generators(generators: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Expand ``generate`` blocks into plain project entries.

    Each block produces ``count`` projects. String values may use ``{n}``
    (1-based index, supports format specs like ``{n:03d}``) and ``{id}``.
    """
    projects: list[dict[str, Any]] = []
    for gen in generators:
        count = int(gen["count"])
        start_id = int(gen["start_id"])
        template = gen.get("project") or {}
        for n in range(1, count + 1):
            pid = start_id + n - 1
            projects.append(_format_template(copy.deepcopy(template), n=n, id=pid) | {"id": pid})
    return projects


def _format_template(value: Any, **ctx: Any) -> Any:
    """Recursively apply str.format(**ctx) to strings (keys and values)."""
    if isinstance(value, str):
        return value.format(**ctx)
    if isinstance(value, list):
        return [_format_template(v, **ctx) for v in value]
    if isinstance(value, dict):
        return {_format_template(k, **ctx): _format_template(v, **ctx) for k, v in value.items()}
    return value


def _resolve_branches(projects_raw: dict[int, dict[str, Any]]) -> dict[int, dict[str, dict[str, str]]]:
    """
    Resolve branch file trees, following ``inherit`` references.

    Branch spec forms::

        main:                        # plain files
          files: {path: content}
        develop:
          inherit: main              # same project branch
          files: {...}               # added/overridden files
          delete: [path, ...]        # removed files
        feature:
          inherit: "101:main"        # branch of another project (forks)
    """
    resolved: dict[tuple[int, str], dict[str, str]] = {}
    in_progress: set[tuple[int, str]] = set()

    def spec_of(pid: int, branch: str) -> dict[str, Any]:
        proj = projects_raw.get(pid)
        if proj is None:
            raise ScenarioError(f"Branch inheritance references unknown project id {pid}.")
        branches = proj.get("branches") or {}
        if branch not in branches:
            raise ScenarioError(f"Branch inheritance references unknown branch {pid}:{branch!r}.")
        return branches[branch] or {}

    def resolve(pid: int, branch: str) -> dict[str, str]:
        key = (pid, branch)
        if key in resolved:
            return resolved[key]
        if key in in_progress:
            raise ScenarioError(f"Circular branch inheritance at {pid}:{branch!r}.")
        in_progress.add(key)

        spec = spec_of(pid, branch)
        files: dict[str, str] = {}
        parent = spec.get("inherit")
        if parent:
            parent = str(parent)
            if ":" in parent and parent.split(":", 1)[0].isdigit():
                ppid_s, pbranch = parent.split(":", 1)
                files.update(resolve(int(ppid_s), pbranch))
            else:
                files.update(resolve(pid, parent))

        for path, content in (spec.get("files") or {}).items():
            files[str(path)] = "" if content is None else str(content)
        for path in spec.get("delete") or []:
            files.pop(str(path), None)

        in_progress.discard(key)
        resolved[key] = files
        return files

    out: dict[int, dict[str, dict[str, str]]] = {}
    for pid, proj in projects_raw.items():
        out[pid] = {str(b): resolve(pid, str(b)) for b in (proj.get("branches") or {})}
    return out


def build_scenario(doc: dict[str, Any], *, source: str | None = None) -> Scenario:
    """Validate a raw scenario document and build the resolved model."""
    name = str(doc.get("name") or (Path(source).stem if source else "inline"))

    instance_raw = doc.get("instance") or {}
    known = set(Instance.__dataclass_fields__)
    unknown = set(instance_raw) - known
    if unknown:
        raise ScenarioError(f"Unknown instance options: {sorted(unknown)}")
    instance = Instance(**instance_raw)

    users = tuple(
        User(
            id=int(u["id"]),
            username=str(u["username"]),
            name=str(u.get("name") or u["username"]),
            tokens=tuple(str(t) for t in u.get("tokens") or []),
            is_admin=bool(u.get("is_admin", False)),
        )
        for u in doc.get("users") or []
    )

    raw_projects = list(doc.get("projects") or []) + _expand_generators(list(doc.get("generate") or []))
    projects_raw: dict[int, dict[str, Any]] = {}
    for p in raw_projects:
        pid = int(p["id"])
        if pid in projects_raw:
            raise ScenarioError(f"Duplicate project id {pid} in scenario {name!r}.")
        if "path_with_namespace" not in p:
            raise ScenarioError(f"Project {pid} has no path_with_namespace.")
        projects_raw[pid] = p

    branch_trees = _resolve_branches(projects_raw)

    projects: list[Project] = []
    for pid, p in projects_raw.items():
        branches = branch_trees[pid]
        default_branch = p.get("default_branch")
        if branches:
            if default_branch is None:
                default_branch = next(iter(branches))
            elif default_branch not in branches:
                raise ScenarioError(f"Project {pid}: default_branch {default_branch!r} is not among its branches.")
        else:
            default_branch = None  # GitLab reports null for empty repositories

        forked_from = p.get("forked_from")
        if isinstance(forked_from, (int, str)) and str(forked_from).isdigit():
            forked_from = int(forked_from)
            if forked_from not in projects_raw:
                raise ScenarioError(
                    f"Project {pid}: forked_from={forked_from} is not in the scenario "
                    f"(use a mapping with id/path_with_namespace for an invisible upstream)."
                )
        elif isinstance(forked_from, dict):
            if "id" not in forked_from:
                raise ScenarioError(f"Project {pid}: forked_from mapping requires 'id'.")
        elif forked_from is not None:
            raise ScenarioError(f"Project {pid}: invalid forked_from value {forked_from!r}.")

        created_at = str(p.get("created_at") or DEFAULT_TIMESTAMP)
        projects.append(
            Project(
                id=pid,
                path_with_namespace=str(p["path_with_namespace"]),
                name=str(p.get("name") or str(p["path_with_namespace"]).rsplit("/", 1)[-1]),
                description=p.get("description"),
                default_branch=default_branch,
                visibility=str(p.get("visibility") or "private"),
                archived=bool(p.get("archived", False)),
                created_at=created_at,
                last_activity_at=str(p.get("last_activity_at") or created_at),
                forked_from=forked_from,
                branches=branches,
            )
        )

    faults = tuple(dict(f) for f in doc.get("faults") or [])
    return Scenario(
        name=name,
        description=str(doc.get("description") or ""),
        instance=instance,
        users=users,
        projects=tuple(projects),
        faults=faults,
        source=source,
    )


def load_scenario(name_or_path: str | os.PathLike[str] | dict[str, Any] | Scenario) -> Scenario:
    """
    Load a scenario by name, file path, raw mapping or pass through a Scenario.

    Raw mappings may use ``extends`` with a built-in or discoverable name.
    """
    if isinstance(name_or_path, Scenario):
        return name_or_path
    if isinstance(name_or_path, dict):
        doc = name_or_path
        if doc.get("extends"):
            base = _load_document(resolve_scenario_path(doc["extends"]))
            doc = _merge_documents(base, doc)
        return build_scenario(doc, source=None)

    path = resolve_scenario_path(name_or_path)
    return build_scenario(_load_document(path), source=str(path))
