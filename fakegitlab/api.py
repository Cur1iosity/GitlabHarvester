"""
GitLab REST API v4 subset served by the Fake GitLab.

Implemented endpoints (everything else returns GitLab-style 404 and is
recorded as *unmatched* so tests can detect unexpected client calls):

=====================================================  ============================
Endpoint                                               Notes
=====================================================  ============================
``GET /api/v4/user``                                   current user (auth check)
``GET /api/v4/version``                                static version payload
``GET /api/v4/projects``                               offset pagination, order_by/sort
``GET /api/v4/projects/:id``                           numeric id or URL-encoded path
``GET /api/v4/projects/:id/repository/branches``       name-sorted, ``search`` filter
``GET /api/v4/projects/:id/search?scope=blobs``        case-insensitive literal search
=====================================================  ============================

Responses follow the documented GitLab shapes and pagination headers
(``X-Page``, ``X-Per-Page``, ``X-Total``, ``X-Total-Pages``, ``X-Next-Page``,
``X-Prev-Page``, ``Link``). Only fields relevant for clients are produced.
"""

from __future__ import annotations

import hashlib
import json
import math
import posixpath
import re
from dataclasses import dataclass
from typing import Any, Callable, Sequence
from urllib.parse import quote, unquote, urlencode

from werkzeug.wrappers import Request, Response

from fakegitlab.scenario import Project, Scenario, User

API_PREFIX = "/api/v4"
# GitLab loads path-matched blobs with Gitlab::Git::Blob.batch(..., blob_size_limit: 1024).
_PATH_MATCH_DATA_LIMIT = 1024

_PROJECT_ORDER_FIELDS: dict[str, Callable[[Project], Any]] = {
    "id": lambda p: p.id,
    "name": lambda p: (p.name.lower(), p.id),
    "path": lambda p: (p.path.lower(), p.id),
    "created_at": lambda p: (p.created_at, p.id),
    "updated_at": lambda p: (p.last_activity_at, p.id),
    "last_activity_at": lambda p: (p.last_activity_at, p.id),
}


def json_response(payload: Any, status: int = 200, headers: dict[str, str] | None = None) -> Response:
    """Build a JSON response with GitLab-like content type."""
    return Response(
        json.dumps(payload, ensure_ascii=False),
        status=status,
        headers={"Content-Type": "application/json", **(headers or {})},
    )


def error_response(status: int, message: str, *, key: str = "message") -> Response:
    """GitLab-style error payload (``{"message": ...}`` or ``{"error": ...}``)."""
    return json_response({key: message}, status=status)


class ApiError(Exception):
    """Internal control-flow exception converted into an error response."""

    def __init__(self, status: int, message: str, key: str = "message") -> None:
        super().__init__(message)
        self.response = error_response(status, message, key=key)


@dataclass(frozen=True, slots=True)
class RouteResult:
    """Response plus the logical endpoint name that produced it."""

    endpoint: str | None
    response: Response


def raw_request_path(request: Request) -> str:
    """
    Return the undecoded request path.

    Werkzeug decodes ``%2F`` in ``request.path``; GitLab project ids may be
    URL-encoded paths (``group%2Fproject``), so routing uses the raw URI.
    """
    raw = request.environ.get("RAW_URI") or request.environ.get("REQUEST_URI")
    if raw:
        return raw.split("?", 1)[0]
    return quote(request.path, safe="/%")


class GitLabApi:
    """Request router and resource serializers bound to one scenario."""

    _routes: list[tuple[str, re.Pattern[str], str]] = [
        ("GET", re.compile(r"^/user/?$"), "user"),
        ("GET", re.compile(r"^/version/?$"), "version"),
        ("GET", re.compile(r"^/projects/?$"), "projects"),
        ("GET", re.compile(r"^/projects/(?P<pid>[^/]+)/?$"), "project"),
        ("GET", re.compile(r"^/projects/(?P<pid>[^/]+)/repository/branches/?$"), "branches"),
        ("GET", re.compile(r"^/projects/(?P<pid>[^/]+)/search/?$"), "project_search"),
    ]

    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario
        self._namespace_ids = self._assign_namespace_ids(scenario.projects)

    # ------------------------------------------------------------------ routing

    def endpoint_for(self, raw_path: str) -> str | None:
        """Return the logical endpoint name for a raw path without executing it."""
        if not raw_path.startswith(API_PREFIX):
            return None
        sub = raw_path[len(API_PREFIX):] or "/"
        for _method, pattern, endpoint in self._routes:
            if pattern.match(sub):
                return endpoint
        return None

    def handle(self, request: Request, base_url: str) -> RouteResult:
        """Route a request and return the response with its endpoint name."""
        path = raw_request_path(request)
        if not path.startswith(API_PREFIX):
            return RouteResult(None, error_response(404, "404 Not Found"))

        sub = path[len(API_PREFIX):] or "/"
        for method, pattern, endpoint in self._routes:
            m = pattern.match(sub)
            if not m:
                continue
            if request.method.upper() != method:
                return RouteResult(endpoint, error_response(405, "405 Method Not Allowed"))
            try:
                user = self._authenticate(request)
                handler = getattr(self, f"_ep_{endpoint}")
                return RouteResult(endpoint, handler(request, base_url, user, **m.groupdict()))
            except ApiError as e:
                return RouteResult(endpoint, e.response)

        return RouteResult(None, error_response(404, "404 Not Found"))

    def _authenticate(self, request: Request) -> User:
        """Resolve the user from PRIVATE-TOKEN, Bearer token or query token."""
        token = request.headers.get("PRIVATE-TOKEN")
        if not token:
            auth = request.headers.get("Authorization", "")
            if auth.lower().startswith("bearer "):
                token = auth[7:].strip()
        if not token:
            token = request.args.get("private_token") or request.args.get("access_token")

        user = self.scenario.user_for_token(token)
        if user is None:
            raise ApiError(401, "401 Unauthorized")
        return user

    # ---------------------------------------------------------------- endpoints

    def _ep_user(self, request: Request, base_url: str, user: User) -> Response:
        return json_response(self.serialize_user(user, base_url))

    def _ep_version(self, request: Request, base_url: str, user: User) -> Response:
        return json_response({"version": self.scenario.instance.version, "revision": "fake0000"})

    def _ep_projects(self, request: Request, base_url: str, user: User) -> Response:
        order_by = request.args.get("order_by", "created_at")
        sort = request.args.get("sort", "desc").lower()
        if order_by not in _PROJECT_ORDER_FIELDS:
            raise ApiError(400, "order_by does not have a valid value", key="error")
        if sort not in ("asc", "desc"):
            raise ApiError(400, "sort does not have a valid value", key="error")

        projects = list(self.scenario.projects)
        search = request.args.get("search")
        if search:
            needle = search.lower()
            projects = [p for p in projects if needle in p.name.lower() or needle in p.path_with_namespace.lower()]
        if request.args.get("archived") in ("true", "false"):
            want = request.args["archived"] == "true"
            projects = [p for p in projects if p.archived == want]

        projects.sort(key=_PROJECT_ORDER_FIELDS[order_by], reverse=(sort == "desc"))
        return self._paginate(request, base_url, projects, lambda p: self.serialize_project(p, base_url))

    def _ep_project(self, request: Request, base_url: str, user: User, pid: str) -> Response:
        return json_response(self.serialize_project(self._get_project(pid), base_url))

    def _ep_branches(self, request: Request, base_url: str, user: User, pid: str) -> Response:
        project = self._get_project(pid)
        names = sorted(project.branches)

        search = request.args.get("search")
        if search:
            names = [n for n in names if _branch_search_match(n, search)]
        if request.args.get("sort") == "name_desc":
            names.reverse()

        return self._paginate(request, base_url, names, lambda n: self.serialize_branch(project, n, base_url))

    def _ep_project_search(self, request: Request, base_url: str, user: User, pid: str) -> Response:
        project = self._get_project(pid)
        scope = request.args.get("scope")
        search = request.args.get("search")
        if not scope:
            raise ApiError(400, "scope is missing, scope does not have a valid value", key="error")
        if search is None:
            raise ApiError(400, "search is missing", key="error")
        if scope != "blobs":
            # Other scopes are valid in GitLab but not modeled: return an empty result set.
            if scope not in {"issues", "merge_requests", "milestones", "notes", "wiki_blobs", "commits", "users"}:
                raise ApiError(400, "scope does not have a valid value", key="error")
            return self._paginate(request, base_url, [], lambda x: x)

        ref = request.args.get("ref") or project.default_branch
        files = project.branches.get(ref) if ref else None
        results = self.search_blobs(project, ref, files or {}, search) if files is not None else []
        return self._paginate(request, base_url, results, lambda x: x)

    # ------------------------------------------------------------------ helpers

    def _get_project(self, pid: str) -> Project:
        """Resolve numeric or URL-encoded path project identifiers."""
        decoded = unquote(pid)
        project = self.scenario.project_by_id(int(decoded)) if decoded.isdigit() else self.scenario.project_by_path(decoded)
        if project is None:
            raise ApiError(404, "404 Project Not Found")
        return project

    def _paginate(
            self,
            request: Request,
            base_url: str,
            items: Sequence[Any],
            serialize: Callable[[Any], Any],
    ) -> Response:
        """Apply GitLab offset pagination and emit pagination headers."""
        inst = self.scenario.instance
        page = _int_arg(request, "page", 1)
        per_page = _int_arg(request, "per_page", inst.default_per_page)
        page = max(page, 1)
        if per_page < 1:
            per_page = inst.default_per_page
        per_page = min(per_page, inst.max_per_page)

        total = len(items)
        total_pages = max(1, math.ceil(total / per_page))
        start = (page - 1) * per_page
        chunk = [serialize(x) for x in items[start:start + per_page]]

        headers: dict[str, str] = {
            "X-Page": str(page),
            "X-Per-Page": str(per_page),
            "X-Next-Page": str(page + 1) if page < total_pages else "",
            "X-Prev-Page": str(page - 1) if 1 < page <= total_pages + 1 else "",
        }
        include_totals = total <= inst.count_limit
        if include_totals:
            headers["X-Total"] = str(total)
            headers["X-Total-Pages"] = str(total_pages)

        links = []
        if page < total_pages:
            links.append((page + 1, "next"))
        if 1 < page <= total_pages + 1:
            links.append((page - 1, "prev"))
        links.append((1, "first"))
        if include_totals:
            links.append((total_pages, "last"))
        headers["Link"] = ", ".join(
            f'<{self._page_url(request, base_url, p, per_page)}>; rel="{rel}"' for p, rel in links
        )
        return json_response(chunk, headers=headers)

    @staticmethod
    def _page_url(request: Request, base_url: str, page: int, per_page: int) -> str:
        """Build a pagination link preserving the original query parameters."""
        params = [(k, v) for k, v in request.args.items(multi=True) if k not in ("page", "per_page")]
        params += [("page", str(page)), ("per_page", str(per_page))]
        return f"{base_url.rstrip('/')}{raw_request_path(request)}?{urlencode(params)}"

    @staticmethod
    def _assign_namespace_ids(projects: Sequence[Project]) -> dict[str, int]:
        """Assign deterministic ids to every namespace (including parents)."""
        ids: dict[str, int] = {}
        for p in sorted(projects, key=lambda x: x.id):
            parts = p.namespace_path.split("/") if p.namespace_path else []
            for i in range(1, len(parts) + 1):
                ns = "/".join(parts[:i])
                if ns not in ids:
                    ids[ns] = 1000 + len(ids) + 1
        return ids

    # -------------------------------------------------------------- serializers

    def serialize_user(self, user: User, base_url: str) -> dict[str, Any]:
        """Serialize the current user (subset of GET /user)."""
        return {
            "id": user.id,
            "username": user.username,
            "name": user.name,
            "state": "active",
            "locked": False,
            "avatar_url": None,
            "web_url": f"{base_url.rstrip('/')}/{user.username}",
            "is_admin": user.is_admin,
            "bot": False,
        }

    def serialize_namespace(self, ns_path: str, base_url: str) -> dict[str, Any]:
        """Serialize a namespace reference."""
        parent = ns_path.rsplit("/", 1)[0] if "/" in ns_path else None
        name = ns_path.rsplit("/", 1)[-1]
        return {
            "id": self._namespace_ids.get(ns_path, 1000),
            "name": name,
            "path": name,
            "kind": "group",
            "full_path": ns_path,
            "parent_id": self._namespace_ids.get(parent) if parent else None,
            "web_url": f"{base_url.rstrip('/')}/groups/{ns_path}",
        }

    def _project_core(self, p: Project, base_url: str) -> dict[str, Any]:
        """Fields shared by full and nested (forked_from_project) representations."""
        web_url = f"{base_url.rstrip('/')}/{p.path_with_namespace}"
        host = base_url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        name_with_ns = " / ".join(seg for seg in p.path_with_namespace.split("/")[:-1]) + f" / {p.name}" \
            if "/" in p.path_with_namespace else p.name
        return {
            "id": p.id,
            "description": p.description,
            "name": p.name,
            "name_with_namespace": name_with_ns,
            "path": p.path,
            "path_with_namespace": p.path_with_namespace,
            "created_at": p.created_at,
            "default_branch": p.default_branch,
            "tag_list": [],
            "topics": [],
            "ssh_url_to_repo": f"git@{host}:{p.path_with_namespace}.git",
            "http_url_to_repo": f"{web_url}.git",
            "web_url": web_url,
            "readme_url": f"{web_url}/-/blob/{p.default_branch}/README.md" if p.default_branch else None,
            "forks_count": sum(1 for x in self.scenario.projects if x.forked_from == p.id),
            "avatar_url": None,
            "star_count": 0,
            "last_activity_at": p.last_activity_at,
            "namespace": self.serialize_namespace(p.namespace_path, base_url),
        }

    def serialize_project(self, p: Project, base_url: str) -> dict[str, Any]:
        """Serialize a project as returned by GET /projects."""
        data = self._project_core(p, base_url)
        data.update(
            {
                "empty_repo": p.empty_repo,
                "archived": p.archived,
                "visibility": p.visibility,
                "_links": {"self": f"{base_url.rstrip('/')}{API_PREFIX}/projects/{p.id}"},
            }
        )
        if p.forked_from is not None:
            if isinstance(p.forked_from, int):
                upstream = self.scenario.project_by_id(p.forked_from)
                assert upstream is not None  # validated by the scenario loader
                data["forked_from_project"] = self._project_core(upstream, base_url)
            else:
                data["forked_from_project"] = dict(p.forked_from)
        return data

    def serialize_branch(self, p: Project, name: str, base_url: str) -> dict[str, Any]:
        """Serialize a branch as returned by GET /projects/:id/repository/branches."""
        sha = hashlib.sha1(f"{p.id}:{name}:{sorted(p.branches[name].items())}".encode()).hexdigest()
        web_url = f"{base_url.rstrip('/')}/{p.path_with_namespace}"
        is_default = name == p.default_branch
        return {
            "name": name,
            "merged": False,
            "protected": is_default,
            "default": is_default,
            "developers_can_push": False,
            "developers_can_merge": False,
            "can_push": True,
            "web_url": f"{web_url}/-/tree/{quote(name, safe='/')}",
            "commit": {
                "id": sha,
                "short_id": sha[:8],
                "created_at": p.last_activity_at,
                "parent_ids": [],
                "title": f"Fixture commit for {name}",
                "message": f"Fixture commit for {name}",
                "author_name": "Fixture Author",
                "author_email": "fixture@example.invalid",
                "authored_date": p.last_activity_at,
                "committer_name": "Fixture Author",
                "committer_email": "fixture@example.invalid",
                "committed_date": p.last_activity_at,
                "web_url": f"{web_url}/-/commit/{sha}",
            },
        }

    def search_blobs(self, p: Project, ref: str, files: dict[str, str], term: str) -> list[dict[str, Any]]:
        """
        Emulate GitLab basic (non-Elasticsearch, non-Zoekt) project blob search.

        Mirrors ``Gitlab::FileFinder#find`` on top of Gitaly ``SearchFilesByContent``
        (``git grep --ignore-case --before-context 2 --after-context 2`` on an
        escaped, i.e. literal, query):

        1. Path matches first: every file whose path contains the term
           (case-insensitive) yields one result with ``startline: 1``, the blob
           id, and the first 1024 bytes of the file as ``data``
           (``instance.search_path_matches``).
        2. Then content matches: lines containing the term; each group of
           matches plus ``instance.search_context_lines`` lines of context
           before/after is one result. Overlapping or adjacent windows merge,
           and ``startline`` is the first line of the group (context included),
           not the matching line.

        A file matching by path and by content appears in both parts, as in GitLab.
        """
        if not term:
            return []
        inst = self.scenario.instance
        ctx = max(0, inst.search_context_lines)
        needle = term.lower()
        results: list[dict[str, Any]] = []

        if inst.search_path_matches:
            for path in sorted(files):
                if needle not in path.lower():
                    continue
                raw = files[path].encode("utf-8")
                results.append(
                    {
                        "basename": posixpath.splitext(path)[0],
                        "data": raw[:_PATH_MATCH_DATA_LIMIT].decode("utf-8", errors="ignore"),
                        "path": path,
                        "filename": path,
                        "id": hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest(),
                        "ref": ref,
                        "startline": 1,
                        "project_id": p.id,
                    }
                )

        for path in sorted(files):
            lines = files[path].splitlines()
            hits = [i for i, line in enumerate(lines) if needle in line.lower()]
            if not hits:
                continue

            chunks: list[list[int]] = []
            for i in hits:
                lo, hi = max(0, i - ctx), min(len(lines) - 1, i + ctx)
                if chunks and lo <= chunks[-1][1] + 1:
                    chunks[-1][1] = max(chunks[-1][1], hi)
                else:
                    chunks.append([lo, hi])

            stem, _ = posixpath.splitext(path)
            for lo, hi in chunks:
                results.append(
                    {
                        "basename": stem,
                        "data": "\n".join(lines[lo:hi + 1]) + "\n",
                        "path": path,
                        "filename": path,
                        "id": None,
                        "ref": ref,
                        "startline": lo + 1,
                        "project_id": p.id,
                    }
                )
        return results


def _int_arg(request: Request, name: str, default: int) -> int:
    """Parse an integer query argument, rejecting malformed values like GitLab."""
    raw = request.args.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise ApiError(400, f"{name} is invalid", key="error") from None


def _branch_search_match(name: str, pattern: str) -> bool:
    """GitLab branch ``search``: substring, with optional ``^``/``$`` anchors."""
    n, s = name.lower(), pattern.lower()
    if s.startswith("^") and s.endswith("$") and len(s) > 1:
        return n == s[1:-1]
    if s.startswith("^"):
        return n.startswith(s[1:])
    if s.endswith("$"):
        return n.endswith(s[:-1])
    return s in n
