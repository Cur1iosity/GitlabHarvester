# glh/domain/planning.py
"""
Which projects and branches a search scans: the scan options, the skip rules,
the branch selection (forks included) and the resulting scan plan.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Mapping

from glh.domain.file_filter import FileFilter
from glh.domain.models import as_project, Project
from glh.domain.project_filter import ProjectFilter
from glh.domain.timewindow import format_bound, TimeWindow

BranchesMode = str | int  # "default" | "all" | int


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """
    Configuration controlling how projects are scanned during keyword search.

    Attributes:
        scan_branches: Branch scanning scope:
            - "default": scan only the default branch from the project index,
            - "all": scan all branches available in the project index,
            - int: scan up to N branches (default branch + N-1 additional branches).
        forks_mode: Strategy for forked projects:
            - "skip": ignore forked projects entirely,
            - "include": treat forks as regular projects and scan normally,
            - "branch-diff": scan a reduced set of branches for forks based on
              upstream comparison and fork_diff_bases,
            - "all-branches": scan every branch of forks (potentially slow).
        fork_diff_bases: Branch names always considered for scanning in forks when
            forks_mode="branch-diff" (e.g., main/master/develop/dev).
        started_from: Optional timezone-aware lower bound for project activity
            (--active-after, alias --started-from). Projects whose indexed
            ``last_activity_at`` is earlier are skipped (GitLab updates it on
            pushes and other activity, at most once per hour, so such
            repositories normally have no changes since that moment).
        active_before: Optional upper bound for project activity (--active-before).
            Projects whose ``last_activity_at`` is later are skipped.
        file_changed_after / file_changed_before: Optional window for the files
            with hits (--file-changed-after/--file-changed-before). A hit is kept
            only if a commit touched its file in the branch inside the window
            (checked with the commits API, one request per file).
        None disables a bound; bounds are inclusive.
        filename / extension: Optional file filters (--filename, --extension),
            see glh/domain/file_filter.py: sent to GitLab inside the search string and
            re-checked on every result path.
        project_filter: Patterns of --project-filter (glh/domain/project_filter.py):
            only indexed projects whose path matches one of them are searched.
        files_only: No search term: collect every file whose name passes the
            file filters (the term is the filter string, e.g. ``filename:*.env``).
        file_listing: How files_only lists the files of a branch: "auto"
            (filter-only search, else the repository tree), "search", "tree".
    """
    scan_branches: BranchesMode = "default"  # default|all|N
    forks_mode: str = "include"  # skip|include|branch-diff|all-branches
    fork_diff_bases: tuple[str, ...] = ("main", "master", "develop", "dev")
    started_from: datetime | None = None
    active_before: datetime | None = None
    file_changed_after: datetime | None = None
    file_changed_before: datetime | None = None
    filename: str | None = None
    extension: str | None = None
    project_filter: tuple[str, ...] = ()
    files_only: bool = False
    file_listing: str = "auto"

    @property
    def projects(self) -> ProjectFilter:
        """Project path filter of the search (falsy when unset)."""
        return ProjectFilter(tuple(self.project_filter))

    @property
    def file_window(self) -> "TimeWindow":
        """Time window for files with hits."""
        return TimeWindow(self.file_changed_after, self.file_changed_before)

    @property
    def file_filter(self) -> FileFilter:
        """File name/extension filter of the search (falsy when unset)."""
        return FileFilter(self.filename, self.extension)


def is_active_since(project: Project, started_from: datetime | None) -> bool:
    """
    Check whether a project had activity at or after ``started_from``.

    Projects without a parsable ``last_activity_at`` are treated as active, so
    the filter never drops a repository it cannot reason about.
    """
    if started_from is None:
        return True
    last_activity = project.last_activity
    if last_activity is None:
        return True
    return last_activity >= started_from


def is_active_before(project: Project, active_before: datetime | None) -> bool:
    """
    Check whether a project's last activity is at or before ``active_before``.

    Projects without a parsable ``last_activity_at`` pass, like in is_active_since().
    """
    if active_before is None:
        return True
    last_activity = project.last_activity
    if last_activity is None:
        return True
    return last_activity <= active_before


def is_fork_project(project: Project | Mapping[str, Any]) -> bool:
    """
    Whether the project is a fork (``forked_from_project`` in the index, or the
    legacy ``upstream_project_id``); see Project.from_record().
    """
    return as_project(project).is_fork


def get_upstream_id(project: Project | Mapping[str, Any]) -> int | None:
    """The id of the project a fork was forked from, when known; None otherwise."""
    return as_project(project).upstream_id


# Reasons a project is left out of a scan (keys of ScanPlan.skipped).
SKIP_FILTERED = "filtered"

SKIP_EMPTY = "empty"

SKIP_FORK = "fork"

SKIP_INACTIVE = "inactive"

SKIP_TOO_RECENT = "too-recent"

SKIP_NO_BRANCHES = "no-branches"


def skip_reason(project: Project, options: ScanOptions) -> str | None:
    """
    Return why a project is excluded from the search, or None if it is scanned.

    Rules, checked in this order:

    - SKIP_FILTERED: the path matches none of options.project_filter.
    - SKIP_EMPTY: empty repositories are always skipped.
    - SKIP_FORK: forked projects are skipped when forks_mode is "skip".
    - SKIP_INACTIVE: projects inactive since options.started_from are skipped.
    - SKIP_TOO_RECENT: projects active after options.active_before are skipped.

    Args:
        project: Project of the index.
        options: ScanOptions defining fork-handling and activity rules.

    Returns:
        One of the SKIP_* constants, or None.
    """
    if options.project_filter and not options.projects.matches(project):
        return SKIP_FILTERED
    if project.empty_repo:
        return SKIP_EMPTY
    if project.is_fork and options.forks_mode == "skip":
        return SKIP_FORK
    if not is_active_since(project, options.started_from):
        return SKIP_INACTIVE
    if not is_active_before(project, options.active_before):
        return SKIP_TOO_RECENT
    return None


def should_scan_project(project: Project, options: ScanOptions) -> bool:
    """
    Determine whether a project should be included in the search process.

    See skip_reason() for the rules.

    Args:
        project: Project of the index.
        options: ScanOptions defining fork-handling rules.

    Returns:
        True if the project should be scanned, otherwise False.
    """
    return skip_reason(project, options) is None


def select_branches_from_index(project: Project, mode: BranchesMode) -> list[str]:
    """
    Select a subset of branches for scanning based on the chosen scan mode.

    The function operates only on branches already stored in the project index
    and does not perform any GitLab API calls.

    Selection rules:

    - "all" → return all indexed branches as-is.
    - "default" → return only the default branch (explicit default_branch
      field, falling back to the first indexed branch). GitLab lists branches
      sorted by name, so the first indexed branch is not necessarily the default.
    - int (N) → return up to N branches, ensuring the default branch is included
      when available (default + N-1 others).

    Args:
        project: Project of the index (its branches and default branch).
        mode: Branch selection mode: "default", "all", or positive integer.

    Returns:
        List of branch names selected for scanning. May be empty if no
        branches are available and default_branch is not defined.
    """
    branches = list(project.branch_names)
    default_branch = project.default_branch

    if mode == "all":
        return list(branches)

    if mode == "default":
        if default_branch:
            return [default_branch]
        return branches[:1]

    n = int(mode)
    if n <= 0:
        return []

    if branches:
        selected = branches[:n]
        if default_branch and default_branch not in selected:
            selected = [default_branch] + [b for b in selected if b != default_branch]
            selected = selected[:n]
        return selected

    return [default_branch] if default_branch else []


def select_fork_branches_diff(
        fork_project: Project,
        upstream_project: Project | None,
        scan_mode: BranchesMode,
        base_branches: tuple[str, ...],
) -> list[str]:
    """
    Select branches for a forked project using a diff-based strategy.

    The goal is to reduce redundant scanning by prioritizing:
    1) The fork's default branch (if present),
    2) A predefined set of base branches (e.g., main/master/develop),
    3) Branches that differ from the upstream: missing there, or pointing at
       another commit.

    A branch is left out only when the upstream has a branch of the same name
    at the same commit (the index stores every branch's head commit), so its
    content is the upstream's. With an index without commits (built before
    1.4.4, see fork_compared_by_name) a branch of the same name counts as the
    same: commits added to it in the fork are then missed.

    Args:
        fork_project: Project entry representing the fork.
        upstream_project: Corresponding upstream project entry, if available.
        scan_mode: Branch limit mode: "default", "all", or integer N.
        base_branches: Tuple of branch names always included when present
            in the fork (e.g., main/master).

    Returns:
        Ordered list of branch names selected for scanning according to
        diff strategy and scan_mode limits.
    """
    fork_branches = set(fork_project.branch_names)
    upstream_branches = set(upstream_project.branch_names) if upstream_project else set()
    same = fork_branches & upstream_branches
    fork_heads = fork_project.heads()
    upstream_heads = upstream_project.heads() if upstream_project else None
    if fork_heads is not None and upstream_heads is not None:
        # Same name is not enough: the fork may have added commits to it.
        same = {b for b in same if fork_heads.get(b) is not None and fork_heads.get(b) == upstream_heads.get(b)}

    selected: list[str] = []

    default_branch = fork_project.default_branch
    if default_branch and default_branch in fork_branches:
        selected.append(default_branch)

    for b in base_branches:
        if b in fork_branches and b not in selected:
            selected.append(b)

    for b in sorted(fork_branches - same):
        if b not in selected:
            selected.append(b)

    if scan_mode == "all":
        return selected
    if scan_mode == "default":
        return selected[:1]
    return selected[: int(scan_mode)]


def fork_compared_by_name(project: Project, options: ScanOptions,
                          projects_by_id: Mapping[int, Project] | None) -> bool:
    """
    True for a fork that --forks branch-diff can compare with its upstream only by
    branch names: the index has no branch commits for one of them.
    """
    if not (project.is_fork and options.forks_mode == "branch-diff" and project.upstream_id and projects_by_id):
        return False
    upstream = projects_by_id.get(project.upstream_id)
    return upstream is not None and (project.branch_heads is None or upstream.branch_heads is None)


def branches_to_scan(
    project: Project,
    options: ScanOptions,
    projects_by_id: Mapping[int, Project] | None = None,
) -> list[str]:
    """
    Determine which branches should be scanned for a given project.

    The selection is derived from the project index data and controlled by
    ScanOptions. Forked projects may use specialized strategies depending
    on forks_mode:

    - "all-branches": scan every indexed branch for forks.
    - "branch-diff": scan fork branches using diff-based selection relative
      to upstream (default + base branches + branches that differ from the
      upstream: missing there or at another commit).
      If upstream is not available in the provided index map, falls back
      to regular branch selection.

    Non-fork projects (or forks with other modes) use the standard
    select_branches_from_index() behavior.

    Args:
        project: Project of the index.
        options: ScanOptions controlling branch scope and fork behavior.
        projects_by_id: Optional mapping of project_id -> Project,
            used to resolve upstream projects for forks in "branch-diff" mode.

    Returns:
        List of branch names to scan for the project. The list may be empty if
        no branch information is available.
    """
    is_fork = project.is_fork

    if is_fork and options.forks_mode == "all-branches":
        return list(project.branch_names)

    if is_fork and options.forks_mode == "branch-diff":
        upstream_id = project.upstream_id
        upstream = projects_by_id.get(upstream_id) if (projects_by_id and upstream_id) else None

        selected = select_fork_branches_diff(
            fork_project=project,
            upstream_project=upstream,
            scan_mode=options.scan_branches,
            base_branches=options.fork_diff_bases,
        )

        # fallback if upstream not available in index
        if not upstream:
            return select_branches_from_index(project, options.scan_branches)

        return selected

    return select_branches_from_index(project, options.scan_branches)


@dataclass(frozen=True, slots=True)
class ScanPlan:
    """
    Projects and branches a search will actually scan, computed once per run.

    Attributes:
        targets: (project, branches) pairs in index order.
        total_projects: Number of projects in the index.
        skipped: Excluded project count per SKIP_* reason.
        started_from: Activity bound used for SKIP_INACTIVE (for messages).
        active_before: Activity bound used for SKIP_TOO_RECENT (for messages).
        project_filter: Patterns used for SKIP_FILTERED (for messages).
        projects_by_id: Index lookup used for fork/upstream resolution.
        forks_by_name: Forks that --forks branch-diff compared with their
            upstream by branch names only (an index without branch commits).
    """
    targets: tuple[tuple[Project, tuple[str, ...]], ...]
    total_projects: int
    skipped: dict[str, int] = field(default_factory=dict)
    started_from: datetime | None = None
    active_before: datetime | None = None
    project_filter: tuple[str, ...] = ()
    projects_by_id: dict[int, Project] = field(default_factory=dict, repr=False)
    forks_by_name: int = 0

    @property
    def project_count(self) -> int:
        """Number of projects that will be scanned."""
        return len(self.targets)

    @property
    def branch_count(self) -> int:
        """Number of (project, branch) searches per term."""
        return sum(len(branches) for _, branches in self.targets)

    def describe(self) -> str:
        """Human-readable summary, e.g. '6 of 9 projects, 8 branches (skipped: 1 empty, 2 inactive since 2024-06-01)'."""
        noun = "project" if self.total_projects == 1 else "projects"
        text = f"{self.project_count:,} of {self.total_projects:,} {noun}, {self.branch_count:,} "
        text += "branch" if self.branch_count == 1 else "branches"
        if reasons := self.skipped_reasons():
            text += f" (skipped: {', '.join(reasons)})"
        return text

    def skipped_reasons(self) -> list[str]:
        """Why projects are left out, one entry per reason: ['1 empty', '3 inactive since 2024-06-02']."""
        reasons: list[str] = []
        if n := self.skipped.get(SKIP_FILTERED, 0):
            reasons.append(f"{n:,} not matching --project-filter {', '.join(self.project_filter)}")
        if n := self.skipped.get(SKIP_EMPTY, 0):
            reasons.append(f"{n:,} empty")
        if n := self.skipped.get(SKIP_FORK, 0):
            reasons.append(f"{n:,} fork{'s' if n != 1 else ''}")
        if n := self.skipped.get(SKIP_INACTIVE, 0):
            reasons.append(f"{n:,} inactive since {format_bound(self.started_from)}")
        if n := self.skipped.get(SKIP_TOO_RECENT, 0):
            reasons.append(f"{n:,} active after {format_bound(self.active_before)}")
        if n := self.skipped.get(SKIP_NO_BRANCHES, 0):
            reasons.append(f"{n:,} without branches to scan")
        return reasons


def build_scan_plan(projects: Iterable[Project | Mapping[str, Any]], options: ScanOptions) -> ScanPlan:
    """
    Decide once which projects and branches a search scans.

    Uses skip_reason() and branches_to_scan(); a project that passes the
    filters but has no branch to scan is counted as SKIP_NO_BRANCHES. Fork
    upstreams are resolved against the full index, so an upstream excluded by
    a filter still serves "branch-diff".

    Args:
        projects: The whole project index (Projects, or index records as dicts).
        options: Scan options.

    Returns:
        ScanPlan with targets in index order and skip counters.
    """
    projects = [as_project(p) for p in projects]
    projects_by_id = {p.id: p for p in projects}
    targets: list[tuple[Project, tuple[str, ...]]] = []
    skipped: Counter[str] = Counter()
    by_name = 0

    for project in projects:
        reason = skip_reason(project, options)
        branches: list[str] = []
        if reason is None:
            branches = branches_to_scan(project, options, projects_by_id=projects_by_id)
            if not branches:
                reason = SKIP_NO_BRANCHES
        if reason is not None:
            skipped[reason] += 1
            continue
        targets.append((project, tuple(branches)))
        by_name += fork_compared_by_name(project, options, projects_by_id)

    return ScanPlan(
        targets=tuple(targets),
        total_projects=len(projects),
        skipped=dict(skipped),
        started_from=options.started_from,
        active_before=options.active_before,
        project_filter=tuple(options.project_filter),
        projects_by_id=projects_by_id,
        forks_by_name=by_name,
    )
