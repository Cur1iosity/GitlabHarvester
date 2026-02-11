# glh/planner.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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
    """
    scan_branches: BranchesMode = "default"  # default|all|N
    forks_mode: str = "include"  # skip|include|branch-diff|all-branches
    fork_diff_bases: tuple[str, ...] = ("main", "master", "develop", "dev")


def is_fork_project(project: dict[str, Any]) -> bool:
    """
    Determine whether the given project represents a fork.

    The function checks for explicit upstream relationship indicators
    commonly stored in the project index:

    - `upstream_project_id` – direct reference to the original project,
    - `forked_from_project` – GitLab attribute present on forked repositories.

    Args:
        project: Project dictionary loaded from the project index.

    Returns:
        True if the project is identified as a fork, otherwise False.
    """
    upstream_id = project.get("upstream_project_id")
    if upstream_id:
        return True

    f = project.get("forked_from_project")
    return bool(f and f is not False)


def get_upstream_id(project: dict[str, Any]) -> int | None:
    """
    Extract the upstream (source) project ID for a forked project.

    The function attempts to resolve the identifier of the original project
    using fields commonly stored in the project index:

    1. `upstream_project_id` – explicit normalized reference if present.
    2. `forked_from_project["id"]` – raw GitLab API structure for forks.

    Args:
        project: Project dictionary loaded from the project index.

    Returns:
        Upstream project ID as int if the project is a fork,
        otherwise None.
    """
    upstream_id = project.get("upstream_project_id")
    if upstream_id:
        return int(upstream_id)

    f = project.get("forked_from_project")
    if isinstance(f, dict) and "id" in f:
        return int(f["id"])

    return None


def should_scan_project(project: dict[str, Any], options: ScanOptions) -> bool:
    """
    Determine whether a project should be included in the search process.

    The decision is based on basic project properties and fork-handling strategy:

    - Empty repositories are always skipped.
    - Forked projects are skipped when forks_mode is set to "skip".
    - All other projects are eligible for scanning.

    Args:
        project: Project dictionary from the project index.
        options: ScanOptions defining fork-handling rules.

    Returns:
        True if the project should be scanned, otherwise False.
    """
    if project.get("empty_repo", False):
        return False
    if is_fork_project(project) and options.forks_mode == "skip":
        return False
    return True


def select_branches_from_index(project: dict[str, Any], mode: BranchesMode) -> list[str]:
    """
    Select a subset of branches for scanning based on the chosen scan mode.

    The function operates only on branches already stored in the project index
    and does not perform any GitLab API calls.

    Selection rules:

    - "all" → return all indexed branches as-is.
    - "default" → return only the default branch (first indexed branch or
      explicit default_branch field).
    - int (N) → return up to N branches, ensuring the default branch is included
      when available (default + N-1 others).

    Args:
        project: Project entry from the index containing "branches" and
            "default_branch" fields.
        mode: Branch selection mode: "default", "all", or positive integer.

    Returns:
        List of branch names selected for scanning. May be empty if no
        branches are available and default_branch is not defined.
    """
    branches = project.get("branches") or []
    default_branch = project.get("default_branch")

    if mode == "all":
        return list(branches)

    if mode == "default":
        if branches:
            return branches[:1]
        return [default_branch] if default_branch else []

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
        fork_project: dict[str, Any],
        upstream_project: dict[str, Any] | None,
        scan_mode: BranchesMode,
        base_branches: tuple[str, ...],
) -> list[str]:
    """
    Select branches for a forked project using a diff-based strategy.

    The goal is to reduce redundant scanning by prioritizing:
    1) The fork's default branch (if present),
    2) A predefined set of base branches (e.g., main/master/develop),
    3) Branches that exist in the fork but not in the upstream project.

    This approach avoids re-scanning branches identical to the upstream
    while still covering fork-specific changes.

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
    fork_branches = set(fork_project.get("branches") or [])
    upstream_branches = set(upstream_project.get("branches") or []) if upstream_project else set()

    selected: list[str] = []

    default_branch = fork_project.get("default_branch")
    if default_branch and default_branch in fork_branches:
        selected.append(default_branch)

    for b in base_branches:
        if b in fork_branches and b not in selected:
            selected.append(b)

    unique = sorted(fork_branches - upstream_branches)
    for b in unique:
        if b not in selected:
            selected.append(b)

    if scan_mode == "all":
        return selected
    if scan_mode == "default":
        return selected[:1]
    return selected[: int(scan_mode)]


def branches_to_scan(
    project: dict[str, Any],
    options: ScanOptions,
    projects_by_id: dict[int, dict[str, Any]] | None = None,
) -> list[str]:
    """
    Determine which branches should be scanned for a given project.

    The selection is derived from the project index data and controlled by
    ScanOptions. Forked projects may use specialized strategies depending
    on forks_mode:

    - "all-branches": scan every indexed branch for forks.
    - "branch-diff": scan fork branches using diff-based selection relative
      to upstream (default + base branches + fork-unique branches).
      If upstream is not available in the provided index map, falls back
      to regular branch selection.

    Non-fork projects (or forks with other modes) use the standard
    select_branches_from_index() behavior.

    Args:
        project: Project entry from the index.
        options: ScanOptions controlling branch scope and fork behavior.
        projects_by_id: Optional mapping of project_id -> project entry,
            used to resolve upstream projects for forks in "branch-diff" mode.

    Returns:
        List of branch names to scan for the project. The list may be empty if
        no branch information is available.
    """
    is_fork = is_fork_project(project)

    if is_fork and options.forks_mode == "all-branches":
        return list(project.get("branches") or [])

    if is_fork and options.forks_mode == "branch-diff":
        upstream_id = get_upstream_id(project)
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
