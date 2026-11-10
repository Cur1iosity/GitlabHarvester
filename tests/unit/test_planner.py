"""Project selection, branch strategies and fork handling (glh.planner)."""

from __future__ import annotations

import pytest

from glh.planner import (
    ScanOptions,
    branches_to_scan,
    get_upstream_id,
    is_fork_project,
    select_branches_from_index,
    select_fork_branches_diff,
    should_scan_project,
)


def proj(pid: int = 1, *, branches=None, default="main", fork_of=None, empty=False, **extra):
    """Build an index-shaped project entry."""
    return {
        "id": pid,
        "web_url": f"http://gitlab.test/g/p{pid}",
        "path_with_namespace": f"g/p{pid}",
        "default_branch": default,
        "empty_repo": empty,
        "forked_from_project": {"id": fork_of} if fork_of else False,
        "branches": list(branches) if branches is not None else ([default] if default else []),
        **extra,
    }


# --------------------------------------------------------------------------- fork detection


@pytest.mark.parametrize(
    ("entry", "is_fork", "upstream"),
    [
        (proj(forked_from_project=False), False, None),
        (proj(forked_from_project=None), False, None),
        (proj(fork_of=7), True, 7),
        (proj(upstream_project_id=9), True, 9),
        (proj(upstream_project_id="11"), True, 11),
        ({"id": 1}, False, None),
    ],
)
def test_fork_detection(entry, is_fork, upstream):
    assert is_fork_project(entry) is is_fork
    assert get_upstream_id(entry) == upstream


# --------------------------------------------------------------------------- project selection


@pytest.mark.parametrize("mode", ["include", "branch-diff", "all-branches", "skip"])
def test_empty_repositories_are_never_scanned(mode):
    assert should_scan_project(proj(empty=True), ScanOptions(forks_mode=mode)) is False


@pytest.mark.parametrize(("mode", "expected"), [("skip", False), ("include", True), ("branch-diff", True),
                                                ("all-branches", True)])
def test_forks_selection_by_mode(mode, expected):
    assert should_scan_project(proj(fork_of=1), ScanOptions(forks_mode=mode)) is expected


def test_regular_project_is_scanned_in_skip_mode():
    assert should_scan_project(proj(), ScanOptions(forks_mode="skip")) is True


# --------------------------------------------------------------------------- branch selection


def test_default_mode_prefers_default_branch_over_name_order():
    # GitLab returns branches sorted by name: "develop" precedes "main".
    p = proj(branches=["develop", "feature/x", "main"], default="main")
    assert select_branches_from_index(p, "default") == ["main"]


def test_default_mode_falls_back_to_first_branch_without_default():
    assert select_branches_from_index(proj(branches=["a", "b"], default=None), "default") == ["a"]


def test_default_mode_without_branch_info_uses_default_branch_field():
    assert select_branches_from_index(proj(branches=[], default="trunk"), "default") == ["trunk"]


def test_default_mode_with_nothing_known_returns_empty():
    assert select_branches_from_index(proj(branches=[], default=None), "default") == []


def test_all_mode_returns_every_indexed_branch_in_order():
    br = ["b", "a", "main"]
    assert select_branches_from_index(proj(branches=br), "all") == br


@pytest.mark.parametrize(
    ("branches", "n", "expected"),
    [
        (["a", "b", "main", "z"], 2, ["main", "a"]),  # default injected first
        (["main", "a", "b"], 2, ["main", "a"]),
        (["a", "b"], 5, ["main", "a", "b"]),  # default not indexed: still included
        (["a", "b", "main"], 1, ["main"]),
    ],
)
def test_limit_mode_always_contains_default_branch(branches, n, expected):
    assert select_branches_from_index(proj(branches=branches, default="main"), n) == expected[:n]


def test_limit_mode_zero_returns_nothing():
    assert select_branches_from_index(proj(branches=["main"]), 0) == []


# --------------------------------------------------------------------------- fork strategies


UPSTREAM = proj(1, branches=["develop", "feature/shared", "main"])
FORK = proj(2, branches=["develop", "feature/shared", "fork/only", "main", "zz-unique"], fork_of=1)


def test_branch_diff_selects_default_bases_and_unique_branches():
    selected = select_fork_branches_diff(FORK, UPSTREAM, "all", ("main", "master", "develop"))
    assert selected == ["main", "develop", "fork/only", "zz-unique"]
    assert "feature/shared" not in selected


def test_branch_diff_respects_limits():
    assert select_fork_branches_diff(FORK, UPSTREAM, "default", ("main", "develop")) == ["main"]
    assert select_fork_branches_diff(FORK, UPSTREAM, 3, ("main", "develop")) == ["main", "develop", "fork/only"]


def test_branch_diff_without_upstream_treats_all_branches_as_unique():
    selected = select_fork_branches_diff(FORK, None, "all", ("main",))
    assert selected[0] == "main"
    assert set(selected) == set(FORK["branches"])


def test_branches_to_scan_branch_diff_uses_upstream_from_index():
    by_id = {1: UPSTREAM, 2: FORK}
    opts = ScanOptions(scan_branches="all", forks_mode="branch-diff", fork_diff_bases=("main", "develop"))
    assert branches_to_scan(FORK, opts, by_id) == ["main", "develop", "fork/only", "zz-unique"]


def test_branches_to_scan_branch_diff_falls_back_when_upstream_missing():
    opts = ScanOptions(scan_branches=2, forks_mode="branch-diff")
    # Upstream 1 is not in the map -> regular limit selection.
    assert branches_to_scan(FORK, opts, {2: FORK}) == select_branches_from_index(FORK, 2)


def test_branches_to_scan_all_branches_mode_ignores_scan_limit_for_forks():
    opts = ScanOptions(scan_branches="default", forks_mode="all-branches")
    assert branches_to_scan(FORK, opts, {}) == FORK["branches"]
    # Non-forks still honor the limit.
    assert branches_to_scan(UPSTREAM, opts, {}) == ["main"]


@pytest.mark.parametrize("mode", ["include", "skip"])
def test_branches_to_scan_include_treats_forks_as_regular(mode):
    opts = ScanOptions(scan_branches="all", forks_mode=mode)
    assert branches_to_scan(FORK, opts, {1: UPSTREAM}) == FORK["branches"]


# --------------------------------------------------------------------------- activity filter (--started-from)

from datetime import datetime, timedelta, timezone  # noqa: E402

from glh.planner import is_active_since, parse_timestamp  # noqa: E402

UTC = timezone.utc


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2024-06-01T12:00:00.000Z", datetime(2024, 6, 1, 12, tzinfo=UTC)),  # GitLab format
        ("2024-06-01T12:00:00Z", datetime(2024, 6, 1, 12, tzinfo=UTC)),
        ("2024-06-01T15:00:00+03:00", datetime(2024, 6, 1, 12, tzinfo=UTC)),
        ("2024-06-01", datetime(2024, 6, 1, tzinfo=UTC)),  # naive -> UTC
        ("2024-06-01 12:00", datetime(2024, 6, 1, 12, tzinfo=UTC)),
        ("garbage", None),
        ("", None),
        (None, None),
        (1717243200, None),
    ],
)
def test_parse_timestamp(raw, expected):
    assert parse_timestamp(raw) == expected


def test_is_active_since_boundaries():
    since = datetime(2024, 6, 1, 12, tzinfo=UTC)
    assert is_active_since(proj(last_activity_at="2024-06-01T12:00:00.000Z"), since) is True  # inclusive
    assert is_active_since(proj(last_activity_at="2024-06-01T11:59:59.999Z"), since) is False
    assert is_active_since(proj(last_activity_at="2024-06-01T14:00:00+03:00"), since) is False  # 11:00 UTC
    assert is_active_since(proj(last_activity_at="2025-01-01T00:00:00Z"), since) is True
    assert is_active_since(proj(last_activity_at="2020-01-01T00:00:00Z"), None) is True  # filter disabled


@pytest.mark.parametrize("value", [None, "", "not-a-date"])
def test_projects_with_unknown_activity_are_kept(value):
    since = datetime(2024, 6, 1, tzinfo=UTC)
    assert is_active_since(proj(last_activity_at=value), since) is True
    assert is_active_since({"id": 1}, since) is True  # old index without the field


@pytest.mark.parametrize("mode", ["include", "branch-diff", "all-branches", "skip"])
def test_should_scan_project_applies_started_from(mode):
    since = datetime(2024, 6, 1, tzinfo=UTC)
    old = proj(last_activity_at=(since - timedelta(days=1)).isoformat())
    new = proj(last_activity_at=(since + timedelta(days=1)).isoformat())
    opts = ScanOptions(forks_mode=mode, started_from=since)
    assert should_scan_project(old, opts) is False
    assert should_scan_project(new, opts) is True
    # Combined with other rules: empty repos and skipped forks stay excluded.
    assert should_scan_project(proj(empty=True, last_activity_at=new["last_activity_at"]), opts) is False


# --------------------------------------------------------------------------- scan plan (what progress counts)

from glh.planner import (  # noqa: E402
    SKIP_EMPTY,
    SKIP_FORK,
    SKIP_INACTIVE,
    SKIP_NO_BRANCHES,
    build_scan_plan,
    skip_reason,
)


def test_skip_reason_order_and_values():
    since = datetime(2024, 6, 1, tzinfo=UTC)
    opts = ScanOptions(forks_mode="skip", started_from=since)
    old = "2020-01-01T00:00:00Z"
    # An empty fork that is also inactive is reported as empty: rules are checked in order.
    assert skip_reason(proj(empty=True, fork_of=1, last_activity_at=old), opts) == SKIP_EMPTY
    assert skip_reason(proj(fork_of=1, last_activity_at=old), opts) == SKIP_FORK
    assert skip_reason(proj(last_activity_at=old), opts) == SKIP_INACTIVE
    assert skip_reason(proj(last_activity_at="2025-01-01T00:00:00Z"), opts) is None


def test_scan_plan_counts_only_scanned_projects_and_branches():
    since = datetime(2024, 6, 1, tzinfo=UTC)
    index = [
        proj(1, branches=["develop", "main"], last_activity_at="2024-07-01T00:00:00Z"),
        proj(2, empty=True, default=None),
        proj(3, fork_of=1, last_activity_at="2024-07-01T00:00:00Z"),
        proj(4, last_activity_at="2023-01-01T00:00:00Z"),
        proj(5, default=None, branches=[], last_activity_at="2024-07-01T00:00:00Z"),
    ]
    plan = build_scan_plan(index, ScanOptions(scan_branches="all", forks_mode="skip", started_from=since))

    assert [p["id"] for p, _ in plan.targets] == [1]
    assert plan.targets[0][1] == ("develop", "main")
    assert (plan.project_count, plan.branch_count, plan.total_projects) == (1, 2, 5)
    assert plan.skipped == {SKIP_EMPTY: 1, SKIP_FORK: 1, SKIP_INACTIVE: 1, SKIP_NO_BRANCHES: 1}
    assert plan.describe() == (
        "1 of 5 projects, 2 branches (skipped: 1 empty, 1 fork, 1 inactive since 2024-06-01, "
        "1 without branches to scan)"
    )


def test_scan_plan_keeps_filtered_upstream_for_branch_diff():
    # The upstream is inactive (excluded from the scan) but still drives the fork's branch diff.
    since = datetime(2024, 6, 1, tzinfo=UTC)
    upstream = proj(1, branches=["feature", "main"], last_activity_at="2023-01-01T00:00:00Z")
    fork = proj(2, fork_of=1, branches=["feature", "main", "mine"], last_activity_at="2024-07-01T00:00:00Z")
    plan = build_scan_plan([upstream, fork], ScanOptions(scan_branches="all", forks_mode="branch-diff",
                                                         started_from=since))
    assert [(p["id"], b) for p, b in plan.targets] == [(2, ("main", "mine"))]
    assert plan.skipped == {SKIP_INACTIVE: 1}


@pytest.mark.parametrize(
    ("since", "text"),
    [
        (datetime(2024, 6, 1, tzinfo=UTC), "since 2024-06-01"),
        (datetime(2024, 6, 1, 12, 30, tzinfo=UTC), "since 2024-06-01T12:30:00+00:00"),
        (datetime(2024, 6, 1, tzinfo=timezone(timedelta(hours=3))), "since 2024-06-01T00:00:00+03:00"),
    ],
)
def test_scan_plan_describes_the_activity_bound(since, text):
    plan = build_scan_plan([proj(last_activity_at="2020-01-01T00:00:00Z")], ScanOptions(started_from=since))
    assert plan.describe() == f"0 of 1 project, 0 branches (skipped: 1 inactive {text})"


def test_scan_plan_without_filters():
    plan = build_scan_plan([proj(1), proj(2)], ScanOptions())
    assert plan.describe() == "2 of 2 projects, 2 branches"
    assert plan.skipped == {}
