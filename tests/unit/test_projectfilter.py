"""--project-filter (glh.projectfilter) and its place in the scan plan."""

from __future__ import annotations

import pytest

from glh.cli import CliParser
from glh.planner import SKIP_FILTERED, ScanOptions, build_scan_plan, skip_reason
from glh.projectfilter import ProjectFilter, ProjectFilterError, parse_patterns, project_path


def project(path: str, pid: int = 1, **extra) -> dict:
    return {"id": pid, "path_with_namespace": path, "default_branch": "main", "branches": ["main"], **extra}


@pytest.mark.parametrize(("patterns", "path", "matches"), [
    (("k8s",), "infra/k8s-deploy", True),
    (("k8s",), "K8S/charts", True),
    (("k8s",), "team/my-k8s", True),
    (("k8s",), "team/kubernetes", False),
    (("infra/*",), "infra/k8s/deploy", True),
    (("infra/*",), "ops/infra/terraform", False),
    (("*-k8s",), "team/my-k8s", True),
    (("*-k8s",), "team/my-k8s-old", False),
    (("api-servic?",), "acme/api-service", False),  # wildcards: the whole path
    (("*/api-servic?",), "acme/api-service", True),
    (("[a]",), "x/[a]/y", True),  # literal, not a character class
    (("k8s", "terraform"), "ops/infra/terraform/modules", True),
])
def test_matching(patterns, path, matches):
    assert ProjectFilter(patterns).matches(project(path)) is matches


def test_empty_filter_passes_everything_and_web_url_is_a_fallback():
    assert not ProjectFilter() and ProjectFilter().matches(project("x"))
    old = {"id": 1, "web_url": "https://gitlab.test/infra/k8s-deploy"}
    assert project_path(old) == "infra/k8s-deploy" and ProjectFilter(("k8s",)).matches(old)
    assert ProjectFilter(("k8s", "infra/*")).describe() == "k8s, infra/*"


def test_parse_patterns():
    assert parse_patterns(" k8s , infra/* ,k8s, /charts/ ") == ("k8s", "infra/*", "charts")
    for bad in ("", " , ", "my project"):
        with pytest.raises(ProjectFilterError):
            parse_patterns(bad)


def test_cli_option():
    assert CliParser.parse(["--project-filter", "k8s,infra/*"]).project_filter == ("k8s", "infra/*")
    assert CliParser.parse([]).project_filter == ()
    with pytest.raises(SystemExit):
        CliParser.parse(["--project-filter", ","])


def test_scan_plan_skips_and_describes_filtered_projects():
    projects = [project("infra/k8s-deploy", 1), project("acme/web", 2), project("ops/k8s-empty", 3, empty_repo=True)]
    options = ScanOptions(project_filter=("k8s",))
    assert skip_reason(projects[1], options) == SKIP_FILTERED
    plan = build_scan_plan(projects, options)
    assert [p["id"] for p, _ in plan.targets] == [1]
    assert plan.skipped == {SKIP_FILTERED: 1, "empty": 1}
    assert "1 not matching --project-filter k8s" in plan.describe()
