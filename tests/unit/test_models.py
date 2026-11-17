"""The records of the project index as objects (glh.domain.models)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from glh.domain.models import as_project, IndexMeta, Project

# A project record as the index writer of 1.4.2 wrote it (key order included).
RECORD = {
    "id": 101,
    "web_url": "https://gitlab.test/acme/api",
    "path_with_namespace": "acme/api",
    "default_branch": "main",
    "empty_repo": False,
    "forked_from_project": False,
    "created_at": "2024-01-01T00:00:00.000Z",
    "last_activity_at": "2024-06-10T12:00:00.000Z",
}
FORK_RECORD = {**RECORD, "id": 102, "forked_from_project": {"id": 101}, "branches": ["develop", "main"]}
META_RECORD = {
    "type": "meta",
    "source": "gitlab_test",
    "timestamp_utc": "2024-06-10T12:00:00+00:00",
    "projects_count": 2,
    "elapsed_seconds": 0.42,
    "order_by": "id",
    "sort": "desc",
    "per_page": 100,
    "last_activity_after": None,
    "last_activity_before": None,
    "is_completed": True,
}


@pytest.mark.parametrize("record", [RECORD, FORK_RECORD, {**RECORD, "branches": []},
                                    {**RECORD, "default_branch": None, "empty_repo": True}])
def test_project_records_round_trip_byte_for_byte(record):
    line = json.dumps(record, ensure_ascii=False)
    assert json.dumps(Project.from_record(json.loads(line)).to_record(), ensure_ascii=False) == line


def test_meta_record_round_trips_byte_for_byte():
    for record in (META_RECORD, {**META_RECORD, "branches": "all"}, {**META_RECORD, "branches": 5}):
        line = json.dumps(record)
        assert json.dumps(IndexMeta.from_record(json.loads(line)).to_record()) == line


@pytest.mark.parametrize(("extra", "is_fork", "upstream"), [
    ({"forked_from_project": False}, False, None),
    ({"forked_from_project": None}, False, None),
    ({"forked_from_project": {"id": 7}}, True, 7),
    ({"forked_from_project": {"id": "8"}}, True, 8),
    ({"forked_from_project": {"name": "no id"}}, True, None),
    ({"upstream_project_id": 9}, True, 9),  # legacy normalized key
    ({"upstream_project_id": "11", "forked_from_project": False}, True, 11),
    ({"upstream_project_id": "garbage"}, True, None),
])
def test_fork_fields(extra, is_fork, upstream):
    project = Project.from_record({"id": 1, **extra})
    assert (project.is_fork, project.upstream_id) == (is_fork, upstream)


def test_old_and_minimal_records_get_defaults():
    project = Project.from_record({"id": "5"})
    assert project == Project(id=5)
    assert project.branches is None and project.branch_names == ()
    assert "branches" not in project.to_record()
    assert Project.from_record({"id": 1, "branches": ["main", 3, None, "dev"]}).branches == ("main", "dev")
    assert Project.from_record({"id": 1, "branches": None}).branches is None


@pytest.mark.parametrize("record", [{}, {"id": None}, {"id": "x"}, {"id": True}])
def test_a_record_without_an_id_is_rejected(record):
    with pytest.raises(ValueError):
        Project.from_record(record)


def test_names_and_paths():
    assert Project.from_record(RECORD).name == "acme/api"
    old = Project.from_record({"id": 1, "web_url": "https://gitlab.test/infra/k8s-deploy"})
    assert old.name == "https://gitlab.test/infra/k8s-deploy" and old.path == "infra/k8s-deploy"
    assert Project(id=1).path == ""


def test_last_activity_is_parsed():
    assert Project.from_record(RECORD).last_activity == datetime(2024, 6, 10, 12, tzinfo=timezone.utc)
    assert Project(id=1, last_activity_at="not-a-date").last_activity is None


def test_with_branches_and_as_project():
    project = Project.from_record(RECORD)
    assert project.with_branches(["main"]).to_record()["branches"] == ["main"]
    assert as_project(project) is project
    assert as_project(RECORD) == project


def test_branch_heads_round_trip_and_tolerate_broken_values():
    record = {**RECORD, "branches": ["develop", "main", "wip"],
              "branch_heads": {"develop": "d" * 40, "main": "0123456789abcdef" * 2 + "01234567"}}
    project = Project.from_record(record)
    assert project.heads() == record["branch_heads"]  # wip: no commit known
    assert len(project.branch_heads) == 3 * 20  # raw SHA-1 digests, not hex strings
    assert project.to_record() == record and list(project.to_record())[-2:] == ["branches", "branch_heads"]
    assert Project.from_record(RECORD).heads() is None and "branch_heads" not in Project.from_record(RECORD).to_record()
    sha256 = {**record, "branch_heads": {"main": "e" * 64}}
    assert Project.from_record(sha256).heads() == {"main": "e" * 64}
    for broken in (["not", "a", "map"], None):
        assert Project.from_record({**record, "branch_heads": broken}).heads() is None
    assert Project.from_record({**record, "branch_heads": {"main": 1, "develop": "zz" * 20}}).heads() == {}
    assert Project.from_record({**record, "branch_heads": {}}).heads() == {}
    assert Project.from_record({"id": 1, "branch_heads": {"main": "d" * 40}}).heads() is None  # no branches


def test_index_meta_of_anything():
    assert IndexMeta.from_record(None) == IndexMeta()
    assert IndexMeta.from_record(["not", "a", "record"]) == IndexMeta()
    meta = IndexMeta.from_record({"timestamp_utc": "2024-06-10T15:00:00+03:00", "is_completed": "yes",
                                  "branches": True, "last_activity_after": "2024-06-01T00:00:00Z"})
    assert meta.is_completed is None and meta.branches is None
    assert meta.built_at == datetime(2024, 6, 10, 12, tzinfo=timezone.utc)
    assert meta.window and meta.window.describe() == "since 2024-06-01"
    assert not IndexMeta().window


def test_index_meta_branches_incomplete():
    meta = IndexMeta.from_record({"is_completed": False, "branches": "all", "branches_incomplete": 3})
    assert meta.branches_incomplete == 3 and meta.incomplete_reason == "branch lists of 3 projects failed"
    assert list(meta.to_record())[-2:] == ["branches", "branches_incomplete"]
    assert IndexMeta(is_completed=False).incomplete_reason == "listing failed"
    assert IndexMeta(is_completed=True).incomplete_reason is None
    assert "branches_incomplete" not in IndexMeta(branches="all").to_record()
