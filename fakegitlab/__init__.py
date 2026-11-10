"""
fakegitlab — a declarative Fake GitLab REST API v4 for GitlabHarvester development.

Not a GitLab emulator: it serves the subset of endpoints GitlabHarvester (via
python-gitlab) actually uses, backed by YAML/JSON scenarios, with pagination,
blob search, fault injection and a request journal.

Typical usage::

    from fakegitlab import FakeGitLab

    with FakeGitLab("default") as fake:
        gl = gitlab.Gitlab(fake.url, private_token=fake.token)
        gl.auth()

Standalone::

    python -m fakegitlab --scenario default --port 8080
"""

from fakegitlab.faults import FaultRule
from fakegitlab.scenario import Scenario, ScenarioError, available_scenarios, load_scenario
from fakegitlab.server import FakeGitLab, RecordedRequest

__all__ = [
    "FakeGitLab",
    "FaultRule",
    "RecordedRequest",
    "Scenario",
    "ScenarioError",
    "available_scenarios",
    "load_scenario",
]
