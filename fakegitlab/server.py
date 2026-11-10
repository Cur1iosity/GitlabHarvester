"""
Fake GitLab HTTP server built on top of ``pytest-httpserver`` (Werkzeug).

The same :class:`FakeGitLab` object powers both usage modes:

- **pytest**: started once per session by ``tests/conftest.py`` and reset
  before every test. Tests may additionally register one-off handlers via
  :attr:`FakeGitLab.httpserver` (``expect_oneshot_request``), which take
  precedence over the data-driven API.
- **standalone**: ``python -m fakegitlab`` (or ``docker compose up``) for
  manual development with the real CLI.

Diagnostics endpoints (not part of GitLab, prefixed with ``/__admin``):

=========================  ==================================================
``GET  /__admin/health``   liveness probe
``GET  /__admin/requests`` request journal (method, path, query, status, ...)
``DELETE /__admin/requests`` clear the journal
``POST /__admin/reset``    reload current scenario, clear journal and faults
``GET  /__admin/scenario`` current scenario summary and available scenarios
``POST /__admin/scenario`` switch scenario: ``{"name": "<scenario>"}``
``GET  /__admin/faults``   active fault rules with counters
``POST /__admin/faults``   add a fault rule (see :mod:`fakegitlab.faults`)
``DELETE /__admin/faults`` remove all fault rules
=========================  ==================================================
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Request, Response

from fakegitlab.api import GitLabApi, json_response, raw_request_path
from fakegitlab.faults import FaultInjector, FaultRule
from fakegitlab.scenario import Scenario, available_scenarios, load_scenario

ADMIN_PREFIX = "/__admin"
_SENSITIVE_HEADERS = {"private-token", "authorization", "job-token"}

logger = logging.getLogger("fakegitlab")


@dataclass(frozen=True, slots=True)
class RecordedRequest:
    """One entry of the request journal."""

    seq: int
    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    status: int
    endpoint: str | None
    faults: list[str] = field(default_factory=list)
    duration_ms: float = 0.0

    def arg(self, name: str) -> str | None:
        """Return the first value of a query parameter."""
        values = self.query.get(name)
        return values[0] if values else None

    def to_dict(self, *, redact: bool = True) -> dict[str, Any]:
        """JSON-friendly representation (tokens redacted by default)."""
        data = asdict(self)
        if redact:
            data["headers"] = {
                k: ("<redacted>" if k.lower() in _SENSITIVE_HEADERS else v) for k, v in self.headers.items()
            }
        return data


class FakeGitLab:
    """Data-driven fake GitLab REST API v4 server."""

    journal_limit: int = 50_000

    def __init__(
            self,
            scenario: str | Scenario | Mapping[str, Any] = "default",
            *,
            host: str = "127.0.0.1",
            port: int = 0,
            external_url: str | None = None,
            threaded: bool = True,
            admin: bool = True,
            ssl_context: Any = None,
    ) -> None:
        # ssl_context (ssl.SSLContext) serves HTTPS, e.g. with a trustme certificate in tests.
        self.httpserver = HTTPServer(host=host, port=port, threaded=threaded, ssl_context=ssl_context)
        self._external_url_override = external_url
        self._admin_enabled = admin
        self._faults = FaultInjector()
        self._journal: list[RecordedRequest] = []
        self._lock = threading.Lock()
        self._seq = 0
        # Set on reset/stop so in-flight artificial delays end immediately.
        self._abort_delays = threading.Event()

        self._scenario_ref: str | Scenario | Mapping[str, Any] = scenario
        self.scenario: Scenario = load_scenario(scenario)  # type: ignore[arg-type]
        self.api = GitLabApi(self.scenario)
        self._faults.load(list(self.scenario.faults))

    # --------------------------------------------------------------- lifecycle

    def start(self) -> "FakeGitLab":
        """Start serving in a background thread."""
        self.httpserver.start()
        self._register_catch_all()
        logger.info("Fake GitLab listening on %s (scenario: %s)", self.url, self.scenario.name)
        return self

    def stop(self) -> None:
        """Stop the server and abort pending delays."""
        self._abort_delays.set()
        if self.httpserver.is_running():
            self.httpserver.stop()

    def __enter__(self) -> "FakeGitLab":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    @property
    def url(self) -> str:
        """Base URL to pass to python-gitlab / the CLI (no trailing slash)."""
        return self.httpserver.url_for("/").rstrip("/")

    @property
    def token(self) -> str:
        """A valid token from the current scenario."""
        return self.scenario.default_token

    # ------------------------------------------------------------------- state

    def reset(self, scenario: str | Scenario | Mapping[str, Any] | None = None) -> None:
        """
        Restore a pristine state.

        Reloads the scenario (optionally switching to another one), restores its
        declared faults, clears the request journal and removes ad-hoc handlers
        registered through :attr:`httpserver`.
        """
        self._abort_delays.set()
        if scenario is not None:
            self._scenario_ref = scenario
        self.scenario = load_scenario(self._scenario_ref)  # type: ignore[arg-type]
        self.api = GitLabApi(self.scenario)
        self._faults.load(list(self.scenario.faults))
        with self._lock:
            self._journal = []
            self._seq = 0
        if self.httpserver.is_running():
            self.httpserver.clear()
            self._register_catch_all()
        self._abort_delays = threading.Event()

    def add_fault(self, rule: Mapping[str, Any] | FaultRule) -> FaultRule:
        """Add a fault rule at runtime (see :mod:`fakegitlab.faults`)."""
        return self._faults.add(rule)

    def clear_faults(self) -> None:
        """Remove all fault rules, including scenario-declared ones."""
        self._faults.clear()

    @property
    def faults(self) -> list[dict[str, Any]]:
        """Summary of fault rules with hit counters."""
        return self._faults.describe()

    # ----------------------------------------------------------------- journal

    @property
    def requests(self) -> list[RecordedRequest]:
        """All recorded requests except admin calls, in arrival order."""
        with self._lock:
            return list(self._journal)

    def api_requests(self, endpoint: str | None = None, path: str | None = None) -> list[RecordedRequest]:
        """Recorded API requests filtered by endpoint name and/or path regex."""
        rx = re.compile(path) if path else None
        return [
            r for r in self.requests
            if (endpoint is None or r.endpoint == endpoint) and (rx is None or rx.search(r.path))
        ]

    def unmatched_requests(self) -> list[RecordedRequest]:
        """Requests that did not hit any implemented endpoint."""
        return [r for r in self.requests if r.endpoint is None]

    def clear_journal(self) -> None:
        """Clear the request journal."""
        with self._lock:
            self._journal = []

    # ---------------------------------------------------------------- dispatch

    def _register_catch_all(self) -> None:
        self.httpserver.expect_request(re.compile(r".*")).respond_with_handler(self._dispatch)

    def _base_url(self, request: Request) -> str:
        return (
            self._external_url_override
            or self.scenario.instance.external_url
            or request.host_url
        ).rstrip("/")

    def _dispatch(self, request: Request) -> Response:
        raw_path = raw_request_path(request)
        if raw_path.startswith(ADMIN_PREFIX):
            if not self._admin_enabled:
                return json_response({"message": "404 Not Found"}, status=404)
            return self._admin(request, raw_path[len(ADMIN_PREFIX):])

        started = time.perf_counter()
        decision = self._faults.evaluate(request, raw_path)
        if decision.delay > 0:
            self._abort_delays.wait(decision.delay)

        endpoint: str | None
        if decision.response is not None:
            response = decision.response
            endpoint = self.api.endpoint_for(raw_path)
        else:
            result = self.api.handle(request, self._base_url(request))
            response, endpoint = result.response, result.endpoint

        self._record(request, raw_path, response, endpoint, decision.applied, started)
        return response

    def _record(
            self,
            request: Request,
            raw_path: str,
            response: Response,
            endpoint: str | None,
            faults: list[str],
            started: float,
    ) -> None:
        with self._lock:
            self._seq += 1
            entry = RecordedRequest(
                seq=self._seq,
                method=request.method,
                path=raw_path,
                query={k: request.args.getlist(k) for k in request.args.keys()},
                headers=dict(request.headers.items()),
                status=response.status_code,
                endpoint=endpoint,
                faults=list(faults),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )
            self._journal.append(entry)
            # Bound memory for long-running standalone sessions.
            if len(self._journal) > self.journal_limit:
                del self._journal[: len(self._journal) - self.journal_limit]
            if len(self.httpserver.log) > 1000:
                del self.httpserver.log[:-100]

        level = logging.WARNING if endpoint is None else logging.INFO
        logger.log(
            level,
            "%s %s%s -> %s%s%s",
            request.method,
            raw_path,
            f"?{request.query_string.decode()}" if request.query_string else "",
            response.status_code,
            f" [faults: {', '.join(faults)}]" if faults else "",
            " [UNMATCHED: endpoint not implemented]" if endpoint is None else "",
        )

    # ------------------------------------------------------------------- admin

    def _admin(self, request: Request, sub: str) -> Response:
        method = request.method.upper()
        sub = sub.rstrip("/") or "/"
        try:
            body = json.loads(request.get_data(as_text=True) or "{}") if method in ("POST", "PUT") else {}
        except json.JSONDecodeError:
            return json_response({"error": "invalid JSON body"}, status=400)

        if sub == "/health":
            return json_response({"status": "ok", "scenario": self.scenario.name})

        if sub == "/requests":
            if method == "DELETE":
                self.clear_journal()
                return json_response({"cleared": True})
            return json_response([r.to_dict() for r in self.requests])

        if sub == "/reset" and method == "POST":
            self.reset()
            return json_response({"reset": True, "scenario": self.scenario.name})

        if sub == "/scenario":
            if method == "POST":
                name = body.get("name")
                if not name:
                    return json_response({"error": "name is required"}, status=400)
                try:
                    self.reset(scenario=name)
                except ValueError as e:
                    return json_response({"error": str(e)}, status=400)
            return json_response(
                {
                    "name": self.scenario.name,
                    "description": self.scenario.description,
                    "source": self.scenario.source,
                    "projects": len(self.scenario.projects),
                    "token": self.scenario.default_token,
                    "available": available_scenarios(),
                }
            )

        if sub == "/faults":
            if method == "POST":
                try:
                    rule = self.add_fault(body)
                except (KeyError, TypeError, ValueError, re.error) as e:
                    return json_response({"error": f"invalid fault rule: {e}"}, status=400)
                return json_response({"added": rule.name}, status=201)
            if method == "DELETE":
                self.clear_faults()
                return json_response({"cleared": True})
            return json_response(self.faults)

        return json_response({"error": f"unknown admin endpoint {sub}"}, status=404)
