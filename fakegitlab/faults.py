"""
Declarative fault injection for the Fake GitLab API.

A fault rule matches incoming requests and either replaces the response
(HTTP errors, malformed bodies, custom headers) or delays it before the
normal handler runs.

Rule format (YAML/JSON or Python dict)::

    - name: projects-page-2-fails        # optional, used in logs
      match:
        method: GET                      # optional, default: any
        path: "^/api/v4/projects$"       # regex matched against the raw path
        query:                           # optional, exact string match
          page: "2"                      # "*" = parameter must be present
        headers:                         # optional, exact match (case-insensitive name)
          PRIVATE-TOKEN: "*"
      after: 0                           # skip the first N matching requests
      times: 1                           # apply at most N times (default: unlimited)
      response:
        delay: 0.2                       # seconds; alone = delay then normal response
        status: 500                      # replaces the response when set
        json: {message: "500 Internal Server Error"}
        body: "<html>not json</html>"    # raw body (takes precedence over json)
        headers: {Retry-After: "0"}
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Mapping

from werkzeug.wrappers import Request, Response

_ANY = "*"


@dataclass(slots=True)
class FaultRule:
    """A single compiled fault rule with its own hit counters."""

    name: str
    method: str | None
    path: re.Pattern[str]
    query: dict[str, str]
    headers: dict[str, str]
    after: int
    times: int | None
    status: int | None
    json_body: Any
    raw_body: str | None
    response_headers: dict[str, str]
    delay: float
    seen: int = 0
    applied: int = 0

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "FaultRule":
        """Compile a rule from its declarative form."""
        match = raw.get("match") or {}
        resp = raw.get("response") or {}
        path = match.get("path", ".*")

        status = resp.get("status")
        has_body = "json" in resp or "body" in resp
        if status is None and has_body:
            status = 200

        times = raw.get("times")
        return cls(
            name=str(raw.get("name") or f"{match.get('method', '*')} {path}"),
            method=str(match["method"]).upper() if match.get("method") else None,
            path=re.compile(path),
            query={str(k): str(v) for k, v in (match.get("query") or {}).items()},
            headers={str(k).lower(): str(v) for k, v in (match.get("headers") or {}).items()},
            after=int(raw.get("after", 0)),
            times=None if times is None else int(times),
            status=None if status is None else int(status),
            json_body=resp.get("json"),
            raw_body=None if resp.get("body") is None else str(resp["body"]),
            response_headers={str(k): str(v) for k, v in (resp.get("headers") or {}).items()},
            delay=float(resp.get("delay", 0) or 0),
        )

    @property
    def exhausted(self) -> bool:
        """True once the rule has been applied ``times`` times."""
        return self.times is not None and self.applied >= self.times

    def matches(self, request: Request, raw_path: str) -> bool:
        """Check method, path, query and header constraints."""
        if self.method and request.method.upper() != self.method:
            return False
        if not self.path.search(raw_path):
            return False
        for k, v in self.query.items():
            actual = request.args.get(k)
            if actual is None or (v != _ANY and actual != v):
                return False
        for k, v in self.headers.items():
            actual = request.headers.get(k)
            if actual is None or (v != _ANY and actual != v):
                return False
        return True

    def build_response(self) -> Response | None:
        """Return the replacement response, or None for delay-only rules."""
        if self.status is None:
            return None
        headers = dict(self.response_headers)
        if self.raw_body is not None:
            headers.setdefault("Content-Type", "application/json")
            return Response(self.raw_body, status=self.status, headers=headers)
        body = "" if self.json_body is None else json.dumps(self.json_body)
        headers.setdefault("Content-Type", "application/json")
        return Response(body, status=self.status, headers=headers)


@dataclass(slots=True)
class FaultDecision:
    """Outcome of fault evaluation for one request."""

    delay: float = 0.0
    response: Response | None = None
    applied: list[str] = field(default_factory=list)


class FaultInjector:
    """Thread-safe ordered collection of fault rules."""

    def __init__(self) -> None:
        self._rules: list[FaultRule] = []
        self._lock = threading.Lock()

    def load(self, rules: list[Mapping[str, Any]]) -> None:
        """Replace all rules (counters are reset)."""
        compiled = [FaultRule.from_dict(r) for r in rules]
        with self._lock:
            self._rules = compiled

    def add(self, rule: Mapping[str, Any] | FaultRule) -> FaultRule:
        """Append a rule and return the compiled object."""
        compiled = rule if isinstance(rule, FaultRule) else FaultRule.from_dict(rule)
        with self._lock:
            self._rules.append(compiled)
        return compiled

    def clear(self) -> None:
        """Remove all rules."""
        with self._lock:
            self._rules = []

    def describe(self) -> list[dict[str, Any]]:
        """Return a JSON-friendly summary of rules and counters."""
        with self._lock:
            return [
                {
                    "name": r.name,
                    "method": r.method,
                    "path": r.path.pattern,
                    "query": r.query,
                    "status": r.status,
                    "delay": r.delay,
                    "after": r.after,
                    "times": r.times,
                    "seen": r.seen,
                    "applied": r.applied,
                }
                for r in self._rules
            ]

    def evaluate(self, request: Request, raw_path: str) -> FaultDecision:
        """
        Evaluate rules in order.

        Delays accumulate across matching rules; the first rule that provides a
        replacement response wins and stops evaluation.
        """
        decision = FaultDecision()
        with self._lock:
            for rule in self._rules:
                if rule.exhausted or not rule.matches(request, raw_path):
                    continue
                rule.seen += 1
                if rule.seen <= rule.after:
                    continue
                rule.applied += 1
                decision.applied.append(rule.name)
                decision.delay += rule.delay
                resp = rule.build_response()
                if resp is not None:
                    decision.response = resp
                    break
        return decision
