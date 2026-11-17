"""
Per-user API rate limits for the Fake GitLab, modelled on GitLab's.

GitLab has two kinds of limits that matter for GitlabHarvester:

- ``api``: every authenticated API request of a user (Rack::Attack
  ``throttle_authenticated_api``; the search API counts too). On HTTP 429 it
  sends ``RateLimit-Name``, ``RateLimit-Limit`` (per minute), ``RateLimit-Observed``,
  ``RateLimit-Remaining``, ``RateLimit-Reset`` (Unix time), ``RateLimit-ResetTime``
  and ``Retry-After``.
- ``search``: the search API only (application limit ``search_rate_limit``),
  usually far lower. Its 429 has no ``RateLimit-*`` headers.

Scenario format (top-level ``rate_limits`` key, or ``FakeGitLab.set_rate_limits``)::

    rate_limits:
      api:    {limit: 600, period: 60}             # requests per period per user
      search: {limit: 10, period: 60, headers: retry-after}
      # headers: full (default for api) | retry-after (default for search) | none
      # on_success: true -> RateLimit-* headers on every response of that bucket

Windows are fixed and aligned to the clock (like Rack::Attack): the count
starts again at every multiple of ``period``.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass
from email.utils import formatdate
from typing import Any, Callable, Mapping

from werkzeug.wrappers import Response

from fakegitlab.api import json_response

# Endpoints of the search bucket (logical names from fakegitlab.api).
SEARCH_ENDPOINTS = frozenset({"project_search"})
_NAMES = {"api": "throttle_authenticated_api", "search": "search_rate_limit"}
_HEADER_MODES = ("full", "retry-after", "none")


@dataclass(frozen=True, slots=True)
class Throttle:
    """One limit: ``limit`` requests per ``period`` seconds per user."""

    bucket: str
    limit: int
    period: float
    headers: str
    on_success: bool

    @classmethod
    def from_dict(cls, bucket: str, raw: Mapping[str, Any]) -> "Throttle":
        headers = str(raw.get("headers") or ("full" if bucket == "api" else "retry-after"))
        if headers not in _HEADER_MODES:
            raise ValueError(f"rate_limits.{bucket}.headers must be one of {_HEADER_MODES}")
        limit, period = int(raw["limit"]), float(raw.get("period", 60))
        if limit < 1 or period <= 0:
            raise ValueError(f"rate_limits.{bucket}: limit >= 1 and period > 0 required")
        return cls(bucket=bucket, limit=limit, period=period, headers=headers,
                   on_success=bool(raw.get("on_success", False)))

    @property
    def name(self) -> str:
        return _NAMES.get(self.bucket, self.bucket)

    @property
    def per_minute(self) -> int:
        """GitLab's RateLimit-Limit: the quota scaled to one minute."""
        return max(1, round(self.limit * 60.0 / self.period))


class RateLimits:
    """Thread-safe request counters per (bucket, user, window)."""

    def __init__(
            self,
            spec: Mapping[str, Any] | None = None,
            *,
            clock: Callable[[], float] = time.time,
    ) -> None:
        spec = dict(spec or {})
        unknown = set(spec) - {"api", "search"}
        if unknown:
            raise ValueError(f"Unknown rate_limits buckets: {sorted(unknown)}")
        self.throttles = [Throttle.from_dict(bucket, raw) for bucket, raw in spec.items() if raw]
        self._clock = clock
        self._lock = threading.Lock()
        self._counts: dict[tuple[str, Any], tuple[int, int]] = {}  # (bucket, user) -> (window, count)
        self.throttled = 0

    def __bool__(self) -> bool:
        return bool(self.throttles)

    def _applies(self, throttle: Throttle, endpoint: str | None) -> bool:
        return throttle.bucket == "api" or endpoint in SEARCH_ENDPOINTS

    def check(self, user_id: Any, endpoint: str | None) -> tuple[Response | None, dict[str, str]]:
        """
        Count one request of ``user_id`` to ``endpoint``.

        Returns (429 response or None, headers to add to a successful response).
        """
        if not self.throttles:
            return None, {}
        now = self._clock()
        extra: dict[str, str] = {}
        with self._lock:
            for throttle in self.throttles:
                if not self._applies(throttle, endpoint):
                    continue
                window = int(now // throttle.period)
                key = (throttle.bucket, user_id)
                current, count = self._counts.get(key, (window, 0))
                if current != window:
                    count = 0
                count += 1
                self._counts[key] = (window, count)
                reset_at = (window + 1) * throttle.period
                if count > throttle.limit:
                    self.throttled += 1
                    return self._limited(throttle, count, reset_at, now), {}
                if throttle.on_success:
                    extra.update(self._headers(throttle, count, reset_at, now))
        return None, extra

    @staticmethod
    def _headers(throttle: Throttle, observed: int, reset_at: float, now: float) -> dict[str, str]:
        return {
            "RateLimit-Name": throttle.name,
            "RateLimit-Limit": str(throttle.per_minute),
            "RateLimit-Observed": str(observed),
            "RateLimit-Remaining": str(max(throttle.limit - observed, 0)),
            "RateLimit-Reset": str(math.ceil(reset_at)),
            "RateLimit-ResetTime": formatdate(reset_at, usegmt=True),
        }

    def _limited(self, throttle: Throttle, observed: int, reset_at: float, now: float) -> Response:
        headers: dict[str, str] = {}
        if throttle.headers != "none":
            headers["Retry-After"] = str(max(1, math.ceil(reset_at - now)))
        if throttle.headers == "full":
            headers.update(self._headers(throttle, observed, reset_at, now))
        if throttle.bucket == "search":
            message = "This endpoint has been requested too many times. Try again later."
        else:
            message = "Retry later"
        response = json_response({"message": message}, status=429)
        response.headers.update(headers)
        return response
