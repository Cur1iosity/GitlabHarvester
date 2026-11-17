# glh/gitlab/factory.py
"""
ClientFactory: the one place python-gitlab clients are created.

Every client of a run — the main one, one per worker thread, the start-up check
of every extra token, the unpaced clients of the rate-limit probe — comes from
here, so they all share the same URL, timeout, TLS verification, proxy and
User-Agent, and every paced client gets:

- a fresh ``requests.Session`` (sessions are not thread-safe, and one pool
  would be too small for many workers), with the proxy if one is set;
- a :class:`~glh.gitlab.throttling.ThrottledAdapter` with its own limiters
  (``--index-rpm``, ``--search-rpm``, ``--jitter``) that also sets the
  User-Agent; with ``adjustable`` it is mounted even without limits, so
  :meth:`ClientFactory.set_pacing` can change the pace of a running scan;
- the response hook (``on_response``), e.g. the HTTP 429 accounting of
  :class:`~glh.gitlab.rate_monitor.RateLimitMonitor`.

TLS verification is never disabled implicitly: only ``ssl_verify=False``
(``--insecure``), which is warned about.
"""

from __future__ import annotations

import logging
import threading
import weakref
from typing import Any, Callable
from urllib.parse import urlparse

from gitlab import Gitlab
from requests import Session

from glh.gitlab import throttling
from glh.gitlab.settings import ClientSettings, Pacing

ResponseHook = Callable[..., Any]


def normalize_proxy(proxy: str) -> str:
    """'127.0.0.1:8080' -> 'http://127.0.0.1:8080'; ValueError for something that isn't a URL."""
    p = proxy.strip()
    if not p:
        return p
    if "://" not in p:
        p = f"http://{p}"
    parsed = urlparse(p)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid proxy URL: {proxy!r}. Example: http://127.0.0.1:8080")
    return p


class ClientFactory:
    """Creates the python-gitlab clients of one run (see the module doc)."""

    def __init__(
            self,
            settings: ClientSettings,
            pacing: Pacing | None = None,
            *,
            adjustable: bool = False,
            on_response: ResponseHook | None = None,
            logger: logging.Logger | None = None,
    ) -> None:
        self.settings = settings
        self.pacing = pacing or Pacing()
        self.adjustable = adjustable
        self.on_response = on_response
        self.logger = logger or logging.getLogger("GitlabHarvesterLogger")
        self.proxy = normalize_proxy(settings.proxy) if settings.proxy else None
        self._adapters: weakref.WeakSet[throttling.ThrottledAdapter] = weakref.WeakSet()
        self._lock = threading.Lock()
        if settings.ssl_verify is False and settings.url:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self.logger.warning(
                "TLS certificate verification is DISABLED (--insecure): the token is sent "
                "without checking who answers at %s.", settings.url,
            )

    # ------------------------------------------------------------------ clients

    def _kwargs(self, token: str | None) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "url": self.settings.url,
            "private_token": token,
            "timeout": self.settings.timeout,
            "ssl_verify": self.settings.ssl_verify,
        }
        if self.proxy:
            session = Session()
            session.proxies.update({"http": self.proxy, "https": self.proxy})
            kwargs["session"] = session
        return kwargs

    def create(self, token: str | None) -> Gitlab:
        """A paced client of ``token`` with the response hook (not authenticated yet)."""
        return self.prepare(Gitlab(**self._kwargs(token)))

    def create_unpaced(self, token: str | None) -> Gitlab:
        """
        A client without pacing and without the response hook: requests go out
        at once and are not counted (the rate-limit probe). The User-Agent still applies.
        """
        gl = Gitlab(**self._kwargs(token))
        throttling.limit_session(gl.session, user_agents=self.settings.user_agents)
        return gl

    def prepare(self, gl: Gitlab) -> Gitlab:
        """Add the response hook and the throttling adapter to the session of ``gl``."""
        session = getattr(gl, "session", None)
        hooks = getattr(session, "hooks", None)
        if self.on_response is not None and isinstance(hooks, dict):
            hooks.setdefault("response", []).append(self.on_response)
        if session is not None and hasattr(session, "mount"):
            adapter = throttling.limit_session(
                session, index_rpm=self.pacing.index_rpm, search_rpm=self.pacing.search_rpm,
                jitter=self.pacing.jitter, user_agents=self.settings.user_agents, always=self.adjustable,
            )
            if adapter is not None:
                with self._lock:
                    self._adapters.add(adapter)
        return gl

    # ------------------------------------------------------------------- pacing

    def set_pacing(self, *, index_rpm: int | None = None, search_rpm: int | None = None) -> None:
        """
        Change the pace of every client made so far (they need ``adjustable``
        if they were made without limits) and of the clients made later.
        """
        if index_rpm is not None:
            self.pacing.index_rpm = max(0, int(index_rpm))
        if search_rpm is not None:
            self.pacing.search_rpm = max(0, int(search_rpm))
        with self._lock:
            adapters = list(self._adapters)
        for adapter in adapters:
            adapter.set_limits(index_rpm=self.pacing.index_rpm, search_rpm=self.pacing.search_rpm,
                               jitter=self.pacing.jitter)
