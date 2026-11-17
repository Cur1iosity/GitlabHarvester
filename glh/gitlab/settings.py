# glh/gitlab/settings.py
"""
How a run reaches GitLab: the client settings (fixed for the run) and the
request pacing (changed on the fly by ``--auto-limits``).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from glh.gitlab.throttling import Jitter, NO_JITTER


@dataclass(frozen=True, slots=True)
class ClientSettings:
    """Everything a python-gitlab client of the run needs, except its token."""

    url: str | None = None
    proxy: str | None = None
    timeout: int = 60
    # True (system CAs), a CA bundle path (--ca-bundle) or False (--insecure).
    ssl_verify: bool | str = True
    # User-Agent of every request: one = fixed, several = random per request; () = python-gitlab's.
    user_agents: tuple[str, ...] = ()


@dataclass(slots=True)
class Pacing:
    """Requests per minute per client (thread) and a random delay; 0 / (0, 0) = off."""

    index_rpm: int = 0
    search_rpm: int = 0
    jitter: Jitter = field(default=NO_JITTER)

    def __post_init__(self) -> None:
        self.index_rpm = max(0, int(self.index_rpm))
        self.search_rpm = max(0, int(self.search_rpm))
        self.jitter = (float(self.jitter[0]), float(self.jitter[1]))
