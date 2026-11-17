"""
Empirical detection of GitLab API rate limits (``-m find-limits``, ``--auto-limits``).

Modules: constants, headers (RateLimit-*), probe (LimitProbe), recommend
(settings and the command line), finder (LimitFinder), advisor (LimitAdvisor:
proposals during a run) and console (LimiterConsole: the non-blocking prompt).

EXPERIMENTAL: the probe, the suggestions and the runtime advice
(``glh.limits.advisor``) may change in behavior, output and options between minor
releases. :data:`EXPERIMENTAL_NOTE` is printed whenever they are used.

GitLab rate-limits the search API separately from (and usually far below) the
rest of the API, and most limits count **per user**, not per token: two tokens
of one user share one budget. The harvester paces the two kinds of requests
with ``--search-rpm`` and ``--index-rpm`` (see ``glh.gitlab.throttling``); this module
finds values for them, and for ``--workers``, by measuring.

How one API is probed (:class:`LimitProbe`):

1. One request. If GitLab announces the limit in ``RateLimit-*`` headers on a
   successful response, that is the answer (no load at all). Not for search:
   such headers belong to the general API throttle, which counts search too.
2. Requests in levels of growing parallelism (1, 2, 4, ... threads) until
   GitLab answers HTTP 429. The successful requests in the window before the
   first 429 are the limit (or ``RateLimit-Limit`` of the 429, if sent);
   ``Retry-After`` / ``RateLimit-Reset`` tell when the budget is back.
3. No 429 within the default budget (search: 60 requests, other API: 300):
   the probe goes on deeper, up to ``max_requests``, to see whether a limit is
   above it and what throughput is really available. It stops early when the
   throughput stops growing with more threads (the server is the bottleneck)
   and a full window passed without a 429 (no per-window limit below it).

Requests of the probe are not paced and not retried (python-gitlab's 429
retries are off), so the probe never waits for GitLab; :meth:`LimitFinder.wait_cooldown`
waits for the window to reset afterwards, before a scan starts.

:func:`recommend` turns the results into ``--workers``, ``--index-rpm`` and
``--search-rpm`` (a ``margin`` below the limit), keeping options the user set
explicitly; :meth:`Recommendation.command` renders the command line to run.
"""

from glh.limits.advisor import LimitAdvisor, Suggestion
from glh.limits.console import LimiterConsole
from glh.limits.constants import (
    API_NAMES,
    DEFAULT_BUDGET,
    DEFAULT_MARGIN,
    DEFAULT_MAX_REQUESTS,
    EXPERIMENTAL_NOTE,
    INDEX,
    KINDS,
    LONG_WINDOW,
    MAX_REQUESTS_LIMIT,
    SEARCH,
    WINDOW,
)
from glh.limits.finder import LimitFinder, probe_project_from_index
from glh.limits.headers import HeaderLimit, parse_limit_headers
from glh.limits.probe import LimitProbe, ProbeResponse, ProbeResult
from glh.limits.recommend import recommend, Recommendation, Settings, strip_limit_options

__all__ = [
    "API_NAMES", "DEFAULT_BUDGET", "DEFAULT_MARGIN", "DEFAULT_MAX_REQUESTS", "EXPERIMENTAL_NOTE", "HeaderLimit",
    "INDEX", "KINDS", "LONG_WINDOW", "LimitAdvisor", "LimitFinder", "LimitProbe", "LimiterConsole",
    "MAX_REQUESTS_LIMIT", "ProbeResponse", "ProbeResult", "Recommendation", "SEARCH", "Settings", "Suggestion",
    "WINDOW", "parse_limit_headers", "probe_project_from_index", "recommend", "strip_limit_options",
]
