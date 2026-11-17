# glh/limits/constants.py
"""
Names, budgets and defaults of the rate-limit detection.
"""

from __future__ import annotations

EXPERIMENTAL_NOTE = ("Rate-limit detection is EXPERIMENTAL: check the suggested values before relying "
                     "on them; behavior and output may change in future releases.")

INDEX = "index"

SEARCH = "search"

KINDS: tuple[str, ...] = (INDEX, SEARCH)

API_NAMES = {INDEX: "other API", SEARCH: "search API"}

# Requests per probed API before the probe decides to go deeper.
DEFAULT_BUDGET = {SEARCH: 60, INDEX: 300}

# Hard cap of requests per probed API (default budget + deep stage): --probe-max.
DEFAULT_MAX_REQUESTS = 600

MAX_REQUESTS_LIMIT = 100_000

MAX_PROBE_CONCURRENCY = 16

# Share of the limit the recommendation uses: --probe-margin.
DEFAULT_MARGIN = 0.85

# Window GitLab counts requests in (Rack::Attack and the application limits: 1 minute).
WINDOW = 60.0

# A Retry-After much longer than WINDOW means a longer (hourly) window.
LONG_WINDOW = 3600.0
