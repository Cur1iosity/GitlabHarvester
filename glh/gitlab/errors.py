# glh/gitlab/errors.py
"""
How GitLab and network errors are classified (permanent or retryable) and described in one line.
"""

from __future__ import annotations

import re

# HTTP statuses that won't change on a retry: no access (403) or the project /
# branch is gone (404). Such searches are skipped without blocking --resume.
PERMANENT_ERROR_CODES = frozenset({403, 404})


def is_permanent_error(error: BaseException) -> bool:
    """True for API errors a retry can't fix (403/404); False for 5xx, 429, 401, timeouts, network."""
    return getattr(error, "response_code", None) in PERMANENT_ERROR_CODES

# Standard reasons for the HTTP statuses the harvester runs into, so a log line
# can say "HTTP 500 Internal Server Error" without the response body.
_HTTP_REASONS = {
    401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 408: "Request Timeout",
    429: "Too Many Requests", 500: "Internal Server Error", 502: "Bad Gateway",
    503: "Service Unavailable", 504: "Gateway Timeout",
}

_CONNECTION_REASON = re.compile(
    r"(Failed to establish a new connection: [^'\")]+|Read timed out|Connection refused|"
    r"Name or service not known|getaddrinfo failed|Temporary failure in name resolution|"
    r"timed out|Remote end closed connection without response|Connection reset by peer)")


def describe_connection_error(error: BaseException) -> str:
    """'ConnectionError: Failed to establish a new connection: [Errno 111] Connection refused' (no urllib3 repr)."""
    match = _CONNECTION_REASON.search(str(error))
    name = type(error).__name__
    return f"{name}: {match.group(1).rstrip('. ')}" if match else describe_api_error(error)


def describe_api_error(error: BaseException) -> str:
    """
    Short, one-line description of a GitLab/requests error, without the response
    body.

    A GitLab HTTP error carries ``response_code`` (and, on a real instance, a
    whole HTML error page as its message); this returns just ``HTTP 500
    Internal Server Error``. Other errors (timeouts, connection resets) use
    their type and first message line. The full exception, body included, is
    logged separately at debug level.
    """
    code = getattr(error, "response_code", None)
    if code is not None:
        reason = _HTTP_REASONS.get(code)
        return f"HTTP {code} {reason}" if reason else f"HTTP {code}"
    first_line = (str(error).strip().splitlines() or [""])[0][:200]
    name = type(error).__name__
    return f"{name}: {first_line}" if first_line else name
