# glh/harvester.py
from __future__ import annotations

import itertools
import json
import re
import logging
import os
import threading
import time
import weakref
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, IO, Any
from urllib.parse import quote, urlparse

import gitlab.exceptions
import requests.exceptions
from gitlab import Gitlab
from gitlab.const import SearchScope
from gitlab.utils import EncodedId
from gitlab.v4.objects import Project
from requests import Session

from glh.downloads import FileDownloader
from glh.exceptions import GitlabHarvesterError
from glh.filefilter import FileFilter
from glh.output import SearchOutput
from glh.planner import (
    ScanOptions,
    ScanPlan,
    TimeWindow,
    branches_to_scan,
    build_scan_plan,
    format_api_time,
    parse_timestamp,
)
from glh import ratelimit, user_agents
from glh import workers as pool
from glh.utils import logging_utils, terminal_utils
from glh.utils.terminal_utils import human_int

# datetime.UTC exists only on Python 3.11+, while the package supports 3.10.
UTC = timezone.utc


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


def client_required(func: Callable) -> Callable:
    """
    Decorator ensuring that a GitLab client is initialized before method execution.

    The decorator checks whether the GitlabHarvester instance has an active
    GitLab client. If the client is not initialized, a GitlabHarvesterError
    is raised, preventing accidental use of API-dependent methods.

    Args:
        func: Method to be wrapped.

    Returns:
        Wrapped function that performs the client availability check
        before invoking the original method.

    Raises:
        GitlabHarvesterError: If the GitLab client is not initialized.
    """

    def wrapper(*args, **kwargs) -> Callable:
        glh: GitlabHarvester = args[0]
        if not glh._gl:
            raise GitlabHarvesterError("You're trying to use Gitlab client before initialization.")
        return func(*args, **kwargs)

    return wrapper


@dataclass(frozen=True, slots=True)
class _BranchTask:
    """One unit of search work: a term in one branch of one planned project."""

    term_no: int
    term: str
    project_no: int
    project: dict[str, Any]
    branches: tuple[str, ...]
    branch_no: int
    file_window: TimeWindow | None = None
    file_filter: FileFilter | None = None
    downloader: FileDownloader | None = None
    # Files-only mode (no term): "auto" | "search" | "tree"; None = term search.
    file_listing: str | None = None

    @property
    def branch(self) -> str:
        return self.branches[self.branch_no]


class GitlabHarvester:
    """High-level GitLab indexing and search engine.

    The harvester manages:
    - GitLab API client initialization
    - Instance Project Index (JSONL) generation/enrichment
    - Term search across projects/branches with progress output
    """

    def __init__(
            self,
            url: str | None = None,
            token: str | None = None,
            search_terms: list | None = None,
            proxy: str | None = None,
            timeout: int = 60,
            *,
            log_level: int | str = logging.WARNING,
            log_file: str | None = None,
            host: str | None = None,  # backward-compat alias for `url`
            workers: int = 1,
            ssl_verify: bool | str = True,
            index_rpm: int = 0,
            search_rpm: int = 0,
            jitter: tuple[float, float] = ratelimit.NO_JITTER,
            user_agents: list[str] | tuple[str, ...] = (),
            tokens: list[str] | tuple[str, ...] | None = None,
            adjustable_limits: bool = False,
    ) -> None:
        self.search_terms: list = search_terms or []
        # Tokens the run spreads its work over, each with its own pool of workers
        # and its own server-side rate-limit budget. A single ``token`` (string)
        # is the one-token case. See glh/tokens.py.
        resolved_tokens = list(tokens) if tokens else ([token] if token else [])
        self.tokens: tuple[str, ...] = tuple(resolved_tokens)
        # Parallel API requests PER TOKEN (1 = sequential). See glh/workers.py.
        self.workers: int = max(1, int(workers))
        # Total concurrent clients across all tokens = tokens x workers-per-token.
        # Every worker thread owns one client bound to one token, so a run keeps
        # this many API connections busy and that many per-worker rpm budgets.
        self.concurrency: int = max(1, len(self.tokens)) * self.workers
        # Round-robin assignment of tokens to worker threads (one token per
        # thread); concurrency is a multiple of len(tokens), so every token gets
        # exactly ``workers`` threads, and it stays balanced across phases.
        self._token_lock = threading.Lock()
        self._next_token = 0
        # Requests per minute per client (thread); 0 = no limit. See glh/ratelimit.py.
        self.index_rpm: int = max(0, int(index_rpm))
        self.search_rpm: int = max(0, int(search_rpm))
        # Random delay range (seconds) before every request; (0, 0) = off.
        self.jitter: tuple[float, float] = (float(jitter[0]), float(jitter[1]))
        # User-Agent of every request: one = fixed, several = random per request; () = python-gitlab's.
        self.user_agents: tuple[str, ...] = tuple(user_agents)
        # --auto-limits: every client gets a throttling adapter (even without
        # limits yet), so set_rate_limits() can change the pace of a running scan.
        self.adjustable_limits = bool(adjustable_limits)
        self._adapters: weakref.WeakSet[ratelimit.ThrottledAdapter] = weakref.WeakSet()
        self._adapters_lock = threading.Lock()
        # Called with every API response (any thread), e.g. glh.autolimit.LimitAdvisor.observe.
        self.limit_observer: Callable[[Any], None] | None = None
        # GitLab user id of every token (same order as self.tokens), from the login check.
        self.token_users: list[Any] = []
        self._local = threading.local()
        self._gl_main: Gitlab | None = None
        self._client_kwargs: dict[str, Any] | None = None
        # (project id, branch, path, window) -> changed inside the window; shared by workers.
        self._file_change_cache: dict[tuple[Any, ...], bool] = {}
        # Terms of the last search_keywords() run that had failed (retryable) searches.
        self.incomplete_terms: list[str] = []
        # Files-only mode, --file-listing auto: "unknown" until the instance has
        # shown whether its search takes filter-only queries ("search") or not ("tree").
        self._file_listing_lock = threading.Lock()
        self._file_listing_state = "unknown"
        self.file_listing_counts: Counter[str] = Counter()  # branches listed per method
        self._file_change_lock = threading.Lock()
        # What every thread is searching right now (status line, slow-task reports).
        self._active = pool.ActiveTasks()
        # Report a search task still running after this many seconds (and again
        # every as many seconds); 0 disables. Parallel search only.
        self.slow_task_report: float = 300.0
        # HTTP 429: python-gitlab waits and retries silently. By default the first
        # one is a warning and the rest only count (status line, final summary);
        # with --debug a warning repeats at most every rate_limit_warn_interval s.
        self.rate_limit_warn_interval: float = 60.0
        self._rate_limit_lock = threading.Lock()
        self._rate_limited = 0
        self._rate_limit_waited = 0.0  # Retry-After seconds, summed over all threads
        self._rate_limit_warned_at: float | None = None

        self.log_level: int = logging_utils.coerce_log_level(log_level)
        self.log_file: str | None = log_file
        self.logger = logging_utils.build_logger(
            name="GitlabHarvesterLogger",
            level=self.log_level,
            log_file=self.log_file,
        )

        url = url or host
        self._gl: Gitlab | None = (
            self._get_gl_client(url=url, token=self.tokens[0], proxy=proxy, timeout=timeout, ssl_verify=ssl_verify)
            if url and self.tokens else None
        )
        # The main client above verified the first token; fail fast on the rest
        # too, so a bad colleague's token is caught before the scan starts.
        if self._gl is not None and len(self.tokens) > 1:
            self._verify_extra_tokens(url)

    @property
    def _gl(self) -> Gitlab | None:
        """GitLab client of the current thread (worker threads get their own one)."""
        return getattr(self._local, "gl", None) or self._gl_main

    @_gl.setter
    def _gl(self, value: Gitlab | None) -> None:
        self._gl_main = value

    def _worker_client_kwargs(self, token: str | None) -> dict[str, Any]:
        """
        Client kwargs for a worker/verification client: a fresh session (the
        requests.Session is not thread-safe and its pool would be too small for
        many workers) and, with several tokens, ``token`` instead of the first.
        """
        kwargs = dict(self._client_kwargs or {})
        main_session = kwargs.pop("session", None)
        if main_session is not None:
            session = Session()
            session.proxies.update(main_session.proxies)
            kwargs["session"] = session
        if token is not None:
            kwargs["private_token"] = token
        return kwargs

    def _next_worker_token(self) -> str | None:
        """Next token for a worker thread (round-robin); None with no tokens (test stub)."""
        if not self.tokens:
            return None
        with self._token_lock:
            token = self.tokens[self._next_token % len(self.tokens)]
            self._next_token += 1
        return token

    def _verify_extra_tokens(self, url: str) -> None:
        """
        Authenticate every token after the first, so an invalid one fails the
        run before any scanning (the first token was verified by the main
        client). Token values are never put in the error message.
        """
        total = len(self.tokens)
        for index, token in enumerate(self.tokens[1:], start=2):
            gl = self._setup_client(Gitlab(**self._worker_client_kwargs(token)))
            try:
                gl.auth()
            except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
                raise GitlabHarvesterError(
                    f"Token #{index} of {total} failed to authenticate to {url}: {e}"
                ) from None
            self.token_users.append(self._user_id(gl, index))

    @staticmethod
    def _user_id(gl: Gitlab, index: int) -> Any:
        """GitLab user id of an authenticated client (a unique stand-in when unknown)."""
        user_id = getattr(getattr(gl, "user", None), "id", None)
        return user_id if user_id is not None else f"token#{index}"

    # ---------------------------------------------------------------- tokens and users

    def token_user_groups(self) -> list[list[int]]:
        """Token indexes (0-based) grouped by GitLab user: tokens of one user share its rate limits."""
        groups: dict[Any, list[int]] = {}
        for index in range(len(self.tokens)):
            user = self.token_users[index] if index < len(self.token_users) else f"token#{index + 1}"
            groups.setdefault(user, []).append(index)
        return list(groups.values())

    def tokens_per_user(self) -> int:
        """Most tokens held by one user (1 = every token has its own budget)."""
        return max((len(g) for g in self.token_user_groups()), default=1)

    def token_user_key(self, token: str | None) -> Any:
        """The user a token belongs to (an opaque key; never the token)."""
        if token is None:
            return None
        for index, known in enumerate(self.tokens):
            if known == token:
                return self.token_users[index] if index < len(self.token_users) else f"token#{index + 1}"
        return None

    # ------------------------------------------------------------------ rate limits

    def set_rate_limits(self, *, index_rpm: int | None = None, search_rpm: int | None = None,
                        workers: int | None = None) -> None:
        """
        Change the pace (and, before a scan starts, the workers) of this run.

        New rpm values apply at once to every existing client (needs
        ``adjustable_limits`` for clients created without limits) and to the
        clients created later. ``workers`` only affects pools started afterwards.
        """
        if index_rpm is not None:
            self.index_rpm = max(0, int(index_rpm))
        if search_rpm is not None:
            self.search_rpm = max(0, int(search_rpm))
        if workers is not None:
            self.workers = max(1, int(workers))
            self.concurrency = max(1, len(self.tokens)) * self.workers
        with self._adapters_lock:
            adapters = list(self._adapters)
        for adapter in adapters:
            adapter.set_limits(index_rpm=self.index_rpm, search_rpm=self.search_rpm, jitter=self.jitter)

    def probe_sender(self, path: str, query: dict[str, Any], token: str | None = None) -> Callable[[], Any]:
        """
        A sender for ``glh.limits.LimitProbe``: one GET of ``path`` per call
        through a fresh client of ``token`` (default: the first) that is not
        paced, not retried on 429 and not counted by the 429 warnings.
        """
        from glh.limits import ProbeResponse

        gl = Gitlab(**self._worker_client_kwargs(token))
        ratelimit.limit_session(gl.session, user_agents=self.user_agents)
        last: dict[str, Any] = {}
        gl.session.hooks.setdefault("response", []).append(lambda r, *a, **k: last.__setitem__("r", r))

        def send() -> ProbeResponse:
            last.clear()
            started = time.perf_counter()
            try:
                gl.http_request("get", path, query_data=dict(query), obey_rate_limit=False, max_retries=0,
                                retry_transient_errors=False)
            except gitlab.exceptions.GitlabError:
                pass  # the status is in the recorded response
            except requests.exceptions.RequestException as e:
                return ProbeResponse(0, {}, time.perf_counter() - started, error=type(e).__name__)
            latency = time.perf_counter() - started
            response = last.get("r")
            if response is None:
                return ProbeResponse(0, {}, latency, error="no response")
            return ProbeResponse(response.status_code, dict(response.headers), latency)

        return send

    @client_required
    def first_project_id(self) -> Any | None:
        """Id of a non-empty project from the first page of /projects (for search probes)."""
        try:
            page = self._gl.http_get("/projects", query_data={"per_page": 20, "order_by": "id", "sort": "desc"})
        except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
            self.logger.warning("Cannot list projects for the limit probe: %s", describe_api_error(e))
            return None
        projects = [p for p in page if isinstance(p, dict) and p.get("id") is not None] if isinstance(page, list) else []
        for project in projects:
            if not project.get("empty_repo", False):
                return project["id"]
        return projects[0]["id"] if projects else None

    def _init_worker_client(self) -> None:
        """
        Give the calling worker thread its own python-gitlab client.

        With several tokens the thread is bound to one of them (round-robin, so
        each token gets an equal share of threads). All tokens were already
        verified at start-up, so no extra /user request is made here.
        """
        if self._client_kwargs is None:
            return  # client not built by _get_gl_client (e.g. a test stub): share it
        self._local.gl = self._setup_client(Gitlab(**self._worker_client_kwargs(self._next_worker_token())))

    def _setup_client(self, gl: Gitlab) -> Gitlab:
        """
        Prepare the requests session of a new client (main or worker).

        - a response hook makes HTTP 429 waits visible (see _on_response);
        - --index-rpm / --search-rpm / --jitter: a throttling adapter with its
          own limiters, so every client (thread) gets the full per-thread budget;
          the same adapter sets the User-Agent (-A, --user-agent-file).
        """
        session = getattr(gl, "session", None)
        hooks = getattr(session, "hooks", None)
        if isinstance(hooks, dict):
            hooks.setdefault("response", []).append(self._on_response)
        if session is not None and hasattr(session, "mount"):
            adapter = ratelimit.limit_session(session, index_rpm=self.index_rpm, search_rpm=self.search_rpm,
                                              jitter=self.jitter, user_agents=self.user_agents,
                                              always=self.adjustable_limits)
            if adapter is not None:
                with self._adapters_lock:
                    self._adapters.add(adapter)
        return gl

    @staticmethod
    def _retry_after(headers: Any) -> float | None:
        """Seconds python-gitlab waits after a 429 (Retry-After / RateLimit-Reset), if known."""
        try:
            if "Retry-After" in headers:
                return max(float(headers["Retry-After"]), 0.0)
            if "RateLimit-Reset" in headers:
                return max(float(headers["RateLimit-Reset"]) - time.time(), 0.0)
        except (TypeError, ValueError):
            pass
        return None

    def _on_response(self, response: Any, *args: Any, **kwargs: Any) -> None:
        """
        requests response hook (runs in the thread that made the request).

        On HTTP 429 python-gitlab waits (Retry-After) and retries up to 10
        times without any output, which looks like a hung scan. Mark the
        running task as waiting, count the response (``HTTP 429 xN`` at the
        end of the status line, :meth:`rate_limit_summary` at the end) and
        warn once; with --debug the warning repeats, throttled.
        """
        observer = self.limit_observer
        if observer is not None:
            try:
                observer(response)
            except Exception:  # noqa: BLE001 - advice must never break a request
                self.logger.debug("Limit observer failed", exc_info=True)
        if getattr(response, "status_code", None) != 429:
            self._active.set_waiting("")
            return None
        wait = self._retry_after(getattr(response, "headers", None) or {})
        wait_text = terminal_utils.format_duration(wait) if wait is not None else "a moment"
        self._active.set_waiting(f"rate limited (HTTP 429), retry in {wait_text}")
        debug = self.log_level <= logging.DEBUG
        with self._rate_limit_lock:
            self._rate_limited += 1
            self._rate_limit_waited += wait or 0.0
            count = self._rate_limited
            now = time.monotonic()
            first = self._rate_limit_warned_at is None
            warn = first or (debug and now - self._rate_limit_warned_at >= self.rate_limit_warn_interval)
            if warn:
                self._rate_limit_warned_at = now
        if first:
            terminal_utils.STATUS.set_tail(self._rate_limit_tail)
        if warn:
            path = urlparse(getattr(response, "url", "") or "").path
            advice = ("--auto-limits will suggest new limits." if self.limit_observer is not None
                      else "Fewer --workers or lower --search-rpm/--index-rpm reduce the request rate "
                           "(-m find-limits measures the limits).")
            if debug:
                self.logger.warning(
                    "GitLab rate limit (HTTP 429) on %s: waiting %s before a retry "
                    "(%s so far; python-gitlab retries up to 10 times). %s",
                    path or "a request", wait_text, terminal_utils.plural(count, "rate-limited response"), advice,
                )
            else:
                self.logger.warning(
                    "GitLab rate limit (HTTP 429) on %s: waiting %s before a retry (python-gitlab retries "
                    "up to 10 times). Further 429s are only counted: HTTP 429 xN in the status line and a "
                    "summary at the end (--debug repeats this warning). %s",
                    path or "a request", wait_text, advice,
                )
        return None

    def _rate_limit_tail(self) -> str:
        """'HTTP 429 x12' for the end of the status line ('' before the first one)."""
        count = self._rate_limited
        return f"HTTP 429 x{count:,}" if count else ""

    @property
    def rate_limited(self) -> int:
        """HTTP 429 responses so far (all threads)."""
        return self._rate_limited

    def rate_limit_summary(self) -> str | None:
        """
        'Rate limit: 190 HTTP 429 responses, retried after 12:30 of waits in total (all workers)';
        None without any 429.
        """
        with self._rate_limit_lock:
            count, waited = self._rate_limited, self._rate_limit_waited
        if not count:
            return None
        waits = (f", retried after {terminal_utils.format_duration(waited)} of waits in total"
                 f"{' (all workers)' if self.concurrency > 1 else ''}" if waited else ", retried")
        return f"Rate limit: {terminal_utils.plural(count, 'HTTP 429 response')}{waits}"

    def _plan_rows(self, keywords: list[str], plan: ScanPlan, options: ScanOptions,
                   downloader: FileDownloader | None) -> list[terminal_utils.Row]:
        """The rows of the 'Search plan' block."""
        if options.files_only:
            first: list[terminal_utils.Row] = [
                ("files", f"every file matching {options.file_filter.describe()} (no term)"),
                ("listing", options.file_listing),
            ]
        else:
            first = [("terms", f"{len(keywords):,}")]
            if options.file_filter:
                first.append(("files", options.file_filter.describe()))
        rows: list[terminal_utils.Row] = [
            *first,
            ("projects", f"{plan.project_count:,} of {plan.total_projects:,}"),
            ("skipped", plan.skipped_reasons()),
            ("branches", f"{plan.branch_count:,}"),
            ("files changed", options.file_window.describe() if options.file_window else ""),
            ("downloads", downloader.target() if downloader is not None else ""),
            ("parallel", self._concurrency_text()),
            ("rate limit", ratelimit.describe(self.index_rpm, self.search_rpm)),
            ("jitter", ratelimit.format_jitter(self.jitter)),
            ("user agent", user_agents.describe(self.user_agents)),
        ]
        return rows

    def _concurrency_text(self) -> str:
        """
        How the run is parallelized, for the search plan line and journal.

        '' for a plain sequential run, 'N workers' for one token, and
        'M tokens x N workers = M*N clients' when several tokens run at once.
        """
        n_tokens = len(self.tokens)
        if n_tokens > 1:
            worker = "worker" if self.workers == 1 else "workers"
            return f"{n_tokens} tokens x {self.workers} {worker} = {self.concurrency} clients"
        if self.workers > 1:
            return f"{self.workers} workers"
        return ""

    def _imap_ordered(self, fn: Callable[[Any], Any], items: Any, *, parallel: bool = True):
        """imap_ordered() with this harvester's total concurrency and per-thread clients."""
        return pool.imap_ordered(fn, items, workers=self.concurrency if parallel else 1,
                                 initializer=self._init_worker_client)

    @staticmethod
    def _emit_record(fp: IO, record: dict[str, Any], indent: int | None = None) -> None:
        """
        Serialize and write a single record to an open file in JSON format.

        The record is written as one line (JSONL/NDJSON). Optional indentation
        can be applied for readability when needed.

        Args:
            fp: Open file-like object for writing text data.
            record: Dictionary to serialize.
            indent: Optional JSON indentation level; if None, compact form is used.

        Returns:
            None
        """
        fp.write(json.dumps(record, ensure_ascii=False, indent=indent))
        fp.write("\n")

    @staticmethod
    def _write_jsonl_line(fp: IO, obj: dict[str, Any]) -> None:
        """
        Write a dictionary as a single JSONL (NDJSON) line to the provided file.

        The object is serialized without ASCII escaping and terminated with
        a newline character to maintain one-object-per-line structure.

        Args:
            fp: Open file-like object for writing text data.
            obj: Dictionary to serialize and append.

        Returns:
            None
        """
        fp.write(json.dumps(obj, ensure_ascii=False))
        fp.write("\n")

    def get_instance_id(self) -> str:
        """Return a filesystem-safe identifier for the configured GitLab instance.

        Returns:
            Instance identifier like 'gitlab_example_com' (a port becomes '_8080'),
            or 'undefined' if no client.
        """
        if not self._gl:
            return "undefined"
        parsed = urlparse(self._gl.url)
        host = (parsed.netloc or parsed.path).strip("/")
        # ':' (host:port) is not allowed in Windows file names and would create
        # an NTFS alternate data stream instead of a regular file.
        return host.replace(".", "_").replace(":", "_")

    def get_host(self) -> str:
        """Backward-compatible alias for get_instance_id()."""
        return self.get_instance_id()

    def _display_host(self) -> str:
        """Instance host as shown to the user, e.g. 'gitlab.example.com:8443'."""
        if not self._gl:
            return "undefined"
        parsed = urlparse(self._gl.url)
        return parsed.netloc or self._gl.url

    def _get_default_log_filename(self) -> str:
        """
        Generate the default filename for the log output.

        The name is derived from the normalized GitLab host identifier
        with a ".log" extension.

        Returns:
            Default log filename as a string.
        """
        return f'{self.get_host()}.log'

    def get_default_projects_filename(self) -> str:
        """
        Generate the default filename for the Instance Project Index.

        The name is based on the normalized GitLab host identifier and
        uses a JSONL extension. If the GitLab client is not initialized,
        a generic placeholder name is returned.

        Returns:
            Default project index filename.
        """
        filename: str = 'undefined_projects.jsonl'
        if self._gl:
            filename: str = f'{self.get_host()}_projects.jsonl'
        return filename

    @staticmethod
    def _normalize_proxy(proxy: str) -> str:
        p = proxy.strip()
        if not p:
            return p
        if "://" not in p:
            p = f"http://{p}"
        parsed = urlparse(p)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid proxy URL: {proxy!r}. Example: http://127.0.0.1:8080")
        return p

    def _get_gl_client(
            self,
            url: str,
            token: str,
            timeout: int = 60,
            proxy: str | None = None,
            ssl_verify: bool | str = True,
            disable_ssl_warnings: bool = True,
    ) -> Gitlab:
        """
        Initialize and authenticate a GitLab API client.

        TLS certificates are always verified unless the caller explicitly passes
        ``ssl_verify=False`` (CLI: --insecure). There is no automatic fallback to
        an unverified connection: it would send the token to whoever answers.

        Args:
            url: GitLab instance URL.
            token: Personal access token for API authentication.
            timeout: Connection timeout in seconds.
            proxy: Optional proxy URL applied to both HTTP and HTTPS.
            ssl_verify: True (system CAs), a CA bundle path (CLI: --ca-bundle),
                or False to disable verification.
            disable_ssl_warnings: Disable urllib3 TLS warnings (only when ssl_verify=False).

        Returns:
            Authenticated Gitlab client instance.

        Raises:
            GitlabHarvesterError: If the TLS certificate can't be verified.
            ValueError: If proxy URL is invalid.
        """
        self.logger.debug("Connecting to GitLab: %s", url)

        kwargs: dict[str, Any] = {
            "url": url,
            "private_token": token,
            "timeout": timeout,
            "ssl_verify": ssl_verify,
        }

        if ssl_verify is False:
            self.logger.warning(
                "TLS certificate verification is DISABLED (--insecure): the token is sent "
                "without checking who answers at %s.", url,
            )

        if proxy:
            proxy = self._normalize_proxy(proxy)
            session = Session()
            session.proxies.update({"http": proxy, "https": proxy})
            kwargs["session"] = session

        def _maybe_disable_warnings() -> None:
            if disable_ssl_warnings and kwargs.get("ssl_verify") is False:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        _maybe_disable_warnings()

        gl = self._setup_client(Gitlab(**kwargs))

        try:
            gl.auth()
            self.logger.debug("Authenticated to GitLab: %s", url)
            self._client_kwargs = dict(kwargs)
            self.token_users = [self._user_id(gl, 1)]
            return gl
        except requests.exceptions.SSLError as e:
            raise GitlabHarvesterError(
                f"TLS certificate verification failed for {url}: {e}\n"
                "If the instance uses a private CA, pass it with --ca-bundle FILE. "
                "To connect anyway without verification, use --insecure "
                "(not recommended: the token would be sent to an unverified server)."
            ) from None
        except requests.exceptions.RequestException as e:
            raise GitlabHarvesterError(
                f"Cannot reach {url} ({describe_connection_error(e)}). Check the URL, the network and --proxy."
            ) from None
        except gitlab.exceptions.GitlabError as e:
            who = "The token" if len(self.tokens) <= 1 else f"Token #1 of {len(self.tokens)}"
            hint = (" Check the token and that it has the read_api scope."
                    if isinstance(e, gitlab.exceptions.GitlabAuthenticationError) else "")
            raise GitlabHarvesterError(
                f"{who} failed to authenticate to {url} ({describe_api_error(e)}).{hint}"
            ) from None

    @client_required
    def fetch_projects(
            self,
            per_page: int = 100,
            filename: str | None = None,
            order_by: str = "id",
            sort: str = "desc",
            last_activity_after: datetime | None = None,
            last_activity_before: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """
        Retrieve projects from the GitLab instance with a reduced set of key fields.

        last_activity_after/last_activity_before are passed to GitLab as API
        filters, so projects outside the window are not even listed.

        Projects can be either collected in memory and returned as a list, or streamed
        directly to a file in NDJSON (JSONL) format to minimize memory usage. When
        streaming is enabled, data is first written to a temporary file and then
        reassembled with a metadata header as the first line.
        """

        def reduce_project_fields(project: Project) -> dict[str, Any]:
            """Extract a minimal set of relevant fields from a GitLab project object."""
            return {
                "id": project.id,
                "web_url": project.web_url,
                "path_with_namespace": project.path_with_namespace,
                "default_branch": getattr(project, "default_branch", None),
                "empty_repo": project.empty_repo,
                "forked_from_project": {"id": fork_data["id"]}
                if (fork_data := getattr(project, "forked_from_project", None))
                else False,
                "created_at": project.created_at,
                "last_activity_at": project.last_activity_at,
            }

        projects: list[dict[str, Any]] = []
        pr_counter = 0
        is_completed: bool = True
        outcome = ""

        start = time.perf_counter()
        tmp_filename = f"{filename}.tmp" if filename else None
        fp = open(tmp_filename, "w", encoding="utf-8") if tmp_filename else None

        host = self.get_host()

        activity: dict[str, str] = {}
        if last_activity_after is not None:
            activity["last_activity_after"] = format_api_time(last_activity_after)
        if last_activity_before is not None:
            activity["last_activity_before"] = format_api_time(last_activity_before)
        window = TimeWindow(last_activity_after, last_activity_before)
        window_text = f" (active {window.describe()})" if window else ""
        progress = terminal_utils.Progress(f"Indexing {self._display_host()}{window_text}", unit="projects").start()

        def fetch_page(number: int) -> list[Project]:
            return self._gl.projects.list(page=number, per_page=per_page, order_by=order_by, sort=sort, **activity)

        try:
            # Pages are fetched up to 2 x workers ahead but processed in order; the
            # first empty page ends the listing (the extra pages are discarded).
            for done in self._imap_ordered(fetch_page, itertools.count(1)):
                batch = done.unwrap()
                if not batch:
                    break
                page = done.item
                if fp is not None:
                    for x in batch:
                        self._emit_record(fp=fp, record=reduce_project_fields(x))
                else:
                    projects.extend(reduce_project_fields(x) for x in batch)

                batch_size = len(batch)
                pr_counter += batch_size
                progress.advance(batch_size, detail=f"page {page}")

        except gitlab.exceptions.GitlabError as e:
            # The listing stopped early: keep what was fetched, but never
            # mark a partial index as complete.
            is_completed = False
            outcome = " (incomplete: GitLab API error)"
            self.logger.error("Gitlab API error (%s). The project list wasn't complete.",
                              describe_api_error(e))
            self.logger.debug("Full project-listing error: %s", e)

        except KeyboardInterrupt:
            is_completed = False
            outcome = " (interrupted)"
            self.logger.error("Interrupted by user (Ctrl+C).")
            raise

        except Exception:
            is_completed = False
            outcome = " (failed)"
            self.logger.exception("Fatal error while loading projects.")
            raise

        finally:
            elapsed = round(time.perf_counter() - start, 2)
            progress.finish(
                f"Indexed {terminal_utils.plural(pr_counter, 'project')}{window_text} from {self._display_host()} in "
                f"{terminal_utils.format_duration(elapsed)}{outcome}"
            )

            if fp is not None:
                fp.close()

            if filename:
                meta = {
                    "type": "meta",
                    "source": host,
                    "timestamp_utc": datetime.now(UTC).isoformat(),
                    "projects_count": pr_counter,
                    "elapsed_seconds": elapsed,
                    "order_by": order_by,
                    "sort": sort,
                    "per_page": per_page,
                    "last_activity_after": activity.get("last_activity_after"),
                    "last_activity_before": activity.get("last_activity_before"),
                    "is_completed": is_completed,
                }
                with open(filename, "w", encoding="utf-8") as out_fp:
                    self._write_jsonl_line(out_fp, meta)
                    with open(tmp_filename, "r", encoding="utf-8") as in_fp:
                        for line in in_fp:
                            out_fp.write(line)

                os.remove(tmp_filename)

        self.logger.info("Loaded %s projects in %s seconds.", pr_counter, elapsed)
        return projects

    @client_required
    def get_branches(
            self,
            project_id: int,
            per_page: int = 100,
            *,
            limit: int | None = None,
    ) -> list[str]:
        """
        Retrieve branch names for a specific GitLab project.

        Args:
            project_id: GitLab project id.
            per_page: Branches API page size.
            limit: Stop after this many branches (None = all).

        Returns:
            Branch names in API order (GitLab sorts them by name). On an API
            error the branches fetched so far are returned and the error is logged.
        """
        branches: list[str] = []
        page = 1
        try:
            while True:
                batch = self._gl.projects.get(project_id, lazy=True).branches.list(page=page, per_page=per_page)
                if not batch:
                    break

                for b in batch:
                    branches.append(b.name)
                    if limit is not None and len(branches) >= limit:
                        return branches

                page += 1

        except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
            self.logger.error(
                "Gitlab API error (%s). The branch list wasn't complete for project with ID: %s.",
                describe_api_error(e), project_id,
            )
            self.logger.debug("Full branch-listing error for project %s: %s", project_id, e)

        self.logger.debug("Loaded %s branches for project with ID: %s.", len(branches), project_id)
        return branches

    def build_project_index(
            self,
            *,
            per_page: int = 100,
            filename: str | None = None,
            order_by: str = "id",
            sort: str = "desc",
            enforce_dump: bool = False,
            branches: str | int = "default",  # "default" | "all" | int
            branches_per_page: int = 100,
            last_activity_after: datetime | None = None,
            last_activity_before: datetime | None = None,
    ) -> str:
        """
        Build (or rebuild) the Instance Project Index file (JSONL/NDJSON) and optionally enrich it with branches.

        last_activity_after/last_activity_before limit the index to projects
        active in that window (GitLab API filter). An existing index built
        with a different window is reused with a warning.

        branches:
            - "default": store only default branch (no GitLab branch API calls)
            - "all": fetch all branches for each non-empty project (slow)
            - int: fetch up to N branches for each non-empty project

        Returns:
            Output filename.
        """
        if not filename:
            filename = f"{self.get_instance_id()}_project_index.jsonl"

        needs_build = enforce_dump or not os.path.exists(filename)
        if needs_build:
            self.logger.info(
                "Building Instance Project Index. Batch size: %s. Output file: %s.",
                per_page,
                filename,
            )
            # Base index (meta + projects without branches)
            self.fetch_projects(per_page=per_page, filename=filename, order_by=order_by, sort=sort,
                                last_activity_after=last_activity_after, last_activity_before=last_activity_before)

            if branches is not None:
                self.enrich_project_index_with_branches(
                    filename=filename,
                    branches=branches,
                    branches_per_page=branches_per_page,
                )
        else:
            self.logger.info("Instance Project Index already exists: %s.", filename)
            try:
                with open(filename, encoding="utf-8") as fp:
                    meta = json.loads(fp.readline() or "{}")
            except (OSError, json.JSONDecodeError):
                meta = {}
            if isinstance(meta, dict) and meta.get("is_completed") is False:
                self.logger.warning(
                    "Existing project index %s is incomplete (previous build failed). "
                    "Use --dump-projects to rebuild it.",
                    filename,
                )
            if isinstance(meta, dict):
                built = (meta.get("last_activity_after"), meta.get("last_activity_before"))
                wanted = tuple(format_api_time(v) if v is not None else None
                               for v in (last_activity_after, last_activity_before))
                if built != wanted:
                    self.logger.warning(
                        "Existing project index %s was built for projects active %s, this run asks for %s. "
                        "It is reused as is; use --dump-projects to rebuild it.",
                        filename, self._window_text(*built), self._window_text(*wanted),
                    )
        return filename

    def enrich_project_index_with_branches(
            self,
            *,
            filename: str,
            branches: str | int = "default",
            branches_per_page: int = 100,
    ) -> str:
        """
        Enrich an existing Instance Project Index (JSONL) with branches and rewrite it in-place.
        """
        if branches == "default":
            self.logger.info("Branches mode: default (no API calls, using default_branch only).")
        elif branches == "all":
            self.logger.info("Branches mode: all (slow).")
        else:
            self.logger.info("Branches mode: limit=%s (slow-ish).", branches)

        tmp_out = f"{filename}.branches.tmp"
        uses_api = branches != "default"
        # Only non-empty repositories cost API calls, so only they are counted.
        to_list = self._count_nonempty_projects(filename) if uses_api else 0
        progress = terminal_utils.Progress("Listing branches", total=to_list, unit="projects")
        listed_branches = 0

        with open(filename, "r", encoding="utf-8") as in_fp, open(tmp_out, "w", encoding="utf-8") as out_fp:
            first_line = in_fp.readline()
            if not first_line:
                raise ValueError(f"Project index file is empty: {filename}")

            meta = json.loads(first_line)
            meta["branches"] = branches
            meta["timestamp_utc"] = datetime.now(UTC).isoformat()
            self._write_jsonl_line(out_fp, meta)

            def index_records():
                for raw in in_fp:
                    raw = raw.strip()
                    if raw:
                        yield json.loads(raw)

            limit = None if branches in ("default", "all") else int(branches)

            def branches_of(project: dict[str, Any]) -> list[str]:
                if project.get("empty_repo", False):
                    return []
                if not uses_api:
                    default_branch = project.get("default_branch")
                    return [default_branch] if default_branch else []
                if self.concurrency <= 1:
                    progress.set_detail(str(project.get("path_with_namespace", project["id"])))
                return self.get_branches(project_id=int(project["id"]), per_page=branches_per_page, limit=limit)

            if uses_api:
                progress.start()
            try:
                # Branch lists are fetched in parallel; the index keeps its order.
                for done in self._imap_ordered(branches_of, index_records(), parallel=uses_api):
                    project = done.item
                    project["branches"] = done.unwrap()
                    if uses_api and not project.get("empty_repo", False):
                        listed_branches += len(project["branches"])
                        progress.advance(detail=str(project.get("path_with_namespace", project["id"])))

                    self._emit_record(out_fp, record=project)
            except BaseException:
                if uses_api:
                    progress.finish(f"{progress.render()} | stopped")
                raise

        if uses_api:
            progress.finish(
                f"Listed {terminal_utils.plural(listed_branches, 'branch', 'branches')} of "
                f"{terminal_utils.plural(progress.done, 'project')} in "
                f"{terminal_utils.format_duration(progress.elapsed)}"
            )

        os.replace(tmp_out, filename)
        if branches != "default":
            self.logger.info("Project index enriched with branches (mode=%s): %s", branches, filename)
        return filename

    @staticmethod
    def _window_text(after: str | None, before: str | None) -> str:
        """Describe an activity window stored as API strings (None = unbounded)."""
        return TimeWindow(parse_timestamp(after), parse_timestamp(before)).describe()

    @staticmethod
    def _count_nonempty_projects(filename: str) -> int:
        """Count non-empty repositories in an index file without loading it into memory."""
        count = 0
        with open(filename, "r", encoding="utf-8") as fp:
            fp.readline()  # meta
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    if not json.loads(line).get("empty_repo", False):
                        count += 1
                except json.JSONDecodeError:
                    continue
        return count

    def download_projects(
            self,
            *,
            per_page: int = 100,
            filename: str | None = None,
            order_by: str = "id",
            sort: str = "desc",
            enforce_dump: bool = False,
            branches: str | int = "default",
            branches_per_page: int = 100,
    ) -> str:
        """
        Create or update the Instance Project Index and optionally enrich it with branches.

        This method is a high-level wrapper around index building that:
            1. Generates the base project index using GitLab API.
            2. Optionally augments each project entry with branch information
               according to the selected depth.

        Args:
            per_page: Number of projects requested per API call.
            filename: Optional output path for the index file.
            order_by: Field used for server-side sorting of projects.
            sort: Sorting direction ("asc" or "desc").
            enforce_dump: Force rebuilding the index even if it already exists.
            branches: Branch collection mode:
                - "default" — store only the default branch,
                - "all" — fetch all branches,
                - integer — fetch up to N branches.
            branches_per_page: Number of branches requested per API call.

        Returns:
            Path to the resulting project index file.
        """
        filename = self.build_project_index(
            per_page=per_page,
            filename=filename,
            order_by=order_by,
            sort=sort,
            enforce_dump=enforce_dump,
        )

        if branches is not None:
            filename = self.enrich_project_index_with_branches(
                filename=filename,
                branches=branches,
                branches_per_page=branches_per_page,
            )

        return filename

    @client_required
    def add_branches_to_projects(self, projects: list[dict], per_page: int = 50) -> list[dict]:
        """
        Enrich a list of project dictionaries with branch information.

        Empty repositories get an empty branch list without API calls and are
        not counted in the progress.
        """
        to_list = sum(1 for p in projects if not p.get("empty_repo", False))

        def branches_of(project: dict[str, Any]) -> list[str]:
            if project.get("empty_repo", False):
                return []
            return self.get_branches(project_id=project["id"], per_page=per_page)

        with terminal_utils.Progress("Listing branches", total=to_list, unit="projects") as progress:
            for done in self._imap_ordered(branches_of, projects):
                project = done.item
                project["branches"] = done.unwrap()
                if not project.get("empty_repo", False):
                    progress.advance(detail=str(project.get("path_with_namespace") or project.get("web_url", "")))

            elapsed = progress.finish(
                f"Listed branches of {terminal_utils.plural(progress.done, 'project')} in "
                f"{terminal_utils.format_duration(progress.elapsed)}"
            )

        self.logger.info("Loaded branches for %s projects in %s seconds.", len(projects), round(elapsed, 2))

        return projects

    def initialize_project_list(
            self,
            per_page: int = 100,
            filename: str | None = None,
            enforce_dump: bool = False,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """
        Ensure the Instance Project Index is available and load it.

        The Project Index is a lightweight inventory of all projects within the GitLab
        instance. It is used later as an input index for traversal strategies
        (e.g., processing order, default-branch-only vs all branches, forks inclusion).

        This function does not perform staleness checks or interact with the user.
        Any decisions about refreshing the Project Index should be handled by the caller.

        Args:
            per_page: Batch size for downloading if the Project Index needs to be created.
            filename: Path to the Project Index file (JSONL/NDJSON). If not provided,
                a default instance-specific path is used.
            enforce_dump: If True, rebuild the Project Index file unconditionally.

        Returns:
            A tuple of (projects, meta), where:
                - projects: list of project dictionaries from the Project Index.
                - meta: metadata header (the first JSONL line) describing the index build.

        Raises:
            Any exception raised by the underlying downloader or file reader.
        """
        filename = filename or self.get_default_projects_filename()

        if enforce_dump:
            self.logger.info("Enforce rebuild requested. Building Instance Project Index.")
            self.fetch_projects(per_page=per_page, filename=filename)

        data = self.load_projects_from_file(filename)
        if not data:
            self.logger.info("Instance Project Index was not found or unreadable. Building it now.")
            self.fetch_projects(per_page=per_page, filename=filename)
            data = self.load_projects_from_file(filename)

        meta = (data or {}).get("meta") or {}
        projects = (data or {}).get("projects") or []

        self.logger.info("Instance Project Index initialization completed.")
        return projects, meta

    def load_projects_from_file(self, filename: str | None = None) -> dict[str, Any]:
        """
        Load the project list from a JSONL/NDJSON file produced by fetch_projects().

        The file format:
          - first line -> metadata object
          - other lines -> individual project objects

        Returns:
            {
                "meta": {...},
                "projects": [...],
            }
        """
        if not filename:
            return {}

        try:
            projects: list[dict[str, Any]] = []

            with open(filename, encoding="utf-8") as f:
                # ---- read meta ----
                first_line = f.readline()
                if not first_line:
                    self.logger.warning(f"File '{filename}' is empty.")
                    return {}

                meta: dict[str, Any] = json.loads(first_line)

                # ---- read projects ----
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        projects.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        self.logger.warning(f"Broken JSON line in '{filename}': {e}")
                        continue

            # ---- logging ----
            ts = meta.get("timestamp_utc")
            ts_str = "unknown"
            if ts:
                try:
                    ts_str = datetime.fromisoformat(ts).strftime("%d-%m-%Y %H:%M:%S")
                except Exception:
                    ts_str = ts

            self.logger.info(
                f"Loaded {len(projects)} projects from '{filename}'. "
                f"Collecting time: {ts_str}"
            )

            return {
                "meta": meta,
                "projects": projects,
            }

        except FileNotFoundError:
            self.logger.debug(f"File with project data ['{filename}'] was not found.")
            return {}

    ##############

    def search_keywords(
            self,
            projects: list[dict[str, Any]],
            keywords: list[str],
            *,
            options: ScanOptions,
            hit_counter: int = 0,
            session_file: IO | None = None,
            output: SearchOutput | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """
        Execute term search across a list of projects.

        The scan plan (which projects and branches pass the filters) is built
        once and printed. Progress counts only planned projects, so projects
        excluded by --forks skip, --started-from or empty repositories never
        inflate the totals. With workers > 1 the (term, project, branch)
        searches run in parallel, see _run_search().

        Args:
            projects: The whole project index.
            keywords: Search terms.
            options: Scan options (branches, forks, activity, file filters).
            hit_counter: Initial hit counter.
            session_file: Open session JSONL to stream hits and checkpoints to
                (shortcut for ``output=SearchOutput(session_file)``).
            output: Where hits, checkpoints and files go (glh/output.py); its
                ``downloader`` saves every file with hits (--download-files),
                and each downloaded hit gets a "file" key with the local path.

        Returns:
            ([{"term", "result"}, ...], total hit counter).
        """
        output = output or SearchOutput(session_file)
        downloader = output.downloader
        plan = build_scan_plan(projects, options)
        n_terms = len(keywords)
        terms_text = terminal_utils.plural(n_terms, "term")
        hits_before = hit_counter
        if options.files_only:
            with self._file_listing_lock:
                self._file_listing_state = "unknown"
                self.file_listing_counts = Counter()
        terminal_utils.STATUS.write_block("Search plan", self._plan_rows(keywords, plan, options, downloader))

        with terminal_utils.Progress(
                "Searching", total=plan.project_count, unit="projects", rounds=n_terms,
        ) as progress:
            res, hit_counter = self._run_search(
                keywords, plan, hit_counter=hit_counter, output=output,
                progress=progress, checkpoints=True, file_window=options.file_window or None,
                file_filter=options.file_filter or None,
                file_listing=options.file_listing if options.files_only else None,
            )
            checks = (f", {terminal_utils.plural(len(self._file_change_cache), 'file check')}"
                      if options.file_window else "")
            incomplete = (f"; INCOMPLETE: {terminal_utils.plural(len(self.incomplete_terms), 'term')} "
                          f"with failed searches, not marked done" if self.incomplete_terms else "")
            if options.files_only and self.file_listing_counts:
                listed = ", ".join(f"{terminal_utils.plural(n, 'branch', 'branches')} by {how}"
                                   for how, n in sorted(self.file_listing_counts.items()))
                checks += f"; files listed: {listed}"
            progress.finish(
                f"Search finished: {terms_text} x {terminal_utils.plural(plan.project_count, 'project')}, "
                f"{terminal_utils.plural(hit_counter - hits_before, 'hit')}{checks} in "
                f"{terminal_utils.format_duration(progress.elapsed)}{incomplete}"
            )

        return res, hit_counter

    def search_keyword(
            self,
            projects: list[dict[str, Any]],
            term: str,
            *,
            options: ScanOptions,
            hit_counter: int = 0,
            session_file: IO | None = None,
            plan: ScanPlan | None = None,
            progress: terminal_utils.Progress | None = None,
            output: SearchOutput | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """
        Search a single term across the planned projects.

        Args:
            projects: The whole project index (used to build the plan if not given).
            term: Search term.
            options: Scan options.
            hit_counter: Initial hit counter.
            session_file: Open session JSONL to stream hits to (no checkpoint record).
            output: Instead of ``session_file``: the output sink (glh/output.py).
            plan: Precomputed scan plan (see build_scan_plan()).
            progress: Progress to update; a standalone one is shown if None.

        Returns:
            (per-project results, updated hit counter).
        """
        plan = plan or build_scan_plan(projects, options)
        own = progress is None
        progress = progress or terminal_utils.Progress(f"Searching '{term}'", total=plan.project_count).start()
        try:
            res, hit_counter = self._run_search([term], plan, hit_counter=hit_counter,
                                                output=output or SearchOutput(session_file),
                                                progress=progress, checkpoints=False,
                                                file_window=options.file_window or None,
                                                file_filter=options.file_filter or None)
        finally:
            if own:
                progress.finish()
        return res[0]["result"], hit_counter

    def _search_branch(self, task: _BranchTask) -> tuple[list[dict[str, Any]], str | None]:
        """
        Worker: search one term in one branch of one project (all result pages).

        Returns:
            (hits, failure): failure describes a retryable error (5xx, 429 after
            retries, 401, timeout, network, invalid response) that may have hidden
            hits, else None. 403/404 are logged and treated as nothing to find.
        """
        project_url = task.project["web_url"]
        name = task.project.get("path_with_namespace", project_url)
        n_branches = len(task.branches)
        label = f"{name} @ {task.branch}" + (f" [{task.branch_no + 1}/{n_branches}]" if n_branches > 1 else "")
        with self._active.running(label, report=f"'{task.term}' in {name} @ {task.branch}"):
            if self.concurrency <= 1:
                # Inline (main thread): show the new task now. Worker threads
                # leave redraws to the status ticker.
                terminal_utils.STATUS.refresh()
            return self._search_branch_task(task, name, project_url)

    def _search_branch_task(self, task: _BranchTask, name: str,
                            project_url: str) -> tuple[list[dict[str, Any]], str | None]:
        """_search_branch() body, while the task is registered as running."""
        if task.file_listing is not None:
            return self._collect_files_task(task, name, project_url)
        project_obj: Project = self._gl.projects.get(task.project["id"], lazy=True)
        path_filter = None
        if task.file_window or task.file_filter:
            def path_filter(path: str) -> bool:
                # The name check first: it's free, the time check costs a request.
                if task.file_filter and not task.file_filter.matches(path):
                    return False
                return not task.file_window or self._file_changed_in_window(
                    task.project["id"], task.branch, path, task.file_window)
        on_files = None
        if task.downloader is not None:
            def on_files(paths: list[str]) -> dict[str, str]:
                return self._download_files(task, name, paths)
        query = task.file_filter.query(task.term) if task.file_filter else None
        errors: list[BaseException] = []
        try:
            hits, _ = self.scan_branch(project=project_obj, branch=task.branch, term=task.term,
                                       project_url=project_url, path_filter=path_filter, errors=errors,
                                       query=query, on_files=on_files)
        except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
            self.logger.warning("Could not search %s @ %s (%s); skipping it, continuing",
                                name, task.branch, describe_api_error(e))
            self.logger.debug("Full error searching %s @ %s: %s", name, task.branch, e)
            errors.append(e)
            hits = []
        retryable = [e for e in errors if not is_permanent_error(e)]
        failure = None
        if retryable:
            failure = f"{name} @ {task.branch}: {describe_api_error(retryable[0])}"
        return hits, failure

    # ------------------------------------------------------------ files-only mode

    def _collect_files_task(self, task: _BranchTask, name: str,
                            project_url: str) -> tuple[list[dict[str, Any]], str | None]:
        """
        Files-only mode (no term): one hit per file of the branch whose name
        passes the file filters (and --file-changed-*), downloaded with
        --download-files.

        ``--file-listing``: "search" asks the search API with the filters only
        (``filename:*.env``), which works where the search backend takes such
        queries (advanced search); "tree" lists the repository tree (any
        GitLab, one request per 100 entries); "auto" tries the search and falls
        back to the tree for a branch with no results or an error, until the
        search has found files once (then it is trusted) or rejected the query
        as invalid (then only the tree is used).
        """
        errors: list[BaseException] = []
        mode = task.file_listing or "auto"
        paths: list[str] | None = None
        how = "tree"
        if mode == "search" or (mode == "auto" and self._file_listing_state != "tree"):
            paths = self._paths_by_search(task, name, errors, strict=mode == "search")
            how = "search"
        if paths is None:
            paths = self._paths_by_tree(task, name, errors)
            how = "tree"
        with self._file_listing_lock:
            self.file_listing_counts[how] += 1

        keep: list[str] = []
        for path in dict.fromkeys(paths):
            if task.file_filter and not task.file_filter.matches(path):
                continue
            if task.file_window and not self._file_changed_in_window(task.project["id"], task.branch, path,
                                                                     task.file_window):
                continue
            keep.append(path)
        local = self._download_files(task, name, keep) if task.downloader is not None and keep else {}
        blob_url = f"{project_url}/-/blob/{quote(task.branch, safe='/')}"
        hits = []
        for path in keep:
            hit: dict[str, Any] = {"url": f"{blob_url}/{quote(path, safe='/')}", "data": ""}
            if path in local:
                hit["file"] = local[path]
            hits.append(hit)
            self.logger.info("[+] File '%s': %s", task.term, hit["url"])
        retryable = [e for e in errors if not is_permanent_error(e)]
        failure = f"{name} @ {task.branch}: {describe_api_error(retryable[0])}" if retryable else None
        return hits, failure

    def _set_file_listing_state(self, state: str, message: str) -> None:
        with self._file_listing_lock:
            if self._file_listing_state == state:
                return
            self._file_listing_state = state
        terminal_utils.STATUS.write_line(message)

    def _paths_by_search(self, task: _BranchTask, name: str, errors: list[BaseException], *,
                         strict: bool) -> list[str] | None:
        """
        Paths from a filter-only blob search of the branch, or None: let the
        repository tree answer for it (auto mode, see _collect_files_task).
        """
        query = task.file_filter.query("").strip() if task.file_filter else ""
        project_obj: Project = self._gl.projects.get(task.project["id"], lazy=True)
        found: dict[str, None] = {}
        page, per_page = 1, 100
        try:
            while True:
                if page > 1:
                    self._active.set_step(f"page {page}")
                batch = project_obj.search(scope=SearchScope.BLOBS, ref=task.branch, search=query,
                                           page=page, per_page=per_page)
                for x in batch:
                    if isinstance(x, dict) and x.get("path"):
                        found.setdefault(x["path"])
                page += 1
                if len(batch) < per_page:
                    break
        except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
            if strict or is_permanent_error(e):
                self.logger.warning("Could not search %s @ %s (%s); skipping it, continuing",
                                    name, task.branch, describe_api_error(e))
                errors.append(e)
                return list(found)
            if getattr(e, "response_code", None) in (400, 422):
                self._set_file_listing_state(
                    "tree", "File listing: the search API rejects filter-only queries here "
                            f"({describe_api_error(e)}); listing repository trees instead")
            else:
                self.logger.debug("Filter-only search of %s @ %s failed (%s); listing the tree",
                                  name, task.branch, describe_api_error(e))
            return None
        if found:
            self._set_file_listing_state(
                "search", "File listing: the search API takes filter-only queries here; using it")
            return list(found)
        if strict or self._file_listing_state == "search":
            return []
        return None  # nothing found, and the search hasn't proven itself: ask the tree

    def _paths_by_tree(self, task: _BranchTask, name: str, errors: list[BaseException]) -> list[str]:
        """Every file (blob) path of the branch from the repository tree API (keyset pagination)."""
        paths: list[str] = []
        try:
            entries = self._gl.http_list(
                f"/projects/{EncodedId(task.project['id'])}/repository/tree",
                query_data={"ref": task.branch, "recursive": "true", "per_page": 100, "pagination": "keyset"},
                iterator=True,
            )
            for n, entry in enumerate(entries, 1):
                if n % 1000 == 0:
                    self._active.set_step(f"{n:,} tree entries")
                if isinstance(entry, dict) and entry.get("type") == "blob" and entry.get("path"):
                    if not task.file_filter or task.file_filter.matches(entry["path"]):
                        paths.append(entry["path"])
        except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
            self.logger.warning("Could not list the files of %s @ %s (%s); skipping it, continuing",
                                name, task.branch, describe_api_error(e))
            errors.append(e)
        return paths

    def _open_raw_file(self, project_id: Any, branch: str, path: str) -> requests.Response:
        """
        GET /projects/:id/repository/files/:path/raw?ref=<branch>, streamed.

        Goes through the thread's python-gitlab client (auth, proxy, TLS, rate
        limits, 429 retries); the caller reads and closes the response.
        """
        return self._gl.http_get(
            f"/projects/{EncodedId(project_id)}/repository/files/{EncodedId(path)}/raw",
            query_data={"ref": branch}, streamed=True, raw=True,
        )

    def _download_files(self, task: _BranchTask, name: str, paths: list[str]) -> dict[str, str]:
        """
        Download the files with hits of one branch search (--download-files).

        Returns:
            {repository path: local path} for the saved files. A file that
            can't be downloaded is logged and skipped: its hits are kept, and
            it doesn't make the term incomplete (nothing was missed in the search).
        """
        downloader = task.downloader
        assert downloader is not None
        saved: dict[str, str] = {}
        for path in paths:
            self._active.set_step(f"downloading {path.rsplit('/', 1)[-1]}")
            try:
                local = downloader.save(
                    project_id=task.project["id"], project_path=name, branch=task.branch, term=task.term,
                    path=path, fetch=lambda p=path: self._open_raw_file(task.project["id"], task.branch, p),
                )
            except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException, OSError) as e:
                downloader.failed()
                self.logger.warning("Could not download %s from %s @ %s (%s); its hits are kept",
                                    path, name, task.branch, describe_api_error(e))
                self.logger.debug("Full error downloading %s from %s @ %s: %s", path, name, task.branch, e)
                continue
            if local is None:
                self.logger.info("Not downloaded (larger than --download-max-size): %s from %s @ %s",
                                 path, name, task.branch)
                continue
            saved[path] = str(local)
        self._active.set_step("")
        return saved

    def _file_changed_in_window(self, project_id: Any, branch: str, path: str, window: TimeWindow) -> bool:
        """
        True if a commit touched ``path`` in ``branch`` inside ``window``.

        Uses GET /projects/:id/repository/commits with ref_name, path, since and
        until (one request per file, cached across terms and workers). On an
        API error the hit is kept and a warning is logged.
        """
        key = (project_id, branch, path, window.after, window.before)
        with self._file_change_lock:
            if key in self._file_change_cache:
                return self._file_change_cache[key]

        params: dict[str, Any] = {"ref_name": branch, "path": path}
        if window.after is not None:
            params["since"] = format_api_time(window.after)
        if window.before is not None:
            params["until"] = format_api_time(window.before)
        try:
            # `path` is reserved by python-gitlab's list() (it overrides the URL),
            # so the API filters go through query_parameters.
            commits = self._gl.projects.get(project_id, lazy=True).commits.list(
                query_parameters=params, page=1, per_page=1)
            changed = bool(commits)
        except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
            self.logger.warning("Cannot check changes of %s in branch %s of project %s (%s), keeping its hits",
                                path, branch, project_id, describe_api_error(e))
            self.logger.debug("Full error checking changes of %s in branch %s of project %s: %s",
                              path, branch, project_id, e)
            changed = True

        with self._file_change_lock:
            self._file_change_cache[key] = changed
        return changed

    def _run_search(
            self,
            terms: list[str],
            plan: ScanPlan,
            *,
            hit_counter: int,
            output: SearchOutput,
            progress: terminal_utils.Progress,
            checkpoints: bool,
            file_window: TimeWindow | None = None,
            file_filter: FileFilter | None = None,
            file_listing: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """
        Search ``terms`` over ``plan`` with ``self.workers`` threads.

        Work is split into (term, project, branch) tasks taken from one shared
        queue by whichever worker is free, so a few huge repositories don't
        leave other workers idle. Workers only do HTTP (search, and the files
        with hits for ``output.downloader``); this (main) thread merges branch
        results into one record per (term, project), hands records to
        ``output`` and updates progress:

        - a project record is written when all its branches are done
          (with workers > 1, records appear in completion order);
        - ``keyword_done`` is written when every task of the term and of all
          earlier terms is done, so checkpoints keep the term order and
          ``--resume`` stays correct; terms still overlap (no idle barrier).

        With workers == 1 the tasks run inline, in order, exactly as a
        sequential scan.
        """
        n_terms = len(terms)
        hits_before = hit_counter
        term_hits = [0] * n_terms
        projects_left = [plan.project_count] * n_terms
        results: list[list[tuple[int, dict[str, Any]]]] = [[] for _ in terms]
        partial: dict[tuple[int, int], dict[int, list[dict[str, Any]]]] = {}
        state = {"next_term": 0, "term_started": progress.elapsed}
        # Failed (retryable) searches per term: such a term is not marked done.
        term_failures: list[list[str]] = [[] for _ in terms]
        self.incomplete_terms = []
        # When the first task of each term was handed out (feeder thread with workers > 1).
        term_begun: dict[int, float] = {}

        def label(number: int) -> str:
            term = terms[number]
            return f"Searching '{term}'" + (f" ({number + 1}/{n_terms})" if n_terms > 1 else "")

        def close_finished_terms() -> None:
            while state["next_term"] < n_terms and projects_left[state["next_term"]] == 0:
                number = state["next_term"]
                failures = term_failures[number]
                if failures:
                    self.incomplete_terms.append(terms[number])
                if checkpoints:
                    record: dict[str, Any] = {
                        # keyword_done is the --resume checkpoint: only for terms searched completely.
                        "type": "keyword_incomplete" if failures else "keyword_done",
                        "term": terms[number],
                        "hit_counter": hits_before + sum(term_hits[:number + 1]),
                        "timestamp_utc": datetime.now(UTC).isoformat(),
                    }
                    if failures:
                        record["failed_searches"] = len(failures)
                        record["failures"] = failures[:20]
                    # Resume checkpoint: flushed, durable even if the process is killed.
                    output.checkpoint(record)
                failed = (f"; {terminal_utils.plural(len(failures), 'search', 'searches')} FAILED, "
                          f"not marked done" if failures else "")
                if checkpoints and (n_terms > 1 or failures):
                    progress.note(
                        f"Term {number + 1}/{n_terms} '{terms[number]}': "
                        f"{terminal_utils.plural(plan.project_count, 'project')}, "
                        f"{terminal_utils.plural(term_hits[number], 'hit')} in "
                        f"{terminal_utils.format_duration(progress.elapsed - state['term_started'])}{failed}"
                    )
                state["term_started"] = progress.elapsed
                state["next_term"] += 1
                if state["next_term"] < n_terms:
                    progress.start_round(state["next_term"] + 1, label(state["next_term"]),
                                         started=term_begun.get(state["next_term"]))
                    progress.done = plan.project_count - projects_left[state["next_term"]]

        def tasks():
            for term_no, term in enumerate(terms):
                term_begun.setdefault(term_no, progress.clock())
                for project_no, (project, branches) in enumerate(plan.targets):
                    for branch_no, branch in enumerate(branches):
                        yield _BranchTask(term_no, term, project_no, project, branches, branch_no, file_window,
                                          file_filter, output.downloader, file_listing)

        def report_slow_tasks() -> None:
            # Main thread only. A search can legitimately run for hours (huge
            # repositories, rate limits): say so instead of looking hung.
            if not self.slow_task_report:
                return
            now = self._active.clock()
            for running in self._active.snapshot():
                since = running.reported_at if running.reported_at is not None else running.started
                if now - since >= self.slow_task_report:
                    running.reported_at = now
                    details = ", ".join(x for x in (running.step, running.waiting) if x)
                    progress.note(
                        f"Still searching {running.report}"
                        f"{f' ({details})' if details else ''}: running for "
                        f"{terminal_utils.format_duration(self._active.elapsed(running))}"
                    )

        if n_terms:
            progress.start_round(1, label(0))
        progress.set_info(f"{human_int(hit_counter)} hits")
        close_finished_terms()  # terms without planned projects

        # The status line shows the tasks running right now (the longest-running
        # first), not the last finished one: the last task of a scan may run long
        # after all the others are done.
        previous_provider = progress.detail_provider
        progress.detail_provider = lambda: self._active.describe(terminal_utils.format_clock)

        try:
            tasks_iter = pool.imap_unordered(self._search_branch, tasks(), workers=self.concurrency,
                                             initializer=self._init_worker_client, on_idle=report_slow_tasks)
            for done in tasks_iter:
                task: _BranchTask = done.item
                hits, failure = done.unwrap()
                if failure:
                    term_failures[task.term_no].append(failure)
                key = (task.term_no, task.project_no)
                got = partial.setdefault(key, {})
                got[task.branch_no] = hits
                if len(got) < len(task.branches):
                    continue

                # All branches of this (term, project) are done: one session record.
                del partial[key]
                project = task.project
                s_res = [{"branch": b, "branch_search_result": got[i]} for i, b in enumerate(task.branches) if got[i]]
                found = sum(len(h) for h in got.values())
                hit_counter += found
                term_hits[task.term_no] += found
                if s_res:
                    out = {
                        "project_id": project["id"],
                        "web_url": project["web_url"],
                        "created_at": project.get("created_at"),
                        "last_activity_at": project.get("last_activity_at"),
                        "project_search_result": s_res,
                    }
                    results[task.term_no].append((task.project_no, out))
                    output.hit(task.term, out)

                projects_left[task.term_no] -= 1
                if task.term_no == state["next_term"]:
                    progress.done = plan.project_count - projects_left[task.term_no]
                progress.completed_units = sum(plan.project_count - left for left in projects_left)
                progress.set_info(f"{human_int(hit_counter)} hits")
                progress.advance(0)
                close_finished_terms()
                report_slow_tasks()

        finally:
            # An interrupted search keeps the running tasks in its "stopped" line.
            progress.detail = self._active.describe(terminal_utils.format_clock) or progress.detail
            progress.detail_provider = previous_provider

        res = [{"term": term, "result": [out for _, out in sorted(results[i], key=lambda x: x[0])]}
               for i, term in enumerate(terms)]
        return res, hit_counter

    def scan_project(
            self,
            project: dict[str, Any],
            term: str,
            *,
            options: ScanOptions,
            projects_by_id: dict[int, dict[str, Any]] | None = None,
            branches: list[str] | tuple[str, ...] | None = None,
            progress: terminal_utils.Progress | None = None,
            hit_counter: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """
        Scan a single project for a term across the selected branches.

        Args:
            project: Project entry from the index.
            term: Search term.
            options: Scan options (used to select branches when not given).
            projects_by_id: Index lookup for fork upstreams.
            branches: Branches to scan; computed with branches_to_scan() if None.
            progress: Progress whose detail shows the current project and branch.
            hit_counter: Initial hit counter.

        Returns:
            ([{"branch", "branch_search_result"}, ...], updated hit counter).
        """
        res: list[dict[str, Any]] = []

        project_obj: Project = self._gl.projects.get(project["id"], lazy=True)
        project_url: str = project["web_url"]

        if branches is None:
            branches = branches_to_scan(project, options, projects_by_id=projects_by_id)
        if not branches:
            return [], hit_counter

        br_len: int = len(branches)
        name = project.get("path_with_namespace", project_url)

        for num, b in enumerate(branches):
            if progress is not None:
                branch_info = b if br_len == 1 else f"{b} [{num + 1}/{br_len}]"
                progress.set_detail(f"{name} @ {branch_info}")

            try:
                s_res, hit_counter = self.scan_branch(
                    project=project_obj,
                    branch=b,
                    term=term,
                    project_url=project_url,
                    hit_counter=hit_counter,
                )
                if s_res:
                    res.append({"branch": b, "branch_search_result": s_res})
            except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
                self.logger.warning("Could not search %s @ %s (%s); skipping it, continuing",
                                    project_url, b, describe_api_error(e))
                self.logger.debug("Full error searching %s @ %s: %s", project_url, b, e)

        return res, hit_counter

    @client_required
    def scan_branch(
            self,
            project: Project,
            branch: str,
            term: str,
            project_url: str,
            hit_counter: int = 0,
            per_page: int = 100,
            path_filter: Callable[[str], bool] | None = None,
            errors: list[BaseException] | None = None,
            query: str | None = None,
            on_files: Callable[[list[str]], dict[str, str]] | None = None,
            **kwargs,
    ) -> tuple[list[dict], int]:
        """
        Search for a term inside a specific branch using GitLab blob search.

        The method performs a full-text search across repository files within
        the given branch (SearchScope.BLOBS). For each match, a direct URL
        with line reference is generated and logged.

        Args:
            project: GitLab Project object (lazy instance allowed).
            branch: Branch name to scan.
            term: Search term.
            project_url: Base web URL of the project.
            per_page: Number of results per page.
            hit_counter: Global hit counter to be incremented.
            path_filter: Optional predicate on the file path; hits in files for
                which it returns False are dropped (file name and time filters).
            errors: Optional list that receives the API error that stopped the
                search early (results of earlier pages are still returned).
            query: Search string sent to GitLab instead of ``term`` (the term
                plus --filename/--extension filters); ``term`` is still logged.
            on_files: Called once with the distinct paths of the kept results
                (--download-files); returns {path: local file} and every hit
                of such a path gets a "file" key.
            **kwargs: Additional parameters passed to GitLab search API.

        Returns:
            Tuple containing:
                - List of matches with "url" and optional "data" snippet.
                - Updated hit counter.
        """
        res: list[dict] = []
        page: int = 1

        search_results: list[dict[str, Any]] = []
        try:
            while True:
                if page > 1:
                    self._active.set_step(f"page {page}")
                batch = project.search(scope=SearchScope.BLOBS,
                                       ref=branch,
                                       search=query or term,
                                       page=page,
                                       per_page=per_page,
                                       **kwargs,
                                       )

                search_results.extend(batch)
                page += 1

                if len(batch) < per_page:
                    break

        except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
            # Keep results of already fetched pages; a timeout must not abort the whole scan.
            self.logger.warning("Could not search %s @ %s (%s); skipping it, continuing",
                                project_url, branch, describe_api_error(e))
            self.logger.debug("Full error searching %s @ %s: %s", project_url, branch, e)
            if errors is not None:
                errors.append(e)

        if path_filter is not None and search_results:
            verdict: dict[str, bool] = {}
            search_results = [x for x in search_results
                              if verdict.setdefault(x["path"], path_filter(x["path"]) if x["path"] not in verdict
                                                    else verdict[x["path"]])]

        # Branch names and paths may contain '#', '?', '%', spaces, etc.
        branch_url: str = f"{project_url}/-/tree/{quote(branch, safe='/')}"
        if search_results:
            local: dict[str, str] = {}
            if on_files is not None:
                local = on_files(list(dict.fromkeys(x["path"] for x in search_results)))
            res = []
            for x in search_results:
                hit = {'url': f'{branch_url}/{quote(x["path"], safe="/")}#L{x["startline"]}', 'data': x.get('data', '')}
                if x["path"] in local:
                    hit["file"] = local[x["path"]]
                res.append(hit)

            for x in res:
                self.logger.info(f"[+] Hitted '{term}': {x['url']}")
            hit_counter += len(res)

        return res, hit_counter
