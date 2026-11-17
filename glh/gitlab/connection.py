# glh/gitlab/connection.py
"""
GitLabConnection: the authenticated clients of one run.

- The main client is created and authenticated by :meth:`GitLabConnection.connect`
  with the first token; every other token is authenticated right after, so a
  revoked or mistyped one fails the run before any scanning. Token values never
  appear in an error message.
- Worker threads call :meth:`init_worker_client` (the pool initializer): each
  thread gets its own client, bound to one token round-robin, so every token
  gets ``workers`` threads; :attr:`gl` is the client of the calling thread.
- The GitLab user id of every token is kept (:attr:`token_users`): most rate
  limits count per user, so tokens of one user share one budget.

Clients come from a :class:`~glh.gitlab.factory.ClientFactory`.
"""

from __future__ import annotations

import logging
import threading
from typing import Any
from urllib.parse import urlparse

import gitlab.exceptions
import requests
import requests.exceptions
from gitlab import Gitlab
from gitlab.utils import EncodedId

from glh.exceptions import GitlabHarvesterError
from glh.gitlab.errors import describe_api_error, describe_connection_error
from glh.gitlab.factory import ClientFactory


class GitLabConnection:
    """The clients of a run, see the module doc."""

    def __init__(self, factory: ClientFactory, tokens: tuple[str, ...] | list[str] = (), *,
                 workers: int = 1, logger: logging.Logger | None = None) -> None:
        self.factory = factory
        # Tokens the run spreads its work over, each with its own pool of workers
        # and its own server-side rate-limit budget.
        self.tokens: tuple[str, ...] = tuple(tokens)
        self.workers = 1
        self.concurrency = 1
        self.set_workers(workers)
        self.logger = logger or logging.getLogger("GitlabHarvesterLogger")
        # GitLab user id of every token (same order as self.tokens), from the login check.
        self.token_users: list[Any] = []
        self._main: Gitlab | None = None
        self._owns_clients = False  # False for an injected client (tests): workers share it
        self._local = threading.local()
        self._token_lock = threading.Lock()
        self._next_token = 0

    # ------------------------------------------------------------------ clients

    @property
    def gl(self) -> Gitlab | None:
        """The client of the calling thread (worker threads have their own one)."""
        return getattr(self._local, "gl", None) or self._main

    @property
    def main(self) -> Gitlab | None:
        """The main client (the main thread's; None before connect())."""
        return self._main

    @property
    def connected(self) -> bool:
        return self._main is not None

    def require(self) -> Gitlab:
        """The client of the calling thread; GitlabHarvesterError without a connection."""
        gl = self.gl
        if gl is None:
            raise GitlabHarvesterError("You're trying to use Gitlab client before initialization.")
        return gl

    def use_client(self, gl: Any) -> None:
        """Use an existing client as the main one (tests, library callers); workers share it."""
        self._main = gl
        self._owns_clients = False

    def connect(self) -> None:
        """Create and authenticate the main client, then check every other token."""
        url = self.factory.settings.url
        if not url or not self.tokens:
            return
        self.logger.debug("Connecting to GitLab: %s", url)
        gl = self.factory.create(self.tokens[0])
        try:
            gl.auth()
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
        self.logger.debug("Authenticated to GitLab: %s", url)
        self._main = gl
        self._owns_clients = True
        self.token_users = [self._user_id(gl, 1)]
        self._verify_extra_tokens(url)

    def _verify_extra_tokens(self, url: str) -> None:
        """Authenticate every token after the first (fail fast on a bad one)."""
        total = len(self.tokens)
        for index, token in enumerate(self.tokens[1:], start=2):
            gl = self.factory.create(token)
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

    def next_token(self) -> str | None:
        """Next token for a worker thread (round-robin); None without tokens."""
        if not self.tokens:
            return None
        with self._token_lock:
            token = self.tokens[self._next_token % len(self.tokens)]
            self._next_token += 1
        return token

    def init_worker_client(self) -> None:
        """
        Pool initializer: give the calling worker thread its own client, bound
        to the next token. All tokens were checked at start-up, so no /user
        request is made here. With an injected client the threads share it.
        """
        if not self._owns_clients:
            return
        self._local.gl = self.factory.create(self.next_token())

    def unpaced_client(self, token: str | None = None) -> Gitlab:
        """A fresh client of ``token`` (default: the first) that is neither paced nor counted (probes)."""
        return self.factory.create_unpaced(token if token is not None else (self.tokens[0] if self.tokens else None))

    # ------------------------------------------------------------------ workers

    def set_workers(self, workers: int) -> None:
        """
        Parallel API requests per token (1 = sequential); the run keeps
        tokens x workers clients busy. Only pools started afterwards change.
        """
        self.workers = max(1, int(workers))
        self.concurrency = max(1, len(self.tokens)) * self.workers

    def concurrency_text(self) -> str:
        """'' (sequential), 'N workers' or 'M tokens x N workers = M*N clients'."""
        n_tokens = len(self.tokens)
        if n_tokens > 1:
            worker = "worker" if self.workers == 1 else "workers"
            return f"{n_tokens} tokens x {self.workers} {worker} = {self.concurrency} clients"
        if self.workers > 1:
            return f"{self.workers} workers"
        return ""

    # ---------------------------------------------------------------- tokens/users

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

    # -------------------------------------------------------------------- instance

    def instance_id(self) -> str:
        """'gitlab_example_com' ('host:port' -> 'host_port'); 'undefined' without a client."""
        gl = self.gl
        if not gl:
            return "undefined"
        parsed = urlparse(gl.url)
        host = (parsed.netloc or parsed.path).strip("/")
        # ':' (host:port) is not allowed in Windows file names and would create
        # an NTFS alternate data stream instead of a regular file.
        return host.replace(".", "_").replace(":", "_")

    def display_host(self) -> str:
        """The instance host as shown to the user, e.g. 'gitlab.example.com:8443'."""
        gl = self.gl
        if not gl:
            return "undefined"
        parsed = urlparse(gl.url)
        return parsed.netloc or gl.url

    def open_raw_file(self, project_id: Any, branch: str, path: str) -> requests.Response:
        """
        GET /projects/:id/repository/files/:path/raw?ref=<branch>, streamed,
        through the thread's client (auth, proxy, TLS, pacing, 429 retries);
        the caller reads and closes the response.
        """
        return self.require().http_get(
            f"/projects/{EncodedId(project_id)}/repository/files/{EncodedId(path)}/raw",
            query_data={"ref": branch}, streamed=True, raw=True,
        )
