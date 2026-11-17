# glh/limits/finder.py
"""
LimitFinder: probes the APIs of a harvester connection and recommends settings for it.
"""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence, TYPE_CHECKING

from glh.engine.workers import MAX_WORKERS
from glh.limits.constants import API_NAMES, DEFAULT_MARGIN, DEFAULT_MAX_REQUESTS, SEARCH, WINDOW
from glh.limits.probe import LimitProbe, ProbeResult, Sender
from glh.limits.recommend import recommend, Recommendation, Settings
from glh.ui import statusline
from glh.ui.formatting import format_duration, plural
from glh.ui.progress import Progress
from glh.ui.statusline import StatusLine

if TYPE_CHECKING:
    from glh.engine.harvester import GitlabHarvester

# --------------------------------------------------------------------------- harvester binding


def probe_project_from_index(path: str | Path) -> Any | None:
    """Id of the first non-empty project in an index file (streamed), or None."""
    try:
        with open(path, encoding="utf-8") as fp:
            fp.readline()  # meta
            fallback = None
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    project = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(project, dict) or project.get("id") is None:
                    continue
                if not project.get("empty_repo", False):
                    return project["id"]
                fallback = fallback if fallback is not None else project["id"]
            return fallback
    except OSError:
        return None


class LimitFinder:
    """
    Find the API limits of a :class:`~glh.engine.harvester.GitlabHarvester` connection
    and recommend settings for it.

    Probes run with the first token; other tokens of the same user share its
    budget (see ``harvester.tokens_per_user``), tokens of other users get the
    same limits (they are instance settings).
    """

    def __init__(
            self,
            harvester: "GitlabHarvester",
            *,
            max_requests: int = DEFAULT_MAX_REQUESTS,
            margin: float = DEFAULT_MARGIN,
            budgets: Mapping[str, int] | None = None,
            window: float = WINDOW,
            status: StatusLine | None = None,
            sleep: Callable[[float], None] = time.sleep,
            clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.harvester = harvester
        self.max_requests = max_requests
        self.margin = margin
        self.budgets = budgets
        self.window = window
        self._status = status if status is not None else statusline.STATUS
        self._sleep = sleep
        self._clock = clock
        self.term = f"glhprobe{secrets.token_hex(6)}"

    # ------------------------------------------------------------------ probing

    def project_for_search(self, index_file: str | Path | None = None) -> Any | None:
        """A project to send probe searches to: from the index, else the first page of /projects."""
        if index_file and Path(index_file).is_file():
            found = probe_project_from_index(index_file)
            if found is not None:
                return found
        return self.harvester.first_project_id()

    def sender_factory(self, project_id: Any = None) -> Callable[[str], Sender]:
        """Senders through fresh, unpaced clients of the harvester's first token."""
        harvester = self.harvester
        term = self.term

        def factory(kind: str) -> Sender:
            if kind == SEARCH:
                path = f"/projects/{project_id}/search"
                query = {"scope": "blobs", "search": term, "per_page": 1}
            else:
                path = "/projects"
                query = {"per_page": 1, "simple": "true"}
            return harvester.probe_sender(path, query)

        return factory

    def find(self, kinds: Sequence[str], *, project_id: Any = None) -> dict[str, ProbeResult]:
        """Probe every API in ``kinds`` (in order), waiting for a hit limit to reset in between."""
        results: dict[str, ProbeResult] = {}
        for n, kind in enumerate(kinds):
            if kind == SEARCH and project_id is None:
                results[kind] = ProbeResult(kind=kind, source="error", error="no project to search in")
                continue
            if n:
                self.wait_cooldown(results.values())
            results[kind] = self._probe_one(kind, project_id)
        return results

    def _probe_one(self, kind: str, project_id: Any) -> ProbeResult:
        progress = Progress(f"Probing {API_NAMES[kind]} limits", unit="requests",
                                           status=self._status)
        probe = LimitProbe(self.sender_factory(project_id), max_requests=self.max_requests,
                           budgets=self.budgets, window=self.window, clock=self._clock, sleep=self._sleep,
                           on_note=progress.note)
        progress.detail_provider = probe.status_text
        base_render = progress.render

        def render() -> str:
            progress.done = probe.sent  # the request counter follows the probe's live counter
            return base_render()

        progress.render = render  # type: ignore[method-assign]
        with progress:
            result = probe.probe(kind)
            limited = f", {plural(result.limited, 'HTTP 429 response')}" if result.limited else ""
            progress.finish(f"Probed {result.api} in {format_duration(result.elapsed)}: "
                            f"{plural(result.sent, 'request')}{limited}")
        return result

    def wait_cooldown(self, results: Iterable[ProbeResult]) -> float:
        """Wait until every rate-limit window the probes ran into has reset; return the seconds waited."""
        until = max((r.finished_at + r.cooldown for r in results if r.limited), default=0.0)
        left = until - self._clock()
        if left <= 0:
            return 0.0
        progress = Progress("Waiting for the rate-limit window to reset", status=self._status)
        progress.detail_provider = lambda: f"{format_duration(max(until - self._clock(), 0.0))} left"
        with progress:
            while (remaining := until - self._clock()) > 0:
                self._sleep(min(remaining, 0.5))
            progress.finish(f"Rate-limit window reset after {format_duration(left)}")
        return left

    def recommend(self, results: Mapping[str, ProbeResult], *, current: Settings,
                  explicit: Iterable[str] = ()) -> Recommendation:
        return recommend(results, current=current, explicit=explicit,
                         tokens_per_user=self.harvester.tokens_per_user(), margin=self.margin,
                         max_workers=MAX_WORKERS)

    def token_note(self) -> str | None:
        """Which tokens share a user (one budget), for the report; None for a single token."""
        groups = self.harvester.token_user_groups()
        if len(self.harvester.tokens) < 2:
            return None
        shared = [g for g in groups if len(g) > 1]
        users = plural(len(groups), "user")
        if not shared:
            return f"Tokens: {len(self.harvester.tokens)} tokens of {users}: each has its own budget."
        text = "; ".join("tokens " + ", ".join(f"#{i + 1}" for i in g) + " share one user" for g in shared)
        return f"Tokens: {len(self.harvester.tokens)} tokens of {users} ({text}: one budget)."
