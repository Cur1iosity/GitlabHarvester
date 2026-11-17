# glh/limits/console.py
"""
:class:`LimiterConsole` asks the user without stopping the run. On a terminal
the question replaces the status line for ``PROMPT_TIMEOUT`` seconds with a
countdown; [Y] applies the new limits at once (``GitlabHarvester.set_rate_limits``),
[N] drops the proposal, no answer keeps it: the status line then starts with
``[Limiter: L]`` and the L key shows the question again. Without a terminal the
proposal is logged as a warning and nothing changes.

Memory stays constant: per (user, API) at most one counter per second of the
last hour.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from typing import Callable

from glh.limits.advisor import LimitAdvisor, Suggestion
from glh.ui import statusline
from glh.ui.keys import KeyReader
from glh.ui.statusline import StatusLine

PROMPT_TIMEOUT = 20.0

BADGE = "[Limiter]"

PENDING_BADGE = "[Limiter: L]"

# Keys, with the same keys of a Russian (ЙЦУКЕН) layout.
YES_KEYS = frozenset("yYнН\r\n")

NO_KEYS = frozenset("nNтТ\x1b")

SHOW_KEYS = frozenset("lLдД")


class LimiterConsole:
    """
    Ask about :class:`LimitAdvisor` proposals without stopping the run.

    A daemon thread reads single keys and drives the status line overlay; the
    scan never waits for it.
    """

    def __init__(
            self,
            advisor: LimitAdvisor,
            *,
            logger: logging.Logger | None = None,
            status: StatusLine | None = None,
            keys: KeyReader | None = None,
            timeout: float = PROMPT_TIMEOUT,
            clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.advisor = advisor
        self.logger = logger or logging.getLogger("GitlabHarvesterLogger")
        self._status = status if status is not None else statusline.STATUS
        self._keys = keys if keys is not None else KeyReader()
        self.timeout = timeout
        self._clock = clock
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.interactive = False
        # Prompt state (console thread only).
        self._shown: int | None = None  # number of the last proposal shown
        self._deadline: float | None = None  # prompt open until
        self._flash_until = 0.0
        self._flash = ""

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> "LimiterConsole":
        self.interactive = self._status.interactive and self._keys.available()
        if self.interactive:
            self._keys.open()
            self._thread = threading.Thread(target=self._loop, name="glh-limiter", daemon=True)
            self._thread.start()
        else:
            self.advisor.on_suggestion = self._log_suggestion
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        self._keys.close()
        self._status.set_overlay(None)
        if self._status.badge in (BADGE, PENDING_BADGE):
            self._status.set_badge("")
        if self.advisor.on_suggestion == self._log_suggestion:
            self.advisor.on_suggestion = None

    def __enter__(self) -> "LimiterConsole":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # ---------------------------------------------------------------- no terminal

    def _log_suggestion(self, suggestion: Suggestion) -> None:
        self.logger.warning(
            "%s %s. Suggested: %s per worker; not applied (no terminal to ask). "
            "Rerun with these options, or run in a terminal to apply them on the fly.",
            BADGE, suggestion.describe(), suggestion.flags(),
        )

    # ------------------------------------------------------------------- terminal

    def prompt_text(self) -> str:
        """The overlay while a question is open (or a short notice)."""
        now = self._clock()
        if self._deadline is not None:
            suggestion = self.advisor.pending
            left = max(0, math.ceil(self._deadline - now))
            text = suggestion.describe() if suggestion is not None else ""
            return f"{BADGE} {text}. Apply? [Y]es / [N]o / ignore: {left}s"
        return f"{BADGE} {self._flash}"

    def handle(self, key: str | None) -> None:
        """One step of the console: react to ``key`` (None = no key) and the clock."""
        now = self._clock()
        suggestion = self.advisor.pending
        if self._deadline is not None:
            if suggestion is None:
                self._close()
            elif key is not None and key in YES_KEYS:
                self._close()
                self.advisor.apply()
            elif key is not None and key in NO_KEYS:
                self._close()
                self.advisor.decline()
            elif now >= self._deadline:
                self._close()  # no answer: keep running, the proposal stays (L)
        else:
            if suggestion is not None and suggestion.number != self._shown:
                self._open(suggestion.number)
            elif key is not None and key in SHOW_KEYS:
                if suggestion is not None:
                    self._open(suggestion.number)
                else:
                    self._flash = "no proposals: GitLab has not rate-limited this run"
                    self._flash_until = now + 3.0
                    self._status.set_overlay(self.prompt_text)
            elif self._flash and now >= self._flash_until:
                self._flash = ""
                self._status.set_overlay(None)
        pending = self.advisor.pending is not None and self._deadline is None
        self._status.set_badge(PENDING_BADGE if pending else "")

    def _open(self, number: int) -> None:
        self._shown = number
        self._flash = ""
        self._deadline = self._clock() + self.timeout
        self._status.set_overlay(self.prompt_text)

    def _close(self) -> None:
        self._deadline = None
        self._status.set_overlay(None)

    def _loop(self) -> None:
        while not self._stop.is_set():
            key = self._keys.read(0.1)
            try:
                self.handle(key)
            except Exception:  # noqa: BLE001 - the console must never break the run
                self.logger.debug("Limiter console failed", exc_info=True)
