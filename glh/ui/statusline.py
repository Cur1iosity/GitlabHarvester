# glh/ui/statusline.py
"""
Console progress output without third-party dependencies.

There is one status line at a time, written to stderr:

- On an interactive terminal the line is redrawn in place with ``\r`` and
  space padding (no ANSI escape sequences, so it works in any Windows console).
  Every redraw re-reads the terminal width and truncates the text to it,
  counting wide (CJK, emoji) and zero-width characters, so the line never wraps.
  While a phase runs, the line is refreshed once per second, so the elapsed
  time keeps moving during slow API calls.
- Otherwise (pipes, files, CI) nothing is redrawn. Only permanent lines are
  written: phase summaries, and a heartbeat line every minute while a long
  phase runs.

Console log records go through :meth:`StatusLine.write_line` (see
``glh.ui.logs.ConsoleHandler``), so they never get mixed with the status line.

On a terminal, an *overlay* (:meth:`StatusLine.set_overlay`) temporarily takes
the place of the status line, e.g. a question with a countdown that must not
stop the run (``--auto-limits``, see ``glh.limits.console``), and a *badge*
(:meth:`StatusLine.set_badge`) is put in front of it, e.g. ``[Limiter]``. A
*tail* (:meth:`StatusLine.set_tail`) is appended to it on every redraw and to the
heartbeat lines off a terminal, e.g. a live ``HTTP 429 x12`` counter.

A *hint* (:meth:`StatusLine.set_hint`) is an extra line in turquoise right above
the status line, e.g. a tip while the project index is built. Permanent lines
and log records are written above it, and removing it erases it from the screen,
so it never stays in the scrollback. It needs a terminal that understands ANSI
escape sequences (on Windows the console's VT mode is switched on); elsewhere it
is not shown at all. ``NO_COLOR`` keeps it uncoloured.
"""

from __future__ import annotations

import os
import shutil
import sys
import threading
import time
from typing import Callable, TextIO

from glh.ui.ansi import _CURSOR_UP_CLEAR, HINT_COLOR, RESET, supports_ansi
from glh.ui.blocks import compact_block, format_block, Row
from glh.ui.formatting import _single_line, display_width, fit_width

# --------------------------------------------------------------------------- status line


class StatusLine:
    """
    A single in-place status line plus permanent lines on the same terminal.

    Text comes from a *provider* callable (see :class:`Progress`), so the
    background ticker can redraw it without knowing what it shows.
    """

    def __init__(
            self,
            stream: TextIO | None = None,
            *,
            interactive: bool | None = None,
            columns: Callable[[], int] | None = None,
            refresh_interval: float = 0.1,
            tick_interval: float = 1.0,
            heartbeat_interval: float = 60.0,
            ticker: bool = True,
            clock: Callable[[], float] = time.monotonic,
            ansi: bool | None = None,
    ) -> None:
        self._stream = stream
        self._interactive = interactive
        self._ansi = ansi
        self._columns = columns
        self._refresh_interval = refresh_interval
        self._tick_interval = tick_interval
        self._heartbeat_interval = heartbeat_interval
        self._ticker_enabled = ticker
        self._clock = clock

        self._lock = threading.RLock()
        self._provider: Callable[[], str] | None = None
        # Shown instead of the provider's text while set (terminal only).
        self._overlay: Callable[[], str] | None = None
        # Put in front of the provider's text, e.g. "[Limiter]".
        self._badge = ""
        # Appended to the provider's text (also in heartbeats), e.g. "HTTP 429 x12"; '' = nothing.
        self._tail: Callable[[], str] | None = None
        # Turquoise line above the status line (ANSI terminals only).
        self._hint: str | None = None
        self._hint_shown = False
        self._listeners: list[Callable[[str], None]] = []
        # The last permanent output ended with an empty line (blocks don't add another one).
        self._after_blank = True
        self._shown_width = 0
        self._last_refresh = 0.0
        self._last_heartbeat = 0.0
        self._ticker: threading.Thread | None = None

    # ----------------------------------------------------------------- environment

    @property
    def stream(self) -> TextIO:
        """Target stream (resolved lazily, so redirected sys.stderr is honored)."""
        return self._stream if self._stream is not None else sys.stderr

    @property
    def interactive(self) -> bool:
        """True when the line can be redrawn in place (a terminal)."""
        if self._interactive is not None:
            return self._interactive
        try:
            return bool(self.stream.isatty())
        except (AttributeError, ValueError, OSError):
            return False

    @property
    def ansi(self) -> bool:
        """True when ANSI escapes can be used (hint line): an ANSI terminal."""
        if self._ansi is None:
            self._ansi = self.interactive and supports_ansi(self.stream)
        return bool(self._ansi) and self.interactive

    def _width(self) -> int:
        cols = self._columns() if self._columns else shutil.get_terminal_size(fallback=(80, 24)).columns
        # Writing into the last column makes some terminals wrap; stay one cell short.
        return max(cols - 1, 1)

    # --------------------------------------------------------------------- drawing

    def _write(self, stream: TextIO, text: str) -> None:
        try:
            stream.write(text)
            stream.flush()
        except (OSError, ValueError):
            pass  # closed or broken stream: progress output is best-effort

    def _erase(self) -> None:
        if self._shown_width:
            self._write(self.stream, "\r" + " " * self._shown_width + "\r")
            self._shown_width = 0

    def _show_hint(self) -> None:
        """Lock held, status line erased: write the hint line; the status line goes below it."""
        if self._hint is None or self._hint_shown or not self.ansi:
            return
        text = fit_width(_single_line(self._hint), self._width())
        colored = text if os.environ.get("NO_COLOR") else f"{HINT_COLOR}{text}{RESET}"
        self._write(self.stream, colored + "\n")
        self._hint_shown = True

    def _hide_hint(self) -> None:
        """Lock held, status line erased: clear the hint line and move back onto it."""
        if self._hint_shown:
            self._write(self.stream, _CURSOR_UP_CLEAR)
            self._hint_shown = False

    def _text(self) -> str | None:
        """What the line shows now: the overlay, else the badge and the provider's text."""
        if self._overlay is not None:
            return self._overlay()
        if self._provider is None:
            return None
        text = self._with_tail(self._provider())
        return f"{self._badge} {text}" if self._badge else text

    def _with_tail(self, text: str) -> str:
        if self._tail is not None:
            try:
                tail = self._tail()
            except Exception:  # noqa: BLE001 - the status line must never break the run
                tail = ""
            if tail:
                return f"{text} | {tail}"
        return text

    def _draw(self) -> None:
        raw = self._text()
        if raw is None:
            return
        text = fit_width(_single_line(raw), self._width())
        width = display_width(text)
        # Pad with spaces to overwrite the remainder of a longer previous line.
        self._write(self.stream, "\r" + text + " " * max(self._shown_width - width, 0))
        self._shown_width = width
        self._last_refresh = self._clock()

    # ------------------------------------------------------------------ public API

    def attach(self, provider: Callable[[], str]) -> None:
        """Show ``provider()`` as the status line until :meth:`detach`."""
        with self._lock:
            self._provider = provider
            self._last_heartbeat = self._clock()
            if self.interactive:
                self._draw()
        self._ensure_ticker()

    def detach(self) -> None:
        """Remove the status line (an overlay stays)."""
        with self._lock:
            self._provider = None
            if self.interactive:
                if self._overlay is not None:
                    self._draw()
                else:
                    self._erase()

    def set_overlay(self, provider: Callable[[], str] | None) -> None:
        """
        Show ``provider()`` instead of the status line until called with None.

        Terminal only: elsewhere nothing is drawn. The ticker redraws it every
        second, so a countdown in it keeps moving.
        """
        with self._lock:
            self._overlay = provider
            if self.interactive:
                if provider is not None or self._provider is not None:
                    self._draw()
                else:
                    self._erase()
        if provider is not None:
            self._ensure_ticker()

    def set_badge(self, badge: str) -> None:
        """Put ``badge`` in front of the status line ('' removes it)."""
        with self._lock:
            if badge == self._badge:
                return
            self._badge = badge
            if self.interactive and (self._provider is not None or self._overlay is not None):
                self._draw()

    @property
    def badge(self) -> str:
        return self._badge

    def set_hint(self, text: str | None) -> None:
        """
        Show ``text`` in turquoise on its own line above the status line until
        called with None, which erases it. Shown only on ANSI terminals.
        """
        with self._lock:
            if text == self._hint:
                return
            if self.interactive:
                self._erase()
                self._hide_hint()
            self._hint = text
            if self.interactive:
                self._show_hint()
                self._draw()

    @property
    def hint(self) -> str | None:
        return self._hint

    def set_tail(self, provider: Callable[[], str] | None) -> None:
        """Append ``provider()`` (when not empty) to the status line; None removes it."""
        with self._lock:
            self._tail = provider
            if self.interactive and (self._provider is not None or self._overlay is not None):
                self._draw()

    def refresh(self, *, force: bool = False) -> None:
        """Redraw the status line (throttled unless ``force``)."""
        with self._lock:
            if (self._provider is None and self._overlay is None) or not self.interactive:
                return
            if force or self._clock() - self._last_refresh >= self._refresh_interval:
                self._draw()

    def write_line(self, text: str, stream: TextIO | None = None) -> None:
        """
        Print a permanent line without breaking the status line.

        The status line is erased, ``text`` is written to ``stream`` (default:
        the status stream, i.e. stderr), and the status line is drawn again.
        """
        with self._lock:
            interactive = self.interactive
            if interactive:
                self._erase()
                self._hide_hint()  # the permanent line goes above the hint
            self._write(stream if stream is not None else self.stream, text + "\n")
            self._after_blank = text == ""
            if interactive:
                self._show_hint()
                self._draw()
        if stream is None:
            # Permanent progress lines (plan, phase summaries) also go to listeners,
            # e.g. the run journal in the log file; log records (stream=stdout) don't.
            for listener in list(self._listeners):
                try:
                    listener(text)
                except Exception:  # noqa: BLE001 - a broken listener must not break output
                    pass

    def write_block(self, title: str, rows: "list[Row]") -> None:
        """
        A block (:func:`format_block`) of permanent lines after an empty line;
        listeners (the run journal) get it as one line (:func:`compact_block`).
        """
        with self._lock:
            lines = ([] if self._after_blank else [""]) + [*format_block(title, rows), ""]
            self._after_blank = True
            interactive = self.interactive
            if interactive:
                self._erase()
                self._hide_hint()
            self._write(self.stream, "\n".join(lines) + "\n")
            if interactive:
                self._show_hint()
                self._draw()
        compact = compact_block(title, rows)
        for listener in list(self._listeners):
            try:
                listener(compact)
            except Exception:  # noqa: BLE001 - a broken listener must not break output
                pass

    def add_listener(self, listener: Callable[[str], None]) -> None:
        """Also pass every permanent status line (not log records) to ``listener``."""
        if listener not in self._listeners:
            self._listeners.append(listener)

    def remove_listener(self, listener: Callable[[str], None]) -> None:
        """Stop passing permanent lines to ``listener``."""
        if listener in self._listeners:
            self._listeners.remove(listener)

    # ---------------------------------------------------------------------- ticker

    def _ensure_ticker(self) -> None:
        if not self._ticker_enabled or self._ticker is not None:
            return
        with self._lock:
            if self._ticker is None:
                self._ticker = threading.Thread(target=self._tick_loop, name="glh-status", daemon=True)
                self._ticker.start()

    def _tick_loop(self) -> None:
        # Event.wait instead of time.sleep: tests patch time.sleep to skip
        # python-gitlab's retry pauses, and the ticker must not depend on it.
        never_set = threading.Event()
        while not never_set.wait(self._tick_interval):
            self.tick()

    def tick(self) -> None:
        """Periodic update: redraw on a terminal, heartbeat line otherwise."""
        with self._lock:
            if self.interactive:
                if self._provider is not None or self._overlay is not None:
                    self._draw()
                return
            if self._provider is None:
                return
            if self._clock() - self._last_heartbeat >= self._heartbeat_interval:
                self._last_heartbeat = self._clock()
                self._write(self.stream, _single_line(self._with_tail(self._provider())) + "\n")

STATUS = StatusLine()
"""Process-wide status line used by the harvester and its console log handler."""
