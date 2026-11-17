# glh/ui/statusline.py
"""
Console progress output without third-party dependencies.

There is one status line at a time, written to stderr:

- On an interactive terminal the line is redrawn in place with ``\r`` and
  space padding (no ANSI escape sequences, so it works in any Windows console),
  or, where ANSI escapes work, as a multi-line *panel* (see below).
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
heartbeat lines off a terminal, e.g. a live ``HTTP 429 x12`` counter. A provider
attached with ``places_tail`` puts the tail itself (a :class:`~glh.ui.progress.Progress`
puts it before the repository it is working on, so the counter doesn't move with
the length of the name).

A provider may also give a *detail* (``attach(detail=...)``), e.g. the
repository being searched, which follows its text on the one-line status, and a
*panel* (``attach(panel=...)``): the same information as several short lines.
On a terminal that understands ANSI the panel is shown instead of the line, with
a spinner in front of its first line, and redrawn in place line by line (each
line fitted to the terminal width, so nothing wraps and nothing is cut off on a
narrow screen). Elsewhere the one-line status is kept: no escape sequences end
up in pipes, files or terminals that can't move the cursor.

A *hint* (:meth:`StatusLine.set_hint`) is an extra line in turquoise right above
the status line, e.g. a tip while the project index is built. Permanent lines
and log records are written above it, and removing it erases it from the screen,
so it never stays in the scrollback. It needs a terminal that understands ANSI
escape sequences (on Windows the console's VT mode is switched on); elsewhere it
is not shown at all. ``NO_COLOR`` keeps it uncoloured.

A *show* (:meth:`StatusLine.set_show`, ``--dont-be-boring``) draws an animated
ASCII scene above the panel while it fits the terminal, and :meth:`StatusLine.hit`
plays a strike in it for every hit, with a flash in the panel (``burst_text``).
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
from glh.ui.dont_be_boring import Show
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
            spin_interval: float = 0.1,
            ticker: bool = True,
            clock: Callable[[], float] = time.monotonic,
            ansi: bool | None = None,
            rows: Callable[[], int] | None = None,
            show_interval: float = 0.05,
    ) -> None:
        self._stream = stream
        self._interactive = interactive
        self._ansi = ansi
        self._columns = columns
        self._rows = rows
        self._show: Show | None = None
        self._show_interval = show_interval
        self._refresh_interval = refresh_interval
        self._tick_interval = tick_interval
        self._heartbeat_interval = heartbeat_interval
        self._spin_interval = spin_interval
        self._spinner: tuple[str, ...] | None = None
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
        self._provider_places_tail = False
        # The provider's detail (e.g. the repository being searched), after its text on the one-line status.
        self._detail: Callable[[], str] | None = None
        # The provider's multi-line form, shown instead on ANSI terminals.
        self._panel: Callable[[], list[str]] | None = None
        # Lines of the status now on the screen (more than one: a panel).
        self._shown_lines = 0
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

    def _height(self) -> int:
        return self._rows() if self._rows else shutil.get_terminal_size(fallback=(80, 24)).lines

    # --------------------------------------------------------------------- drawing

    def _write(self, stream: TextIO, text: str) -> None:
        try:
            stream.write(text)
            stream.flush()
        except (OSError, ValueError):
            pass  # closed or broken stream: progress output is best-effort

    def _erase(self) -> None:
        if self._shown_lines > 1:
            # Clear the last panel line, then every line above it; the cursor ends at the first one.
            self._write(self.stream, "\r\x1b[2K" + _CURSOR_UP_CLEAR * (self._shown_lines - 1))
        elif self._shown_width:
            self._write(self.stream, "\r" + " " * self._shown_width + "\r")
        self._shown_lines = 0
        self._shown_width = 0

    def _spinner_frame(self) -> str:
        """The spinner frame for now (braille dots, or |/-\\ where the stream can't encode them)."""
        if self._spinner is None:
            frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
            try:
                frames.encode(getattr(self.stream, "encoding", None) or "utf-8")
            except (UnicodeEncodeError, LookupError):
                frames = "|/-\\"
            self._spinner = tuple(frames)
        return self._spinner[int(self._clock() / self._spin_interval) % len(self._spinner)]

    def _panel_lines(self) -> list[str] | None:
        """The panel to draw now (ANSI terminals), or None for the one-line status."""
        if self._panel is None or self._overlay is not None or self._provider is None or not self.ansi:
            return None
        try:
            lines = [_single_line(x) for x in self._panel() if x is not None]
        except Exception:  # noqa: BLE001 - the status line must never break the run
            return None
        if not lines:
            return None
        lines[0] = f"{self._spinner_frame()} {self._badge + ' ' if self._badge else ''}{lines[0]}"
        return lines

    def _draw_panel(self, lines: list[str]) -> None:
        """Redraw the panel in place: back to its first line, then every line cleared and rewritten."""
        columns = self._width()
        lines = [fit_width(x, columns) for x in lines]
        if (burst := self._burst()) is not None:
            # The flash of a hit, colored once the line has its final width.
            text, style = burst
            lines = [x.replace(text, f"\x1b[{style}m{text}{RESET}", 1) if text in x else x for x in lines]
        if self._show is not None:
            # The scene above the panel, if it fits with it (the scene's lines fit the width already).
            scene = self._show.lines(columns, self._height() - len(lines) - 1, color=not os.environ.get("NO_COLOR"))
            lines = (scene or []) + lines
        out = [f"\x1b[{self._shown_lines - 1}A" if self._shown_lines > 1 else "", "\r"]
        out.append("\n".join("\x1b[2K" + x for x in lines))
        if (extra := self._shown_lines - len(lines)) > 0:
            # A shorter panel: clear the lines left below it, then come back.
            out.append("\n\x1b[2K" * extra + f"\x1b[{extra}A")
        self._write(self.stream, "".join(out))
        self._shown_lines = len(lines)
        self._shown_width = display_width(lines[-1])

    def _burst(self) -> tuple[str, str] | None:
        if self._show is None or not self.ansi:
            return None
        try:
            return self._show.burst()
        except Exception:  # noqa: BLE001 - the status line must never break the run
            return None

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

    def _parts(self) -> tuple[str, str] | None:
        """(text, detail) shown now: the overlay, else the badge, the provider's text and its detail."""
        if self._overlay is not None:
            return self._overlay(), ""
        if self._provider is None:
            return None
        text = self._with_tail(self._provider())
        return (f"{self._badge} {text}" if self._badge else text), self._detail_text()

    def _detail_text(self) -> str:
        if self._detail is None:
            return ""
        try:
            return self._detail() or ""
        except Exception:  # noqa: BLE001 - the status line must never break the run
            return ""

    def _text(self) -> str | None:
        """What the line shows now, as one line."""
        parts = self._parts()
        if parts is None:
            return None
        text, detail = parts
        return f"{text} | {detail}" if detail else text

    def _with_tail(self, text: str) -> str:
        if self._provider_places_tail:
            return text
        tail = self.tail_text()
        return f"{text} | {tail}" if tail else text

    def tail_text(self) -> str:
        """The current tail ('' without one); never raises."""
        if self._tail is None:
            return ""
        try:
            return self._tail() or ""
        except Exception:  # noqa: BLE001 - the status line must never break the run
            return ""

    def _draw(self) -> None:
        panel = self._panel_lines()
        if panel is not None:
            self._draw_panel(panel)
            self._last_refresh = self._clock()
            return
        raw = self._text()
        if raw is None:
            return
        if self._shown_lines > 1:
            self._erase()  # from a panel back to one line (e.g. an overlay)
        line = fit_width(_single_line(raw), self._width())
        width = display_width(line)
        # Pad with spaces to overwrite the remainder of a longer previous line.
        self._write(self.stream, "\r" + line + " " * max(self._shown_width - width, 0))
        self._shown_width = width
        self._shown_lines = 1
        self._last_refresh = self._clock()

    # ------------------------------------------------------------------ public API

    def attach(self, provider: Callable[[], str], *, places_tail: bool = False,
               detail: Callable[[], str] | None = None, panel: Callable[[], list[str]] | None = None) -> None:
        """
        Show ``provider()`` as the status line until :meth:`detach`; with
        ``places_tail`` the provider includes :meth:`tail_text` itself.
        ``detail()`` follows it on the line; ``panel()`` is shown instead on
        ANSI terminals (see the module doc).
        """
        with self._lock:
            self._provider = provider
            self._provider_places_tail = places_tail
            self._detail = detail
            self._panel = panel
            self._last_heartbeat = self._clock()
            if self.interactive:
                self._draw()
        self._ensure_ticker()

    def detach(self) -> None:
        """Remove the status line (an overlay stays)."""
        with self._lock:
            self._provider = None
            self._provider_places_tail = False
            self._detail = None
            self._panel = None
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

    def set_show(self, show: Show | None) -> None:
        """Animate ``show`` above the panel (ANSI terminals; None stops it)."""
        with self._lock:
            self._show = show
            if self.interactive and self._provider is not None:
                self._draw()

    @property
    def show(self) -> Show | None:
        return self._show

    def hit(self, count: int = 1) -> None:
        """``count`` new hits: the show plays a strike (nothing without a show)."""
        if self._show is not None and count > 0 and self.ansi:
            self._show.hit(count)
            self._ensure_ticker()

    def burst_text(self) -> str:
        """The flash of the last hit for the panel ('' without one): the status line colors it."""
        burst = self._burst()
        return burst[0] if burst else ""

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
        while not never_set.wait(self._next_tick()):
            self.tick()

    def _next_tick(self) -> float:
        """Seconds to the next redraw: the show's frame rate, the spinner's, or once a second."""
        if not self._spinning():
            return self._tick_interval
        if self._show is not None and self._show.busy:
            return self._show_interval  # a strike or a flash is on: a smooth frame rate
        return self._spin_interval

    def _spinning(self) -> bool:
        """A panel with its spinner is on the screen: redraw it often."""
        return self._panel is not None and self._provider is not None and self.interactive and self.ansi

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
                text, detail = self._with_tail(self._provider()), self._detail_text()
                self._write(self.stream, _single_line(f"{text} | {detail}" if detail else text) + "\n")

STATUS = StatusLine()
"""Process-wide status line used by the harvester and its console log handler."""
