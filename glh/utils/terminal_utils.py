# glh/utils/terminal_utils.py
"""
Console progress output without third-party dependencies.

There is one status line at a time, written to stderr:

- On an interactive terminal the line is redrawn in place with ``\\r`` and
  space padding (no ANSI escape sequences, so it works in any Windows console).
  Every redraw re-reads the terminal width and truncates the text to it,
  counting wide (CJK, emoji) and zero-width characters, so the line never wraps.
  While a phase runs, the line is refreshed once per second, so the elapsed
  time keeps moving during slow API calls.
- Otherwise (pipes, files, CI) nothing is redrawn. Only permanent lines are
  written: phase summaries, and a heartbeat line every minute while a long
  phase runs.

Console log records go through :meth:`StatusLine.write_line` (see
``logging_utils.ConsoleHandler``), so they never get mixed with the status line.

On a terminal, an *overlay* (:meth:`StatusLine.set_overlay`) temporarily takes
the place of the status line, e.g. a question with a countdown that must not
stop the run (``--auto-limits``, see ``glh.autolimit``), and a *badge*
(:meth:`StatusLine.set_badge`) is put in front of it, e.g. ``[Limiter]``. A
*tail* (:meth:`StatusLine.set_tail`) is appended to it on every redraw and to the
heartbeat lines off a terminal, e.g. a live ``HTTP 429 x12`` counter.

A *hint* (:meth:`StatusLine.set_hint`) is an extra line in turquoise right above
the status line, e.g. a tip while the project index is built. Permanent lines
and log records are written above it, and removing it erases it from the screen,
so it never stays in the scrollback. It needs a terminal that understands ANSI
escape sequences (on Windows the console's VT mode is switched on); elsewhere it
is not shown at all. ``NO_COLOR`` keeps it uncoloured.

Summaries with several facts (the index, the search plan, the results of a
run) are *blocks* (:func:`format_block`): a title, then one aligned
``label  value`` row per fact, so nothing has to be read out of a sentence::

    Search plan
      terms     2
      projects  5 of 9
      skipped   1 empty
                3 inactive since 2024-06-02
      branches  13

The run journal gets a block as one line (:func:`compact_block`), so it stays
easy to grep: ``Search plan: terms 2; projects 5 of 9; skipped 1 empty, ...``.
"""

from __future__ import annotations

import os
import shutil
import sys
import threading
import time
import unicodedata
from typing import Callable, TextIO

ELLIPSIS = "…"
HINT_COLOR = "\x1b[38;5;80m"  # turquoise (xterm-256 #5fd7d7)
RESET = "\x1b[0m"
_CURSOR_UP_CLEAR = "\x1b[1A\r\x1b[2K"


def _enable_windows_vt(stream: TextIO) -> bool:
    """Switch the Windows console of ``stream`` to VT mode (ANSI escapes); False if impossible."""
    try:
        import ctypes
        import msvcrt

        handle = msvcrt.get_osfhandle(stream.fileno())
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        vt = 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return bool(mode.value & vt) or bool(kernel32.SetConsoleMode(handle, mode.value | vt))
    except Exception:  # noqa: BLE001 - no console, no ctypes: just no ANSI
        return False


def supports_ansi(stream: TextIO) -> bool:
    """True if ``stream`` is a terminal that understands ANSI escape sequences."""
    try:
        if not stream.isatty():
            return False
    except (AttributeError, ValueError, OSError):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return _enable_windows_vt(stream) if os.name == "nt" else True


# --------------------------------------------------------------------------- formatting


def human_int(n: int) -> str:
    """
    Format integer into compact human-readable form.

    Examples:
        532 -> "532"
        1200 -> "1.2K"
        532000 -> "532K"
        1200000 -> "1.2M"
        3400000000 -> "3.4B"
    """
    if n < 1000:
        return str(n)

    for unit, div in (
        ("K", 1_000),
        ("M", 1_000_000),
        ("B", 1_000_000_000),
        ("T", 1_000_000_000_000),
    ):
        if n < div * 1000:
            val = n / div
            return f"{val:.1f}{unit}" if val < 10 else f"{val:.0f}{unit}"

    return f"{n:.0e}"


def plural(n: int, word: str, plural_form: str | None = None) -> str:
    """'1 hit', '2 hits', '1,234 branches' (plural_form overrides the '+s' rule)."""
    form = word if n == 1 else (plural_form or f"{word}s")
    return f"{n:,} {form}"


def format_clock(seconds: float) -> str:
    """Format a duration as a clock: '0:07', '12:34', '1:02:03'."""
    total = max(0, int(seconds))
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes}:{secs:02d}"


def format_duration(seconds: float) -> str:
    """Format a finished phase duration: '0.4s', '12.3s', '1:05', '1:02:03'."""
    if seconds < 60:
        return f"{max(seconds, 0.0):.1f}s"
    return format_clock(seconds)


def _char_width(ch: str) -> int:
    """Terminal cell width of one character (0, 1 or 2)."""
    if unicodedata.category(ch) in ("Mn", "Me", "Cf"):
        return 0  # combining marks, variation selectors, zero-width joiners
    if unicodedata.east_asian_width(ch) in ("W", "F"):
        return 2
    return 1


def display_width(text: str) -> int:
    """Number of terminal cells needed to print ``text``."""
    return sum(_char_width(ch) for ch in text)


def fit_width(text: str, width: int) -> str:
    """Truncate ``text`` to at most ``width`` terminal cells, ending with an ellipsis."""
    if width <= 0:
        return ""
    if display_width(text) <= width:
        return text
    out: list[str] = []
    used = 0
    for ch in text:
        w = _char_width(ch)
        if used + w > width - 1:  # keep one cell for the ellipsis
            break
        out.append(ch)
        used += w
    return "".join(out) + ELLIPSIS


def _single_line(text: str) -> str:
    """Replace control characters (newlines, tabs, ...) so the text stays on one line."""
    return "".join(" " if unicodedata.category(ch) == "Cc" else ch for ch in text)


COMMAND_STYLE = "1;94"  # bold bright blue


def style(text: str, codes: str, stream: TextIO) -> str:
    """``text`` in the ANSI style ``codes`` (e.g. '1;94') on an ANSI terminal without NO_COLOR, else as is."""
    if os.environ.get("NO_COLOR") or not supports_ansi(stream):
        return text
    return f"\x1b[{codes}m{text}{RESET}"


# --------------------------------------------------------------------------- blocks

# A block row: a label and its value; a list value continues on the next lines.
Row = tuple[str, "str | int | list[str]"]


def _values(value: "str | int | list[str]") -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def format_block(title: str, rows: "list[Row]") -> list[str]:
    """
    A title and aligned ``label  value`` rows; rows with an empty value are left out.

    A list value puts its first item next to the label and the others on
    their own lines, aligned under it.
    """
    rows = [(label, value) for label, value in rows if _values(value) and any(_values(value))]
    width = max((len(label) for label, _ in rows), default=0)
    lines = [title]
    for label, value in rows:
        values = [v for v in _values(value) if v]
        lines.append(f"  {label.ljust(width)}  {values[0]}")
        lines += [f"  {' ' * width}  {v}" for v in values[1:]]
    return lines


def compact_block(title: str, rows: "list[Row]") -> str:
    """The block as one line, for the run journal: 'Title: label value; label value, value'."""
    parts = [f"{label} {', '.join(v for v in _values(value) if v)}" for label, value in rows
             if any(_values(value))]
    return f"{title}: {'; '.join(parts)}"


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


# ---------------------------------------------------------------------- progress


class Progress:
    """
    Count the work of one phase and show it on a :class:`StatusLine`.

    One round (or no rounds)::

        label | 3/8 projects (37%) | info | 0:05 | ETA 0:09 | detail

    ``rounds`` repeats the same total several times (one round per search
    term). Then the current round and all rounds get their own counters::

        label | term 3/5 projects (60%) 0:02 ETA 0:01 | total 8/15 (53%) 0:07 ETA 0:06 | info | detail
    """

    def __init__(
            self,
            label: str,
            *,
            total: int | None = None,
            unit: str = "projects",
            rounds: int = 1,
            status: StatusLine | None = None,
            clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.label = label
        self.total = total
        self.unit = unit
        self.rounds = max(rounds, 1)
        self.round = 1
        self.done = 0
        self.info = ""
        self.detail = ""
        # Called on every redraw (also by the ticker thread) to describe the
        # work running right now; its non-empty text replaces ``detail``.
        self.detail_provider: Callable[[], str] | None = None
        # Work done across all rounds when rounds overlap (parallel search);
        # None = derive it from round/done.
        self.completed_units: int | None = None
        self._status = status if status is not None else STATUS
        self._clock = clock
        self._started: float | None = None
        self._round_started: float | None = None
        self._finished = False

    # ------------------------------------------------------------------ lifecycle

    def __enter__(self) -> "Progress":
        return self.start()

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if not self._finished:
            # Leave a trace of how far the phase got (Ctrl+C, fatal errors).
            self.finish(f"{self.render()} | stopped" if exc_type is not None else None)

    def start(self) -> "Progress":
        """Start the clock and show the status line."""
        self._started = self._clock()
        self._round_started = self._started
        self._status.attach(self.render)
        return self

    def finish(self, summary: str | None = None) -> float:
        """Remove the status line, print ``summary`` (if any) and return the elapsed time."""
        elapsed = self.elapsed
        if not self._finished:
            self._finished = True
            self._status.detach()
            if summary:
                self._status.write_line(summary)
        return elapsed

    def note(self, text: str) -> None:
        """Print a permanent line while the phase keeps running."""
        self._status.write_line(text)

    # -------------------------------------------------------------------- updates

    def advance(self, n: int = 1, *, detail: str | None = None) -> None:
        """Count ``n`` finished items."""
        self.done += n
        if detail is not None:
            self.detail = detail
        self._status.refresh()

    def set_detail(self, detail: str) -> None:
        """Describe the item being processed right now."""
        self.detail = detail
        self._status.refresh()

    def set_info(self, info: str) -> None:
        """Set the extra counter shown after the item count (e.g. hits)."""
        self.info = info
        self._status.refresh()

    def start_round(self, number: int, label: str | None = None, *, started: float | None = None) -> None:
        """
        Begin round ``number`` (1-based) of ``rounds``.

        ``started`` is when the round's work really began (a :meth:`clock`
        value); rounds overlap with parallel workers. Default: now.
        """
        self.round = min(max(number, 1), self.rounds)
        self.done = 0
        if label is not None:
            self.label = label
        self.detail = ""
        self._round_started = started if started is not None else self._clock()
        self._status.refresh(force=True)

    # ------------------------------------------------------------------- metrics

    def clock(self) -> float:
        """Current reading of this progress' clock (for start_round(started=...))."""
        return self._clock()

    @property
    def elapsed(self) -> float:
        """Seconds since :meth:`start`."""
        return 0.0 if self._started is None else self._clock() - self._started

    @property
    def round_elapsed(self) -> float:
        """Seconds since the current round started."""
        return 0.0 if self._round_started is None else max(self._clock() - self._round_started, 0.0)

    @property
    def units_done(self) -> int:
        """Items finished across all rounds."""
        if self.completed_units is not None:
            return self.completed_units
        return (self.total or 0) * (self.round - 1) + self.done

    @staticmethod
    def _estimate(elapsed: float, done: int, total: int) -> float | None:
        """Seconds left at the current rate; None while unknown or sub-second (noise)."""
        if elapsed < 1.0 or done <= 0 or done >= total:
            return None
        return elapsed / done * (total - done)

    @staticmethod
    def _percent(done: int, total: int) -> str:
        """' (37%)' rounded down, so 100% means really finished; '' for an empty total."""
        return f" ({done * 100 // total}%)" if total > 0 else ""

    def eta(self) -> float | None:
        """Estimated seconds left for all rounds, or None if unknown."""
        if not self.total:
            return None
        return self._estimate(self.elapsed, self.units_done, self.total * self.rounds)

    def round_eta(self) -> float | None:
        """Estimated seconds left for the current round, or None if unknown."""
        if not self.total:
            return None
        return self._estimate(self.round_elapsed, self.done, self.total)

    def render(self) -> str:
        """Status line text."""
        parts = [self.label]
        if self.total is None:
            parts += [f"{self.done:,} {self.unit}"]
            parts += [self.info] if self.info else []
            parts += [format_clock(self.elapsed)]
        elif self.rounds > 1:
            # Current round (search term) and all rounds, without repeating labels.
            term = f"term {self.done:,}/{self.total:,} {self.unit}{self._percent(self.done, self.total)} " \
                   f"{format_clock(self.round_elapsed)}"
            if (eta := self.round_eta()) is not None:
                term += f" ETA {format_clock(eta)}"
            units_total = self.total * self.rounds
            total = f"total {self.units_done:,}/{units_total:,}{self._percent(self.units_done, units_total)} " \
                    f"{format_clock(self.elapsed)}"
            if (eta := self.eta()) is not None:
                total += f" ETA {format_clock(eta)}"
            parts += [term, total]
            parts += [self.info] if self.info else []
        else:
            parts += [f"{self.done:,}/{self.total:,} {self.unit}{self._percent(self.done, self.total)}"]
            parts += [self.info] if self.info else []
            parts += [format_clock(self.elapsed)]
            if (eta := self.eta()) is not None:
                parts += [f"ETA {format_clock(eta)}"]
        detail = self.detail
        if self.detail_provider is not None:
            try:
                detail = self.detail_provider() or detail
            except Exception:  # noqa: BLE001 - the status line must never break the phase
                pass
        if detail:
            parts.append(detail)
        return " | ".join(parts)
