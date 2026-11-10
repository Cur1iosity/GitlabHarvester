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
"""

from __future__ import annotations

import shutil
import sys
import threading
import time
import unicodedata
from typing import Callable, TextIO

ELLIPSIS = "…"


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
    ) -> None:
        self._stream = stream
        self._interactive = interactive
        self._columns = columns
        self._refresh_interval = refresh_interval
        self._tick_interval = tick_interval
        self._heartbeat_interval = heartbeat_interval
        self._ticker_enabled = ticker
        self._clock = clock

        self._lock = threading.RLock()
        self._provider: Callable[[], str] | None = None
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

    def _draw(self) -> None:
        if self._provider is None:
            return
        text = fit_width(_single_line(self._provider()), self._width())
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
        """Remove the status line."""
        with self._lock:
            if self.interactive:
                self._erase()
            self._provider = None

    def refresh(self, *, force: bool = False) -> None:
        """Redraw the status line (throttled unless ``force``)."""
        with self._lock:
            if self._provider is None or not self.interactive:
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
            self._write(stream if stream is not None else self.stream, text + "\n")
            if interactive:
                self._draw()

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
            if self._provider is None:
                return
            if self.interactive:
                self._draw()
            elif self._clock() - self._last_heartbeat >= self._heartbeat_interval:
                self._last_heartbeat = self._clock()
                self._write(self.stream, _single_line(self._provider()) + "\n")


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
        if self.detail:
            parts.append(self.detail)
        return " | ".join(parts)
