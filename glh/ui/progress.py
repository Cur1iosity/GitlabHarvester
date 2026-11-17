# glh/ui/progress.py
"""
Progress of one phase (counters, ETA, current task) on the status line.
"""

from __future__ import annotations

import time
from typing import Callable

from glh.ui import statusline
from glh.ui.blocks import format_block, Row
from glh.ui.formatting import format_clock
from glh.ui.statusline import StatusLine

# ---------------------------------------------------------------------- progress


class Progress:
    """
    Count the work of one phase and show it on a :class:`StatusLine`.

    One round (or no rounds)::

        label | 3/8 projects (37%) | info | 0:05 | ETA 0:09 | tail | detail

    ``rounds`` repeats the same total several times (one round per search
    term). Then the current round and all rounds get their own counters::

        label | term 3/5 projects (60%) 0:02 ETA 0:01 | total 8/15 (53%) 0:07 ETA 0:06 | info | tail | detail

    The counters come first and the detail (the repository being searched)
    last, so the numbers keep their place while the name changes length; the
    status line's tail (``HTTP 429 xN``) goes before the detail too.
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
        # The same as several lines for the panel (e.g. one per running task); empty: the detail.
        self.detail_lines_provider: Callable[[], list[str]] | None = None
        # Label of the info row of the panel ("found" for the hits of a search).
        self.info_label = "status"
        # Work done across all rounds when rounds overlap (parallel search);
        # None = derive it from round/done.
        self.completed_units: int | None = None
        self._status = status if status is not None else statusline.STATUS
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
        self._status.attach(self.render_counters, places_tail=True, detail=self.render_detail,
                            panel=self.render_panel)
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
        """The whole status text as one line: the counters, then the detail."""
        counters, detail = self.render_counters(), self.render_detail()
        return f"{counters} | {detail}" if detail else counters

    def render_detail(self) -> str:
        """What is being worked on (the provider's text when set, else the last detail)."""
        if self.detail_provider is not None:
            try:
                return self.detail_provider() or self.detail
            except Exception:  # noqa: BLE001 - the status line must never break the phase
                pass
        return self.detail

    def render_panel(self) -> list[str]:
        """
        The status as a block of short lines for terminals that can redraw
        several lines (see glh.ui.statusline)::

            Searching 'api_key' (2/3)
              term     32/99 projects (32%) · 0:01 · ETA 0:02
              total    131/297 (44%) · 0:04 · ETA 0:06
              found    304 hits · HTTP 429 x3
              running  acme/api @ main, page 3, 0:01
        """
        rows: list[Row] = []
        if self.total is None:
            rows.append(("done", f"{self.done:,} {self.unit} · {format_clock(self.elapsed)}"))
        elif self.rounds > 1:
            rows.append(("term", self._counter(self.done, self.total, self.unit, self.round_elapsed,
                                               self.round_eta())))
            rows.append(("total", self._counter(self.units_done, self.total * self.rounds, "", self.elapsed,
                                                self.eta())))
        else:
            rows.append(("progress", self._counter(self.done, self.total, self.unit, self.elapsed, self.eta())))
        rows.append((self.info_label, " · ".join(x for x in (self.info, self._status.tail_text()) if x)))
        rows.append(("running", self.render_detail_lines()))
        return format_block(self.label, rows)

    def _counter(self, done: int, total: int, unit: str, elapsed: float, eta: float | None) -> str:
        text = f"{done:,}/{total:,}{' ' + unit if unit else ''}{self._percent(done, total)} · {format_clock(elapsed)}"
        return text + (f" · ETA {format_clock(eta)}" if eta is not None else "")

    def render_detail_lines(self) -> list[str]:
        """The detail as lines (one per running task when the provider gives them)."""
        if self.detail_lines_provider is not None:
            try:
                if lines := self.detail_lines_provider():
                    return list(lines)
            except Exception:  # noqa: BLE001 - the status line must never break the phase
                pass
        detail = self.render_detail()
        return [detail] if detail else []

    def render_counters(self) -> str:
        """Everything but the detail: label, counters, times, info and the status line's tail."""
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
        if tail := self._status.tail_text():
            parts.append(tail)
        return " | ".join(parts)
