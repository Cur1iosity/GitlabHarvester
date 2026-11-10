"""Console progress output (glh.utils.terminal_utils) and its log handler."""

from __future__ import annotations

import logging

import pytest

from glh.utils import logging_utils, terminal_utils
from glh.utils.terminal_utils import (
    Progress,
    StatusLine,
    display_width,
    fit_width,
    format_clock,
    format_duration,
    human_int,
    plural,
)
from tests.helpers import FakeStream


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make_status(*, tty: bool = True, columns: int = 40, clock: FakeClock | None = None) -> tuple[StatusLine, FakeStream]:
    stream = FakeStream(tty)
    status = StatusLine(stream, columns=lambda: columns, ticker=False, clock=clock or FakeClock())
    return status, stream


# --------------------------------------------------------------------------- formatting


@pytest.mark.parametrize(("n", "text"), [(0, "0"), (999, "999"), (1200, "1.2K"), (532_000, "532K"), (3_400_000_000, "3.4B")])
def test_human_int(n, text):
    assert human_int(n) == text


def test_plural():
    assert plural(1, "hit") == "1 hit"
    assert plural(0, "hit") == "0 hits"
    assert plural(1234, "branch", "branches") == "1,234 branches"


@pytest.mark.parametrize(("seconds", "clock", "duration"), [
    (0.04, "0:00", "0.0s"),
    (7.25, "0:07", "7.2s"),
    (65, "1:05", "1:05"),
    (3723, "1:02:03", "1:02:03"),
    (-3, "0:00", "0.0s"),
])
def test_durations(seconds, clock, duration):
    assert format_clock(seconds) == clock
    assert format_duration(seconds) == duration


@pytest.mark.parametrize(("text", "width"), [
    ("main", 4),
    ("ветка", 5),           # Cyrillic: one cell per letter
    ("分支", 4),             # CJK: two cells per character
    ("é", 1),         # combining accent takes no cell
    ("🔥", 2),
    ("a‍b", 2),        # zero-width joiner
])
def test_display_width(text, width):
    assert display_width(text) == width


def test_fit_width_truncates_by_cells_with_ellipsis():
    assert fit_width("abcdef", 6) == "abcdef"
    assert fit_width("abcdef", 4) == "abc…"
    assert fit_width("分支分支", 5) == "分支…"  # 2+2+1 cells, never splits a wide character
    assert display_width(fit_width("分支分支", 4)) <= 4
    assert fit_width("abc", 0) == ""


# --------------------------------------------------------------------------- status line on a terminal


def test_interactive_line_is_redrawn_in_place_and_padded():
    status, stream = make_status()
    text = ["Indexing | 100 projects"]
    status.attach(lambda: text[0])
    assert stream.getvalue() == "\rIndexing | 100 projects"

    text[0] = "Indexing | 2 p"
    status.refresh(force=True)
    # A shorter line is padded so no characters of the previous one remain.
    assert stream.getvalue().endswith("\rIndexing | 2 p" + " " * 9)
    assert "\n" not in stream.getvalue()


def test_interactive_line_is_truncated_to_terminal_width():
    status, stream = make_status(columns=20)
    status.attach(lambda: "Searching 'password' | 3/6 projects | acme/backend/api-service @ main")
    drawn = stream.getvalue().split("\r")[-1]
    assert display_width(drawn) == 19  # one cell short of the width: no auto-wrap
    assert drawn.endswith("…")


def test_width_is_reread_on_every_redraw():
    cols = [80]
    stream = FakeStream(True)
    status = StatusLine(stream, columns=lambda: cols[0], ticker=False, clock=FakeClock())
    status.attach(lambda: "x" * 60)
    assert stream.getvalue().split("\r")[-1] == "x" * 60
    cols[0] = 30  # terminal resized
    status.refresh(force=True)
    assert stream.getvalue().split("\r")[-1].rstrip() == "x" * 28 + "…"


def test_refresh_is_throttled_but_forced_redraws_are_not():
    clock = FakeClock()
    status, stream = make_status(clock=clock)
    status.attach(lambda: "x")
    writes = stream.getvalue().count("\r")
    status.refresh()
    assert stream.getvalue().count("\r") == writes  # too soon
    clock.now += 0.2
    status.refresh()
    assert stream.getvalue().count("\r") == writes + 1
    status.refresh(force=True)
    assert stream.getvalue().count("\r") == writes + 2


def test_control_characters_never_break_the_line():
    status, stream = make_status()
    status.attach(lambda: "term\nwith\ttabs")
    assert stream.getvalue() == "\rterm with tabs"


def test_permanent_line_erases_and_redraws_the_status():
    status, stream = make_status()
    status.attach(lambda: "status")
    status.write_line("Indexed 9 projects")
    assert stream.getvalue() == "\rstatus" + "\r      \r" + "Indexed 9 projects\n" + "\rstatus"


def test_permanent_line_to_another_stream_still_clears_the_status():
    status, stream = make_status()
    other = FakeStream(True)
    status.attach(lambda: "status")
    status.write_line("[WARNING] slow project", stream=other)
    assert other.getvalue() == "[WARNING] slow project\n"
    assert stream.getvalue() == "\rstatus\r      \r\rstatus"


def test_detach_erases_the_line():
    status, stream = make_status()
    status.attach(lambda: "abc")
    status.detach()
    assert stream.getvalue() == "\rabc\r   \r"
    status.refresh(force=True)  # nothing attached: no output
    assert stream.getvalue() == "\rabc\r   \r"


def test_ticker_tick_redraws_on_a_terminal():
    clock = FakeClock()
    status, stream = make_status(clock=clock)
    seconds = [0]
    status.attach(lambda: f"elapsed {seconds[0]}")
    seconds[0] = 1
    status.tick()
    assert stream.getvalue().endswith("\relapsed 1")


# --------------------------------------------------------------------------- status line in pipes / files


def test_non_interactive_output_has_only_permanent_lines():
    status, stream = make_status(tty=False)
    status.attach(lambda: "status")
    status.refresh(force=True)
    status.write_line("Indexed 9 projects")
    status.detach()
    assert stream.getvalue() == "Indexed 9 projects\n"


def test_non_interactive_heartbeat_once_per_interval():
    clock = FakeClock()
    status, stream = make_status(tty=False, clock=clock)
    status.attach(lambda: "Searching | 3/6 projects")
    status.tick()
    assert stream.getvalue() == ""
    clock.now += 60
    status.tick()
    status.tick()
    assert stream.getvalue() == "Searching | 3/6 projects\n"


def test_broken_stream_is_ignored():
    stream = FakeStream(True)
    stream.close()
    status = StatusLine(stream, columns=lambda: 40, ticker=False)
    status.attach(lambda: "x")  # must not raise
    status.write_line("y")
    status.detach()


# --------------------------------------------------------------------------- progress


def test_progress_render_with_and_without_total():
    clock = FakeClock()
    status, _ = make_status(clock=clock)
    p = Progress("Indexing gitlab.test", unit="projects", status=status, clock=clock).start()
    p.advance(1200, detail="page 12")
    clock.now += 5
    assert p.render() == "Indexing gitlab.test | 1,200 projects | 0:05 | page 12"

    q = Progress("Listing branches", total=8, status=status, clock=clock).start()
    clock.now += 10
    q.advance(2, detail="acme/api")
    q.set_info("3 hits")
    # 2 of 8 done in 10 s -> 30 s left.
    assert q.render() == "Listing branches | 2/8 projects | 3 hits | 0:10 | ETA 0:30 | acme/api"


def test_progress_eta_covers_all_rounds():
    clock = FakeClock()
    status, _ = make_status(clock=clock)
    p = Progress("Searching", total=5, rounds=2, status=status, clock=clock).start()
    p.start_round(1, "Searching 'a' (1/2)")
    p.advance(5)
    clock.now += 10
    p.start_round(2, "Searching 'b' (2/2)")
    assert p.done == 0 and p.label == "Searching 'b' (2/2)"
    # Count is per round, ETA is for the 5 remaining units of 10.
    assert p.render() == "Searching 'b' (2/2) | 0/5 projects | 0:10 | ETA 0:10"


def test_progress_without_work_has_no_eta():
    clock = FakeClock()
    status, _ = make_status(clock=clock)
    p = Progress("Searching", total=0, status=status, clock=clock).start()
    assert p.eta() is None
    assert p.render() == "Searching | 0/0 projects | 0:00"


def test_progress_finish_prints_summary_once_and_returns_elapsed():
    clock = FakeClock()
    status, stream = make_status(tty=False, clock=clock)
    p = Progress("Indexing", status=status, clock=clock).start()
    clock.now += 2.5
    assert p.finish("Indexed 3 projects in 2.5s") == 2.5
    p.finish("again")
    assert stream.getvalue() == "Indexed 3 projects in 2.5s\n"


def test_progress_context_manager_reports_where_it_stopped():
    clock = FakeClock()
    status, stream = make_status(tty=False, clock=clock)
    with pytest.raises(KeyboardInterrupt):
        with Progress("Searching", total=6, status=status, clock=clock) as p:
            p.advance(2, detail="acme/api @ main")
            raise KeyboardInterrupt
    assert stream.getvalue() == "Searching | 2/6 projects | 0:00 | acme/api @ main | stopped\n"


def test_progress_context_manager_is_silent_on_success_without_summary():
    status, stream = make_status(tty=False)
    with Progress("Searching", total=1, status=status) as p:
        p.advance()
    assert stream.getvalue() == ""


# --------------------------------------------------------------------------- logging next to the status line


def test_console_log_handler_goes_to_stdout_around_the_status_line(monkeypatch):
    status, err = make_status()
    out = FakeStream(True)
    monkeypatch.setattr(terminal_utils, "STATUS", status)
    monkeypatch.setattr("sys.stdout", out)

    logger = logging_utils.build_logger(name="glh-test-console", level=logging.WARNING, fmt="%(levelname)s %(message)s")
    try:
        status.attach(lambda: "Searching | 1/2 projects")
        logger.warning("500 | http://gitlab.test/p Branch: main")
        status.detach()
    finally:
        for h in list(logger.handlers):
            logger.removeHandler(h)

    assert out.getvalue() == "WARNING 500 | http://gitlab.test/p Branch: main\n"
    blank = " " * len("Searching | 1/2 projects")
    assert err.getvalue() == (
        "\rSearching | 1/2 projects" + f"\r{blank}\r" + "\rSearching | 1/2 projects" + f"\r{blank}\r"
    )
