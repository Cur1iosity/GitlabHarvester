"""And remember: --dont-be-boring (glh/ui/dont_be_boring.py and its place in the status panel)."""

from __future__ import annotations

import re

import pytest

from glh.cli.parser import CliParser
from glh.ui.dont_be_boring import HEIGHT, Scene, SHOUTS, Show, WIDTH
from glh.ui.progress import Progress
from glh.ui.statusline import StatusLine
from tests.helpers import FakeStream

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


# --------------------------------------------------------------------------- scenes


@pytest.mark.parametrize("name", Scene.NAMES)
def test_every_frame_has_the_canvas_size(name):
    scene = Scene(name)
    for i in range(101):
        frame = scene.frame(i / 100)
        assert len(frame.rows) == HEIGHT and {len(r) for r in frame.rows} == {WIDTH}
        assert frame.caption
    assert scene.idle(0.0).caption and scene.idle(1.0).rows != scene.idle(0.0).rows or name == "harvest"
    with pytest.raises(ValueError):
        Scene("nope")


def test_the_hammer_lands_on_the_instance():
    scene = Scene("harvest")
    strike = scene.strike(0)
    assert scene.strike(1) == strike and strike.word == "BONK!"
    frame = scene.frame(strike.impact)
    assert frame.impact and "-- BONK! --" in "\n".join(frame.rows) and "GITLAB" in "\n".join(frame.rows)
    assert scene.idle(0.0).caption == "HANDCRAFTED API REQUESTS."
    captions = {scene.frame(i / 50).caption for i in range(51)}
    assert {"WINDING UP ANOTHER REQUEST...", "BONK!  HARVESTING SECRETS.", "ANOTHER ONE FOR THE BASKET."} <= captions


def test_sparring_takes_turns_and_vasilechek_remembers():
    scene = Scene("sparring")
    karych, vasilechek = scene.strike(0), scene.strike(1)
    assert (karych.word, vasilechek.word) == ("PAF!", "POF!") and scene.strike(2) == karych
    paf = scene.frame(karych.impact)
    assert paf.impact and "* PAF! *" in "\n".join(paf.rows) and paf.caption == "KARYCH: YOUR TURN TO RETRY."
    pof = scene.frame(vasilechek.impact)
    assert pof.impact and "* POF! *" in "\n".join(pof.rows) and pof.caption == "VASILECHEK: HTTP 429."
    # Before his blow he asks.
    wind_up = scene.frame(vasilechek.start + 0.05)
    assert "< Remember me? >" in "\n".join(wind_up.rows) and wind_up.caption == "VASILECHEK: REMEMBER ME?"
    assert "Remember me?" not in "\n".join(scene.frame(karych.impact).rows)
    assert scene.idle(0.0).caption == "EXPONENTIAL BACKOFF. PERSONAL EDITION."


# --------------------------------------------------------------------------- show


def test_a_hit_plays_one_strike_and_flashes_when_the_blow_lands():
    clock = FakeClock()
    show = Show(Scene("harvest"), clock=clock, pick=lambda shouts: None)
    assert show.lines(WIDTH, 40, color=False) is not None  # on screen
    assert not show.busy and show.burst() is None
    show.hit(2)
    assert show.busy and show.burst() is None  # still winding up
    strike = show.scene.strike(0)
    clock.now += strike.lands_after + 0.1
    assert show.frame().impact
    assert show.burst() == ("<*> BONK! +2", "1;30;103")
    clock.now += 0.25
    assert show.burst()[0] == " *  BONK! +2"  # fading (0.35 s after the blow)
    clock.now += strike.seconds  # strike over, flash gone
    assert show.burst() is None and not show.busy
    assert show.frame().caption == "HANDCRAFTED API REQUESTS."


@pytest.mark.parametrize("shout", [s for s in SHOUTS if s])
def test_a_blow_may_shout_until_the_strike_ends(shout):
    clock = FakeClock()
    show = Show(Scene("sparring"), clock=clock, pick=lambda shouts: shout)
    show.lines(WIDTH, 40)
    show.hit(1)
    strike = show.scene.strike(0)
    assert show.frame().caption != shout  # not before the blow
    clock.now += strike.lands_after + 0.01
    assert show.frame().caption == shout
    clock.now += (strike.seconds - strike.lands_after) * 0.9
    assert show.frame().caption == shout
    clock.now += strike.seconds
    assert show.frame().caption == "EXPONENTIAL BACKOFF. PERSONAL EDITION."
    assert len(shout) <= WIDTH and "R4BacuJIe4ek" in SHOUTS


def test_hits_queue_up_to_a_limit():
    clock = FakeClock()
    show = Show(Scene("sparring"), clock=clock, max_queue=2)
    show.lines(WIDTH, 40, color=False)
    for _ in range(5):
        show.hit(1)  # one plays, two wait (the last one takes the extra hits)
    words = []
    for _ in range(4):
        strike = show.scene.strike(len(words))
        clock.now += strike.lands_after + 0.01
        if (burst := show.burst()) is not None:
            words.append(burst[0])
        clock.now += strike.seconds - strike.lands_after
    assert words == ["<*> PAF! +1", "<*> POF! +1", "<*> PAF! +3"]


def test_an_unseen_show_flashes_right_away():
    clock = FakeClock()
    show = Show(Scene("harvest"), clock=clock)
    assert show.lines(WIDTH - 1, 40) is None and show.lines(WIDTH, show.height - 1) is None
    show.hit(1)
    assert show.burst() == ("<*> BONK! +1", "1;30;103")


def test_colors_are_optional():
    show = Show(Scene("harvest"), clock=FakeClock())
    colored, plain = show.lines(WIDTH, 40), show.lines(WIDTH, 40, color=False)
    assert len(colored) == len(plain) == show.height
    assert any("\x1b[38;5;111m" in x for x in colored) and not any("\x1b" in x for x in plain)
    assert [_ANSI.sub("", x) for x in colored] == plain


# --------------------------------------------------------------------------- status panel


def panel(status: StatusLine, clock: FakeClock, stream: FakeStream) -> str:
    progress = Progress("Searching 'password' (1/1)", total=9, status=status, clock=clock)
    progress.info_label = "found"
    progress.start()
    progress.set_info("3 hits")
    return progress


def test_the_scene_goes_above_the_panel_and_the_hit_flashes_in_the_found_row(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    clock = FakeClock()
    stream = FakeStream(tty=True)
    status = StatusLine(stream, interactive=True, ticker=False, ansi=True, columns=lambda: 120,
                        rows=lambda: 50, clock=clock)
    status.set_show(Show(Scene("harvest"), clock=clock))
    progress = panel(status, clock, stream)
    status.refresh(force=True)
    out = stream.getvalue()
    assert "GITLAB" in out and "HANDCRAFTED API REQUESTS." in out and "\x1b[38;5;111m" in out

    progress.found(3)
    clock.now += status.show.scene.strike(0).lands_after + 0.01
    before = len(stream.getvalue())
    status.refresh(force=True)
    redraw = stream.getvalue()[before:]
    assert "-- BONK! --" in redraw
    assert "3 hits · \x1b[1;30;103m<*> BONK! +3\x1b[0m" in redraw
    # Every line of the scene is redrawn in place with the panel.
    assert redraw.startswith(f"\x1b[{status.show.height + 2}A\r")  # scene + title, progress, found
    progress.finish()
    status.set_show(None)


def test_no_scene_on_a_small_terminal_without_ansi_or_without_color(monkeypatch):
    clock = FakeClock()
    small = FakeStream(tty=True)
    status = StatusLine(small, interactive=True, ticker=False, ansi=True, columns=lambda: 70,
                        rows=lambda: 50, clock=clock)
    status.set_show(Show(Scene("harvest"), clock=clock))
    progress = panel(status, clock, small)
    progress.found(1)
    status.refresh(force=True)
    assert "GITLAB" not in small.getvalue() and "<*> BONK! +1" in small.getvalue()  # the flash still shows
    progress.finish()

    plain = FakeStream(tty=True)
    status = StatusLine(plain, interactive=True, ticker=False, ansi=False, columns=lambda: 200,
                        rows=lambda: 80, clock=clock)
    status.set_show(Show(Scene("harvest"), clock=clock))
    progress = panel(status, clock, plain)
    progress.found(1)
    status.refresh(force=True)
    assert "GITLAB" not in plain.getvalue() and "BONK" not in plain.getvalue() and "\x1b" not in plain.getvalue()
    progress.finish()

    monkeypatch.setenv("NO_COLOR", "1")
    nocolor = FakeStream(tty=True)
    status = StatusLine(nocolor, interactive=True, ticker=False, ansi=True, columns=lambda: 120,
                        rows=lambda: 50, clock=clock)
    status.set_show(Show(Scene("sparring"), clock=clock))
    progress = panel(status, clock, nocolor)
    status.refresh(force=True)
    assert "EXPONENTIAL BACKOFF" in nocolor.getvalue() and "\x1b[38;5" not in nocolor.getvalue()
    progress.finish()


# --------------------------------------------------------------------------- the flag


def test_the_flag_is_a_secret_with_a_hint(capsys):
    assert CliParser.parse(["-dbb", "-s", "x"]).dont_be_boring
    assert CliParser.parse(["--dont-be-boring", "-s", "x"]).dont_be_boring
    assert not CliParser.parse(["-s", "x"]).dont_be_boring
    with pytest.raises(SystemExit):
        CliParser.parse(["--help"])
    help_text = capsys.readouterr().out
    assert help_text.rstrip().endswith("And remember: --dont-be-boring.")
    assert help_text.count("dont-be-boring") == 1 and "-dbb" not in help_text
