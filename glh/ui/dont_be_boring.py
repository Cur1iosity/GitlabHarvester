# glh/ui/dont_be_boring.py
"""
And remember: ``--dont-be-boring``.

ASCII scenes for the live status panel (:mod:`glh.ui.statusline`): Karych
hammering a GitLab instance, or Karych and Vasilechek sparring. The cast idles
while the search runs, and every hit plays one strike: the hammer comes down on
the instance, or one of the two lands a punch (they take turns). At the moment
of impact the ``found`` row of the panel flashes.

Scenes are pure: :meth:`Scene.frame` maps a phase of the strike to a frame,
with no I/O and no thread. :class:`Show` decides what plays when (queued
strikes, idle blinking) and renders the frame as colored lines; the status
line draws them above its panel when the terminal is big enough, and leaves
them out otherwise.
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, replace
from typing import Callable, Sequence

WIDTH, HEIGHT = 76, 19

CROW = (
    '           \\|/',
    '       .-"""""""-.',
    "     .'           '.",
    '    /   ___   ___   \\',
    '   /   /___\\ /___\\   \\',
    '  |    ( o ) ( o )    |',
    '  |      \\___  \\_______',
    '  |       \\  ________/>',
    '  |        \\/______/  |',
    '   \\        >o<      /',
    "    '.             .'",
    "      '-._______.-'",
    '         / \\ / \\',
    '        /__V V__\\',
)

MOUSE = (
    '   .----.    .----.',
    '  /      \\__/      \\',
    ' (   .-.      .-.   )',
    '  \\_/  .------.  \\_/',
    "     .'        '.",
    '    /  __   __   \\',
    '   |  ( o) (o )   |',
    '   | <(  .--. )   |',
    '   |    /_||_\\    |',
    "    \\    '--'    /",
    "     '.        .'",
    "       '-.__.-'",
    '         /  \\',
    '        /_/\\_\\',
)

SERVER = (
    ' .------------.',
    ' |   GITLAB   |',
    ' |------------|',
    ' | [==]   o o |',
    ' | [==]   o o |',
    ' |   .env     |',
    ' |____________|',
    '    /      \\ ',
)

# Layers of the picture and their colors (xterm-256 foreground, bold for effects).
CROW_INK, MOUSE_INK, TOOL_INK, FX_INK, LOOT_INK = "crow", "mouse", "tool", "fx", "loot"
PALETTE = {
    CROW_INK: "38;5;111",
    MOUSE_INK: "38;5;254",
    TOOL_INK: "38;5;221",
    FX_INK: "1;38;5;209",
    LOOT_INK: "38;5;114",
}
CAPTION_STYLE = "38;5;221"

# What a blow may shout from the moment it lands to the end of the strike, one at
# random per strike: None keeps the scene's own lines.
SHOUTS: tuple[str | None, ...] = (
    None,
    "R4BacuJIe4ek",
    "Here's the thing: Every Scar Leaves a Trace",
)
RESET = "\x1b[0m"


class Canvas:
    """A fixed-size grid of characters, each with the layer that drew it."""

    def __init__(self) -> None:
        self.cells: list[list[tuple[str, str | None]]] = [[(" ", None)] * WIDTH for _ in range(HEIGHT)]

    def text(self, x: int, y: int, text: str, ink: str | None = None) -> None:
        if 0 <= y < HEIGHT:
            for i, ch in enumerate(text):
                if 0 <= x + i < WIDTH:
                    self.cells[y][x + i] = (ch, ink)

    def sprite(self, x: int, y: int, lines: tuple[str, ...], ink: str | None = None) -> None:
        for row, line in enumerate(lines):
            # Spaces are transparent when composing limbs and sprites.
            for col, ch in enumerate(line):
                if ch != " ":
                    self.text(x + col, y + row, ch, ink)

    def line(self, start: tuple[int, int], end: tuple[int, int], ink: str | None = None) -> None:
        x0, y0 = start
        x1, y1 = end
        dx, dy = x1 - x0, y1 - y0
        steps = max(abs(dx), abs(dy), 1)
        ch = "-" if abs(dx) > 2 * abs(dy) else ("|" if abs(dy) > 2 * abs(dx) else ("\\" if dx * dy > 0 else "/"))
        for i in range(steps + 1):
            self.text(round(x0 + dx * i / steps), round(y0 + dy * i / steps), ch, ink)

    def finish(self) -> tuple[tuple[tuple[str, str | None], ...], ...]:
        return tuple(tuple(row) for row in self.cells)


Cells = tuple[tuple[tuple[str, "str | None"], ...], ...]


@dataclass(frozen=True)
class Frame:
    cells: Cells
    caption: str
    # The blow lands in this frame; ``word`` is the sound it makes.
    impact: bool = False
    word: str = ""

    @property
    def rows(self) -> tuple[str, ...]:
        """The picture without colors."""
        return tuple("".join(ch for ch, _ in row) for row in self.cells)


@dataclass(frozen=True)
class Strike:
    """One strike: a span of the scene's cycle (phases) played over ``seconds``."""

    start: float
    end: float
    seconds: float
    # Phase at which the blow lands (the flash in the 'found' row starts then), and its sound.
    impact: float
    word: str

    @property
    def lands_after(self) -> float:
        """Seconds from the start of the strike to the blow."""
        return (self.impact - self.start) / (self.end - self.start) * self.seconds


class Scene:
    """Fixed-size ASCII frames, with no I/O or animation thread."""

    NAMES = ("harvest", "sparring")

    def __init__(self, name: str = "harvest") -> None:
        if name not in self.NAMES:
            raise ValueError(f"unknown scene: {name}")
        self.name = name

    @property
    def top(self) -> int:
        """First canvas row the scene ever draws on (the rows above it are left out)."""
        return 0 if self.name == "harvest" else 2

    @property
    def height(self) -> int:
        return HEIGHT - self.top

    def strike(self, number: int) -> Strike:
        """Strike ``number`` (0-based): the hammer every time, or the two sparring in turns."""
        if self.name == "harvest":
            return Strike(0.0, 1.0, 1.6, 0.43, "BONK!")
        if number % 2 == 0:
            return Strike(0.0, 0.5, 1.2, 0.20, "PAF!")  # Karych hits Vasilechek
        return Strike(0.5, 1.0, 1.2, 0.61, "POF!")  # Vasilechek hits back

    def idle(self, elapsed: float) -> Frame:
        """Between strikes: the guard pose, blinking now and then (and bouncing, when sparring)."""
        blink = elapsed % 3.7 < 0.15
        if self.name == "harvest":
            return self._harvest(0.0, blink=blink)
        return self._sparring(0.4, blink=blink, bounce=int(elapsed / 0.45) % 2)

    def frame(self, phase: float) -> Frame:
        """The frame at ``phase`` (0..1) of the scene's whole cycle."""
        phase = min(max(phase, 0.0), 1.0)
        return self._harvest(phase) if self.name == "harvest" else self._sparring(phase)

    # ---------------------------------------------------------------- drawing

    @staticmethod
    def _crow(canvas: Canvas, x: int = 3, y: int = 4, hit: bool = False, blink: bool = False) -> None:
        sprite = list(CROW)
        if hit:
            sprite[4] = "   /   \\___\\ /___/   \\"
            sprite[5] = "  |    ( > ) ( < )    |"
        elif blink:
            sprite[5] = "  |    ( - ) ( - )    |"
        canvas.sprite(x, y, tuple(sprite), CROW_INK)

    @staticmethod
    def _hammer(canvas: Canvas, head: tuple[int, int], grip: tuple[int, int]) -> None:
        hx, hy = head
        canvas.line((27, 13), grip, CROW_INK)
        canvas.line(grip, (hx, hy + 1), TOOL_INK)
        canvas.sprite(hx - 4, hy - 1, (".-------.", "|#######|", "'---+---'"), TOOL_INK)
        canvas.text(grip[0] - 1, grip[1], "(#)", TOOL_INK)

    def _harvest(self, phase: float, *, blink: bool = False) -> Frame:
        c = Canvas()
        impact = 0.43 <= phase < 0.53
        recovering = 0.53 <= phase < 0.72
        self._crow(c, x=4 if impact else 3, y=5 if impact else 4, blink=blink or phase > 0.92)
        offset = 2 if impact else (-1 if recovering else 0)
        c.sprite(53 + offset, 10 if impact else 9, SERVER, TOOL_INK)
        if phase < 0.22:
            head, grip, caption = (35, 5), (31, 12), "HANDCRAFTED API REQUESTS."
        elif phase < 0.36:
            head, grip, caption = (30, 1), (30, 10), "WINDING UP ANOTHER REQUEST..."
        elif phase < 0.43:
            head, grip, caption = (44, 4), (35, 12), "WINDING UP ANOTHER REQUEST..."
            c.text(38, 2, ".  .  .", FX_INK)
        elif impact:
            head, grip, caption = (60, 8), (36, 13), "BONK!  HARVESTING SECRETS."
            c.text(48, 4, r"\  |  /", FX_INK)
            c.text(47, 5, "-- BONK! --", FX_INK)
            c.text(48, 6, "/  |  \\", FX_INK)
        elif recovering:
            head, grip, caption = (45, 5), (34, 12), "ANOTHER ONE FOR THE BASKET."
            c.text(61, 5, "o--m", LOOT_INK)
            c.text(66, 3, "token", LOOT_INK)
            c.text(49, 2, ".env", LOOT_INK)
        elif phase < 0.86:
            head, grip, caption = (38, 5), (32, 12), "ANOTHER ONE FOR THE BASKET."
            c.text(66, 6, "o--m", LOOT_INK)
        else:
            head, grip, caption = (35, 5), (31, 12), "HANDCRAFTED API REQUESTS."
        self._hammer(c, head, grip)
        return Frame(c.finish(), caption, impact, "BONK!" if impact else "")

    def _sparring(self, phase: float, *, blink: bool = False, bounce: int = 0) -> Frame:
        c = Canvas()
        mouse_hit = 0.20 <= phase < 0.30  # Karych lands one
        crow_hit = 0.61 <= phase < 0.71  # Vasilechek lands one
        mouse_talks = 0.52 <= phase < 0.80
        self._crow(c, x=1 if crow_hit else 3, y=4, hit=crow_hit, blink=blink or phase > 0.92)
        mouse = list(MOUSE)
        if mouse_hit:
            mouse[6] = "   |  ( x) (x )   |"
        c.sprite(52 if mouse_hit else 50, 4, tuple(mouse), MOUSE_INK)
        if mouse_hit:
            c.line((27, 13), (53, 11), CROW_INK)
            c.text(51, 11, "(###)", CROW_INK)
            c.text(42, 7, "* PAF! *", FX_INK)
            caption = "KARYCH: YOUR TURN TO RETRY."
        elif crow_hit:
            c.line((54, 13), (31, 11), MOUSE_INK)
            c.text(29, 11, "(###)", MOUSE_INK)
            c.text(31, 6, "* POF! *", FX_INK)
            caption = "VASILECHEK: HTTP 429."
        else:
            c.line((27, 13), (33 - bounce, 12), CROW_INK)
            c.text(32 - bounce, 12, "(##)", CROW_INK)
            c.line((54, 13), (47 + bounce, 12), MOUSE_INK)
            c.text(44 + bounce, 12, "(##)", MOUSE_INK)
            caption = "VASILECHEK: REMEMBER ME?" if mouse_talks else "EXPONENTIAL BACKOFF. PERSONAL EDITION."
        if mouse_talks:
            c.text(46, 2, "< Remember me? >", MOUSE_INK)
        word = "PAF!" if mouse_hit else ("POF!" if crow_hit else "")
        return Frame(c.finish(), caption, mouse_hit or crow_hit, word)


def paint(cells: Cells, color: bool) -> str:
    """One row of a frame as text, with its layers' colors when ``color``."""
    if not color:
        return "".join(ch for ch, _ in cells).rstrip()
    out: list[str] = []
    current: str | None = None
    for ch, ink in cells:
        ink = ink if ch != " " else current  # spaces never switch colors
        if ink != current:
            out.append(RESET if ink is None else f"\x1b[{PALETTE[ink]}m")
            current = ink
        out.append(ch)
    text = "".join(out).rstrip()
    return text + RESET if current is not None else text


# Frames of the flash in the 'found' row after a blow lands: (seconds since it landed, prefix, style).
BURST = (
    (0.12, "<*>", "1;30;103"),  # black on bright yellow
    (0.30, "-*-", "1;93"),
    (0.50, " * ", "38;5;209"),
    (0.70, " . ", "2"),
)


class Show:
    """
    What the scene shows when: the cast idles, and every :meth:`hit` queues one
    strike (at most ``max_queue`` wait; more hits join the last one).

    Thread-safe: the search loop calls :meth:`hit`, the status line's ticker
    renders.
    """

    def __init__(self, scene: Scene | None = None, *, clock: Callable[[], float] = time.monotonic,
                 max_queue: int = 3, shouts: Sequence[str | None] = SHOUTS,
                 pick: Callable[[Sequence[str | None]], str | None] = random.choice) -> None:
        self.scene = scene if scene is not None else Scene(random.choice(Scene.NAMES))
        self._shouts = tuple(shouts)
        self._pick = pick
        self._shout: str | None = None  # what the current strike shouts once it lands
        self._clock = clock
        self._max_queue = max_queue
        self._lock = threading.Lock()
        self._queue: list[int] = []
        self._strikes = 0  # strikes started so far (sparring takes turns by it)
        self._current: tuple[Strike, float, int] | None = None  # (strike, started at, hits)
        # The last blow: (landed at, hits, word) for the flash in the 'found' row.
        self._landed: tuple[float, int, str] | None = None
        self._visible = False
        self._started = clock()

    def hit(self, count: int = 1) -> None:
        """``count`` new hits: one more strike."""
        if count <= 0:
            return
        with self._lock:
            if len(self._queue) >= self._max_queue:
                self._queue[-1] += count
            else:
                self._queue.append(count)
            self._advance(self._clock())

    @property
    def busy(self) -> bool:
        """A strike is playing or waiting, or the flash is on: redraw often."""
        now = self._clock()
        with self._lock:
            self._advance(now)
            flashing = self._landed is not None and now - self._landed[0] < BURST[-1][0]
            return self._current is not None or bool(self._queue) or flashing

    def _advance(self, now: float) -> None:
        """
        Lock held: land the blows whose time came, end finished strikes and start
        the queued ones back to back (each when the one before ended).
        """
        while True:
            if self._current is not None:
                strike, started, count = self._current
                lands = started + strike.lands_after
                if now >= lands and (self._landed is None or self._landed[0] < lands):
                    self._landed = (lands, count, strike.word)
                if now - started < strike.seconds:
                    return
                self._current = None
                begins = started + strike.seconds
            else:
                begins = now
            if not self._queue:
                return
            strike = self.scene.strike(self._strikes)
            self._strikes += 1
            count = self._queue.pop(0)
            if not self._visible:
                # Nobody sees the swing: no strike to wait for, the flash comes right away.
                self._landed = (now, count, strike.word)
                return
            self._current = (strike, begins, count)
            self._shout = self._pick(self._shouts) if self._shouts else None

    def frame(self) -> Frame:
        """The frame for now."""
        now = self._clock()
        with self._lock:
            self._advance(now)
            if self._current is None:
                return self.scene.idle(now - self._started)
            strike, started, _ = self._current
            progress = min((now - started) / strike.seconds, 1.0)
            frame = self.scene.frame(strike.start + (strike.end - strike.start) * progress)
            if self._shout and now >= started + strike.lands_after:
                frame = replace(frame, caption=self._shout)
            return frame

    def lines(self, columns: int, rows: int, *, color: bool = True) -> list[str] | None:
        """
        The scene and its caption as lines, or None when they don't fit
        ``columns`` x ``rows`` (the panel goes on without them).
        """
        if columns < WIDTH or rows < self.scene.height + 1:
            self._visible = False
            return None
        self._visible = True
        frame = self.frame()
        lines = [paint(row, color) for row in frame.cells[self.scene.top:]]
        caption = frame.caption
        lines.append(f"\x1b[{CAPTION_STYLE}m{caption}{RESET}" if color else caption)
        return lines

    @property
    def height(self) -> int:
        """Lines :meth:`lines` takes: the scene and its caption."""
        return self.scene.height + 1

    def burst(self) -> tuple[str, str] | None:
        """(text, ANSI style) of the flash in the 'found' row right after a blow, or None."""
        now = self._clock()
        with self._lock:
            self._advance(now)
            landed = self._landed
        if landed is None:
            return None
        since, count, word = now - landed[0], landed[1], landed[2]
        for until, prefix, style in BURST:
            if since < until:
                return f"{prefix} {word} +{count}", style
        return None
