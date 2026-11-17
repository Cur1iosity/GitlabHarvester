"""
The README demo (docs/demo/demo.tape) against the real CLI output.

The GIF is recorded only when a release is published (``demo-gif.yml``), so a
change of the console output used to break it only after the release. VHS's
``Wait+Screen /re/`` matches the first ``rows`` lines of the terminal buffer,
not its visible bottom: once the output outgrows the terminal, its end is never
seen and the recording fails on the timeout (1.4.1: new output blocks, and the
final ``Done. Keywords`` line became the ``Results`` block).

This test runs the recorded command against the demo scenario and checks that
the whole final screen fits the tape's terminal (no line wraps, no scrolling)
and that every pattern the tape waits for appears on it.
"""

from __future__ import annotations

import math
import re
import shlex
from pathlib import Path
from urllib.parse import urlparse

import yaml

from fakegitlab import FakeGitLab

DEMO = Path(__file__).resolve().parents[2] / "docs" / "demo"
DEMO_URL = "https://gitlab.example.com"

# Terminal cell of VHS (xterm.js with its default font) per pixel of FontSize,
# measured on a recording: FontSize 16 gives 21.6 px rows and about 10.3 px
# columns (Height 800 with Padding 18 has 35 rows).
ROW_PX_PER_FONT_PX = 1.35
COL_PX_PER_FONT_PX = 0.64
# Rows above the scan: '$ pipx install gitlab-harvester', 'installed package ...',
# 'These apps are now globally available', '- gitlab-harvester', 'done!'.
PIPX_ROWS = 5

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def read_tape() -> tuple[dict[str, str], list[tuple[str, list[str]]]]:
    """(Set options, [(typed text, patterns waited for after it)])."""
    settings: dict[str, str] = {}
    commands: list[tuple[str, list[str]]] = []
    for raw in (DEMO / "demo.tape").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if m := re.fullmatch(r"Set (\w+) (.+)", line):
            settings[m[1]] = m[2].strip('"')
        elif m := re.fullmatch(r'Type "(.*)"', line):
            commands.append((m[1], []))
        elif m := re.fullmatch(r"Wait(?:\+\w+)?(?:@\S+)? /(.*)/", line):
            commands[-1][1].append(m[1])
    return settings, commands


def demo_terms() -> str:
    """The term file setup.sh writes (printf '...' > words.txt)."""
    m = re.search(r"printf '(.*)' > words\.txt", (DEMO / "setup.sh").read_text(encoding="utf-8"))
    assert m, "setup.sh no longer writes words.txt with printf"
    return m[1].replace("\\n", "\n")


def demo_scenario() -> dict:
    """demo.yaml without its response delays and with a few generated projects (same output lines, faster)."""
    doc = yaml.safe_load((DEMO / "demo.yaml").read_text(encoding="utf-8"))
    doc.pop("faults", None)
    for generator in doc.get("generate", []):
        generator["count"] = min(generator["count"], 3)
    return doc


def screen_lines(text: str) -> list[str]:
    """Permanent lines as a terminal shows them (no colors, in-place redraws collapsed)."""
    return [line.split("\r")[-1] for line in _ANSI.sub("", text).split("\n")]


def test_demo_tape_fits_the_terminal_and_sees_its_patterns(fake_gitlab: FakeGitLab, run_cli, tmp_path: Path):
    settings, commands = read_tape()
    [(command, patterns)] = [c for c in commands if c[0].startswith("gitlab-harvester ")]
    assert patterns, "the tape must wait for the end of the scan"

    fake_gitlab.reset(scenario=demo_scenario())
    (tmp_path / "words.txt").write_text(demo_terms(), encoding="utf-8")
    argv = shlex.split(command)[1:]
    argv[argv.index("-u") + 1] = fake_gitlab.url
    argv[argv.index("-t") + 1] = fake_gitlab.token  # $GITLAB_TOKEN in the tape
    proc = run_cli(*argv, check=True)

    # What the recording shows: the fake's address as the demo's.
    netloc = urlparse(fake_gitlab.url).netloc
    output = (proc.stderr + proc.stdout).replace(fake_gitlab.url, DEMO_URL).replace(netloc, "gitlab.example.com")
    output = output.replace(netloc.replace(".", "_").replace(":", "_"), "gitlab_example_com")
    lines = screen_lines(output)
    while lines and not lines[-1].strip():
        lines.pop()
    screen = ["$ pipx install gitlab-harvester"] * PIPX_ROWS + [f"$ {command}", *lines, "$ "]

    font = int(settings["FontSize"])
    padding = int(settings.get("Padding", "0"))
    rows = math.floor((int(settings["Height"]) - 2 * padding) / (font * ROW_PX_PER_FONT_PX))
    cols = math.floor((int(settings["Width"]) - 2 * padding) / (font * COL_PX_PER_FONT_PX))

    wrapped = [line for line in screen if len(line) > cols]
    assert not wrapped, f"lines wider than the tape's terminal ({cols} columns): {wrapped}"
    assert len(screen) <= rows, (
        f"the demo needs {len(screen)} terminal rows, the tape has {rows}: raise 'Set Height' "
        f"in docs/demo/demo.tape (about {math.ceil(font * ROW_PX_PER_FONT_PX)} px per row)\n" + "\n".join(screen)
    )
    visible = "\n".join(screen[:rows])
    for pattern in patterns:
        assert re.search(pattern, visible), f"the tape waits for /{pattern}/, which the output doesn't show:\n{visible}"
