"""
Generate docs/assets/use-cases.svg, the README's "use cases at a glance" picture.

A tree: the gitlab-harvester command branches into the scenarios of
docs/USE_CASES.md (the number on a branch is the section number there), each
with its main flags as chips; shortcut flags (-b, --time-after, --rpm) show
what they expand to, and features new in a release get a NEW badge.

When flags or use-case sections change, edit ROWS (and COMMAND) below and run,
from any directory (standard library only):

    python docs/assets/make_use_cases_svg.py

The SVG uses no external fonts or scripts, so GitHub renders it as an image.
Chip widths come from a monospace advance of 0.6em (MONO_PX), a little wider
than most monospace fonts, so text never overflows; an assertion fails if a
row gets wider than the picture. To check the result, open the SVG in a
browser, e.g. ``chrome --headless --screenshot=out.png --window-size=1200,800
file:///.../use-cases.svg``.
"""

from pathlib import Path
from xml.sax.saxutils import escape

OUT = Path(__file__).resolve().parent / "use-cases.svg"

W = 1200
PAD = 32
ROW_H = 54
ROWS_Y = 132
CHIP_H = 26
MONO_PX = 7.6        # advance of one monospace char at 12.5px (generous: 0.6em)
SANS_SMALL_PX = 6.6  # rough advance of the 11.5px sans text (for the notes)
CHIPS_X = 560

C = {
    "bg": "#0d1117", "panel": "#161b22", "border": "#30363d", "text": "#e6edf3",
    "muted": "#8b949e", "faint": "#6e7681", "flag": "#79c0ff", "value": "#a5d6ff",
    "short": "#e3b341", "short_bg": "#2a2111", "new": "#3fb950", "new_bg": "#12261a",
    "line": "#3d444d", "prompt": "#3fb950",
}
# One accent per branch.
ACCENTS = ["#58a6ff", "#3fb950", "#3fb950", "#a371f7", "#f778ba", "#d29922",
           "#39c5cf", "#ff7b72", "#58a6ff", "#8b949e"]

# (section in USE_CASES.md, title, subtitle, new in 1.3, items)
# item: ("flag", text) | ("short", text, expands-to) | ("note", text)
ROWS = [
    (1, "Search terms", "one term or a list, resumable", False,
     [("flag", "-s password"), ("flag", "-f words.txt"), ("flag", "--session audit"), ("flag", "--resume")]),
    (2, "Only some files", "exact name, * mask or extension", True,
     [("flag", "--filename settings.py"), ("flag", "--filename '*.env'"), ("flag", "--extension py")]),
    (3, "Keep the files", "copies for offline analysis", True,
     [("flag", "--download-files"), ("flag", "--download-max-size 10M"), ("flag", "--output-separated")]),
    (4, "Project inventory", "index only, no search", False,
     [("flag", "-m dump-index"), ("flag", "--index-branches all"), ("flag", "--dump-projects")]),
    (5, "Branches & forks", "which branches, what about forks", False,
     [("short", "-b all", "--index-branches + --scan-branches"), ("flag", "--forks branch-diff")]),
    (6, "Fresh findings only", "time windows on three levels", False,
     [("short", "--time-after DATE", "index + projects + files"), ("flag", "--file-changed-after DATE")]),
    (7, "Speed & rate limits", "parallel, paced, no fixed rhythm", False,
     [("flag", "-w 8"), ("short", "--rpm 30", "--index-rpm + --search-rpm"), ("flag", "--jitter 0.5-3")]),
    (8, "Several tokens", "red team: beat per-user limits", False,
     [("flag", "-t \"tok1;tok2\""), ("flag", "--token-file tokens.txt"), ("flag", "--user-agent-file ua.txt")]),
    (10, "Reports & history", "dedup, JSON, a log of every run", False,
     [("flag", "--post-process dedup,convert"), ("flag", "--final-only"), ("flag", "--log-file run.log")]),
    (12, "Config file", "the same options in an INI file", False,
     [("flag", "-c config.ini"), ("note", "command-line flags override the file")]),
]

COMMAND = ['$ ', 'gitlab-harvester ', '-u ', 'https://gitlab.example.com ', '-t ', '"$GITLAB_TOKEN" ',
           '-f ', 'words.txt ', '-b ', 'all ', '--extension ', 'yml ', '--download-files']


def mono_w(text: str) -> float:
    return len(text) * MONO_PX


def chip_w(text: str) -> float:
    return mono_w(text) + 22


def flag_tspans(text: str) -> str:
    """Flag name in the flag color, its value in the value color."""
    if " " in text:
        name, value = text.split(" ", 1)
        return (f'<tspan fill="{C["flag"]}">{escape(name)}</tspan>'
                f'<tspan fill="{C["value"]}"> {escape(value)}</tspan>')
    return f'<tspan fill="{C["flag"]}">{escape(text)}</tspan>'


rows_end = ROWS_Y + ROW_H * len(ROWS)
cmd_y = rows_end + 18
legend_y = cmd_y + 76
H = legend_y + 30

out: list[str] = []
add = out.append
add(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
    f'role="img" aria-labelledby="t d">')
add('<title id="t">GitlabHarvester use cases and their flags</title>')
add('<desc id="d">A tree: the gitlab-harvester command branches into use cases (search terms, only some files, '
    'keep the files, project inventory, branches and forks, fresh findings, speed and rate limits, several tokens, '
    'reports and history, config file), each with its main command-line flags. Shortcut flags show what they '
    'expand to.</desc>')
add('<style>'
    '.sans{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}'
    '.mono{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace}'
    '</style>')
add(f'<rect x="0.5" y="0.5" width="{W - 1}" height="{H - 1}" rx="14" fill="{C["bg"]}" stroke="{C["border"]}"/>')

# Title
add(f'<text x="{PAD}" y="50" class="sans" font-size="22" font-weight="600" fill="{C["text"]}">'
    f'Use cases at a glance</text>')
add(f'<text x="{PAD}" y="76" class="sans" font-size="13.5" fill="{C["muted"]}">'
    f'Every branch is a scenario from docs/USE_CASES.md (the number is its section); '
    f'combine flags from any of them in one run.</text>')

# Root
root_cy = ROWS_Y + ROW_H * len(ROWS) / 2 - ROW_H / 2
rx, rw, rh = PAD, 214, 74
add(f'<rect x="{rx}" y="{root_cy - rh / 2}" width="{rw}" height="{rh}" rx="10" fill="{C["panel"]}" '
    f'stroke="{C["flag"]}" stroke-width="1.5"/>')
add(f'<text x="{rx + 18}" y="{root_cy - 6}" class="mono" font-size="16" font-weight="700" fill="{C["text"]}">'
    f'gitlab-harvester</text>')
add(f'<text x="{rx + 18}" y="{root_cy + 18}" class="mono" font-size="12.5">'
    f'{flag_tspans("-u URL")}<tspan fill="{C["value"]}"> </tspan>{flag_tspans("-t TOKEN")}</text>')

node_x = 300
trunk_x = rx + rw
for i, (section, title, subtitle, new, items) in enumerate(ROWS):
    cy = ROWS_Y + i * ROW_H
    accent = ACCENTS[i]
    mid = (trunk_x + node_x) / 2
    add(f'<path d="M{trunk_x},{root_cy} C{mid},{root_cy} {mid},{cy} {node_x - 13},{cy}" fill="none" '
        f'stroke="{accent}" stroke-opacity="0.55" stroke-width="1.6"/>')
    add(f'<circle cx="{node_x}" cy="{cy}" r="13" fill="{C["bg"]}" stroke="{accent}" stroke-width="1.6"/>')
    add(f'<text x="{node_x}" y="{cy + 4.5}" text-anchor="middle" class="sans" font-size="12" font-weight="700" '
        f'fill="{accent}">{section}</text>')

    tx = node_x + 24
    add(f'<text x="{tx}" y="{cy - 3}" class="sans" font-size="14.5" font-weight="600" fill="{C["text"]}">'
        f'{escape(title)}</text>')
    if new:
        bx = tx + len(title) * 8.4 + 10
        add(f'<rect x="{bx}" y="{cy - 16}" width="34" height="17" rx="8.5" fill="{C["new_bg"]}" '
            f'stroke="{C["new"]}"/>')
        add(f'<text x="{bx + 17}" y="{cy - 4}" text-anchor="middle" class="sans" font-size="10.5" '
            f'font-weight="700" fill="{C["new"]}">NEW</text>')
    add(f'<text x="{tx}" y="{cy + 14}" class="sans" font-size="11.5" fill="{C["muted"]}">{escape(subtitle)}</text>')

    # Dotted leader from the label to the chips.
    add(f'<line x1="{CHIPS_X - 26}" y1="{cy}" x2="{CHIPS_X - 8}" y2="{cy}" stroke="{accent}" '
        f'stroke-opacity="0.5" stroke-width="1.4" stroke-dasharray="2 3"/>')

    x = CHIPS_X
    for item in items:
        kind = item[0]
        if kind == "note":
            add(f'<text x="{x + 2}" y="{cy + 4}" class="sans" font-size="12" font-style="italic" '
                f'fill="{C["muted"]}">{escape(item[1])}</text>')
            x += len(item[1]) * SANS_SMALL_PX + 16
            continue
        text = item[1]
        w = chip_w(text)
        if kind == "short":
            add(f'<rect x="{x}" y="{cy - CHIP_H / 2}" width="{w}" height="{CHIP_H}" rx="6" fill="{C["short_bg"]}" '
                f'stroke="{C["short"]}" stroke-dasharray="4 3"/>')
            name, value = (text.split(" ", 1) + [""])[:2]
            add(f'<text x="{x + 11}" y="{cy + 4.5}" class="mono" font-size="12.5">'
                f'<tspan fill="{C["short"]}" font-weight="700">{escape(name)}</tspan>'
                f'<tspan fill="{C["value"]}">{" " + escape(value) if value else ""}</tspan></text>')
            x += w + 8
            expands = "= " + item[2]
            add(f'<text x="{x}" y="{cy + 4.5}" class="mono" font-size="11.5" fill="{C["faint"]}">'
                f'{escape(expands)}</text>')
            x += len(expands) * 7.0 + 16
        else:
            add(f'<rect x="{x}" y="{cy - CHIP_H / 2}" width="{w}" height="{CHIP_H}" rx="6" fill="{C["panel"]}" '
                f'stroke="{C["border"]}"/>')
            add(f'<text x="{x + 11}" y="{cy + 4.5}" class="mono" font-size="12.5">{flag_tspans(text)}</text>')
            x += w + 8
    assert x <= W - PAD + 8, (title, x)

# Example command
cw = W - 2 * PAD
add(f'<rect x="{PAD}" y="{cmd_y}" width="{cw}" height="44" rx="8" fill="#010409" stroke="{C["border"]}"/>')
spans = []
for n, part in enumerate(COMMAND):
    if n == 0:
        color = C["prompt"]
    elif n == 1:
        color = C["text"]
    elif part.startswith("-"):
        color = C["flag"]
    else:
        color = C["value"]
    spans.append(f'<tspan fill="{color}">{escape(part)}</tspan>')
add(f'<text x="{PAD + 18}" y="{cmd_y + 27}" class="mono" font-size="13" xml:space="preserve">{"".join(spans)}</text>')
cmd_len = mono_w("".join(COMMAND)) * 13 / 12.5
assert PAD + 18 + cmd_len < W - PAD, cmd_len

# Legend
lx = PAD
ly = legend_y
add(f'<rect x="{lx}" y="{ly - 13}" width="46" height="20" rx="5" fill="{C["panel"]}" stroke="{C["border"]}"/>')
add(f'<text x="{lx + 23}" y="{ly + 1}" text-anchor="middle" class="mono" font-size="11.5" fill="{C["flag"]}">--flag</text>')
add(f'<text x="{lx + 56}" y="{ly + 1}" class="sans" font-size="12" fill="{C["muted"]}">option</text>')
lx += 120
add(f'<rect x="{lx}" y="{ly - 13}" width="30" height="20" rx="5" fill="{C["short_bg"]}" stroke="{C["short"]}" '
    f'stroke-dasharray="4 3"/>')
add(f'<text x="{lx + 15}" y="{ly + 1}" text-anchor="middle" class="mono" font-size="11.5" font-weight="700" '
    f'fill="{C["short"]}">-b</text>')
add(f'<text x="{lx + 40}" y="{ly + 1}" class="sans" font-size="12" fill="{C["muted"]}">'
    f'shortcut: sets several options at once (a specific option wins)</text>')
lx += 420
add(f'<rect x="{lx}" y="{ly - 12}" width="34" height="17" rx="8.5" fill="{C["new_bg"]}" stroke="{C["new"]}"/>')
add(f'<text x="{lx + 17}" y="{ly}" text-anchor="middle" class="sans" font-size="10.5" font-weight="700" '
    f'fill="{C["new"]}">NEW</text>')
add(f'<text x="{lx + 44}" y="{ly + 1}" class="sans" font-size="12" fill="{C["muted"]}">in 1.3</text>')
add(f'<text x="{W - PAD}" y="{ly + 1}" text-anchor="end" class="sans" font-size="12" fill="{C["faint"]}">'
    f'all options: docs/usage.md</text>')

add('</svg>')
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")
print(f"{OUT} ({W}x{H})")
