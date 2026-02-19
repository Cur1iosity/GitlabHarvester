#glh/terminal_utils.py
from __future__ import annotations

import shutil
import textwrap
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from tqdm import tqdm

GET_PROJECTS_ANIM_FRAMES: list[str] = ["🤔", "🐕❓", "📄❓", "🐒❓", "🌳‼️", "🌳🌳🌳", "🕺🌳", "💸🧙", "🍶", "🫠"]
GET_BRANCHES_ANIM_FRAMES: list[str] = ["🍌", "🍌", "🍌💃", "💃🍌", "🕺🍌", "🍌🕺"]


def term_cols(fallback: int = 120) -> int:
    """Return current terminal width in columns (best-effort)."""
    return shutil.get_terminal_size(fallback=(fallback, 20)).columns


def shorten(text: str, width: int) -> str:
    """Shorten text to fit `width` using an ellipsis placeholder."""
    if width <= 0:
        return ""
    return textwrap.shorten(str(text), width=width, placeholder="…")


def calc_tqdm_widths(*, cols: int) -> tuple[int, int]:
    """
    Compute (desc_width, postfix_width) budgets for tqdm.
    Goal: keep progress bar wide and stable.
    """
    desc_w = max(18, min(42, int(cols * 0.28)))   # ~28% of terminal
    post_w = max(12, min(28, int(cols * 0.18)))   # ~18% of terminal
    return desc_w, post_w


def animate_desc(base: str, frames: Iterable[str], i: int) -> str:
    """Return animated description string for iteration index `i`."""
    frames_list = list(frames)
    if not frames_list:
        return base
    return f"{frames_list[i % len(frames_list)]} {base}"


@dataclass(frozen=True, slots=True)
class TqdmLayout:
    """Computed layout budgets for a single terminal width."""
    cols: int
    desc_w: int
    post_w: int


def layout(fallback_cols: int = 120) -> TqdmLayout:
    """Compute stable tqdm layout budgets from terminal width."""
    cols = term_cols(fallback=fallback_cols)
    desc_w, post_w = calc_tqdm_widths(cols=cols)
    return TqdmLayout(cols=cols, desc_w=desc_w, post_w=post_w)


def bar_format_default() -> str:
    """Stable tqdm format with left+bar+right sections."""
    return "{l_bar}{bar}{r_bar}"


def bar_format_stable(lay: TqdmLayout) -> str:
    """
    Stable tqdm format where desc and postfix have fixed width.

    This prevents the progress bar from expanding/shrinking when desc/postfix length changes.
    """
    return (
        f"{{desc:<{lay.desc_w}}} "
        f"[{{elapsed}}<{{remaining}}]"
        f"{{percentage:3.0f}}% "
        f"{{bar}} "
        f"[{{n_fmt}}/{{total_fmt}}] "
        f"{{postfix}}"
    )


def mk_tqdm(
        *,
        total: int | None,
        position: int = 0,
        leave: bool = False,
        layout_: TqdmLayout | None = None,
        bar_format: str | None = None,
        **kwargs: Any,
) -> tqdm:
    """
    Create a tqdm progress bar with stable width.

    - Uses fixed ncols and disables dynamic_ncols to prevent jitter.
    - Uses a stable bar_format by default.
    """
    lay = layout_ or layout()
    return tqdm(
        total=total,
        position=position,
        leave=leave,
        ncols=lay.cols,
        dynamic_ncols=False,
        bar_format=bar_format or bar_format_stable(lay),
        **kwargs,
    )


def layout_header(fallback_cols: int = 120) -> TqdmLayout:
    cols = term_cols(fallback=fallback_cols)
    desc_w = max(40, cols - 2)
    return TqdmLayout(cols=cols, desc_w=desc_w, post_w=0)


def mk_header(
        *,
        position: int = 0,
        leave: bool = True,
        layout_: TqdmLayout | None = None,
) -> tqdm:
    """
    Create a one-line pinned header tqdm (no bar/counters).

    Useful for single-term outer “status” line without jitter.
    """
    lay = layout_ or layout_header()
    return tqdm(
        total=1,
        position=position,
        leave=leave,
        ncols=lay.cols,
        dynamic_ncols=False,
        bar_format=f"{{desc:<{lay.cols}}}",
    )


def set_desc(pbar: tqdm, text: str, lay: TqdmLayout) -> None:
    """Set shortened description respecting computed layout width."""
    pbar.set_description_str(shorten(text, lay.desc_w), refresh=True)


def set_postfix(pbar: tqdm, text: str, lay: TqdmLayout) -> None:
    """Set shortened postfix respecting computed layout width."""
    pbar.set_postfix_str(shorten(text, lay.post_w), refresh=True)
