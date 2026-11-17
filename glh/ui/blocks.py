# glh/ui/blocks.py
"""
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
