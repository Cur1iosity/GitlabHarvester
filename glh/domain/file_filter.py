# glh/domain/file_filter.py
"""
File filters for the search: ``--filename`` and ``--extension``.

GitLab code search (``scope=blobs``, basic and advanced search) understands
filters written into the search string itself: ``password filename:*.env``
searches "password" only in files whose name matches ``*.env``. There is no
separate API parameter, so the harvester appends the filters to every term in
the request (``FileFilter.query``); the term stored in the session stays as
the user wrote it.

The filters are also re-checked on the client (``FileFilter.matches``) against
the ``path`` of every result, for two reasons:

- an instance or GitLab version that ignores a filter still yields only the
  files asked for;
- GitLab's basic search is looser than the option promises: its ``filename:``
  matches the *end of the whole path* (``filename:config.yml`` also returns
  ``app/myconfig.yml``), while ``--filename`` matches the file name exactly.

Matching (both filters case-insensitive, ``*`` is the only wildcard and
matches any characters):

- ``--filename PATTERN``: the file name (basename), e.g. ``settings.py``,
  ``*.env``, ``config*``, ``docker-compose*.yml``. A pattern with ``/``
  matches the end of the path instead (``config/*.yml``).
- ``--extension EXT``: the file name ends with ``.EXT``. Leading ``*``/``.``
  and trailing dots are dropped, so ``.py``, ``py`` and ``*.py`` are the same.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


class FileFilterError(ValueError):
    """An invalid --filename / --extension value."""


def _check_no_spaces(value: str, option: str) -> None:
    # GitLab reads a filter value up to the next whitespace: a space would turn
    # the rest of the value into a search term.
    if any(ch.isspace() for ch in value):
        raise FileFilterError(f"{option} must not contain spaces: {value!r}")


def normalize_filename(value: str) -> str:
    """
    Validate a --filename pattern: no spaces, not empty; a leading '/' is
    dropped (GitLab paths have none).
    """
    v = value.strip().lstrip("/")
    if not v or not v.strip("*"):
        raise FileFilterError("--filename needs a file name or a mask, e.g. settings.py or *.env")
    _check_no_spaces(v, "--filename")
    return v


def normalize_extension(value: str) -> str:
    """
    Validate an --extension value and drop the extra dots: '.py', 'py', '..py',
    '*.py' and 'py.' all become 'py'. Inner dots stay ('tar.gz').
    """
    v = value.strip().lstrip("*.").rstrip(".")
    if not v:
        raise FileFilterError("--extension needs an extension, e.g. py or .py")
    _check_no_spaces(v, "--extension")
    if "/" in v:
        raise FileFilterError(f"--extension must not contain '/': {value!r}")
    return v


def _wildcard(pattern: str) -> str:
    """Regex for a pattern where only '*' is special."""
    return ".*".join(re.escape(part) for part in pattern.split("*"))


@dataclass(frozen=True, slots=True)
class FileFilter:
    """
    The file filters of a search; empty (falsy) when neither is set.

    Values are normalized on construction (``normalize_filename``,
    ``normalize_extension``), so library callers get the same behavior as the
    CLI (``extension=".py"`` means ``py``); invalid values raise FileFilterError.
    """

    filename: str | None = None
    extension: str | None = None

    def __post_init__(self) -> None:
        # Frozen dataclass: normalize through object.__setattr__.
        if self.filename is not None:
            object.__setattr__(self, "filename", normalize_filename(self.filename))
        if self.extension is not None:
            object.__setattr__(self, "extension", normalize_extension(self.extension))

    def __bool__(self) -> bool:
        return bool(self.filename or self.extension)

    def query(self, term: str) -> str:
        """The search string sent to GitLab: the term plus the filters."""
        parts = [term]
        if self.filename:
            parts.append(f"filename:{self.filename}")
        if self.extension:
            parts.append(f"extension:{self.extension}")
        return " ".join(parts)

    def matches(self, path: str) -> bool:
        """True if the file at ``path`` (repository path, '/'-separated) passes the filters."""
        name = path.rsplit("/", 1)[-1]
        if self.filename:
            if "/" in self.filename:
                ok = re.fullmatch(f"(?:.*/)?{_wildcard(self.filename)}", path, re.IGNORECASE)
            else:
                ok = re.fullmatch(_wildcard(self.filename), name, re.IGNORECASE)
            if not ok:
                return False
        if self.extension:
            if not re.fullmatch(rf".*\.{_wildcard(self.extension)}", name, re.IGNORECASE):
                return False
        return True

    def describe(self) -> str:
        """'filename *.env, extension py' (for the search plan and the run journal)."""
        parts = []
        if self.filename:
            parts.append(f"filename {self.filename}")
        if self.extension:
            parts.append(f"extension {self.extension}")
        return ", ".join(parts)

    def to_meta(self) -> dict[str, Any]:
        """Session meta fields."""
        return {"filename": self.filename, "extension": self.extension}
