# glh/output.py
"""
Output of a search run, kept apart from the search engine.

The engine (``GitlabHarvester.search_keywords``) only produces events: a hit
record of one (term, project), a term checkpoint, a file with hits. It hands
them to a ``SearchOutput`` and never decides file names or directories, so
the same engine can feed a session file, an in-memory stream (tests, library
use) or any other sink.

- ``OutputLayout`` decides where everything goes:

      <dir>/<session>.jsonl                    the session: every term, --resume checkpoints
      <dir>/<term>/<session>.jsonl             --output-separated: the hits of one term
      <dir>/<term>/files/<downloaded file>     --download-files (glh/downloads.py)

  ``<dir>`` is the session's directory (``results/`` by default). ``<term>``
  is a file-system-safe name of the term (``safe_term_filenames``).

- ``SearchOutput`` is the sink the engine writes to: JSONL records to a text
  stream, checkpoints flushed to disk, and an optional ``FileDownloader``
  that saves files with hits.

- ``SessionOutput`` is the ``SearchOutput`` of a CLI search: it opens the
  session file (append on --resume) and also writes the run's control
  records (``meta``, ``resume``, ``summary``).
"""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from glh.downloads import FileDownloader

# Everything except these becomes '_', so the name is safe on Windows, macOS and
# Linux: no path separators (/ \), no Windows-forbidden chars (< > : " | ? *),
# no spaces or control chars. A path separator in a term therefore can't escape
# the output directory. Dots are kept but trimmed from the ends.
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
# Keep per-term names short; a long term (e.g. "BEGIN RSA PRIVATE KEY") is cut.
MAX_TERM_LEN = 60
# Windows reserved device names (any case); never used as a bare base name.
_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)
FILES_DIR = "files"


def _safe_base(term: str) -> str:
    """Filesystem-safe base name for one term (not yet de-duplicated)."""
    base = _UNSAFE.sub("_", term.strip()).strip("._")[:MAX_TERM_LEN] or "term"
    if base.lower() in _RESERVED:  # CON, NUL, COM1 … are special on Windows
        base = f"{base}_"
    return base


def safe_term_filenames(terms: list[str] | tuple[str, ...], *, taken: set[str] | None = None) -> dict[str, str]:
    """
    Map each term to a distinct, filesystem-safe base name.

    The mapping is deterministic in the given order: unsafe characters become
    ``_`` (see ``_UNSAFE``), the name is shortened to ``MAX_TERM_LEN`` and
    de-duplicated case-insensitively (Windows file names are case-insensitive),
    so two terms never share a name. Duplicate terms map to the same name
    (they are searched once). Lower-case names in ``taken`` are avoided too.
    """
    mapping: dict[str, str] = {}
    used: set[str] = set(taken or ())
    for term in terms:
        if term in mapping:
            continue
        base = _safe_base(term)
        candidate, n = base, 1
        while candidate.lower() in used:
            n += 1
            candidate = f"{base}_{n}"
        used.add(candidate.lower())
        mapping[term] = candidate
    return mapping


class OutputLayout:
    """
    Paths of everything a search run writes, see the module doc.

    Args:
        session_path: The session JSONL; its directory holds the term directories.
        terms: The run's terms in order (the full supplied list, so a resumed
            run uses the same names); they fix the term directory names. A
            term outside the list gets a fresh name that doesn't clash.
    """

    def __init__(self, session_path: Path | str, terms: list[str] | tuple[str, ...] = ()) -> None:
        self.session_path = Path(session_path)
        self.root = self.session_path.parent
        self._lock = threading.Lock()
        # The session file's own name is never a term directory name.
        self._reserved = {self.session_path.name.lower()}
        self._names = safe_term_filenames(list(terms), taken=self._reserved)

    def term_name(self, term: str) -> str:
        """Directory name of a term."""
        with self._lock:
            name = self._names.get(term)
            if name is None:
                taken = self._reserved | {n.lower() for n in self._names.values()}
                name = self._names[term] = safe_term_filenames([term], taken=taken)[term]
            return name

    def term_dir(self, term: str) -> Path:
        """``<dir>/<term>``."""
        return self.root / self.term_name(term)

    def term_results_path(self, term: str) -> Path:
        """``<dir>/<term>/<session>.jsonl``: the term's hits (--output-separated)."""
        return self.term_dir(term) / (self.session_path.name or "session.jsonl")

    def files_dir(self, term: str) -> Path:
        """``<dir>/<term>/files``: the term's downloaded files (--download-files)."""
        return self.term_dir(term) / FILES_DIR

    def describe_files(self) -> str:
        """'results/<term>/files' for messages."""
        return str(self.root / "<term>" / FILES_DIR)


class SearchOutput:
    """
    Where the engine puts the results of a search.

    Args:
        stream: Text stream for JSONL records (the session); None = records
            are dropped (results are still returned by the engine).
        downloader: Saves the files with hits (--download-files), or None.
    """

    def __init__(self, stream: IO[str] | None = None, *, downloader: FileDownloader | None = None) -> None:
        self.stream = stream
        self.downloader = downloader

    def write(self, record: dict[str, Any]) -> None:
        """Write one JSONL record."""
        if self.stream is not None:
            self.stream.write(json.dumps(record, ensure_ascii=False))
            self.stream.write("\n")

    def hit(self, term: str, result: dict[str, Any]) -> None:
        """The hits of one term in one project."""
        self.write({"term": term, "result": result})

    def checkpoint(self, record: dict[str, Any]) -> None:
        """A term finished (``keyword_done``/``keyword_incomplete``): written and flushed to disk."""
        self.write(record)
        if self.stream is not None:
            self.stream.flush()


class SessionOutput(SearchOutput):
    """
    The session file of a CLI search, opened as a context manager.

    A new session is written from scratch; with ``resume`` new records are
    appended after the existing ones. The parent directory is created.
    """

    def __init__(self, layout: OutputLayout, *, resume: bool = False,
                 downloader: FileDownloader | None = None) -> None:
        super().__init__(None, downloader=downloader)
        self.layout = layout
        self.resume = resume

    def __enter__(self) -> "SessionOutput":
        self.layout.root.mkdir(parents=True, exist_ok=True)
        self.stream = self.layout.session_path.open("a" if self.resume else "w", encoding="utf-8")
        return self

    def __exit__(self, *exc: object) -> None:
        if self.stream is not None:
            self.stream.close()

    def meta(self, **fields: Any) -> None:
        """The ``meta`` record that starts a new session (the run's parameters)."""
        self.write({"type": "meta", **fields})

    def resumed(self, **fields: Any) -> None:
        """The ``resume`` record that starts the appended part of a resumed session."""
        self.write({"type": "resume", **fields})

    def summary(self, **fields: Any) -> None:
        """The ``summary`` record that ends a run."""
        self.write({"type": "summary", **fields})
