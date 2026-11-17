# glh/output/sink.py
"""
Where the search engine puts its results: a JSONL stream (SearchOutput) or the session file
of a CLI run with its meta/resume/summary records (SessionOutput).
"""

from __future__ import annotations

import json
from typing import Any, IO, TYPE_CHECKING

from glh.output.layout import OutputLayout

if TYPE_CHECKING:
    from glh.output.downloads import FileDownloader


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
