# glh/ui/journal.py
"""
The run journal: a summary of every run appended to the --log-file.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Final

from glh.ui import statusline
from glh.ui.logs import _DEFAULT_DATEFMT


class RunJournal:
    """
    Summary of every run, appended to the log file whatever the log level.

    Lines look like ``[10-11-2026 14:02:11][SUMMARY][run 3f2a91c0] Search plan: ...``.
    The run id groups the lines of one run, so runs can be compared later
    (time per filter set, hits per term, which index, which output files).
    Permanent progress lines (index, search plan, per-term and phase summaries)
    are added automatically through ``statusline.STATUS``.
    """

    LOGGER_NAME: Final[str] = "GitlabHarvesterRunJournal"
    FORMAT: Final[str] = "[%(asctime)s][SUMMARY][run %(run_id)s] %(message)s"

    def __init__(self) -> None:
        self.run_id = uuid.uuid4().hex[:8]
        self._logger: logging.Logger | None = None

    @property
    def active(self) -> bool:
        """True while a log file is attached."""
        return self._logger is not None

    def open(self, log_file: str) -> None:
        """Start writing to ``log_file`` (appending) with a fresh run id."""
        self.close()
        path = Path(log_file).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        logger = logging.getLogger(self.LOGGER_NAME)
        logger.propagate = False
        logger.setLevel(logging.INFO)
        for h in list(logger.handlers):
            logger.removeHandler(h)
            h.close()
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setFormatter(logging.Formatter(self.FORMAT, datefmt=_DEFAULT_DATEFMT))
        logger.addHandler(handler)
        self.run_id = uuid.uuid4().hex[:8]
        self._logger = logger
        statusline.STATUS.add_listener(self.write)

    def write(self, message: str) -> None:
        """Append one summary line (no-op without a log file)."""
        if self._logger is not None:
            self._logger.info(message, extra={"run_id": self.run_id})

    def close(self) -> None:
        """Detach from the log file."""
        statusline.STATUS.remove_listener(self.write)
        if self._logger is not None:
            for h in list(self._logger.handlers):
                self._logger.removeHandler(h)
                h.close()
        self._logger = None

JOURNAL = RunJournal()
"""Process-wide run journal (see RunJournal)."""
