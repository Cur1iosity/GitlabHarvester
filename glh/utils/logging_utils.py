# glh/utils/logging_utils.py
"""
Logging utilities for console output next to the progress status line.

Console records are written through ``terminal_utils.STATUS`` so a log line
never lands in the middle of the in-place status line.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Final

from glh.utils import terminal_utils

_DEFAULT_FMT: Final[str] = "[%(asctime)s][%(levelname)s] %(message)s"
_DEFAULT_DATEFMT: Final[str] = "%d-%m-%Y %H:%M:%S"


class ConsoleHandler(logging.Handler):
    """
    Logging handler that prints records to stdout around the status line.

    The status line (stderr) is erased before the record is written and drawn
    again afterwards. stdout is resolved per record, so redirection is honored.
    """

    def __init__(self, level: int | str = logging.NOTSET) -> None:
        super().__init__(level)

    def emit(self, record: logging.LogRecord) -> None:
        """
        Emit a log record as one console line.

        Args:
            record: Logging record.
        """
        try:
            msg = self.format(record)
            terminal_utils.STATUS.write_line(msg, stream=sys.stdout)
        except Exception:
            self.handleError(record)


def coerce_log_level(value: int | str | None) -> int:
    """Coerce a human-friendly log level into a logging module constant."""
    if value is None:
        return logging.WARNING
    if isinstance(value, int):
        return value
    v = value.strip().upper()
    mapping = {
        "CRITICAL": logging.CRITICAL,
        "ERROR": logging.ERROR,
        "WARN": logging.WARNING,
        "WARNING": logging.WARNING,
        "INFO": logging.INFO,
        "DEBUG": logging.DEBUG,
    }
    return mapping.get(v, logging.WARNING)


def build_logger(
        *,
        name: str,
        level: int,
        log_file: str | None = None,
        fmt: str = _DEFAULT_FMT,
        datefmt: str = _DEFAULT_DATEFMT,
) -> logging.Logger:
    """
    Build and configure a logger with console output and optional file logging.

    This function:
    - disables propagation to avoid duplicate output
    - resets existing handlers on the named logger
    - adds a console handler that cooperates with the progress status line
    - optionally adds a file handler
    """
    logger = logging.getLogger(name)
    logger.propagate = False
    logger.setLevel(level)

    # Reset handlers to avoid duplicates (e.g. multiple instances)
    for h in list(logger.handlers):
        logger.removeHandler(h)
        try:
            h.close()
        except Exception:
            pass

    formatter = logging.Formatter(fmt, datefmt=datefmt)

    console_h = ConsoleHandler(level=level)
    console_h.setFormatter(formatter)
    logger.addHandler(console_h)

    if log_file:
        log_path = Path(log_file).expanduser().resolve()
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_h = logging.FileHandler(log_path, encoding="utf-8")
        file_h.setLevel(level)
        file_h.setFormatter(formatter)
        logger.addHandler(file_h)

    return logger
