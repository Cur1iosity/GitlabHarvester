# glh/logging_utils.py
"""
Logging utilities for tqdm-compatible output.
Provides handlers that prevent logging output from breaking tqdm progress bars.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Final

from tqdm import tqdm

_DEFAULT_FMT: Final[str] = "[%(asctime)s][%(levelname)s] %(message)s"
_DEFAULT_DATEFMT: Final[str] = "%d-%m-%Y %H:%M:%S"


class TqdmLoggingHandler(logging.Handler):
    """
    Logging handler that prints messages using tqdm.write().

    This prevents log lines from corrupting active tqdm progress bars.
    """

    def __init__(self, level: int | str = logging.NOTSET) -> None:
        super().__init__(level)

    def emit(self, record: logging.LogRecord) -> None:
        """
        Emit a log record via tqdm.write().

        Args:
            record: Logging record.
        """
        try:
            msg = self.format(record)
            tqdm.write(msg)
        except Exception:
            self.handleError(record)


def install_tqdm_logging(
        level: int | str = logging.INFO,
        fmt: str | None = None,
        logger: logging.Logger | None = None,
) -> None:
    """
    Install tqdm-compatible logging handler on a logger.

    This replaces existing handlers to guarantee clean output.

    Args:
        level: Logging level.
        fmt: Formatter string. If None, defaults to "%(message)s".
        logger: Target logger. Defaults to root logger.
    """
    target = logger or logging.getLogger()

    target.handlers.clear()
    target.propagate = False

    handler = TqdmLoggingHandler(level)

    formatter = logging.Formatter(fmt or "%(message)s")
    handler.setFormatter(formatter)

    target.addHandler(handler)
    target.setLevel(level)


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
    Build and configure a logger with tqdm-compatible console output and optional file logging.

    This function:
    - disables propagation to avoid duplicate output
    - resets existing handlers on the named logger
    - adds a tqdm-compatible console handler
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

    tqdm_h = TqdmLoggingHandler(level=level)
    tqdm_h.setFormatter(formatter)
    logger.addHandler(tqdm_h)

    if log_file:
        log_path = Path(log_file).expanduser().resolve()
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_h = logging.FileHandler(log_path, encoding="utf-8")
        file_h.setLevel(level)
        file_h.setFormatter(formatter)
        logger.addHandler(file_h)

    return logger
