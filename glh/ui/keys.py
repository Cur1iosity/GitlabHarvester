# glh/ui/keys.py
"""
Single key presses from the terminal, without blocking and without Enter.

Used by the ``--auto-limits`` advisor (``glh.limits.console``) to take answers
while a search keeps running. Only works when stdin is a terminal
(:func:`KeyReader.available`); otherwise nothing is read.

- Windows: ``msvcrt.kbhit``/``getwch`` (the console, whatever the stream).
- POSIX: stdin is switched to cbreak mode (no line buffering, no echo;
  Ctrl+C still interrupts) while the reader is open, and restored by
  :meth:`KeyReader.close` and at exit.
"""

from __future__ import annotations

import atexit
import os
import sys
import time
from typing import Any

_POLL = 0.05  # seconds between console polls on Windows


class KeyReader:
    """Non-blocking reader of single key presses (use as a context manager)."""

    def __init__(self, stream: Any = None) -> None:
        self._stream = stream
        self._saved: Any = None
        self._fd: int | None = None
        self._open = False

    @property
    def stream(self) -> Any:
        return self._stream if self._stream is not None else sys.stdin

    def available(self) -> bool:
        """True when key presses can be read (stdin is a terminal)."""
        try:
            return bool(self.stream.isatty())
        except (AttributeError, ValueError, OSError):
            return False

    # ------------------------------------------------------------------ lifecycle

    def open(self) -> "KeyReader":
        if self._open or not self.available():
            return self
        if os.name != "nt":
            import termios
            import tty

            try:
                self._fd = self.stream.fileno()
                self._saved = termios.tcgetattr(self._fd)
                tty.setcbreak(self._fd)
            except (termios.error, OSError, ValueError, AttributeError):
                self._fd = None
                self._saved = None
                return self
            atexit.register(self.close)
        self._open = True
        return self

    def close(self) -> None:
        if self._saved is not None and self._fd is not None:
            import termios

            try:
                termios.tcsetattr(self._fd, termios.TCSADRAIN, self._saved)
            except (termios.error, OSError, ValueError):
                pass
            self._saved = None
        self._open = False

    def __enter__(self) -> "KeyReader":
        return self.open()

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---------------------------------------------------------------------- read

    def read(self, timeout: float) -> str | None:
        """
        Return one key pressed within ``timeout`` seconds, or None.

        Special keys (arrows, function keys) are returned as ''.
        """
        if not self._open:
            time.sleep(max(timeout, 0.0))
            return None
        if os.name == "nt":
            return self._read_windows(timeout)
        return self._read_posix(timeout)

    @staticmethod
    def _read_windows(timeout: float) -> str | None:
        import msvcrt

        deadline = time.monotonic() + max(timeout, 0.0)
        while True:
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch in ("\x00", "\xe0"):  # prefix of a special key: drop its code
                    msvcrt.getwch()
                    return ""
                return ch
            if time.monotonic() >= deadline:
                return None
            time.sleep(_POLL)

    def _read_posix(self, timeout: float) -> str | None:
        import select

        if self._fd is None:
            return None
        try:
            ready, _, _ = select.select([self._fd], [], [], max(timeout, 0.0))
        except (OSError, ValueError):
            return None
        if not ready:
            return None
        try:
            data = os.read(self._fd, 32)  # an escape sequence arrives at once
        except OSError:
            return None
        if not data:
            return None
        if data.startswith(b"\x1b") and len(data) > 1:
            return ""
        return data[:1].decode("utf-8", errors="replace")
