# glh/ui/ansi.py
"""
ANSI escape sequences: detection (Windows VT mode included), colors, styles.

Used only where the terminal understands them; NO_COLOR turns colors off.
"""

from __future__ import annotations

import os
from typing import TextIO

HINT_COLOR = "\x1b[38;5;80m"  # turquoise (xterm-256 #5fd7d7)

RESET = "\x1b[0m"

_CURSOR_UP_CLEAR = "\x1b[1A\r\x1b[2K"


def _enable_windows_vt(stream: TextIO) -> bool:
    """Switch the Windows console of ``stream`` to VT mode (ANSI escapes); False if impossible."""
    try:
        import ctypes
        import msvcrt

        handle = msvcrt.get_osfhandle(stream.fileno())
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        vt = 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return bool(mode.value & vt) or bool(kernel32.SetConsoleMode(handle, mode.value | vt))
    except Exception:  # noqa: BLE001 - no console, no ctypes: just no ANSI
        return False


def supports_ansi(stream: TextIO) -> bool:
    """True if ``stream`` is a terminal that understands ANSI escape sequences."""
    try:
        if not stream.isatty():
            return False
    except (AttributeError, ValueError, OSError):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return _enable_windows_vt(stream) if os.name == "nt" else True

COMMAND_STYLE = "1;94"  # bold bright blue


def style(text: str, codes: str, stream: TextIO) -> str:
    """``text`` in the ANSI style ``codes`` (e.g. '1;94') on an ANSI terminal without NO_COLOR, else as is."""
    if os.environ.get("NO_COLOR") or not supports_ansi(stream):
        return text
    return f"\x1b[{codes}m{text}{RESET}"
