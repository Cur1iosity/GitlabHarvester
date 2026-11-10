#!/usr/bin/env python3

from __future__ import annotations

import signal
import sys

from glh.cli import CliParser, get_banner
from glh.modes import run_mode

__all__ = ["main"]


def _handle_exit(signum: int, _frame) -> None:  # noqa: ANN001
    """Handle SIGINT/SIGTERM with a clean exit code and no traceback."""
    print("\n[!] Interrupted — exiting.", file=sys.stderr)
    code = 130 if signum == signal.SIGINT else 143  # 128 + SIGINT(2) / SIGTERM(15)
    raise SystemExit(code)


def _tolerate_unencodable_output() -> None:
    """
    Never crash on characters the console encoding lacks.

    A redirected Windows console uses a legacy code page (cp1252, cp866, ...):
    printing e.g. a branch name in another script would raise UnicodeEncodeError.
    stderr already uses errors="backslashreplace"; do the same for stdout.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="backslashreplace")
            except (ValueError, OSError):
                pass


def main(argv: list[str] | None = None) -> None:
    """CLI entrypoint."""
    _tolerate_unencodable_output()
    signal.signal(signal.SIGINT, _handle_exit)
    signal.signal(signal.SIGTERM, _handle_exit)

    argv = list(sys.argv[1:] if argv is None else argv)

    if not any(a in {"-h", "--help", "-V", "--version"} for a in argv):
        print(get_banner(sys.stderr), file=sys.stderr)

    try:
        args = CliParser.parse(argv)
        run_mode(args)
    except KeyboardInterrupt:
        _handle_exit(signal.SIGINT, None)


if __name__ == "__main__":
    main()
