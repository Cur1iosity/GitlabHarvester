#!/usr/bin/env python3
from __future__ import annotations

import sys

from glh.cli import CliParser
from glh.modes import run_mode

__all__ = ["main"]


def main(argv: list[str] | None = None) -> None:
    """
    Entry point for the GitLab Harvester CLI.

    Parses CLI arguments and dispatches work to the appropriate mode
    handler in `glh.modes.run_mode`.
    """
    args = CliParser.parse(argv)
    run_mode(args)


if __name__ == "__main__":
    # When installed with setuptools/entry_points, this block is not used;
    # instead, the console script will call main() directly.
    main(sys.argv[1:])
