# glh/version.py
"""
The installed package version.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version


def get_version() -> str:
    """Return installed package version (or 'unknown' if not installed)."""
    try:
        return version("gitlab-harvester")
    except PackageNotFoundError:
        return "unknown"


__version__ = get_version()
