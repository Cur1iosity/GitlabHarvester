# glh/cli/banner.py
"""
The CLI banner.
"""

from __future__ import annotations

from glh.version import get_version

_BANNER = r"""
┏┓• ┓  ┓ ┓┏
┃┓┓╋┃┏┓┣┓┣┫┏┓┏┓┓┏┏┓┏╋┏┓┏┓
┗┛┗┗┗┗┻┗┛┛┗┗┻┛ ┗┛┗ ┛┗┗ ┛
""".rstrip()


def _can_encode(text: str, stream: object) -> bool:
    """True if ``stream``'s encoding can represent ``text`` (no encoding attribute = assume UTF-8)."""
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        text.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def get_banner(stream: object | None = None) -> str:
    """
    Return the CLI banner with version suffix.

    The box-drawing banner needs a Unicode-capable stream. If ``stream`` uses
    an encoding without those characters (e.g. cp1252 or cp866 in a redirected
    Windows console), a plain-text banner is returned instead.
    """
    if stream is not None and not _can_encode(_BANNER, stream):
        return f"GitlabHarvester v{get_version()}"
    return f"{_BANNER} v{get_version()}"
