# glh/user_agents.py
"""
User-Agent of the API requests.

- ``-A/--user-agent STRING``: one fixed User-Agent for every request.
- ``--user-agent-file FILE``: one User-Agent per line; every request gets a
  string chosen at random from the list. Blank lines and lines starting with
  ``#`` are skipped (like the terms file).

Both are applied by ``ratelimit.ThrottledAdapter`` (retries included).
Without them, python-gitlab's own User-Agent is sent.
"""

from __future__ import annotations

import os
from pathlib import Path

MAX_LENGTH = 1024


class UserAgentError(ValueError):
    """A User-Agent string HTTP can't carry, or an unusable User-Agent file."""


def check_user_agent(value: str) -> str:
    """
    Return ``value`` stripped, or raise if it can't be sent as a header.

    Raises:
        UserAgentError: empty, longer than MAX_LENGTH, control characters,
            or characters outside Latin-1.
    """
    value = value.strip()
    if not value:
        raise UserAgentError("the User-Agent is empty")
    if len(value) > MAX_LENGTH:
        raise UserAgentError(f"the User-Agent is longer than {MAX_LENGTH} characters")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise UserAgentError("control characters are not allowed in a User-Agent")
    try:
        value.encode("latin-1")
    except UnicodeEncodeError:
        raise UserAgentError("only Latin-1 characters can be sent in an HTTP header") from None
    return value


def load_user_agents(path: str | os.PathLike[str]) -> list[str]:
    """
    Read the User-Agent strings of ``path`` (one per line).

    Raises:
        UserAgentError: if the file can't be read, isn't UTF-8, has no
            strings, or a line isn't a valid User-Agent (with its number).
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8-sig")
    except OSError as e:
        raise UserAgentError(f"Cannot read the User-Agent file {p}: {e.strerror or e}") from None
    except UnicodeDecodeError:
        raise UserAgentError(f"The User-Agent file {p} is not UTF-8 text") from None

    agents: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        try:
            agents.append(check_user_agent(value))
        except UserAgentError as e:
            raise UserAgentError(f"{p}, line {number}: {e}") from None
    if not agents:
        raise UserAgentError(f"The User-Agent file {p} has no User-Agent strings")
    return agents


def describe(agents: list[str] | tuple[str, ...]) -> str:
    """'fixed User-Agent' / 'random User-Agent of 12'; '' when not set."""
    if not agents:
        return ""
    return "fixed User-Agent" if len(agents) == 1 else f"random User-Agent of {len(agents)}"
