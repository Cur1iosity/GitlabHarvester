"""
GitLab API tokens for a run.

A run can use several tokens at once, spreading its work over multiple accounts
so an instance that rate-limits per user (or per token) is scanned faster: each
token has its own server-side budget.

- ``-t/--token "tok1;tok2"``: tokens separated by ``;`` on the command line.
- ``--token-file FILE``: one token per line (blank lines and ``#`` comments
  skipped), handy when there are many or they should stay out of the shell
  history.

Each token runs its own pool of ``--workers`` python-gitlab clients, so the run
keeps ``len(tokens) × workers`` clients busy and every client is paced by its
own ``--*-rpm`` budget (see ``glh.engine.harvester`` and ``glh.gitlab.throttling``):

    tokens  ->  workers per token  ->  rpm per worker

Tokens are secrets: they are never logged, nor written to the session file or
the run journal (only their count is). Duplicate tokens are dropped, since the
same token shares one server-side budget and would only waste worker threads.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Separator for several tokens in one ``-t/--token`` value. GitLab tokens are
#: made of ``[A-Za-z0-9_-]`` (``glpat-…``, OAuth, deploy and job tokens alike),
#: so ``;`` can never be part of a token.
SEPARATOR = ";"


class TokenError(ValueError):
    """An empty token list, or a token/token file that can't be used."""


def check_token(value: str) -> str:
    """
    Return ``value`` stripped, or raise if it can't be sent as a ``PRIVATE-TOKEN`` header.

    Raises:
        TokenError: empty, contains whitespace, or has characters outside Latin-1.
    """
    value = value.strip()
    if not value:
        raise TokenError("the token is empty")
    if any(ch.isspace() for ch in value):
        raise TokenError("a token cannot contain whitespace")
    try:
        value.encode("latin-1")
    except UnicodeEncodeError:
        raise TokenError("a token can only contain Latin-1 characters") from None
    return value


def _dedup(tokens: list[str]) -> list[str]:
    """Drop later duplicates, keeping the first occurrence and the order."""
    seen: set[str] = set()
    unique: list[str] = []
    for token in tokens:
        if token not in seen:
            seen.add(token)
            unique.append(token)
    return unique


def parse_tokens(value: str) -> list[str]:
    """
    Split a ``;``-separated ``-t/--token`` value into validated, de-duplicated tokens.

    Raises:
        TokenError: if no non-empty token remains, or a token is invalid.
    """
    tokens = [check_token(part) for part in value.split(SEPARATOR) if part.strip()]
    if not tokens:
        raise TokenError("no token given")
    return _dedup(tokens)


def load_tokens(path: str | os.PathLike[str]) -> list[str]:
    """
    Read the tokens of ``path`` (one per line; blank lines and ``#`` comments skipped).

    Raises:
        TokenError: if the file can't be read, isn't UTF-8, has no tokens, or a
            line isn't a valid token (reported with its line number).
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8-sig")
    except OSError as e:
        raise TokenError(f"Cannot read the token file {p}: {e.strerror or e}") from None
    except UnicodeDecodeError:
        raise TokenError(f"The token file {p} is not UTF-8 text") from None

    tokens: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        try:
            tokens.append(check_token(value))
        except TokenError as e:
            raise TokenError(f"{p}, line {number}: {e}") from None
    if not tokens:
        raise TokenError(f"The token file {p} has no tokens")
    return _dedup(tokens)


def describe(tokens: list[str] | tuple[str, ...]) -> str:
    """'1 token' / '3 tokens'; '' when empty."""
    n = len(tokens)
    if n == 0:
        return ""
    return "1 token" if n == 1 else f"{n} tokens"


TOKEN_PLACEHOLDER = "<TOKEN>"
_TOKEN_OPTIONS = ("-t", "--token")
_PROXY_OPTIONS = ("-p", "--proxy")


def _mask_url_password(url: str) -> str:
    """'http://user:secret@host' -> 'http://user:***@host'."""
    scheme, sep, rest = url.partition("://")
    if not sep or "@" not in rest.split("/", 1)[0]:
        return url
    creds, _, host = rest.partition("@")
    user, colon, _ = creds.partition(":")
    return f"{scheme}://{user}{':***' if colon else ''}@{host}"


def mask_argv(argv: list[str] | tuple[str, ...]) -> list[str]:
    """
    The command-line arguments with secrets hidden, for printing and the run
    journal: token values (``-t``, ``--token``, ``--token=…``, ``-t…``) become
    ``<TOKEN>``, a password in a proxy URL becomes ``***``.
    """
    out: list[str] = []
    args = list(argv)
    i = 0
    while i < len(args):
        arg = args[i]
        name, eq, value = arg.partition("=")
        if name in _TOKEN_OPTIONS:
            out.append(f"{name}={TOKEN_PLACEHOLDER}" if eq else name)
            if not eq:
                if i + 1 < len(args):
                    out.append(TOKEN_PLACEHOLDER)
                i += 1
        elif arg.startswith("-t") and not arg.startswith("--") and len(arg) > 2:
            out.append(f"-t{TOKEN_PLACEHOLDER}")
        elif name in _PROXY_OPTIONS:
            if eq:
                out.append(f"{name}={_mask_url_password(value)}")
            else:
                out.append(name)
                if i + 1 < len(args):
                    out.append(_mask_url_password(args[i + 1]))
                i += 1
        else:
            out.append(arg)
        i += 1
    return out
