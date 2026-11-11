# glh/config.py
"""
Configuration file support for the CLI (``-c/--config``).

The file is INI (stdlib ``configparser``). Keys are the long CLI option names
(``index-branches``, ``forks``, ``started-from``, ...); ``_`` may be used
instead of ``-``. Sections only group keys for readability: any key may live
in any section, but a key may appear only once per file.

Values go through the same converters and choices as the CLI arguments, so a
config value is validated exactly like the equivalent command-line argument.

Extras that have no CLI counterpart:

- ``terms``: search terms, one per line (an alternative to ``terms-file``).
- ``token = env:NAME`` reads the token from the environment variable NAME.

Relative paths (``index-file``, ``terms-file``, ``session-file``, ``log-file``,
``input-file``, ``output-file``, ``sqlite-path``, ``ca-bundle``, ``user-agent-file``) are resolved against the
directory of the config file, so the config works from any working directory.
"""

from __future__ import annotations

import argparse
import configparser
import os
from pathlib import Path
from typing import Any

# Keys (argparse dests) that hold file system paths.
PATH_DESTS = frozenset({"index_file", "terms_file", "session_file", "log_file", "input_file", "output_file",
                        "sqlite_path", "ca_bundle", "user_agent_file"})
# Config-only keys (no CLI option).
TERMS_DEST = "terms"
# Options that make no sense in a config file.
_FORBIDDEN_DESTS = frozenset({"help", "version", "config"})
ENV_PREFIX = "env:"


class ConfigError(ValueError):
    """Raised for a missing, malformed or invalid configuration file."""


def _option_map(parser: argparse.ArgumentParser) -> dict[str, argparse.Action]:
    """Map normalized long option names ('index-branches') to their argparse actions."""
    mapping: dict[str, argparse.Action] = {}
    for action in parser._actions:  # noqa: SLF001 - argparse exposes no public accessor
        if action.dest in _FORBIDDEN_DESTS:
            continue
        for opt in action.option_strings:
            if opt.startswith("--") and not opt.startswith("--no-"):
                mapping[opt[2:]] = action
    return mapping


def _convert(action: argparse.Action, raw: str, where: str) -> Any:
    """Convert a raw string the way argparse would for ``action``."""
    if isinstance(action, argparse.BooleanOptionalAction) or action.nargs == 0:
        value = raw.strip().lower()
        if value not in configparser.ConfigParser.BOOLEAN_STATES:
            raise ConfigError(f"{where}: expected true/false, got {raw!r}")
        return configparser.ConfigParser.BOOLEAN_STATES[value]

    value: Any = raw
    if action.type is not None:
        try:
            value = action.type(raw)
        except (argparse.ArgumentTypeError, TypeError, ValueError) as e:
            raise ConfigError(f"{where}: invalid value {raw!r}: {e}") from None
    if action.choices is not None and value not in action.choices:
        choices = ", ".join(map(str, action.choices))
        raise ConfigError(f"{where}: invalid value {raw!r} (choose from {choices})")
    return value


def _parse_terms(raw: str) -> tuple[str, ...]:
    """One term per line; blank lines are ignored."""
    return tuple(line.strip() for line in raw.splitlines() if line.strip())


def _resolve_env(raw: str, where: str) -> str:
    """Resolve 'env:NAME' references."""
    name = raw[len(ENV_PREFIX):].strip()
    value = os.environ.get(name)
    if not name or value is None:
        raise ConfigError(f"{where}: environment variable {name or '(empty name)'} is not set")
    return value


def load_config(path: str | os.PathLike[str], parser: argparse.ArgumentParser) -> dict[str, Any]:
    """
    Read a configuration file into ``{argparse dest: converted value}``.

    Empty values are treated as "not set", so a template can keep placeholders
    like ``token =``.

    Args:
        path: Path to the INI file.
        parser: The CLI parser; option names, converters and choices come from it.

    Returns:
        Converted values keyed by argparse dest (plus ``terms`` for the config-only list).

    Raises:
        ConfigError: If the file is missing, malformed, or contains unknown keys
            or invalid values.
    """
    cfg_path = Path(path)
    if not cfg_path.is_file():
        raise ConfigError(f"Config file not found: {cfg_path}")

    cp = configparser.ConfigParser(interpolation=None, default_section="__defaults__")
    try:
        with cfg_path.open(encoding="utf-8") as fp:
            cp.read_file(fp)
    except (configparser.Error, UnicodeDecodeError) as e:
        raise ConfigError(f"Cannot parse config file {cfg_path}: {e}") from None

    options = _option_map(parser)
    base_dir = cfg_path.resolve().parent
    values: dict[str, Any] = {}
    seen: dict[str, str] = {}

    for section in cp.sections():
        for key, raw in cp.items(section, raw=True):
            name = key.strip().lower().replace("_", "-")
            where = f"{cfg_path}: [{section}] {key}"
            if name in seen:
                raise ConfigError(f"{where}: duplicate key (already set in [{seen[name]}])")
            seen[name] = section

            if name == TERMS_DEST:
                terms = _parse_terms(raw)
                if terms:
                    values[TERMS_DEST] = terms
                continue

            action = options.get(name)
            if action is None:
                known = ", ".join(sorted([*options, TERMS_DEST]))
                raise ConfigError(f"{where}: unknown key. Known keys: {known}")
            if not raw.strip():
                continue  # empty placeholder = not set

            if action.dest in values:  # e.g. both started-from and its alias active-after
                raise ConfigError(f"{where}: duplicate key (same option as another key in the file)")

            if name == "token" and raw.strip().startswith(ENV_PREFIX):
                raw = _resolve_env(raw.strip(), where)

            value = _convert(action, raw.strip(), where)
            if action.dest in PATH_DESTS and isinstance(value, str):
                p = Path(value).expanduser()
                value = str(p if p.is_absolute() else base_dir / p)
            values[action.dest] = value

    # The same exclusivity rules as on the command line.
    for group in (("search", "terms_file", TERMS_DEST), ("session", "session_file"), ("user_agent", "user_agent_file")):
        present = [d for d in group if d in values]
        if len(present) > 1:
            names = ", ".join(d.replace("_", "-") for d in present)
            raise ConfigError(f"{cfg_path}: keys {names} are mutually exclusive")

    return values
