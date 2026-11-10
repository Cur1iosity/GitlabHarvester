"""Config file support (-c/--config): parsing, validation and CLI precedence."""

from __future__ import annotations

from pathlib import Path

import pytest

from glh.cli import CliParser
from glh.config import ConfigError, load_config
from tests.conftest import REPO_ROOT

EXAMPLE = REPO_ROOT / "config.example.ini"


def write_cfg(tmp_path: Path, text: str, name: str = "glh.ini") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def parse(*argv: str):
    return CliParser.parse(list(argv))


# --------------------------------------------------------------------------- example file


def test_example_config_is_valid_and_matches_builtin_defaults():
    """Every key in config.example.ini is known, and its values equal the CLI defaults."""
    load_config(EXAMPLE, CliParser.build())  # raises on unknown keys / invalid values
    from_file = parse("-c", str(EXAMPLE))
    builtin = parse()
    assert from_file.terms == ("password", "api_key", "BEGIN RSA PRIVATE KEY")
    for field in builtin.__dataclass_fields__:
        if field not in {"config", "terms"}:
            assert getattr(from_file, field) == getattr(builtin, field), field


def test_example_config_documents_every_option():
    """New CLI options must be added to config.example.ini."""
    text = EXAMPLE.read_text(encoding="utf-8")
    parser = CliParser.build()
    for action in parser._actions:
        longs = [o for o in action.option_strings if o.startswith("--") and not o.startswith("--no-")]
        if not longs or action.dest in {"help", "version", "config"}:
            continue
        assert any(f"\n{o[2:]} =" in text for o in longs), f"{longs[0]} is missing in config.example.ini"


# --------------------------------------------------------------------------- values


def test_values_are_converted_like_cli_arguments(tmp_path):
    cfg = write_cfg(tmp_path, """
[connection]
url = https://gitlab.example.com
token = cfg-token
timeout = 15
[search]
index_branches = all
scan-branches = 3
forks = branch-diff
started-from = 2024-06-01T12:00:00+03:00
dump-projects = yes
""")
    a = parse("-c", str(cfg))
    assert (a.url, a.token, a.timeout) == ("https://gitlab.example.com", "cfg-token", 15)
    assert (a.index_branches, a.scan_branches, a.forks) == ("all", 3, "branch-diff")
    assert a.started_from.isoformat() == "2024-06-01T12:00:00+03:00"
    assert a.dump_projects is True


def test_relative_paths_are_resolved_against_the_config_directory(tmp_path):
    sub = tmp_path / "audit"
    sub.mkdir()
    absolute = (tmp_path / "shared" / "terms.txt").resolve()
    cfg = write_cfg(sub, f"[x]\nindex-file = idx.jsonl\nsession-file = out/s.jsonl\nterms-file = {absolute}\n")
    a = parse("-c", str(cfg))
    assert Path(a.index_file) == sub.resolve() / "idx.jsonl"
    assert Path(a.session_file) == sub.resolve() / "out" / "s.jsonl"
    assert Path(a.terms_file) == absolute


def test_token_from_environment(tmp_path, monkeypatch):
    cfg = write_cfg(tmp_path, "[connection]\ntoken = env:GLH_TEST_TOKEN\n")
    monkeypatch.setenv("GLH_TEST_TOKEN", "from-env")
    assert parse("-c", str(cfg)).token == "from-env"
    monkeypatch.delenv("GLH_TEST_TOKEN")
    with pytest.raises(ConfigError, match="GLH_TEST_TOKEN is not set"):
        load_config(cfg, CliParser.build())


def test_empty_values_mean_not_set(tmp_path):
    cfg = write_cfg(tmp_path, "[x]\nurl =\nforks =\nterms =\n")
    a = parse("-c", str(cfg))
    assert (a.url, a.forks, a.terms) == (None, "include", ())


def test_terms_list_skips_blank_lines(tmp_path):
    cfg = write_cfg(tmp_path, "[search]\nterms =\n    password\n\n    p@ss w0rd!\n    ключ\n")
    assert parse("-c", str(cfg)).terms == ("password", "p@ss w0rd!", "ключ")


def test_percent_signs_are_literal(tmp_path):
    cfg = write_cfg(tmp_path, "[search]\nsearch = 50%off\n")
    assert parse("-c", str(cfg)).search == "50%off"


# --------------------------------------------------------------------------- errors


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[x]\nfork = skip\n", "unknown key"),
        ("[x]\nforks = sometimes\n", "choose from"),
        ("[x]\nindex-branches = 0\n", "invalid value"),
        ("[x]\nstarted-from = yesterday\n", "ISO 8601"),
        ("[x]\ntimeout = soon\n", "invalid value"),
        ("[x]\nresume = maybe\n", "expected true/false"),
        ("[a]\nforks = skip\n[b]\nforks = include\n", "duplicate key"),
        ("[x]\nsearch = a\nterms-file = t.txt\n", "mutually exclusive"),
        ("[x]\nsession = a\nsession-file = b.jsonl\n", "mutually exclusive"),
        ("[x]\nversion = 1\n", "unknown key"),
        ("forks = skip\n", "Cannot parse"),  # no section header
    ],
)
def test_invalid_config_is_a_usage_error(tmp_path, capsys, text, message):
    cfg = write_cfg(tmp_path, text)
    with pytest.raises(SystemExit) as e:
        parse("-c", str(cfg))
    assert e.value.code == 2
    err = capsys.readouterr().err
    assert message in err and str(cfg) in err


def test_missing_config_file(tmp_path, capsys):
    with pytest.raises(SystemExit):
        parse("-c", str(tmp_path / "nope.ini"))
    assert "Config file not found" in capsys.readouterr().err


# --------------------------------------------------------------------------- precedence


@pytest.fixture
def full_cfg(tmp_path):
    return write_cfg(tmp_path, """
[connection]
url = https://from-config.example
token = cfg-token
timeout = 15
[index]
index-branches = all
dump-projects = true
[search]
scan-branches = all
forks = skip
started-from = 2024-06-01
terms =
    password
    api_key
[session]
session-file = cfg-session.jsonl
resume = true
""")


def test_cli_arguments_override_config_values(full_cfg):
    a = parse("-c", str(full_cfg), "-u", "https://cli.example", "--timeout", "5", "--forks", "include",
              "--started-from", "2025-01-01")
    assert (a.url, a.timeout, a.forks) == ("https://cli.example", 5, "include")
    assert a.started_from.isoformat() == "2025-01-01T00:00:00+00:00"
    assert a.token == "cfg-token"  # not given on the CLI: from the file


def test_cli_can_switch_off_boolean_config_values(full_cfg):
    a = parse("-c", str(full_cfg))
    assert (a.resume, a.dump_projects) == (True, True)
    a = parse("-c", str(full_cfg), "--no-resume", "--no-dump-projects")
    assert (a.resume, a.dump_projects) == (False, False)


@pytest.mark.parametrize(
    ("argv", "search", "terms_file", "terms"),
    [
        ([], None, None, ("password", "api_key")),
        (["-s", "token"], "token", None, ()),
        (["-f", "words.txt"], None, "words.txt", ()),
    ],
)
def test_cli_search_source_replaces_config_terms(full_cfg, argv, search, terms_file, terms):
    a = parse("-c", str(full_cfg), *argv)
    assert (a.search, a.terms_file, a.terms) == (search, terms_file, terms)


def test_cli_session_name_replaces_config_session_file(full_cfg):
    assert parse("-c", str(full_cfg)).session_file.endswith("cfg-session.jsonl")
    a = parse("-c", str(full_cfg), "--session", "audit")
    assert (a.session, a.session_file) == ("audit", None)


def test_cli_branches_shortcut_overrides_config_branch_modes(full_cfg):
    a = parse("-c", str(full_cfg), "-b", "3")
    assert (a.index_branches, a.scan_branches) == (3, 3)
    a = parse("-c", str(full_cfg), "-b", "3", "--scan-branches", "default")
    assert (a.index_branches, a.scan_branches) == (3, "default")


def test_config_branches_shortcut_and_explicit_keys(tmp_path):
    cfg = write_cfg(tmp_path, "[x]\nbranches = all\nscan-branches = 2\n")
    a = parse("-c", str(cfg))
    assert (a.index_branches, a.scan_branches) == ("all", 2)
    a = parse("-c", str(cfg), "--index-branches", "default")
    assert (a.index_branches, a.scan_branches) == ("default", 2)


def test_legacy_no_normalize_hits_flag_still_works(tmp_path):
    assert parse("--no-normalize-hits").normalize_hits is False
    cfg = write_cfg(tmp_path, "[postprocess]\nnormalize-hits = false\n")
    assert parse("-c", str(cfg)).normalize_hits is False
    assert parse("-c", str(cfg), "--normalize-hits").normalize_hits is True
