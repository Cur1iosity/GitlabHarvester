"""CLI argument parsing (glh.cli)."""

from __future__ import annotations

import argparse

import pytest

from glh.cli import CliParser, parse_branches


@pytest.mark.parametrize(("raw", "expected"), [("default", "default"), (" ALL ", "all"), ("10", 10), ("1", 1)])
def test_parse_branches_valid(raw, expected):
    assert parse_branches(raw) == expected


@pytest.mark.parametrize("raw", ["0", "-1", "some", "1.5", ""])
def test_parse_branches_invalid(raw):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_branches(raw)


def test_defaults():
    a = CliParser.parse([])
    assert a.mode == "search"
    assert a.index_branches == "default" and a.scan_branches == "default"
    assert a.forks == "include"
    assert a.batch_size == 100 and a.timeout == 60
    assert a.normalize_hits is True


def test_branches_shortcut_sets_both_but_explicit_values_win():
    a = CliParser.parse(["-b", "all"])
    assert (a.index_branches, a.scan_branches) == ("all", "all")
    a = CliParser.parse(["-b", "all", "--scan-branches", "3"])
    assert (a.index_branches, a.scan_branches) == ("all", 3)


def test_host_alias_maps_to_url():
    assert CliParser.parse(["-H", "https://gitlab.test"]).url == "https://gitlab.test"


def test_debug_overrides_log_level():
    assert CliParser.parse(["--debug", "--log-level", "ERROR"]).log_level == "DEBUG"


@pytest.mark.parametrize(
    "argv",
    [
        ["-s", "x", "-f", "terms.txt"],  # mutually exclusive search sources
        ["--session", "a", "--session-file", "b.jsonl"],  # mutually exclusive session options
        ["--forks", "sometimes"],
        ["-m", "explode"],
    ],
)
def test_invalid_combinations_exit(argv, capsys):
    with pytest.raises(SystemExit) as e:
        CliParser.parse(argv)
    assert e.value.code == 2


def test_started_from_default_is_disabled():
    assert CliParser.parse([]).started_from is None


@pytest.mark.parametrize(
    ("raw", "iso"),
    [
        ("2024-06-01", "2024-06-01T00:00:00+00:00"),
        ("2024-06-01T12:30", "2024-06-01T12:30:00+00:00"),
        ("2024-06-01T12:30:00+03:00", "2024-06-01T12:30:00+03:00"),
        ("2024-06-01T09:30:00Z", "2024-06-01T09:30:00+00:00"),
    ],
)
def test_started_from_is_timezone_aware(raw, iso):
    value = CliParser.parse(["--started-from", raw]).started_from
    assert value.tzinfo is not None
    assert value.isoformat() == iso


@pytest.mark.parametrize("raw", ["yesterday", "01.06.2024", "2024-13-01", ""])
def test_started_from_rejects_invalid_values(raw, capsys):
    with pytest.raises(SystemExit) as e:
        CliParser.parse(["--started-from", raw])
    assert e.value.code == 2
    assert "ISO 8601" in capsys.readouterr().err


# --------------------------------------------------------------------------- time filters

from pathlib import Path  # noqa: E402

TIME_FIELDS = ("index_active_after", "index_active_before", "started_from", "active_before",
               "file_changed_after", "file_changed_before")


def iso(args, field):
    value = getattr(args, field)
    return value.date().isoformat() if value else None


def test_time_filters_are_off_by_default():
    a = CliParser.parse([])
    assert all(getattr(a, f) is None for f in TIME_FIELDS)


def test_group_options_set_every_level():
    a = CliParser.parse(["--time-after", "2024-01-01", "--time-before", "2024-12-31"])
    assert [iso(a, f) for f in TIME_FIELDS] == ["2024-01-01", "2024-12-31"] * 3


def test_specific_options_override_the_group():
    a = CliParser.parse(["--time-after", "2024-01-01", "--file-changed-after", "2024-06-01",
                         "--index-active-before", "2024-09-01"])
    assert iso(a, "index_active_after") == "2024-01-01"
    assert iso(a, "started_from") == "2024-01-01"
    assert iso(a, "file_changed_after") == "2024-06-01"
    assert iso(a, "index_active_before") == "2024-09-01"
    assert iso(a, "active_before") is None


@pytest.mark.parametrize("flag", ["--started-from", "--active-after"])
def test_started_from_is_an_alias_of_active_after(flag):
    a = CliParser.parse([flag, "2024-06-01"])
    assert iso(a, "started_from") == "2024-06-01"
    assert a.index_active_after is None and a.file_changed_after is None


@pytest.mark.parametrize("argv", [
    ["--time-after", "2024-06-01", "--time-before", "2024-01-01"],
    ["--active-after", "2024-06-01", "--active-before", "2024-05-31"],
    ["--time-before", "2024-01-01", "--file-changed-after", "2024-02-01"],
])
def test_start_later_than_end_is_rejected(argv, capsys):
    with pytest.raises(SystemExit) as e:
        CliParser.parse(argv)
    assert e.value.code == 2
    assert "is later than the end" in capsys.readouterr().err


def test_time_bounds_precedence_with_config_file(tmp_path: Path):
    cfg = tmp_path / "c.ini"
    cfg.write_text("[time]\ntime-after = 2024-01-01\nactive-after = 2024-02-01\nfile-changed-before = 2024-11-30\n",
                   encoding="utf-8")
    a = CliParser.parse(["-c", str(cfg)])
    assert [iso(a, f) for f in TIME_FIELDS] == [
        "2024-01-01", None, "2024-02-01", None, "2024-01-01", "2024-11-30"]

    # A CLI group option beats any key from the file; a CLI specific option beats the CLI group.
    a = CliParser.parse(["-c", str(cfg), "--time-after", "2024-05-01", "--active-after", "2024-05-15"])
    assert [iso(a, f) for f in TIME_FIELDS] == [
        "2024-05-01", None, "2024-05-15", None, "2024-05-01", "2024-11-30"]


def test_config_alias_and_option_together_is_a_duplicate(tmp_path: Path, capsys):
    cfg = tmp_path / "c.ini"
    cfg.write_text("[time]\nstarted-from = 2024-01-01\nactive-after = 2024-02-01\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        CliParser.parse(["-c", str(cfg)])
    assert "duplicate key" in capsys.readouterr().err


# --------------------------------------------------------------------------- banner and console encodings

import io  # noqa: E402

from glh.cli import _BANNER, get_banner  # noqa: E402


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_banner_art_on_unicode_streams(encoding):
    stream = io.TextIOWrapper(io.BytesIO(), encoding=encoding)
    assert get_banner(stream).startswith(_BANNER)


@pytest.mark.parametrize("encoding", ["cp1252", "cp866", "ascii", "latin-1"])
def test_plain_banner_on_legacy_code_pages(encoding):
    stream = io.TextIOWrapper(io.BytesIO(), encoding=encoding)
    banner = get_banner(stream)
    assert banner.startswith("GitlabHarvester v")
    banner.encode(encoding)  # must not raise


def test_banner_without_stream_keeps_the_art():
    assert get_banner().startswith(_BANNER)


# --------------------------------------------------------------------------- request rate limits


def test_rate_limits_are_off_by_default():
    a = CliParser.parse([])
    assert (a.index_rpm, a.search_rpm) == (0, 0)


def test_rpm_sets_both_limits_and_a_specific_option_overrides_it():
    a = CliParser.parse(["--rpm", "120"])
    assert (a.index_rpm, a.search_rpm) == (120, 120)
    a = CliParser.parse(["--rpm", "120", "--search-rpm", "20"])
    assert (a.index_rpm, a.search_rpm) == (120, 20)
    a = CliParser.parse(["--search-rpm", "20"])
    assert (a.index_rpm, a.search_rpm) == (0, 20)


def test_rate_limit_precedence_with_config_file(tmp_path: Path):
    cfg = tmp_path / "c.ini"
    cfg.write_text("[connection]\nrpm = 100\nsearch-rpm = 10\n", encoding="utf-8")
    a = CliParser.parse(["-c", str(cfg)])
    assert (a.index_rpm, a.search_rpm) == (100, 10)

    # A CLI group option beats any key from the file; a CLI specific option beats the CLI group.
    a = CliParser.parse(["-c", str(cfg), "--rpm", "50"])
    assert (a.index_rpm, a.search_rpm) == (50, 50)
    a = CliParser.parse(["-c", str(cfg), "--rpm", "50", "--index-rpm", "0"])
    assert (a.index_rpm, a.search_rpm) == (0, 50)


@pytest.mark.parametrize("value", ["-1", "1.5", "abc", ""])
def test_invalid_rate_limit_is_rejected(value, capsys):
    with pytest.raises(SystemExit) as e:
        CliParser.parse(["--search-rpm", value])
    assert e.value.code == 2
    assert "non-negative integer" in capsys.readouterr().err


def test_jitter_is_off_by_default_and_parsed():
    assert CliParser.parse([]).jitter == (0.0, 0.0)
    assert CliParser.parse(["--jitter", "10ms-50ms"]).jitter == pytest.approx((0.01, 0.05))


def test_jitter_from_config_file_and_cli_override(tmp_path: Path):
    cfg = tmp_path / "c.ini"
    cfg.write_text("[connection]\njitter = 0.03\n", encoding="utf-8")
    assert CliParser.parse(["-c", str(cfg)]).jitter == pytest.approx((0.0, 0.03))
    assert CliParser.parse(["-c", str(cfg), "--jitter", "0"]).jitter == (0.0, 0.0)


def test_invalid_jitter_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as e:
        CliParser.parse(["--jitter", "0.05-0.01"])
    assert e.value.code == 2
    assert "larger than the maximum" in capsys.readouterr().err


# --------------------------------------------------------------------------- User-Agent


def test_token_options():
    a = CliParser.parse([])
    assert a.token is None and a.token_file is None
    # -t keeps the raw value; the ';' split into a token list happens in modes._resolve_tokens.
    assert CliParser.parse(["-t", "glpat-a;glpat-b"]).token == "glpat-a;glpat-b"
    assert CliParser.parse(["--token-file", "tokens.txt"]).token_file == "tokens.txt"


def test_token_and_token_file_exclude_each_other(capsys):
    with pytest.raises(SystemExit) as e:
        CliParser.parse(["-t", "glpat-a", "--token-file", "tokens.txt"])
    assert e.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err


def test_token_file_from_config_file(tmp_path: Path, capsys):
    (tmp_path / "tokens.txt").write_text("glpat-a\nglpat-b\n", encoding="utf-8")
    cfg = tmp_path / "c.ini"
    cfg.write_text("[connection]\ntoken-file = tokens.txt\n", encoding="utf-8")
    a = CliParser.parse(["-c", str(cfg)])
    assert a.token_file == str(tmp_path / "tokens.txt")  # relative to the config file
    # One of them on the command line replaces the other from the file.
    a = CliParser.parse(["-c", str(cfg), "-t", "glpat-cli"])
    assert a.token == "glpat-cli" and a.token_file is None

    cfg.write_text("[connection]\ntoken = glpat-a\ntoken-file = tokens.txt\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        CliParser.parse(["-c", str(cfg)])
    assert "mutually exclusive" in capsys.readouterr().err


def test_user_agent_options():
    a = CliParser.parse([])
    assert a.user_agent is None and a.user_agent_file is None
    assert CliParser.parse(["-A", "Mozilla/5.0 (X11)"]).user_agent == "Mozilla/5.0 (X11)"
    assert CliParser.parse(["--user-agent-file", "ua.txt"]).user_agent_file == "ua.txt"


def test_user_agent_and_file_exclude_each_other(capsys):
    with pytest.raises(SystemExit) as e:
        CliParser.parse(["-A", "curl/8", "--user-agent-file", "ua.txt"])
    assert e.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err


def test_invalid_user_agent_is_a_usage_error(capsys):
    with pytest.raises(SystemExit):
        CliParser.parse(["-A", "Мозилла"])
    assert "Latin-1" in capsys.readouterr().err


def test_user_agent_from_config_file(tmp_path: Path, capsys):
    (tmp_path / "ua.txt").write_text("a/1\n", encoding="utf-8")
    cfg = tmp_path / "c.ini"
    cfg.write_text("[connection]\nuser-agent-file = ua.txt\n", encoding="utf-8")
    a = CliParser.parse(["-c", str(cfg)])
    assert a.user_agent_file == str(tmp_path / "ua.txt")  # relative to the config file
    # One of them on the command line replaces the other from the file.
    a = CliParser.parse(["-c", str(cfg), "-A", "curl/8"])
    assert a.user_agent == "curl/8" and a.user_agent_file is None

    cfg.write_text("[connection]\nuser-agent = curl/8\nuser-agent-file = ua.txt\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        CliParser.parse(["-c", str(cfg)])
    assert "mutually exclusive" in capsys.readouterr().err
