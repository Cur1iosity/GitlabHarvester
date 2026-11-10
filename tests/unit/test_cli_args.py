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
