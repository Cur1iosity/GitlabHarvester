"""Token parsing/loading (glh.tokens): several tokens from -t and --token-file."""

from __future__ import annotations

from pathlib import Path

import pytest

from glh import tokens


# --------------------------------------------------------------------------- check_token


@pytest.mark.parametrize("raw", ["glpat-abc", "  glpat-abc  ", "a_b-c.d"])
def test_check_token_accepts_and_strips(raw):
    assert tokens.check_token(raw) == raw.strip()


@pytest.mark.parametrize(("raw", "message"), [
    ("", "empty"),
    ("   ", "empty"),
    ("has space", "whitespace"),
    ("tab\ttoken", "whitespace"),
    ("токен", "Latin-1"),
])
def test_check_token_rejects(raw, message):
    with pytest.raises(tokens.TokenError, match=message):
        tokens.check_token(raw)


# --------------------------------------------------------------------------- parse_tokens


def test_parse_tokens_single():
    assert tokens.parse_tokens("glpat-abc") == ["glpat-abc"]


def test_parse_tokens_splits_on_semicolon_and_strips():
    assert tokens.parse_tokens(" a ; b ;c ") == ["a", "b", "c"]


def test_parse_tokens_skips_blanks_and_dedups_keeping_order():
    assert tokens.parse_tokens("a;;b;a;;c;b") == ["a", "b", "c"]


@pytest.mark.parametrize("raw", ["", ";", "  ;  ;"])
def test_parse_tokens_without_a_token_is_an_error(raw):
    with pytest.raises(tokens.TokenError):
        tokens.parse_tokens(raw)


def test_parse_tokens_propagates_an_invalid_token():
    with pytest.raises(tokens.TokenError, match="whitespace"):
        tokens.parse_tokens("good;bad token")


# --------------------------------------------------------------------------- load_tokens


def test_load_tokens_one_per_line_with_comments(tmp_path: Path):
    f = tmp_path / "tokens.txt"
    f.write_text("# colleagues' tokens\nglpat-a\n\n  glpat-b  \n# trailing\nglpat-c\n", encoding="utf-8")
    assert tokens.load_tokens(f) == ["glpat-a", "glpat-b", "glpat-c"]


def test_load_tokens_dedups(tmp_path: Path):
    f = tmp_path / "tokens.txt"
    f.write_text("glpat-a\nglpat-b\nglpat-a\n", encoding="utf-8")
    assert tokens.load_tokens(f) == ["glpat-a", "glpat-b"]


def test_load_tokens_reports_the_offending_line(tmp_path: Path):
    f = tmp_path / "tokens.txt"
    f.write_text("glpat-a\nbad token\n", encoding="utf-8")
    with pytest.raises(tokens.TokenError, match="line 2"):
        tokens.load_tokens(f)


def test_load_tokens_empty_file_is_an_error(tmp_path: Path):
    f = tmp_path / "tokens.txt"
    f.write_text("# only comments\n\n", encoding="utf-8")
    with pytest.raises(tokens.TokenError, match="no tokens"):
        tokens.load_tokens(f)


def test_load_tokens_missing_file_is_an_error(tmp_path: Path):
    with pytest.raises(tokens.TokenError, match="Cannot read"):
        tokens.load_tokens(tmp_path / "nope.txt")


# --------------------------------------------------------------------------- describe


@pytest.mark.parametrize(("items", "text"), [([], ""), (["a"], "1 token"), (["a", "b"], "2 tokens")])
def test_describe(items, text):
    assert tokens.describe(items) == text
