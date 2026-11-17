"""Output blocks (glh.utils.terminal_utils.format_block), the echoed command and its masking."""

from __future__ import annotations

from glh.tokens import mask_argv
from glh.utils import terminal_utils
from glh.utils.terminal_utils import StatusLine, compact_block, format_block, style
from tests.helpers import FakeStream, parse_blocks

ROWS = [("terms", 1), ("projects", "23,982 of 30,639"), ("skipped", ["496 empty", "2,087 forks"]),
        ("files", ""), ("downloads", []), ("branches", "23,982")]


def test_format_block_aligns_labels_and_continues_lists():
    assert format_block("Search plan", ROWS) == [
        "Search plan",
        "  terms     1",
        "  projects  23,982 of 30,639",
        "  skipped   496 empty",
        "            2,087 forks",
        "  branches  23,982",
    ]


def test_compact_block_is_one_greppable_line():
    assert compact_block("Search plan", ROWS) == (
        "Search plan: terms 1; projects 23,982 of 30,639; skipped 496 empty, 2,087 forks; branches 23,982")


def test_blocks_round_trip_through_the_test_parser():
    text = "\n".join(format_block("Results", [("hits", "33"), ("downloaded", ["2 files", "1 copied"])]))
    assert parse_blocks(text) == {"Results": {"hits": ["33"], "downloaded": ["2 files", "1 copied"]}}


def test_write_block_separates_blocks_by_one_empty_line_and_journals_one_line():
    stream = FakeStream(tty=False)
    status = StatusLine(stream, interactive=False, ticker=False)
    seen: list[str] = []
    status.add_listener(seen.append)
    status.write_line("Indexed 9 projects")
    status.write_block("Index", [("file", "idx.jsonl")])
    status.write_block("Search plan", [("terms", "2")])
    status.write_line("Term 1/2 'password': 9 hits")
    assert stream.getvalue() == ("Indexed 9 projects\n\nIndex\n  file  idx.jsonl\n\n"
                                 "Search plan\n  terms  2\n\nTerm 1/2 'password': 9 hits\n")
    assert seen == ["Indexed 9 projects", "Index: file idx.jsonl", "Search plan: terms 2",
                    "Term 1/2 'password': 9 hits"]


def test_mask_argv_hides_tokens_and_proxy_passwords():
    argv = ["-u", "https://g", "-t", "glpat-SECRET", "--token=a;b", "-tX", "-p", "http://me:pw@proxy:8080",
            "--proxy=http://proxy:3128", "--token-file", "tokens.txt", "-s", "pass word"]
    assert mask_argv(argv) == ["-u", "https://g", "-t", "<TOKEN>", "--token=<TOKEN>", "-t<TOKEN>",
                               "-p", "http://me:***@proxy:8080", "--proxy=http://proxy:3128",
                               "--token-file", "tokens.txt", "-s", "pass word"]
    assert mask_argv(["-t"]) == ["-t"]


def test_style_only_on_an_ansi_terminal(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(terminal_utils, "supports_ansi", lambda stream: True)
    assert style("$ cmd", "1;94", FakeStream(tty=True)) == "\x1b[1;94m$ cmd\x1b[0m"
    monkeypatch.setenv("NO_COLOR", "1")
    assert style("$ cmd", "1;94", FakeStream(tty=True)) == "$ cmd"
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setattr(terminal_utils, "supports_ansi", lambda stream: False)
    assert style("$ cmd", "1;94", FakeStream(tty=False)) == "$ cmd"
