"""User-Agent of the API requests (glh.user_agents, applied by ratelimit.ThrottledAdapter)."""

from __future__ import annotations

import pytest
from requests import Session

from glh.ratelimit import ThrottledAdapter, limit_session
from glh.user_agents import UserAgentError, check_user_agent, describe, load_user_agents


def test_load_skips_blank_lines_and_comments(tmp_path):
    f = tmp_path / "ua.txt"
    f.write_text("﻿# browsers\nMozilla/5.0 (X11; Linux x86_64)\n\n  curl/8.5.0  \n# end\n", encoding="utf-8")
    assert load_user_agents(f) == ["Mozilla/5.0 (X11; Linux x86_64)", "curl/8.5.0"]


@pytest.mark.parametrize(("text", "message"), [
    ("# only comments\n\n", "has no User-Agent strings"),
    ("ok/1.0\nМозилла/5.0\n", "line 2: only Latin-1"),
    ("ok/1.0\nbad\tvalue\n", "line 2: control characters"),
    ("x" * 1025 + "\n", "line 1: the User-Agent is longer than 1024"),
])
def test_unusable_files_are_rejected_with_the_line(tmp_path, text, message):
    f = tmp_path / "ua.txt"
    f.write_text(text, encoding="utf-8")
    with pytest.raises(UserAgentError, match=message):
        load_user_agents(f)


def test_missing_and_binary_files_are_rejected(tmp_path):
    with pytest.raises(UserAgentError, match="Cannot read"):
        load_user_agents(tmp_path / "nope.txt")
    f = tmp_path / "ua.bin"
    f.write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(UserAgentError, match="not UTF-8"):
        load_user_agents(f)


def test_check_user_agent():
    assert check_user_agent("  Mozilla/5.0 (Windows NT 10.0)  ") == "Mozilla/5.0 (Windows NT 10.0)"
    for bad in ("", "   ", "a\r\nX-Injected: 1"):
        with pytest.raises(UserAgentError):
            check_user_agent(bad)


def test_describe():
    assert describe([]) == ""
    assert describe(["curl/8"]) == "fixed User-Agent"
    assert describe(["a", "b", "c"]) == "random User-Agent of 3"


class _Request:
    def __init__(self) -> None:
        self.url = "https://g/api/v4/projects/1/search?search=x"
        self.headers = {"User-Agent": "python-gitlab/8.6.0"}


class FixedChoice:
    def __init__(self, *picks: int) -> None:
        self.picks = list(picks)

    def choice(self, seq):
        return seq[self.picks.pop(0)]


def test_adapter_sets_a_random_user_agent_per_request(monkeypatch):
    sent: list[str] = []
    monkeypatch.setattr("requests.adapters.HTTPAdapter.send",
                        lambda self, request, *a, **k: sent.append(request.headers["User-Agent"]))
    adapter = ThrottledAdapter(user_agents=["a/1", "b/2", "c/3"], rng=FixedChoice(2, 0, 2))
    for _ in range(3):
        adapter.send(_Request())
    assert sent == ["c/3", "a/1", "c/3"]
    assert adapter.index_limiter is None and adapter.search_limiter is None  # no pacing


def test_user_agents_alone_mount_the_adapter():
    session = Session()
    limit_session(session, user_agents=["fixed/1.0"])
    adapter = session.get_adapter("https://gitlab.test")
    assert isinstance(adapter, ThrottledAdapter) and adapter.user_agents == ("fixed/1.0",)
