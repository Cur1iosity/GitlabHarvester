"""Downloads of files with hits (glh.downloads, --download-files / --download-max-size)."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from glh.cli import DEFAULT_DOWNLOAD_MAX_SIZE, CliParser
from glh.downloads import CHUNK_SIZE, FileDownloader, file_name, format_size, parse_size
from glh.output import OutputLayout

STAMP = "20261117093000"
PREFIX = "acme_backend_api-service_main_20261117093000_password_"


class FakeResponse:
    """Streamed response stand-in: chunks, headers, close tracking."""

    def __init__(self, data: bytes, *, content_length: bool = True, chunk: int = 4, fail_after: int | None = None):
        self.data = data
        self.headers = {"Content-Length": str(len(data))} if content_length else {}
        self.chunk = chunk
        self.fail_after = fail_after
        self.closed = False
        self.read = 0

    def iter_content(self, chunk_size: int):
        assert chunk_size == CHUNK_SIZE
        for i in range(0, len(self.data), self.chunk):
            if self.fail_after is not None and self.read >= self.fail_after:
                raise ConnectionError("connection reset")
            part = self.data[i:i + self.chunk]
            self.read += len(part)
            yield part

    def close(self) -> None:
        self.closed = True


def downloader(root: Path, terms=("password",), **kw) -> FileDownloader:
    return FileDownloader(OutputLayout(root / "audit.jsonl", list(terms)), STAMP, **kw)


def save(d: FileDownloader, response: FakeResponse | None = None, *, term="password", path="config/settings.py",
         project_id=101, project="acme/backend/api-service", branch="main", calls: list | None = None):
    def fetch():
        if calls is not None:
            calls.append(path)
        assert response is not None, "no request expected"
        return response
    return d.save(project_id=project_id, project_path=project, branch=branch, term=term, path=path, fetch=fetch)


def files_under(root: Path) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())


# --------------------------------------------------------------------------- sizes


@pytest.mark.parametrize(("raw", "expected"), [
    ("0", 0), ("1024", 1024), ("500k", 500 * 1024), ("10M", 10 * 1024 ** 2), ("10m", 10 * 1024 ** 2),
    ("10MB", 10 * 1024 ** 2), ("10MiB", 10 * 1024 ** 2), ("1.5G", int(1.5 * 1024 ** 3)), (" 2 kb ", 2048),
])
def test_parse_size(raw, expected):
    assert parse_size(raw) == expected


@pytest.mark.parametrize("raw", ["", "M", "-1", "10X", "ten", "1,5M"])
def test_parse_size_invalid(raw):
    with pytest.raises(ValueError):
        parse_size(raw)


def test_format_size():
    assert format_size(512) == "512 B"
    assert format_size(500 * 1024) == "500 KiB"
    assert format_size(10 * 1024 ** 2) == "10 MiB"
    assert format_size(int(1.5 * 1024 ** 3)) == "1.5 GiB"


def test_cli_download_options(capsys):
    a = CliParser.parse([])
    assert a.download_files is False and a.download_max_size == DEFAULT_DOWNLOAD_MAX_SIZE == 10 * 1024 ** 2
    a = CliParser.parse(["--download-files", "--download-max-size", "500k"])
    assert a.download_files is True and a.download_max_size == 500 * 1024
    with pytest.raises(SystemExit):
        CliParser.parse(["--download-max-size", "10X"])
    assert "--download-max-size" in capsys.readouterr().err


def test_download_options_from_config_file(tmp_path: Path):
    cfg = tmp_path / "c.ini"
    cfg.write_text("[session]\ndownload-files = true\ndownload-max-size = 1M\n", encoding="utf-8")
    a = CliParser.parse(["-c", str(cfg)])
    assert (a.download_files, a.download_max_size) == (True, 1024 ** 2)
    a = CliParser.parse(["-c", str(cfg), "--no-download-files", "--download-max-size", "0"])
    assert (a.download_files, a.download_max_size) == (False, 0)


# --------------------------------------------------------------------------- names


def test_file_name_layout():
    assert file_name("acme/backend/api-service", "main", STAMP, "password", "config/settings.py") == \
        "acme_backend_api-service_main_20261117093000_password_config_settings.py"


def test_file_name_is_filesystem_safe():
    name = file_name("acme/frontend/web-app", "fix/#42-login", STAMP, "p@ss w0rd!", "docs/setup guide.md")
    assert name == "acme_frontend_web-app_fix_42-login_20261117093000_p_ss_w0rd_docs_setup_guide.md"
    name = file_name("g/p", "ünïcode-ветка", STAMP, "ключ", "i18n/ru.txt")
    assert all(ch.isascii() for ch in name) and name.endswith("_i18n_ru.txt")
    assert "/" not in file_name("g/p", "../../etc", STAMP, "../x", "../../passwd")
    assert "\\" not in file_name("g/p", "main", STAMP, "a\\b", "c\\d.txt")


def test_dot_files_keep_their_dot():
    assert file_name("g/p", "main", STAMP, "t", ".env") == "g_p_main_20261117093000_t_.env"
    assert file_name("g/p", "main", STAMP, "t", "deploy/.env.") == "g_p_main_20261117093000_t_deploy_.env"


def test_long_parts_are_shortened_and_the_path_keeps_its_end():
    name = file_name("g/" + "p" * 200, "b" * 100, STAMP, "t" * 100, "/".join(["dir"] * 60) + "/secrets.yml")
    assert len(name) <= 200
    assert name.endswith("secrets.yml")


# --------------------------------------------------------------------------- saving


def test_saves_into_the_files_directory_of_the_term(tmp_path: Path):
    d = downloader(tmp_path)
    assert not (tmp_path / "password").exists()  # created on the first download
    resp = FakeResponse(b"DB_PASSWORD = 'x'\n")
    local = save(d, resp)
    assert local == tmp_path / "password" / "files" / f"{PREFIX}config_settings.py"
    assert local.read_bytes() == b"DB_PASSWORD = 'x'\n"
    assert resp.closed
    assert (d.stats.saved, d.stats.bytes, d.stats.files) == (1, 18, 1)
    assert files_under(tmp_path) == [f"password/files/{local.name}"]


def test_term_directories_match_the_output_layout(tmp_path: Path):
    terms = ["api/key", "a b", "a_b"]
    layout = OutputLayout(tmp_path / "audit.jsonl", terms)
    d = FileDownloader(layout, STAMP)
    got = {t: save(d, FakeResponse(b"x"), term=t).parent for t in terms}
    assert got == {t: layout.files_dir(t) for t in terms}
    assert [p.parent.name for p in got.values()] == ["api_key", "a_b", "a_b_2"]


def test_same_file_for_another_term_is_copied_not_requested(tmp_path: Path):
    d = downloader(tmp_path, ["password", "api_key"])
    calls: list[str] = []
    first = save(d, FakeResponse(b"secret"), calls=calls)
    second = save(d, None, term="api_key", calls=calls)
    assert calls == ["config/settings.py"]
    assert first.parent == tmp_path / "password" / "files" and second.parent == tmp_path / "api_key" / "files"
    assert second.name == "acme_backend_api-service_main_20261117093000_api_key_config_settings.py"
    assert second.read_bytes() == b"secret"
    assert (d.stats.saved, d.stats.copied, d.stats.files, d.stats.bytes) == (1, 1, 2, 6)


def test_another_branch_or_project_is_downloaded_again(tmp_path: Path):
    d = downloader(tmp_path)
    calls: list[str] = []
    a = save(d, FakeResponse(b"a"), calls=calls)
    b = save(d, FakeResponse(b"b"), branch="develop", calls=calls)
    c = save(d, FakeResponse(b"c"), project_id=201, project="alice/api-service", calls=calls)
    assert len(calls) == 3 and len({a, b, c}) == 3
    assert [p.read_bytes() for p in (a, b, c)] == [b"a", b"b", b"c"]


def test_name_collisions_get_a_suffix_before_the_extension(tmp_path: Path):
    d = downloader(tmp_path)
    a = save(d, FakeResponse(b"1"), path="a b.py")
    b = save(d, FakeResponse(b"2"), path="a_b.py")
    c = save(d, FakeResponse(b"3"), path="A_B.py")  # case-insensitive file systems
    assert [p.name for p in (a, b, c)] == [f"{PREFIX}a_b.py", f"{PREFIX}a_b~2.py", f"{PREFIX}A_B~3.py"]


def test_existing_files_are_never_overwritten(tmp_path: Path):
    d = downloader(tmp_path)
    target = tmp_path / "password" / "files" / f"{PREFIX}.env"
    target.parent.mkdir(parents=True)
    target.write_text("old", encoding="utf-8")
    local = save(d, FakeResponse(b"new"), path=".env")
    assert local.name == f"{PREFIX}.env~2"
    assert target.read_text(encoding="utf-8") == "old" and local.read_bytes() == b"new"


def test_too_large_by_content_length_is_skipped_without_reading(tmp_path: Path):
    d = downloader(tmp_path, max_size=10)
    resp = FakeResponse(b"x" * 11)
    assert save(d, resp) is None
    assert resp.read == 0 and resp.closed
    assert files_under(tmp_path) == []
    assert (d.stats.too_large, d.stats.saved) == (1, 0)
    # Exactly at the limit is fine.
    assert save(d, FakeResponse(b"x" * 10)).read_bytes() == b"x" * 10


def test_too_large_without_content_length_stops_the_stream(tmp_path: Path):
    d = downloader(tmp_path, max_size=10)
    resp = FakeResponse(b"x" * 1000, content_length=False)
    assert save(d, resp) is None
    assert resp.read <= 12 and resp.closed  # stopped right after passing the limit
    assert files_under(tmp_path) == []  # no .part left behind
    assert d.stats.too_large == 1


def test_no_size_limit(tmp_path: Path):
    d = downloader(tmp_path, max_size=0)
    assert save(d, FakeResponse(b"x" * 5000, chunk=1000)).stat().st_size == 5000


def test_failed_stream_leaves_nothing_and_frees_the_name(tmp_path: Path):
    d = downloader(tmp_path)
    resp = FakeResponse(b"x" * 100, fail_after=8)
    with pytest.raises(ConnectionError):
        save(d, resp)
    assert resp.closed
    assert files_under(tmp_path) == []
    # The name is free again: a retry gets the plain name.
    local = save(d, FakeResponse(b"ok"))
    assert "~" not in local.name and local.read_bytes() == b"ok"


def test_failed_request_leaves_nothing(tmp_path: Path):
    d = downloader(tmp_path)

    def fetch():
        raise ConnectionError("refused")

    with pytest.raises(ConnectionError):
        d.save(project_id=1, project_path="g/p", branch="main", term="password", path="a.txt", fetch=fetch)
    d.failed()
    assert d.stats.failed == 1 and files_under(tmp_path) == []


def test_parallel_saves_get_distinct_files(tmp_path: Path):
    d = downloader(tmp_path)
    results: list[Path] = []
    lock = threading.Lock()

    def worker(n: int) -> None:
        local = save(d, FakeResponse(str(n).encode()), path="same.txt", project_id=n)
        with lock:
            results.append(local)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(results)) == 8
    assert sorted(p.read_text() for p in results) == [str(n) for n in range(8)]


def test_describe_and_summary(tmp_path: Path):
    d = downloader(tmp_path / "results", ["t", "u"], max_size=10 * 1024 ** 2)
    where = str(tmp_path / "results" / "<term>" / "files")
    assert d.describe() == f"download files to {where} (max 10 MiB each)"
    assert downloader(tmp_path).describe().endswith("(no size limit)")
    save(d, FakeResponse(b"abc"), term="t")
    save(d, None, term="u")
    d.stats.too_large, d.stats.failed = 1, 2
    assert d.summary() == (f"2 files (3 B) downloaded to {where} (1 copied locally: same file, "
                           f"another term), 1 skipped: larger than 10 MiB, 2 FAILED (see the warnings)")
