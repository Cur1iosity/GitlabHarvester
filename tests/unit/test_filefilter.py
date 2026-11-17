"""File filters (glh.domain.file_filter, --filename / --extension)."""

from __future__ import annotations

import pytest

from glh.cli.parser import CliParser
from glh.domain.file_filter import FileFilter, FileFilterError, normalize_extension, normalize_filename
from glh.domain.planning import ScanOptions


# --------------------------------------------------------------------------- normalization


@pytest.mark.parametrize("raw", ["py", ".py", "..py", "*.py", "py.", " .py ", "*py"])
def test_extension_dots_and_mask_are_dropped(raw):
    assert normalize_extension(raw) == "py"


def test_extension_keeps_inner_dots_and_case():
    assert normalize_extension(".tar.gz") == "tar.gz"
    assert normalize_extension(".YML") == "YML"


@pytest.mark.parametrize("raw", ["", ".", "..", "*.", "p y", "a/b"])
def test_invalid_extension(raw):
    with pytest.raises(FileFilterError):
        normalize_extension(raw)


@pytest.mark.parametrize(("raw", "expected"), [
    ("settings.py", "settings.py"), ("*.env", "*.env"), (" config* ", "config*"),
    ("/config/app.yml", "config/app.yml"), (".env", ".env"),
])
def test_filename_values(raw, expected):
    assert normalize_filename(raw) == expected


@pytest.mark.parametrize("raw", ["", "  ", "*", "**", "my file.txt", "/"])
def test_invalid_filename(raw):
    with pytest.raises(FileFilterError):
        normalize_filename(raw)


# --------------------------------------------------------------------------- query and matching


def test_query_appends_gitlab_filters_to_the_term():
    assert FileFilter("*.env").query("password") == "password filename:*.env"
    assert FileFilter(extension="py").query("api key") == "api key extension:py"
    assert FileFilter("config*", "yml").query("token") == "token filename:config* extension:yml"


def test_empty_filter_is_falsy():
    assert not FileFilter()
    assert FileFilter("a")
    assert FileFilter(extension="py")
    assert not ScanOptions().file_filter
    assert ScanOptions(filename="*.env").file_filter == FileFilter("*.env")


@pytest.mark.parametrize(("pattern", "path", "expected"), [
    ("settings.py", "config/settings.py", True),
    ("settings.py", "settings.py", True),
    ("SETTINGS.PY", "config/settings.py", True),          # case-insensitive
    ("config.yml", "app/myconfig.yml", False),            # exact name, unlike GitLab basic search
    ("*.env", "deploy/prod.env", True),
    ("*.env", ".env", True),
    ("*.env", "deploy/env.example", False),
    ("config*", "src/config.js", True),
    ("config*", "config/settings.py", False),             # matches the name, not a directory
    ("docker-compose*.yml", "docker-compose.prod.yml", True),
    ("*secret*", "k8s/my-secret-values.yaml", True),
    ("a.b", "aXb", False),                                # only * is special
    ("file?.txt", "file1.txt", False),
    ("file?.txt", "file?.txt", True),
    ("config/*.yml", "config/app.yml", True),            # with '/': end of the path
    ("config/*.yml", "deploy/config/app.yml", True),
    ("config/*.yml", "myconfig/app.yml", False),
])
def test_filename_matching(pattern, path, expected):
    assert FileFilter(filename=pattern).matches(path) is expected


@pytest.mark.parametrize(("ext", "path", "expected"), [
    ("py", "config/settings.py", True),
    ("PY", "a/b.Py", True),
    ("py", "a/b.pyc", False),
    ("py", "py", False),
    ("env", ".env", True),
    ("tar.gz", "dist/x.tar.gz", True),
    ("gz", "dist/x.tar.gz", True),
    ("example", "deploy/env.example", True),
])
def test_extension_matching(ext, path, expected):
    assert FileFilter(extension=ext).matches(path) is expected


def test_both_filters_must_match():
    f = FileFilter("config*", "yml")
    assert f.matches("config.yml")
    assert not f.matches("config.json")
    assert not f.matches("app.yml")


def test_describe_and_meta():
    f = FileFilter("*.env", "py")
    assert f.describe() == "filename *.env, extension py"
    assert f.to_meta() == {"filename": "*.env", "extension": "py"}
    assert FileFilter().to_meta() == {"filename": None, "extension": None}


# --------------------------------------------------------------------------- CLI


def test_cli_options_are_normalized():
    a = CliParser.parse(["--filename", "*.env", "--extension", ".py"])
    assert (a.filename, a.extension) == ("*.env", "py")
    a = CliParser.parse([])
    assert (a.filename, a.extension) == (None, None)


@pytest.mark.parametrize("argv", [["--filename", "a b"], ["--extension", "."], ["--filename", "*"]])
def test_cli_rejects_invalid_filters(argv, capsys):
    with pytest.raises(SystemExit) as e:
        CliParser.parse(argv)
    assert e.value.code == 2
    assert argv[0] in capsys.readouterr().err


def test_filters_from_config_file(tmp_path):
    cfg = tmp_path / "c.ini"
    cfg.write_text("[search]\nfilename = settings*\nextension = *.PY\n", encoding="utf-8")
    a = CliParser.parse(["-c", str(cfg)])
    assert (a.filename, a.extension) == ("settings*", "PY")
    a = CliParser.parse(["-c", str(cfg), "--extension", "yml"])
    assert a.extension == "yml"


def test_values_are_normalized_for_library_callers_too():
    assert FileFilter(extension=".py") == FileFilter(extension="py")
    assert ScanOptions(extension="*.PY", filename="/config/*.yml").file_filter == FileFilter("config/*.yml", "PY")
    with pytest.raises(FileFilterError):
        FileFilter(filename="a b")
