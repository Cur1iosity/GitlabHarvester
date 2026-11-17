# glh/archive.py
"""
Pack the results of a search run into one ZIP archive (``--to-zip``).

The archive sits next to the session, ``<dir>/<session>.zip``, and keeps the
layout of ``glh.output.OutputLayout``: every member is named by its path
relative to ``<dir>``::

    <session>.jsonl                      the session (unless --final-only removed it)
    <session>.deduped.jsonl, ...         --post-process outputs left on disk
    <term>/<session>.jsonl               --output-separated
    <term>/files/<downloaded file>       --download-files

Only files of this session go in, never everything in ``<dir>`` (the default
``results/`` is shared by all sessions): the downloaded files are the ones the
session's hits point to (their ``"file"`` key), so files downloaded before a
``--resume`` are included too. A file outside ``<dir>`` goes under
``external/``.

Members are compressed one at a time in chunks (constant memory, ZIP64 for big
archives), into ``<session>.zip.part`` renamed when complete, so an interrupted
run never leaves a half-written archive under the final name. An existing
archive of the same session is replaced. The original files stay where they are.
"""

from __future__ import annotations

import json
import os
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from glh.downloads import format_size

ZIP_SUFFIX = ".zip"
PART_SUFFIX = ".part"
EXTERNAL_DIR = "external"
COMPRESSION = zipfile.ZIP_DEFLATED
COMPRESS_LEVEL = 6


def archive_path(session_path: Path | str) -> Path:
    """``<dir>/<session>.zip`` for ``<dir>/<session>.jsonl``."""
    session_path = Path(session_path)
    return session_path.with_name(session_path.stem + ZIP_SUFFIX)


def downloaded_files(session_path: Path | str) -> Iterator[str]:
    """
    The local paths in the ``"file"`` keys of the session's hit records, in
    order (repeated when several hits share a file); the session is streamed.
    """
    try:
        fp = Path(session_path).open(encoding="utf-8")
    except OSError:
        return
    with fp:
        for line in fp:
            line = line.strip()
            if not line or '"file"' not in line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            result = record.get("result") if isinstance(record, dict) and "term" in record else None
            if not isinstance(result, dict):
                continue
            for branch in result.get("project_search_result") or ():
                for hit in (branch.get("branch_search_result") or ()) if isinstance(branch, dict) else ():
                    if isinstance(hit, dict) and isinstance(hit.get("file"), str) and hit["file"]:
                        yield hit["file"]


@dataclass(slots=True)
class ZipResult:
    """What went into an archive."""

    path: Path
    files: int = 0
    size: int = 0  # bytes before compression
    compressed: int = 0  # size of the archive
    missing: list[str] = field(default_factory=list)  # paths that were gone

    def describe(self) -> str:
        """'results/x.zip (12 files, 3.4 MiB -> 1.1 MiB)'."""
        text = (f"{self.path} ({self.files} file{'s' if self.files != 1 else ''}, "
                f"{format_size(self.size)} -> {format_size(self.compressed)})")
        if self.missing:
            text += f"; {len(self.missing)} missing, not archived"
        return text


def _member_name(path: Path, root: Path) -> str:
    """The path relative to ``root`` (POSIX separators); outside it: ``external/<name>``."""
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return f"{EXTERNAL_DIR}/{path.name}"


def zip_results(zip_path: Path | str, root: Path | str, paths: Iterable[Path | str]) -> ZipResult:
    """
    Write ``paths`` into the ZIP ``zip_path`` under their paths relative to ``root``.

    Duplicates (the same member name) are archived once; paths that don't
    exist (any more) are listed in ``missing``. The archive itself is never
    a member.

    Raises:
        OSError: if the archive can't be written; nothing is left behind then.
    """
    zip_path, root = Path(zip_path), Path(root)
    part = zip_path.with_name(zip_path.name + PART_SUFFIX)
    result = ZipResult(path=zip_path)
    names: set[str] = set()  # member names, lower-case (unpacked on case-insensitive file systems too)
    # Files already archived (several hits share a file), and the archive itself.
    done = {os.path.normcase(str(p.resolve())) for p in (zip_path, part)}
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(part, "w", compression=COMPRESSION, compresslevel=COMPRESS_LEVEL,
                             allowZip64=True) as zf:
            for raw in paths:
                path = Path(raw)
                key = os.path.normcase(str(path.resolve()))
                if key in done:
                    continue
                if not path.is_file():
                    if str(raw) not in result.missing:
                        result.missing.append(str(raw))
                    continue
                done.add(key)
                name = base = _member_name(path, root)
                n = 1
                while name.lower() in names:  # two different files, one name (external/)
                    n += 1
                    stem, dot, ext = base.rpartition(".")
                    name = f"{stem}~{n}.{ext}" if dot and "/" not in ext else f"{base}~{n}"
                names.add(name.lower())
                zf.write(path, name)
                result.files += 1
                result.size += path.stat().st_size
        part.replace(zip_path)
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    result.compressed = zip_path.stat().st_size
    return result
