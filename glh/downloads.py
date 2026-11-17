# glh/downloads.py
"""
Download the files with hits (``--download-files``).

Every file that produced a hit is saved once per (term, project, branch, path)
into the term's ``files`` directory, ``<dir>/<term>/files/`` (see
``glh.output.OutputLayout``; ``results/<term>/files/`` with the default session
location), created on the first download. The name follows the other
GitlabHarvester outputs (``<host>_session_<timestamp>.jsonl``):

    <project>_<branch>_<timestamp>_<term>_<path>

e.g. ``results/password/files/acme_backend_api-service_main_20261117093000_password_config_settings.py``.
``/`` in the project and the file path become ``_``, so the name ends with the
original file name and extension. The timestamp is the run's start (UTC), the
same as in a default session name. Unsafe characters become ``_`` (safe on
Windows, macOS and Linux, a name can't escape its directory), long parts are
shortened (the file path keeps its end), and a name that is taken gets a
``~2``, ``~3`` … suffix before the extension.

Files are streamed to ``<name>.part`` and renamed when complete, so memory stays
constant and an interrupted download never looks like a finished file.
``--download-max-size`` skips larger files: by ``Content-Length`` before any
data is read, else as soon as the stream passes the limit.

The same file hit by another term is copied from the earlier download instead
of being requested again. That cache and the taken names grow with the number
of downloaded files (like the file-change cache), not with the instance size.

The downloader doesn't talk to GitLab itself: the engine passes a ``fetch``
callable that opens the streamed response, so this module only deals with
names, sizes and the file system.
"""

from __future__ import annotations

import re
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol

# Like the term names (glh/output.py): everything else becomes '_'.
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
# Part lengths; the whole name stays well below the 255-char limit of most file systems.
MAX_PROJECT_LEN = 50
MAX_BRANCH_LEN = 30
MAX_TERM_LEN = 30
MAX_PATH_LEN = 70
CHUNK_SIZE = 64 * 1024
PART_SUFFIX = ".part"

_SIZE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?)(?:i?b)?\s*$", re.IGNORECASE)
_UNITS = {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3, "t": 1024 ** 4}


def parse_size(value: str) -> int:
    """
    Parse a size: bytes or with a binary unit k/M/G/T (optional B/iB, any case):
    '1048576', '500k', '10M', '1.5G', '10MB', '10MiB'. 0 means no limit.

    Raises:
        ValueError: If the value is not a size.
    """
    m = _SIZE.match(value or "")
    if not m:
        raise ValueError(f"invalid size {value!r}")
    return int(float(m.group(1)) * _UNITS[m.group(2).lower()])


def format_size(size: int) -> str:
    """'512 B', '500 KiB', '10 MiB', '1.5 GiB'."""
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            text = f"{value:.1f}".rstrip("0").rstrip(".")
            return f"{text} {unit}"
        value /= 1024
    return f"{size} B"  # pragma: no cover


def _safe(text: str, limit: int, *, keep_end: bool = False, last: bool = False) -> str:
    """
    Filesystem-safe name part, at most ``limit`` chars (from the end with keep_end).

    Dots and '_' are trimmed from the ends, except a leading dot of the ``last``
    part (the file path, so ``.env`` stays ``.env``): only the name's end must
    not be a dot (Windows drops trailing dots).
    """
    safe = _UNSAFE.sub("_", str(text).strip())
    safe = safe.lstrip("_").rstrip("._") if last else safe.strip("._")
    if len(safe) > limit:
        safe = safe[-limit:].lstrip("_" if last else "._") if keep_end else safe[:limit].rstrip("._")
    return safe or "_"


def file_name(project: str, branch: str, stamp: str, term: str, path: str) -> str:
    """Base name of a downloaded file (before de-duplication), see the module doc."""
    return "_".join((
        _safe(project.replace("/", "_"), MAX_PROJECT_LEN, keep_end=True),
        _safe(branch, MAX_BRANCH_LEN),
        _safe(stamp, 20),
        _safe(term, MAX_TERM_LEN),
        _safe(path.replace("/", "_"), MAX_PATH_LEN, keep_end=True, last=True),
    ))


class FileTooLarge(Exception):
    """The file is larger than --download-max-size."""


class Layout(Protocol):
    """Where the files of a term go (glh.output.OutputLayout)."""

    def files_dir(self, term: str) -> Path: ...

    def describe_files(self) -> str: ...


class Response(Protocol):
    """What a download needs from a streamed HTTP response (requests.Response)."""

    headers: Any

    def iter_content(self, chunk_size: int) -> Iterable[bytes]: ...

    def close(self) -> None: ...


@dataclass(slots=True)
class DownloadStats:
    """Counters of a run's downloads."""

    saved: int = 0      # downloaded from GitLab
    copied: int = 0     # same file for another term: copied locally
    too_large: int = 0  # skipped by --download-max-size
    failed: int = 0     # API or file system error
    bytes: int = 0      # downloaded bytes (copies not counted)

    @property
    def files(self) -> int:
        return self.saved + self.copied


class FileDownloader:
    """
    Saves files with hits into the term directories; thread-safe (search workers call it).

    Args:
        layout: Gives the directory of each term's files (``files_dir``),
            created on the first download.
        stamp: Run timestamp for the names (``%Y%m%d%H%M%S``, UTC).
        max_size: Skip files larger than this many bytes; 0 = no limit.
    """

    def __init__(self, layout: Layout, stamp: str, *, max_size: int = 0) -> None:
        self.layout = layout
        self.stamp = stamp
        self.max_size = max(0, int(max_size))
        self.stats = DownloadStats()
        self._lock = threading.Lock()
        # Lower-case full paths (Windows/macOS file names are case-insensitive).
        self._taken: set[str] = set()
        self._saved: dict[tuple[Any, str, str], Path] = {}  # (project id, branch, path) -> first download

    def target(self) -> str:
        """'results/<term>/files (max 10 MiB each)' for the search plan."""
        limit = f"max {format_size(self.max_size)} each" if self.max_size else "no size limit"
        return f"{self.layout.describe_files()} ({limit})"

    def summary_lines(self) -> list[str]:
        """The summary() as separate facts: the files, then copies, skipped and failed ones."""
        s = self.stats
        lines = [f"{s.files} file{'s' if s.files != 1 else ''} ({format_size(s.bytes)}) in "
                 f"{self.layout.describe_files()}"]
        if s.copied:
            lines.append(f"{s.copied} copied locally (same file, another term)")
        if s.too_large:
            lines.append(f"{s.too_large} skipped: larger than {format_size(self.max_size)}")
        if s.failed:
            lines.append(f"{s.failed} FAILED (see the warnings)")
        return lines

    def describe(self) -> str:
        """'download files to results/<term>/files (max 10 MiB each)' for the search plan."""
        limit = f"max {format_size(self.max_size)} each" if self.max_size else "no size limit"
        return f"download files to {self.layout.describe_files()} ({limit})"

    def summary(self) -> str:
        """'3 files (12 KiB) downloaded to results/<term>/files, 1 skipped: larger than 10 MiB'."""
        s = self.stats
        text = (f"{s.files} file{'s' if s.files != 1 else ''} ({format_size(s.bytes)}) "
                f"downloaded to {self.layout.describe_files()}")
        if s.copied:
            text += f" ({s.copied} copied locally: same file, another term)"
        if s.too_large:
            text += f", {s.too_large} skipped: larger than {format_size(self.max_size)}"
        if s.failed:
            text += f", {s.failed} FAILED (see the warnings)"
        return text

    @staticmethod
    def _key(target: Path) -> str:
        return str(target).lower()

    def _reserve(self, folder: Path, base: str) -> Path:
        """A free path for ``base`` in ``folder`` (lock held): adds ~2, ~3 … before the extension if taken."""
        stem, dot, ext = base.rpartition(".")
        if not stem or stem.endswith("_"):  # no extension, or a dot file like ".env"
            stem, dot, ext = base, "", ""
        candidate, n = folder / base, 1
        while self._key(candidate) in self._taken or candidate.exists():
            n += 1
            candidate = folder / f"{stem}~{n}{dot}{ext}"
        self._taken.add(self._key(candidate))
        return candidate

    def _release(self, target: Path) -> None:
        with self._lock:
            self._taken.discard(self._key(target))

    def failed(self) -> None:
        """Count a download the caller couldn't make (API error)."""
        with self._lock:
            self.stats.failed += 1

    def save(
            self,
            *,
            project_id: Any,
            project_path: str,
            branch: str,
            term: str,
            path: str,
            fetch: Callable[[], Response],
    ) -> Path | None:
        """
        Save one file; ``fetch`` opens the streamed raw-file response.

        Returns:
            The local path, or None if the file is larger than ``max_size``.

        Raises:
            Whatever ``fetch`` or reading the stream raises (API/network
            errors), and OSError for file system errors; nothing is left on
            disk then and the caller should call ``failed()``.
        """
        key = (project_id, branch, path)
        base = file_name(project_path, branch, self.stamp, term, path)
        folder = self.layout.files_dir(term)
        with self._lock:
            earlier = self._saved.get(key)
            target = self._reserve(folder, base)
        folder.mkdir(parents=True, exist_ok=True)

        if earlier is not None and earlier.is_file():
            try:
                shutil.copyfile(earlier, target)
            except OSError:
                self._release(target)
                target.unlink(missing_ok=True)
                raise
            with self._lock:
                self.stats.copied += 1
            return target

        part = target.with_name(target.name + PART_SUFFIX)
        written = 0
        try:
            response = fetch()
            try:
                length = _content_length(response.headers)
                if self.max_size and length is not None and length > self.max_size:
                    raise FileTooLarge(length)
                with part.open("wb") as fp:
                    for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                        if not chunk:
                            continue
                        written += len(chunk)
                        if self.max_size and written > self.max_size:
                            raise FileTooLarge(None)
                        fp.write(chunk)
            finally:
                response.close()
            part.replace(target)
        except FileTooLarge:
            part.unlink(missing_ok=True)
            self._release(target)
            with self._lock:
                self.stats.too_large += 1
            return None
        except BaseException:
            part.unlink(missing_ok=True)
            self._release(target)
            raise

        with self._lock:
            self.stats.saved += 1
            self.stats.bytes += written
            self._saved.setdefault(key, target)
        return target


def _content_length(headers: Any) -> int | None:
    try:
        value = headers.get("Content-Length") if headers is not None else None
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
