# glh/postprocess/pipeline.py
"""
Post-processing chain run after a search (``--post-process dedup,convert``).

Steps always run in the order dedup -> convert (convert produces a JSON array,
which dedup cannot read). Output names extend the session name:

    audit.jsonl -> audit.deduped.jsonl -> audit.deduped.converted.json
    audit.jsonl -> audit.converted.json                  (convert only)

With ``final_only`` the session JSONL and the intermediate files are deleted
once every step has succeeded, so only the last file remains.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from glh.postprocess.convert import convert_jsonl_to_json
from glh.postprocess.dedup import dedup_session_file

STEP_DEDUP = "dedup"
STEP_CONVERT = "convert"
STEPS: tuple[str, ...] = (STEP_DEDUP, STEP_CONVERT)  # canonical order


def normalize_steps(value: str) -> tuple[str, ...]:
    """
    Parse 'dedup,convert' into the canonical, de-duplicated step order.

    Raises:
        ValueError: On an empty list or an unknown step.
    """
    requested = {part.strip().lower() for part in value.split(",") if part.strip()}
    if not requested:
        raise ValueError("no post-processing step given")
    unknown = requested - set(STEPS)
    if unknown:
        raise ValueError(f"unknown post-processing step(s): {', '.join(sorted(unknown))}")
    return tuple(s for s in STEPS if s in requested)


def _base_name(session_path: Path) -> str:
    """'audit.jsonl' -> 'audit' (other names are kept whole)."""
    name = session_path.name
    return name[: -len(".jsonl")] if name.endswith(".jsonl") else name


def _remove(path: Path) -> None:
    """Delete a file and SQLite side files, ignoring missing ones."""
    for p in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass


@dataclass
class PipelineResult:
    """Files produced (in order) and files removed by the chain."""

    outputs: list[Path] = field(default_factory=list)
    removed: list[Path] = field(default_factory=list)
    # One human-readable line per step, e.g. "dedup: a.jsonl -> a.deduped.jsonl (kept 7, dropped 2)".
    notes: list[str] = field(default_factory=list)

    @property
    def final(self) -> Path | None:
        """The last produced file."""
        return self.outputs[-1] if self.outputs else None


def run_pipeline(
        session_path: Path,
        steps: tuple[str, ...],
        *,
        final_only: bool = False,
        sqlite_path: Path | None = None,
        hash_algo: str = "blake2b",
        normalize: bool = True,
        sort_keys: bool = False,
) -> PipelineResult:
    """
    Apply ``steps`` to a finished session file.

    Args:
        session_path: Session JSONL written by the search.
        steps: Steps from normalize_steps().
        final_only: Delete the session file and intermediate outputs at the end.
        sqlite_path: dedup seen-hash store; default: a temporary file next to the
            output that is deleted afterwards. A given path is kept.
        hash_algo: dedup hash algorithm.
        normalize: dedup whitespace normalization.
        sort_keys: convert: sort JSON keys.

    Returns:
        PipelineResult. If a step raises, nothing is deleted and the error propagates.
    """
    result = PipelineResult()
    current = session_path
    base = _base_name(session_path)
    directory = session_path.parent

    for step in normalize_steps(",".join(steps)):
        if step == STEP_DEDUP:
            base += ".deduped"
            output = directory / f"{base}.jsonl"
            store = sqlite_path or directory / f"{base}.jsonl.seen.sqlite"
            try:
                stats = dedup_session_file(input_path=current, output_path=output, sqlite_path=store,
                                           hash_algo=hash_algo, normalize=normalize)
            finally:
                if sqlite_path is None:
                    _remove(store)
            result.notes.append(f"dedup: {current} -> {output} (kept {stats['kept']} records, "
                                f"dropped {stats['dropped']} duplicate-only hit records)")
        else:
            output = directory / f"{base}.converted.json"
            count = convert_jsonl_to_json(input_path=current, output_path=output, sort_keys=sort_keys)
            result.notes.append(f"convert: {current} -> {output} ({count} objects)")
        result.outputs.append(output)
        current = output

    if final_only and result.outputs:
        for path in [session_path, *result.outputs[:-1]]:
            _remove(path)
            result.removed.append(path)
    return result
