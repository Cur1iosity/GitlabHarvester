# glh/limits/recommend.py
"""
Settings recommended from probe results, and the command line to run them.
"""

from __future__ import annotations

import math
import shlex
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

from glh.limits.constants import DEFAULT_MARGIN, INDEX, KINDS, SEARCH
from glh.limits.probe import ProbeResult
from glh.ui.formatting import format_duration

# --------------------------------------------------------------------------- recommendation


@dataclass(frozen=True, slots=True)
class Settings:
    """Concurrency and pacing of a run: --workers (per token), --index-rpm, --search-rpm (per worker)."""

    workers: int = 1
    index_rpm: int = 0
    search_rpm: int = 0

    def rpm(self, kind: str) -> int:
        return self.index_rpm if kind == INDEX else self.search_rpm


@dataclass(slots=True)
class Recommendation:
    """Suggested --workers / --index-rpm / --search-rpm and why."""

    workers: int
    index_rpm: int
    search_rpm: int
    notes: list[str] = field(default_factory=list)
    kept: tuple[str, ...] = ()  # options set explicitly and left as they are

    @property
    def settings(self) -> Settings:
        return Settings(self.workers, self.index_rpm, self.search_rpm)

    def differs_from(self, current: Settings) -> bool:
        return self.settings != current

    def flags(self) -> list[str]:
        return ["--workers", str(self.workers), "--index-rpm", str(self.index_rpm),
                "--search-rpm", str(self.search_rpm)]

    def describe(self) -> str:
        def rpm(value: int) -> str:
            return str(value) if value else "0 (no limit)"
        kept = f" (kept as set: {', '.join(self.kept)})" if self.kept else ""
        return (f"--workers {self.workers} --index-rpm {rpm(self.index_rpm)} "
                f"--search-rpm {rpm(self.search_rpm)}{kept}")

    def ini(self) -> str:
        return (f"workers = {self.workers}\n"
                f"index-rpm = {self.index_rpm}\n"
                f"search-rpm = {self.search_rpm}")

    def command(self, argv: Sequence[str], *, prog: str = "gitlab-harvester", auto_limits: bool = True) -> str:
        """The command line to run: ``argv`` without its limit options, plus :meth:`flags`."""
        args = strip_limit_options(argv)
        if auto_limits and "--auto-limits" not in args:
            args.append("--auto-limits")
        return shlex.join([prog, *args, *self.flags()])


def recommend(
        results: Mapping[str, ProbeResult],
        *,
        current: Settings,
        explicit: Iterable[str] = (),
        tokens_per_user: int = 1,
        margin: float = DEFAULT_MARGIN,
        max_workers: int = 64,
) -> Recommendation:
    """
    Turn probe results into settings.

    Per probed API the target is ``margin`` x the limit (or x the measured
    throughput when no limit was found) for all threads of one user together:
    ``workers x tokens_per_user`` threads share it. Workers are as many as
    needed to reach the target at the measured latency; options named in
    ``explicit`` (``workers``, ``index_rpm``, ``search_rpm``) are kept.
    """
    explicit = set(explicit)
    tpu = max(1, int(tokens_per_user))
    notes: list[str] = []
    targets: dict[str, int] = {}
    for kind, r in results.items():
        if r.source == "error":
            notes.append(f"{r.api}: not measured ({r.error}); its setting is left as it is.")
            continue
        if r.limit_rpm is not None:
            targets[kind] = max(1, math.floor(r.limit_rpm * margin))
        elif r.peak_rpm > 0:
            targets[kind] = max(1, math.floor(r.peak_rpm * margin))
            notes.append(f"{r.api}: no GitLab limit found; the pace is set to {margin:.0%} of the measured "
                         f"throughput (~{r.peak_rpm:,.0f} req/min) to keep the load reasonable.")
        elif r.source == "429":
            notes.append(f"{r.api}: rate limited before anything could be measured; probe again later "
                         f"(after {format_duration(r.cooldown)}).")

    if "workers" in explicit:
        workers = current.workers
    else:
        needs = []
        for kind, target in targets.items():
            r = results[kind]
            threads = max(1, math.ceil(target * max(r.latency, 0.01) / 60.0))
            if r.saturated:
                threads = min(threads, max(1, r.peak_concurrency))
            needs.append(math.ceil(threads / tpu))
        workers = min(max(needs, default=current.workers), max_workers)
        # Per-worker rpm is an integer: don't spread a small budget over so many
        # threads that rounding down wastes more than a fifth of it.
        for target in targets.values():
            while workers > 1 and (target // (workers * tpu)) * workers * tpu < 0.8 * target:
                workers -= 1
        workers = max(1, workers)

    threads = workers * tpu
    rpm: dict[str, int] = {}
    kept = ["workers"] if "workers" in explicit else []
    for kind in KINDS:
        dest = f"{kind}_rpm"
        value = current.rpm(kind)
        if dest in explicit:
            kept.append(dest.replace("_", "-"))
            rpm[kind] = value
            r = results.get(kind)
            if r is not None and r.limit_rpm is not None and (value == 0 or value * threads > r.limit_rpm):
                total = "no limit" if value == 0 else f"{value * threads:,} req/min"
                notes.append(f"--{kind}-rpm {value} is kept as set, but {threads} threads per user send "
                             f"{total}, above the limit (~{r.limit_rpm:,.0f}/min): expect HTTP 429 waits.")
        elif kind in targets:
            rpm[kind] = max(1, targets[kind] // threads)
        else:
            rpm[kind] = value
    if tpu > 1:
        notes.append(f"{tpu} tokens belong to the same user and share one budget; "
                     f"the per-worker rates account for it ({workers} workers x {tpu} tokens).")
    return Recommendation(workers=workers, index_rpm=rpm[INDEX], search_rpm=rpm[SEARCH],
                          notes=notes, kept=tuple(kept))

# --------------------------------------------------------------------------- command line

# Options (flag -> takes a value) dropped from a command line before the
# recommended ones are added; --mode only when it is find-limits.
_LIMIT_OPTIONS: dict[str, bool] = {
    "-w": True, "--workers": True, "--rpm": True, "--index-rpm": True, "--search-rpm": True,
    "--probe-apis": True, "--probe-max": True, "--probe-margin": True,
}

_TOKEN_OPTIONS = ("-t", "--token")

TOKEN_PLACEHOLDER = "<TOKEN>"


def strip_limit_options(argv: Sequence[str]) -> list[str]:
    """
    ``argv`` without limit/probe options and ``-m find-limits``; tokens are
    replaced by :data:`TOKEN_PLACEHOLDER` (a printed command must not show them).
    """
    out: list[str] = []
    args = list(argv)
    i = 0
    while i < len(args):
        arg = args[i]
        name, eq, value = arg.partition("=")
        nxt = args[i + 1] if i + 1 < len(args) else None
        if name in _LIMIT_OPTIONS:
            i += 1 if eq else 2
            continue
        if name in ("-m", "--mode"):
            mode = value if eq else nxt
            if mode == "find-limits":
                i += 1 if eq else 2
                continue
        if name in _TOKEN_OPTIONS:
            out += [name, TOKEN_PLACEHOLDER]
            i += 1 if eq else 2
            continue
        if arg.startswith("-t") and not arg.startswith("--") and len(arg) > 2:
            out += ["-t", TOKEN_PLACEHOLDER]  # -tTOKEN
            i += 1
            continue
        if arg.startswith("-w") and not arg.startswith("--") and len(arg) > 2 and arg[2:].isdigit():
            i += 1  # -w4
            continue
        out.append(arg)
        i += 1
    return out
