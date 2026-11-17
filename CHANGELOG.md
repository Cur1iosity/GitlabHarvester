# Changelog

All notable changes to GitlabHarvester are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/).

## [1.3.0] - 2026-11-17

### Added

- **Search only in specific files**: `--filename PATTERN` and `--extension EXT`.
  `--filename` takes an exact file name, which may include the extension
  (`settings.py`, `.env`, `Dockerfile`), or a mask where `*` matches any characters
  (`*.env`, `config*`, `docker-compose*.yml`); a pattern with `/` matches the end of
  the path (`config/*.yml`). `--extension` drops the extra dots, so `py`, `.py` and
  `*.py` are the same. Both are case-insensitive and combine (a file must match
  both). GitLab does the filtering — the options become the code search
  `filename:`/`extension:` filters in the search string, so there are fewer result
  pages — and the harvester re-checks every result path, so the session holds only
  the files asked for even where GitLab is looser (basic search matches `filename:`
  against the end of the whole path) or ignores a filter. The term in the session
  stays as typed; the filters are recorded in the session `meta`, and `--resume`
  with other filters warns. With `--file-changed-*`, files outside the filter never
  cost a commits request.
- **Download the files with hits** for offline analysis: `--download-files` saves
  every file that produced a hit to `<term>/files/` next to the session
  (`results/<term>/files/` by default), named
  `<project>_<branch>_<timestamp>_<term>_<path>` (file-system-safe, the original
  file name and extension at the end, never overwriting an existing file). Every hit
  of a downloaded file gets a `"file"` key with the local path. Files are streamed
  (constant memory, no half-written files left behind), go through the same client,
  token, proxy, TLS settings and `--index-rpm` limit as the other requests, run in
  the search workers, and a file found by several terms is downloaded once and
  copied locally. A failed download is a one-line warning: the hits are kept and the
  term still counts as done. The run ends with a `Downloaded files: …` summary.
- **Size limit for downloads**: `--download-max-size SIZE` (default `10M`; bytes or
  `k`, `M`, `G`; `0` = no limit) skips big files — by `Content-Length` before any
  data is read, else as soon as the stream passes the limit.
- New options in `config.example.ini`: `filename`, `extension`, `download-files`,
  `download-max-size`.
- Use cases "Search only in specific files" and "Save the files with hits for deeper
  analysis" in `docs/USE_CASES.md`; `docs/usage.md` documents the filters, the
  downloads and the output layout.
- README: a "use cases at a glance" picture (`docs/assets/use-cases.svg`): the
  scenarios of `docs/USE_CASES.md` as branches with their main flags and what the
  shortcuts expand to. Regenerate it with `python docs/assets/make_use_cases_svg.py`.

### Changed

- **Per-term output directories.** `--output-separated` now writes each term's hits
  to `<dir>/<term>/<session>.jsonl` (was `<dir>/<session>.<term>.jsonl`), the same
  term directory that holds the term's downloaded `files/`:

  ```
  results/
    <host>_session_<ts>.jsonl          the session (every term, --resume)
    password/
      <host>_session_<ts>.jsonl        --output-separated
      files/                           --download-files
  ```

  The session file itself stays where it was. Scripts that read
  `<session>.<term>.jsonl` need the new path.
- **Output kept apart from the search engine.** A new module `glh/output.py` owns
  everything a run writes: `OutputLayout` (where the session, per-term files and
  downloads go), `SearchOutput` (the sink the engine hands hit records, checkpoints
  and files to) and `SessionOutput` (the session file with its `meta`, `resume` and
  `summary` records). `GitlabHarvester.search_keywords()` takes `output=` (the
  `session_file=` stream still works), so the engine can feed any sink.
- Fake GitLab: blob search parses the `filename:`, `path:` and `extension:` filters
  like GitLab basic search, and serves `GET /projects/:id/repository/files/:path/raw`.

**Compatibility:** Python 3.10–3.14. No new dependencies. Existing commands, config
files and sessions keep working; only the location of the `--output-separated` files
changed.

## [1.2.2] - 2026-11-13

### Added

- **Parallel scanning across several tokens** (`-t "a;b;c"` separated by `;`, or
  `--token-file FILE` with one token per line). The model is
  `token -> workers per token -> rpm per worker`: `--workers` counts per token, so
  the run keeps `tokens × workers` clients busy, each with its own server-side
  rate-limit budget — useful against an instance that rate-limits per user. Tasks
  share one queue, so the tokens load-balance themselves (one token stalling on a
  429 doesn't idle the rest). Every token is authenticated at start-up (a bad one
  aborts before any scanning), duplicates are dropped, and tokens are never written
  to logs, the session or the run journal — only their count.
- **Per-term output files** (`--output-separated`): with several search terms, each
  term's hits are also written to `<session>.<term>.jsonl` next to the session, so a
  single kind of finding can be triaged on its own. The full session is still
  written; the per-term files are an extra view of it, each a valid session-hit file
  that `-m dedup` / `-m convert` accept. Only terms with hits get a file; the split
  covers `--resume` and runs before `--final-only`. Term names are sanitised for the
  file system (safe on Windows, macOS and Linux) and cannot escape the session's
  directory.

### Fixed

- **Quieter failures.** When a project can't be fetched (unreachable project, GitLab
  500, timeout), the log no longer dumps the server's whole HTML error page. By
  default it prints one concise line — `Could not search <url> @ <branch> (HTTP 500
  Internal Server Error); skipping it, continuing` — and the scan continues. The full
  error (body included) is logged only with `--debug`, and the session's
  `keyword_incomplete` `failures` entries use the same short form. Retryable failures
  still keep the term out of the `keyword_done` checkpoint, so `--resume` searches
  them again.

### Changed

- Richer README demo dataset (~100 projects, hundreds of hits) for a more
  representative recording.
- Documentation: multi-token usage, a Red Team use case for several tokens, and
  architecture notes (`docs/usage.md`, `docs/USE_CASES.md`, `docs/architecture.md`).

**Compatibility:** Python 3.10–3.14. No breaking changes; existing commands, config
files and sessions keep working.

## [1.1.0]

### Added

- Fixed or random **User-Agent** for every request: `-A/--user-agent STRING` or
  `--user-agent-file FILE` (one per line, chosen at random).
- Random per-request delay: `--jitter MIN-MAX` (seconds or `ms`), on top of the rpm
  spacing, so requests don't come at a fixed rhythm.
- Per-worker request **rate limits**: `--rpm`, `--index-rpm`, `--search-rpm`
  (search is limited separately from the rest of the API).

## [1.0.0]

### Changed

- **Explicit TLS verification.** Certificates are always verified; there is no silent
  fallback to an unverified connection. Use `--ca-bundle FILE` for a private CA, or
  `--insecure` to opt out (warned on every run).

### Fixed

- **Resumable failed terms.** A term whose searches failed is recorded as
  `keyword_incomplete` instead of `keyword_done`, so `--resume` searches it again
  rather than skipping it.
