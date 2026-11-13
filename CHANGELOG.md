# Changelog

All notable changes to GitlabHarvester are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/).

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
