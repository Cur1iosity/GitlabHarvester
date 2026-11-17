# Changelog

All notable changes to GitlabHarvester are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/).

## [1.4.3] - 2026-11-17

A technical release: the command line, the config file and every file format are
unchanged. The index and session files are byte-identical to the ones 1.4.2 writes.

### Changed

- **Data models.** The records of the project index and of the session file are
  defined once, as frozen slots dataclasses with `from_record()` (any version) and
  `to_record()` (this version, keys in file order):
  - `glh.domain.models`: `Project`, `IndexMeta`, `ProjectIndex`;
  - `glh.output.records`: `SessionMeta`, `ResumeRecord`, `HitRecord`,
    `ProjectResult`, `BranchResult`, `Hit`, `Checkpoint`, `SummaryRecord`, and
    `read_record()` for any session line.

  What it gives: one definition of each file format for its writers and
  readers (a field can no longer be written under one name and read under
  another), typed access instead of string keys in the engine, and less memory.
  See [docs/architecture.md](docs/architecture.md), "Data models".
- **Performance**, measured against 1.4.2 on an index of 30,000 projects with
  3 branches each:

  | | 1.4.2 | 1.4.3 |
  |---|---|---|
  | peak memory of the CLI process (index + plan) | 84 MB | 62 MB (−26%) |
  | the loaded index | 41.0 MB | 20.7 MB (−50%) |
  | planning a search (which projects and branches) | 0.044 s | 0.033 s (−25%) |
  | loading the index | 0.17 s | 0.26 s (+0.09 s) |

  Typed objects cost a little time to build. That is paid once per run, and
  half the memory is worth it on large instances. The search itself is as fast
  as before: its time goes to API requests. A full search of a
  1,000-project instance with 1 and 4 workers takes the same time within the
  noise.
- `GitlabHarvester` keeps its dict interface. `search_keywords`, `search_keyword`
  and `scan_project` take `Project` objects or index records. They and
  `scan_branch` return dicts, and so does `load_projects_from_file`.
- For code that imported modules below the facade:
  - the `glh.domain.planning` functions (`skip_reason`, `branches_to_scan`,
    `select_*`, `is_active_*`), `ProjectFilter.matches` and `ScanPlan.targets` work
    on `Project` (`build_scan_plan`, `is_fork_project` and `get_upstream_id` still
    take dicts too);
  - `SearchOutput.hit` / `checkpoint` and `SessionOutput.meta` / `resumed` /
    `summary` take the record objects;
  - `glh.output.session_reader.load_session_meta` returns a `SessionMeta`;
  - `glh.cli.report.index_rows` / `describe_index` take an `IndexMeta`.

### Added

- `GitlabHarvester.load_index()`: the index file as `IndexMeta` and `Project`
  objects.

### Fixed

- **Files by name without a term, `--file-listing auto`.** Once the search API had
  proven to take filter-only queries, a failed search of one branch (a timeout or
  a 5xx, typically on a very large repository) silently fell back to listing that
  repository's whole tree. On a monorepo that took hours, while the output still
  said the search was used. Now such a branch counts as a failed search: it is
  warned about, the run is not marked done, and `--resume` searches it again. The
  tree is only used while the search hasn't proven itself. A long-running task now
  says what it does: `Still listing the files (filename:*env) of group/repo @ main
  (45,000 tree entries)`, not `Still searching`.
- **The status line keeps its numbers in place.** The `HTTP 429 xN` counter was
  appended after the repository being searched, so it jumped left and right with
  the length of each name, and a narrow terminal cut it off. All the counters
  (hits, HTTP 429) now come before the repository name.

## [1.4.2] - 2026-11-17

A technical release: the command line, the config file and every file format
(index, session, results) are unchanged.

### Changed

- **Layered package.** `glh` is split into layers with a one-way dependency rule:
  `cli → limits → engine → {gitlab, output} → domain`, `postprocess → output`, and
  `ui` for all of them. `tests/unit/test_architecture.py` enforces the rule. Objects
  are made by one factory per layer: `ClientFactory` creates every python-gitlab
  client, `HarvesterFactory` builds a harvester from `HarvesterSettings`, and
  `glh.cli.factory` assembles a CLI run. `GitlabHarvester` is now a facade over
  `GitLabConnection`, `RateLimitMonitor`, `ProjectIndexer`, `SearchEngine` and
  `FileLister`. Its constructor and public methods are unchanged, and
  `GitlabHarvester.from_settings(HarvesterSettings(...))` is new. See
  [docs/architecture.md](docs/architecture.md), Part I.

  What it gives:
  - **One place for every client.** TLS verification, proxy, timeout,
    User-Agent and request pacing are the same for the main client, every
    worker thread and the rate-limit probe. A new client setting is added in
    one place.
  - **Replaceable parts.** Tests swap a part (`harvester.connection.use_client(stub)`)
    instead of patching private attributes, and the layer rule is a test.
  - **Smaller modules.** The largest module went from 2,014 lines
    (`harvester.py`) to under 600, and `docs/architecture.md` says where new code
    goes.

  It is a structural change only: speed and memory are the same as 1.4.1 within
  the noise. Measured on an index of 30,000 projects (loading 0.19 s vs 0.20 s,
  planning 0.05 s vs 0.06 s, peak memory of the CLI 84.5 MB vs 84.2 MB) and on a
  full search of a 1,000-project instance.
- **Module paths.** Only `from glh import GitlabHarvester, CliParser, __version__`
  is stable. Code that imported other modules needs the new paths:

  | 1.4.1 | 1.4.2 |
  |---|---|
  | `glh.harvester` | `glh.engine.harvester` (facade), split into `glh.engine.indexer`, `glh.engine.search`, `glh.engine.file_listing`, `glh.engine.file_checks`, `glh.gitlab.connection`, `glh.gitlab.factory`, `glh.gitlab.rate_monitor`; error helpers in `glh.gitlab.errors` |
  | `glh.cli` (module) | `glh.cli.parser` (`CliParser`), `glh.cli.args` (`CliArgs`), `glh.cli.values` (`parse_*`), `glh.cli.banner`, `glh.version`; `MAX_WORKERS` in `glh.engine.workers` |
  | `glh.modes` | `glh.cli.app` (`run_mode`), `glh.cli.commands.*` (one module per mode), `glh.cli.report`, `glh.cli.factory` |
  | `gitlab_harvester.main` | still importable; defined in `glh.cli.main` (`gitlab_harvester.py` is a thin wrapper) |
  | `glh.config`, `glh.tokens` | `glh.cli.config`, `glh.cli.tokens` |
  | `glh.planner` | `glh.domain.planning`, `glh.domain.timewindow` |
  | `glh.filefilter`, `glh.projectfilter` | `glh.domain.file_filter`, `glh.domain.project_filter` |
  | `glh.workers` | `glh.engine.workers` |
  | `glh.ratelimit`, `glh.user_agents` | `glh.gitlab.throttling`, `glh.gitlab.user_agents` |
  | `glh.limits` (module), `glh.autolimit` | `glh.limits` (package): `constants`, `headers`, `probe`, `recommend`, `finder`, `advisor`, `console` |
  | `glh.output` (module) | `glh.output.layout` (`OutputLayout`), `glh.output.sink` (`SearchOutput`, `SessionOutput`) |
  | `glh.session`, `glh.downloads`, `glh.archive` | `glh.output.session_reader`, `glh.output.downloads`, `glh.output.archive` |
  | `glh.utils.terminal_utils` | `glh.ui.statusline`, `glh.ui.progress`, `glh.ui.blocks`, `glh.ui.formatting`, `glh.ui.ansi` |
  | `glh.utils.logging_utils`, `glh.utils.keys` | `glh.ui.logs`, `glh.ui.journal`, `glh.ui.keys` |
  | `glh.postprocess.*` | unchanged |

- `docs/architecture.md` has a new Part I on the package architecture: layers,
  package map, core objects and factories, the path of a search, threads and rate
  limits, output and the run journal, and where new code goes. The Fake GitLab
  research and the API contract follow as Part II.

### Added

- `python -m glh` runs the command line, like `gitlab-harvester`.

### Removed

- `GitlabHarvester.probe_sender`, an internal of the rate-limit probe: the probe
  now builds its sender from `GitlabHarvester.unpaced_client()`. Private
  attributes such as `_gl` and `_active` are gone; use the parts
  (`harvester.connection.gl`, `harvester.active`).

## [1.4.1] - 2026-11-17

### Changed

- **Easier to read output**: the command as typed is echoed right after the banner
  (bold blue on a terminal; tokens as `<TOKEN>`, a proxy password as `***`), before any
  warning. The index, the search plan and the results of a run are blocks with one
  aligned `label  value` row per fact (skip reasons, download details and per-term
  files one per line) instead of comma-packed sentences; `-m find-limits`,
  `-m dump-index`, `-m dedup` and `-m convert` report the same way. The run journal
  gets each block as one greppable line (`Search plan: terms 2; projects 5 of 9; …`)
  and a new `Command:` line. `dedup`/`convert` no longer print from the library
  (`dedup_session_file` also returns `seen_db`).

### Fixed

- A wrong token or an unreachable URL ends the run with one clear line instead of a
  Python traceback: `The token failed to authenticate to <url> (HTTP 401 Unauthorized).
  Check the token and that it has the read_api scope.` (`Token #1 of N ...` with
  several tokens) or `Cannot reach <url> (...). Check the URL, the network and --proxy.`

## [1.4.0] - 2026-11-17

### Added

The rate-limit detection below (`-m find-limits`, `--auto-limits`, the `probe-*`
options) is **experimental**: its behavior, output and options may change in a
minor release. Runs that use it say so.

- **Find the API rate limits** (experimental): `-m find-limits` measures the limits of the token
  and prints the `--workers`, `--index-rpm` and `--search-rpm` to use, the command
  line (the token shown as `<TOKEN>`) and the config file keys. It reads GitLab's
  `RateLimit-*` headers when they are sent, else sends requests at a growing
  parallelism until HTTP 429; without `RateLimit-Limit` it waits for the window to
  reset and counts one full window from its start (the limit and the window
  length). No 429 within the default budget (search 60, other API 300 requests): it
  probes deeper, up to `--probe-max` (default 600), to find a higher limit or the
  real throughput, and notices when more threads stop helping. The suggestion keeps
  `--probe-margin` (default 0.85) below the limit, picks the workers from the
  measured latency, and splits the budget over tokens of the same user (GitLab
  counts most limits per user; tokens are grouped by their `GET /user` id).
- **`--auto-limits`** (experimental) measures before a search — only the search API when the
  project index exists, both when it has to be built — and asks on a terminal to
  apply the settings (elsewhere it prints the command and exits). Options set
  explicitly are kept; with all of them set nothing is measured. It then waits for
  the probed windows to reset and **watches the search**: after HTTP 429 it proposes
  a lower `--search-rpm`/`--index-rpm` per worker without stopping the scan — the
  question replaces the status line for 20 seconds, `Y` applies the new pace to every
  worker at once, `N` drops it, no answer leaves `[Limiter: L]` in the status line
  and `L` shows the proposal again. Without a terminal proposals are logged. The run
  ends with the limits to start the next run with.
- `-m dump-index --auto-limits` measures the other API only.
- **Every file by name, without a term**: `--filename`/`--extension` with no
  `-s`/`-f`/`terms` collect every matching file (one hit per file; downloaded with
  `--download-files`), e.g. all `*.env` files of the instance for offline analysis.
  The session term is the filter string (`filename:*.env`). `--file-listing` picks
  how the files of a branch are found: `search` (the search API with the filters
  only, for backends that take it), `tree` (the repository tree API: any GitLab) or
  `auto` (default: search, falling back to the tree per branch until the search has
  proven itself or rejected the query). New `file-listing` key in `config.example.ini`;
  the session `meta` has `files_only` and `file_listing`.
- **Search only some projects of the index**: `--project-filter PATTERNS`
  (comma-separated, case-insensitive) keeps the projects whose
  `group/subgroup/project` path contains a pattern (`k8s`) or matches a mask
  (`infra/*`, `*-k8s`). It filters the existing index at search time — no API
  requests for the others, the index stays complete — and the search plan counts
  them (`N not matching --project-filter …`). Stored in the session `meta`; `--resume`
  with another filter warns. New `project-filter` key in `config.example.ini`.
- **Index reuse tip**: while the project index is built, a turquoise line above the
  status line says how to reuse it next time (`--index-file …`; `--dump-projects`
  rebuilds) and disappears when the index is done. Shown on ANSI terminals only
  (VT mode is switched on in the Windows console); `NO_COLOR` keeps it plain.
- **All results in one archive**: `--to-zip` packs the results of a search run into
  `<session>.zip` next to the session, with the same layout inside — the session,
  the `--post-process` outputs, the `--output-separated` term files and the
  `--download-files` files (`<term>/files/…`). Only this session's files go in (the
  downloaded files are those its hits point to, earlier runs before `--resume`
  included), not the rest of `results/`. It runs last (with `--final-only`: the final
  file and the downloads), streams one file at a time (ZIP64), writes
  `<session>.zip.part` and renames it when complete, and keeps the original files.
  New `to-zip` key in `config.example.ini`; the session `meta` records `to_zip`.
- New options in `config.example.ini` (`[limits]`): `auto-limits`, `probe-apis`,
  `probe-max`, `probe-margin`. `workers` is empty there now (still 1 by default), so
  `--auto-limits` may choose it.
- Fake GitLab: per-user rate limits (`rate_limits` in a scenario,
  `FakeGitLab.set_rate_limits`, `/__admin/rate-limits`) with GitLab's 429 headers,
  and a `ratelimited` scenario.

### Changed

- HTTP 429 no longer floods the log: the first one of a run is a warning, the
  others are counted — `HTTP 429 xN` at the end of the status line (and the
  heartbeat lines off a terminal) and `Rate limit: N HTTP 429 responses, retried after
  … of waits in total` at the end of the run and in the run journal. With `--debug`
  the warning still repeats at most once a minute with the count so far. It points to
  `-m find-limits` (or says that `--auto-limits` will propose limits).

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
