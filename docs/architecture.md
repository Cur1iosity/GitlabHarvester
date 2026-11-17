# Architecture

How GitlabHarvester is built. **Part I** describes the `glh` package: its layers, the
objects of a run and how a search flows through them. **Part II** records why the
test environment (the Fake GitLab) looks the way it does, and the GitLab API contract
the harvester relies on. For day-to-day use of the test environment see
[testing.md](testing.md); for the command line see [usage.md](usage.md).

**Part I. Package architecture**

- [1. Layers and the dependency rule](#1-layers-and-the-dependency-rule)
- [2. Package map](#2-package-map)
- [3. Core objects and factories](#3-core-objects-and-factories)
- [4. Data models](#4-data-models)
- [5. A search, from the command line to the session file](#5-a-search-from-the-command-line-to-the-session-file)
- [6. Threads, tokens and rate limits](#6-threads-tokens-and-rate-limits)
- [7. Output, progress and the run journal](#7-output-progress-and-the-run-journal)
- [8. Where new code goes](#8-where-new-code-goes)

**Part II. Fake GitLab: research, design and API contract**

- [9. Goals](#9-goals)
- [10. Survey of existing tools](#10-survey-of-existing-tools)
- [11. Decision](#11-decision)
- [12. Test environment](#12-test-environment)
- [13. GitLab API contract used by GitlabHarvester](#13-gitlab-api-contract-used-by-gitlabharvester)
- [14. Defects found while building the environment](#14-defects-found-while-building-the-environment)
- [15. Known limitations of the emulation](#15-known-limitations-of-the-emulation)

## Part I. Package architecture

### 1. Layers and the dependency rule

The package is split into layers. A layer may import only from itself and from the
layers its arrows point to:

```
 ┌──────────────────────────────── cli ─────────────────────────────────┐
 │ main → app.run_mode → commands/*        factory: builds every object │
 └──────┬──────────────────────┬─────────────────────────────┬──────────┘
        ▼                      │                             │
 ┌── limits ──┐                │                             │
 │experimental│                │                             │
 └─────┬──────┘                │                             │
       ▼                       ▼                             ▼
 ┌─────────────────── engine ──────────────────┐    ┌── postprocess ──┐
 │ GitlabHarvester (facade), HarvesterFactory, │    │ dedup, convert, │
 │ ProjectIndexer, SearchEngine, workers       │    │ split, pipeline │
 └────────┬─────────────────────────┬──────────┘    └────────┬────────┘
          ▼                         ▼                        │
 ┌─────── gitlab ───────┐   ┌────── output ──────┐◄──────────┘
 │ clients, connection, │   │ paths, session,    │
 │ pacing, 429, errors  │   │ downloads, archive │
 └──────────┬───────────┘   └─────────┬──────────┘
            ▼                         ▼
 ┌──────────────────────── domain ─────────────────────────┐
 │ scan planning, time windows, file and project filters   │
 └─────────────────────────────────────────────────────────┘

 ui, exceptions, version: used by every layer, import nothing else from glh
```

| Layer | Holds | May import |
|---|---|---|
| `cli` | the command line: options, config file, the command of each mode, reports, the composition root | every layer |
| `limits` | experimental rate-limit detection (`-m find-limits`, `--auto-limits`) | `engine`, `gitlab`, `domain` |
| `engine` | the work of a run: project index, search, worker pool, the `GitlabHarvester` facade | `gitlab`, `output`, `domain` |
| `gitlab` | everything that talks to the GitLab API: clients, connection, pacing, HTTP 429, errors | `domain` |
| `output` | where results go: paths, session sink, downloaded files, ZIP archive, reading a session back | `domain` |
| `postprocess` | dedup, convert and the per-term split of finished session files | `output` |
| `domain` | pure rules: no GitLab, no files, no terminal | — |
| `ui` | console output without third-party dependencies: status line, progress, blocks, logs, run journal | — |

`ui`, `exceptions` and `version` are available to every layer. The rule is enforced
by `tests/unit/test_architecture.py`. It parses every module and counts every import,
including imports inside functions and under `TYPE_CHECKING`. It also fails on a
relative import, and on a new subpackage that has no entry in its table.

Only `from glh import GitlabHarvester, CliParser, __version__`, the command line and
the file formats are stable between releases. Modules may move (1.4.2 moved all of
them, see [CHANGELOG](../CHANGELOG.md)).

### 2. Package map

```
gitlab_harvester.py       the gitlab-harvester command (top-level module) → glh.cli.main.main
glh/
├── __init__.py           public API: GitlabHarvester, CliParser, __version__
├── __main__.py           python -m glh
├── version.py            installed version (importlib.metadata)
├── exceptions.py         GitlabHarvesterError
├── cli/
│   ├── main.py           entry point: signal handlers, banner, echoed command (token masked)
│   ├── app.py            run_mode: run journal, dispatch by mode
│   ├── parser.py         CliParser: argparse, config file, group shortcuts, defaults
│   ├── args.py           CliArgs: the resolved options of a run
│   ├── values.py         value converters (argparse type= functions, shared with the config file)
│   ├── config.py         INI file (-c/--config)
│   ├── tokens.py         -t "a;b", --token-file, masking tokens in command lines
│   ├── banner.py         the banner
│   ├── report.py         Summary and the result blocks printed at the end of a run
│   ├── factory.py        composition root: harvester, scan options, run output, limit finder/watch
│   └── commands/         search, dump_index, find_limits, postprocess (one per mode),
│                         auto_limits (--auto-limits around a run), common (paths, terms)
├── limits/               EXPERIMENTAL
│   ├── constants.py      API names, probe budgets, defaults
│   ├── headers.py        RateLimit-* and Retry-After
│   ├── probe.py          LimitProbe: the limit of one API, by load
│   ├── recommend.py      Settings, Recommendation, the next command line and config lines
│   ├── finder.py         LimitFinder: probes the APIs through unpaced clients
│   ├── advisor.py        LimitAdvisor: watches every response of a run (--auto-limits)
│   └── console.py        LimiterConsole: non-blocking prompt, L key, [Limiter] badge
├── engine/
│   ├── harvester.py      GitlabHarvester: the facade
│   ├── factory.py        HarvesterSettings, HarvesterFactory, HarvesterParts
│   ├── indexer.py        ProjectIndexer: build, enrich and load the project index
│   ├── search.py         SearchEngine: term search over a scan plan
│   ├── tasks.py          BranchTask: one (term, project, branch)
│   ├── file_listing.py   FileLister: files-only mode (search / tree / auto)
│   ├── file_checks.py    FileChangeChecker (--file-changed-*), FileFetcher (--download-files)
│   └── workers.py        thread pool (imap_ordered, imap_unordered), ActiveTasks, MAX_WORKERS
├── gitlab/
│   ├── settings.py       ClientSettings (fixed for a run), Pacing (changeable)
│   ├── factory.py        ClientFactory: every python-gitlab client
│   ├── connection.py     GitLabConnection: authenticated clients of a run
│   ├── rate_monitor.py   RateLimitMonitor: the response hook (HTTP 429 accounting)
│   ├── throttling.py     RateLimiter, ThrottledAdapter, jitter
│   ├── user_agents.py    -A / --user-agent-file
│   └── errors.py         permanent or retryable, one-line descriptions
├── output/
│   ├── records.py        session records: SessionMeta, HitRecord, Checkpoint, SummaryRecord, …
│   ├── layout.py         OutputLayout: every path of a run
│   ├── sink.py           SearchOutput, SessionOutput
│   ├── session_reader.py done terms and meta of a session (--resume)
│   ├── downloads.py      FileDownloader
│   └── archive.py        --to-zip
├── postprocess/          dedup, convert, split (--output-separated), pipeline (--post-process)
├── domain/
│   ├── models.py         index records: Project, IndexMeta, ProjectIndex
│   ├── planning.py       ScanOptions, ScanPlan, build_scan_plan, skip reasons, branch selection
│   ├── timewindow.py     TimeWindow and timestamps
│   ├── file_filter.py    FileFilter (--filename, --extension)
│   └── project_filter.py ProjectFilter (--project-filter)
└── ui/
    ├── statusline.py     StatusLine and its singleton STATUS
    ├── progress.py       Progress of one phase
    ├── blocks.py         format_block, compact_block
    ├── formatting.py     counts, durations, terminal widths
    ├── ansi.py           colors, styles, Windows VT mode
    ├── keys.py           key presses without Enter
    ├── logs.py           ConsoleHandler, build_logger
    ├── journal.py        RunJournal and its singleton JOURNAL
    └── dont_be_boring.py and remember: --dont-be-boring
```

### 3. Core objects and factories

Objects are created by factories, one per layer, next to what they build:

- `glh.gitlab.factory.ClientFactory` creates every python-gitlab client: the main one,
  one per worker thread, the start-up check of every extra token, and the unpaced
  clients of the rate-limit probe. All of them share the URL, timeout, TLS
  verification, proxy and User-Agent. Every paced client also gets its own
  `requests.Session`, a `ThrottledAdapter` and the response hook.
- `glh.engine.factory.HarvesterFactory` turns one `HarvesterSettings` into the wired
  parts of a harvester (`HarvesterParts`).
- `glh.cli.factory` is the composition root of a CLI run. It turns the options
  (`CliArgs`) into the harvester, the scan options, the run output and the session
  sink, and the rate-limit finder and watch. The commands use these objects and
  never assemble them.

There is one factory per layer rather than a shared `factories` package: the public
`GitlabHarvester(...)` constructor uses the engine factory, so such a package would
import the engine and be imported by it.

What `HarvesterFactory.build()` wires together:

```
HarvesterSettings ──► logger
                      RateLimitMonitor ──on_response──┐
                      ClientFactory ◄─────────────────┘   ClientSettings + Pacing
                      GitLabConnection(ClientFactory)     tokens, workers; connect() authenticates
                      ActiveTasks ◄──on_wait── RateLimitMonitor
                      FileChangeChecker, FileFetcher, FileLister
                      ProjectIndexer(connection)
                      SearchEngine(connection, active, checks, fetcher, lister)
```

| Object | Module | Responsibility |
|---|---|---|
| `GitlabHarvester` | `engine/harvester.py` | Facade and public API. Its constructor keeps the 1.x signature and builds `HarvesterSettings`; `GitlabHarvester.from_settings(settings)` takes them directly. Exposes the parts (`connection`, `clients`, `monitor`, `active`, `indexer`, `search`) and delegates the 1.x methods and properties to them |
| `GitLabConnection` | `gitlab/connection.py` | The authenticated main client and the per-thread worker clients (`gl` is the calling thread's client), token round-robin, the GitLab user of every token, instance id, raw-file requests |
| `ClientFactory` | `gitlab/factory.py` | Client creation, the pacing of all clients at once (`set_pacing`) |
| `RateLimitMonitor` | `gitlab/rate_monitor.py` | HTTP 429 counting and warnings, waits reported to `ActiveTasks`, every response handed to an observer (`LimitAdvisor`) |
| `ProjectIndexer` | `engine/indexer.py` | `/projects` listing, branch enrichment and loading of the index file |
| `SearchEngine` | `engine/search.py` | Scan plan, `BranchTask`s on the worker pool, merging branch results into session records, checkpoints, the search's progress |
| `FileLister` | `engine/file_listing.py` | Files-only mode: files by search or repository tree, `--file-listing auto` state |
| `FileChangeChecker`, `FileFetcher` | `engine/file_checks.py` | `--file-changed-*` (cached commit queries), `--download-files` through the thread's client |
| `ActiveTasks` | `engine/workers.py` | What every thread is searching right now (status line, slow-task notes) |
| `LimitFinder`, `LimitAdvisor`, `LimiterConsole` | `limits/` | Probe, runtime advice and its prompt (experimental) |
| `OutputLayout`, `SessionOutput`, `FileDownloader` | `output/` | Paths, session records, downloaded files |
| `ScanOptions`, `ScanPlan` | `domain/planning.py` | Which projects and branches a search covers, and why the others are skipped |

Tests replace a part instead of patching private attributes. For example,
`harvester.connection.use_client(stub)` injects a client, a test can patch
`SearchEngine.search_branch`, and `harvester.clients.create` can be wrapped to see
every client that is made.

### 4. Data models

The files a run reads and writes are defined once, as frozen slots dataclasses:

| File | Record | Model | Module |
|---|---|---|---|
| index | first line (`"type": "meta"`) | `IndexMeta` | `domain/models.py` |
| index | one line per project | `Project` | `domain/models.py` |
| session | `meta` | `SessionMeta` (built by `cli.factory.session_meta`) | `output/records.py` |
| session | `resume` | `ResumeRecord` | `output/records.py` |
| session | `{"term", "result"}` | `HitRecord` → `ProjectResult` → `BranchResult` → `Hit` | `output/records.py` |
| session | `keyword_done`, `keyword_incomplete` | `Checkpoint` | `output/records.py` |
| session | `summary` | `SummaryRecord` | `output/records.py` |

- **`to_record()`** gives the record this version writes, with the keys in file
  order. The files are byte-identical to the ones earlier versions wrote:
  `tests/unit/test_models.py` and `test_records.py` round-trip records of the
  1.4.2 writer, and `tests/e2e/test_session_format.py` round-trips every line of
  a real session and index.
- **`from_record()`** reads a record of any version. Missing keys get defaults,
  old forms are understood (`upstream_project_id`, the `keyword` of old
  checkpoints), and a malformed part is skipped instead of raising. The one
  exception is a project without an id: `Project.from_record` raises
  `ValueError`, and `load_index` skips such a line with a warning.
  `records.read_record()` picks the model of any session line.
- **Read through a model, rewrite as a dict.** Adding branches to an existing
  index appends them to the raw records, so keys this version doesn't know
  survive. dedup, convert and the per-term split stream the session as dicts
  for the same reason: they pass through records of any version unchanged.
- **RAM and speed.** The engine works on `Project`. An index of 30,000
  projects with 3 branches each takes 41.0 MB of RAM as dicts and 20.7 MB as
  `Project` objects (`ProjectIndexer.load_index`). The CLI process peaks at 62 MB
  of RAM instead of 84 MB, and planning a search is about 25% faster. Loading costs about 0.09 s
  more, because `Project.from_record` runs once per line and is kept lean for that
  reason. See the CHANGELOG of 1.4.3 for the measurements.
- **RAM doesn't grow with the hits.** A project's hits are held in RAM until all its
  branches are searched (the session has one record per project), then written;
  the CLI calls `search_keywords(..., keep_results=False)`, so nothing of them
  stays. RAM is bounded by the projects being searched at the moment (about
  `--workers` of them), not by the run: with 300,000 hits the process peaks at
  47 MB of RAM, as with 150,000 (1.4.3: 206 MB and 125 MB); the session file on
  disk (59 MB for 300,000 hits) is the same either way. The facade keeps returning every hit by default.
- **Dicts at the facade.** `GitlabHarvester` keeps its dict interface:
  - `search_keywords` and `scan_project` take Projects or index records;
  - they and `scan_branch` return dicts;
  - `load_projects_from_file` returns dicts;
  - `load_index` returns the models.
- **No pydantic.** It would add a binary runtime dependency (see the Debian/Kali
  packaging rules in [packaging.md](packaging.md)) and more memory per object.
  There is nothing untrusted to validate: the records come from this program or
  from python-gitlab.

### 5. A search, from the command line to the session file

1. `gitlab_harvester.py` calls `glh.cli.main.main`. It installs the SIGINT/SIGTERM
   handlers (exit codes 130/143), prints the banner and the echoed command (token
   masked) on stderr, and parses the options with `CliParser` into `CliArgs`
   (CLI > config file > defaults).
2. `glh.cli.app.run_mode` opens the run journal (`--log-file`), writes the start,
   command and options, and dispatches by mode. At the end it writes
   `Run finished` / `Run failed`.
3. `commands/search.run_search` gets the harvester from
   `cli.factory.create_harvester`: `HarvesterSettings` → `GitlabHarvester.from_settings`
   → `HarvesterFactory.build`, and `GitLabConnection.connect()` authenticates every
   token. A failure ends the run with one line (exit code 1). The terms come from
   `-s`, `-f` or the config file. With no term but with `--filename`/`--extension`,
   the run is in files-only mode and its term is the filter string.
4. With `--auto-limits`, `commands/auto_limits` runs the `LimitFinder` probe, offers
   the settings (`GitlabHarvester.set_rate_limits` applies them), then lets a
   `LimitAdvisor` and its `LimiterConsole` watch the run.
5. `ProjectIndexer.build_project_index` reuses or builds the index while the status
   line shows the tip about reusing it. `load_index` reads it as `IndexMeta` and
   `Project` objects, and it is shown as the `Index` block.
6. `cli.factory` makes the `ScanOptions`, the run output (`OutputLayout`,
   `FileDownloader`) and the session sink. `--resume` reads the terms already done
   (`output.session_reader`). `SessionOutput` writes the `meta` record
   (`SessionMeta`, from `cli.factory.session_meta`), or `resume` when resuming.
7. `SearchEngine.search_keywords` builds the scan plan (`domain.planning.build_scan_plan`)
   and shows it as the `Search plan` block. Then it queues one `BranchTask` per
   (term, project, branch) on `workers.imap_unordered`:
   - a worker thread runs `SearchEngine.search_branch`:
     - for a term, `scan_branch` fetches the blob search pages, keeps paths that
       pass `FileFilter` and `FileChangeChecker`, and lets `FileFetcher` download
       the files with hits;
     - in files-only mode, `FileLister.collect` lists the files instead;
   - the main thread merges the branches of a project into one `ProjectResult`
     (`SearchOutput.hit`) and writes a `Checkpoint` (`keyword_done` or
     `keyword_incomplete`) in term order (`SearchOutput.checkpoint`, flushed). It
     also keeps the progress.
8. After the search, `SessionOutput` writes the `summary` record. Then, in order:
   - `--output-separated` splits the session by term (`postprocess.split`);
   - `--post-process` runs `postprocess.pipeline` (dedup, convert);
   - `--to-zip` packs the run's own files (`output.archive`);
   - `cli.report.Summary` prints the `Results` block.

### 6. Threads, tokens and rate limits

- **One writer.** Worker threads only make HTTP requests. Downloaded files are the
  exception: workers write them through the thread-safe `FileDownloader`. The main
  thread alone writes the session, counters, progress and status line.
- **Concurrency.** It is `tokens × workers` (`GitLabConnection.concurrency`).
  `GitLabConnection.init_worker_client` is the pool initializer: each thread gets its
  own client from `ClientFactory.create`, bound to the next token round-robin, so
  every token has `workers` threads and its own rate-limit budget. With concurrency 1
  the tasks run inline, with no threads, exactly like a sequential scan.
- **Order.** The index listing and branch enrichment use `imap_ordered`, so the index
  keeps its order. The search uses `imap_unordered`, and checkpoints still follow the
  term order.
- **Pacing.** Each client paces its own requests with a `ThrottledAdapter`:
  `--search-rpm` for `…/search` requests, `--index-rpm` for all others, plus
  `--jitter`; the same adapter sets the User-Agent. Pacing is therefore per (token,
  worker). `ClientFactory` keeps a reference to every adapter, so `set_pacing` changes
  a running scan. With `--auto-limits` the adapter is mounted even without limits.
- **HTTP 429.** python-gitlab retries silently. `RateLimitMonitor.on_response` sees
  every response. It warns once and then only counts (`HTTP 429 xN` on the status
  line, a summary row at the end); only `--debug` repeats the warning, throttled.
  It reports the wait to `ActiveTasks`, so the status line and the
  `Still searching …` notes show it, and it hands the response to the observer (the
  `LimitAdvisor`).
- **The probe** uses unpaced clients (`GitlabHarvester.unpaced_client`) without 429
  retries; its responses are not counted.
- **Errors.** `gitlab.errors.is_permanent_error` sorts failures:
  - 403 and 404 are permanent: the project is skipped and the term can still be done;
  - 5xx, 429 after retries, 401, timeouts and network errors are retryable: the term
    is written as `keyword_incomplete`, and `--resume` searches it again.

### 7. Output, progress and the run journal

- **Output.** `OutputLayout` decides every path: `<dir>/<session>.jsonl`, per-term
  files and `<term>/files/`. `SearchOutput` is the sink the engine hands hit records
  and checkpoints to. `SessionOutput` adds the `meta`, `resume` and `summary`
  records. The engine never builds a path. `--to-zip` packs only the files of the
  session: the downloads come from the hits' `file` keys, never from a directory
  walk.
- **Console.** stderr carries one in-place status line (`ui.statusline.STATUS`,
  updated by `Progress`) plus permanent lines (`STATUS.write_line`, `Progress.note`,
  `Progress.finish`) and blocks (`Index`, `Search plan`, via `STATUS.write_block`).
  stdout carries the log records and the final result blocks (`cli.report`). Log
  records go through `ConsoleHandler`, which clears the status line before writing
  and redraws it after. Off a terminal, only the permanent lines are written.
- **Run journal.** With `--log-file`, `ui.journal.JOURNAL` appends
  `[SUMMARY][run <id>]` lines whatever the log level: the start, command and
  options, every permanent progress line (a `STATUS` listener), each result block in
  one line, and `Run finished` / `Run failed`. Tokens are never written.

### 8. Where new code goes

| Change | Where |
|---|---|
| A CLI option | `cli/parser.py` (and a converter in `cli/values.py`), a `CliArgs` field, `config.example.ini` (enforced by `tests/unit/test_config.py`), and `cli/factory.py` if it shapes an object |
| A mode | `cli/commands/<mode>.py`, dispatched in `cli/app.py` |
| A rule about what to scan | `domain/` (pure, unit-tested without HTTP) |
| A field of the index or the session | its model in `domain/models.py` or `output/records.py`: `to_record()` keeps the key order, and `from_record()` must accept records without the field. Extend `tests/unit/test_models.py` or `test_records.py` |
| A GitLab request | the use case in `engine/`, client concerns in `gitlab/`. Also extend `fakegitlab/api.py` and the [contract table](#13-gitlab-api-contract-used-by-gitlabharvester) |
| A new output file | its path in `output/layout.py`, its writer in `output/` |
| A user-facing summary line | `STATUS.write_line` / `Progress.note`, or a block through `cli/report.py`, so that it reaches the run journal |
| A new subpackage | its layer rule in `tests/unit/test_architecture.py` |

## Part II. Fake GitLab: research, design and API contract

### 9. Goals

- Run GitlabHarvester, including its real CLI, against a **virtual GitLab REST API v4**.
  No real GitLab, no PostgreSQL or Redis, and no patching of `python-gitlab` internals.
- Serve **two modes** from one implementation and one dataset:
  - a long-running server for manual development (Docker Compose or plain Python);
  - an in-process server for deterministic pytest runs.
- Keep the data **declarative** (YAML/JSON). Support pagination, content search,
  forks, special characters and configurable failures.

### 10. Survey of existing tools

| Criterion | WireMock OSS (+ GitLab template) | pytest-httpserver | requests-mock / responses | Existing "fake GitLab" projects |
|---|---|---|---|---|
| Works with real `python-gitlab` | Yes (real HTTP) | Yes (real HTTP) | Yes, but by patching the `requests` transport inside the test process | Mostly no: language-specific (Perl `GitLab::API::v4::Mock`) or embedded in other projects (TypeScript mock in `gitlab-mcp`) |
| Standalone HTTP server | Yes (JVM or Docker) | Yes (Werkzeug thread, usable outside pytest) | **No**, so it can't serve a CLI subprocess or manual runs | n/a |
| GitLab REST v4 coverage | Template library has ~1800 v4 endpoints, as **static** example responses | None built-in | None built-in | Minimal, unmaintained or test-local |
| Static JSON responses | Excellent (mapping files) | Easy (`respond_with_json`) | Easy | — |
| Pagination & headers | Static per stub. Dynamic `X-Next-Page`/`Link` needs templating per page | Full control in a Python handler | Full control | — |
| Errors & delays | Built-in faults and fixed/random delays | Via handler code | Via callbacks; no real timeouts | — |
| Data-driven content search | Not without a Java extension. Static stubs would need one mapping per (project, ref, term, page) | Natural in Python | Natural, in-process only | — |
| Scenarios & datasets | Scenario state machine; files per mapping | Whatever the handler loads | Same | — |
| Isolation & reset | `/__admin/reset`, request journal | `clear()`, `log`, one-shot/ordered handlers | Per-test mocker | — |
| Docker / CI | Official image; JVM in CI otherwise | Pure Python, pip only | Pure Python | — |
| License / cost | Apache-2.0 (OSS); the hosted GitLab template sandbox is a WireMock Cloud service | MIT | Apache-2.0 | — |
| Fit for GitlabHarvester | Good for static contract replay; poor for a coherent dataset | **Best fit as the HTTP layer** | Good for unit tests only | Not reusable |

Notes:

- **The WireMock GitLab template** returns canned example payloads for each endpoint.
  It does not keep a consistent world: projects, their branches and file contents
  don't relate to each other. Search results don't depend on `search`/`ref`. That
  coherence is exactly what GitlabHarvester's planner and post-processing need.
  Reproducing it with static stubs means generating thousands of mapping files,
  plus a JVM or container even for unit-speed tests.
- **requests-mock / responses** intercept `requests` inside one Python process.
  They can't serve the CLI started as a subprocess (end-to-end tests) or a
  developer running the tool by hand. They also bypass real socket behavior
  (timeouts, connection errors).
- No maintained, general-purpose Python "GitLab emulator" exists. Running a
  real GitLab CE container (several GB, minutes to boot, PostgreSQL/Redis inside)
  contradicts the "no heavy infrastructure" requirement.

### 11. Decision

**`pytest-httpserver` (Werkzeug) as the HTTP layer, plus a thin data-driven
GitLab layer (`fakegitlab/`), plus declarative YAML scenarios.**

- No custom HTTP framework. Threading, request parsing, request log, `clear()`,
  one-shot/ordered handlers and assertions all come from `pytest-httpserver`.
- The GitLab-specific code covers only what an off-the-shelf tool can't express
  declaratively: routing for the endpoints of §13, GitLab pagination headers, blob
  search over scenario files, rate limits and fault rules.
- The same `FakeGitLab` class runs:
  - in pytest (session-scoped, reset per test);
  - standalone (`python -m fakegitlab`, Docker Compose).
  So there is exactly **one dataset** for both modes.
- Tests can still use the native `pytest-httpserver` API
  (`fake.httpserver.expect_oneshot_request(...)`). Such handlers take precedence
  over the data-driven API, which helps with ad-hoc edge cases.
- `requests-mock`/`responses` aren't needed. Unit tests use plain in-memory stubs
  instead (see `tests/unit/test_harvester_offline.py`).

WireMock remains a valid option for future *recorded* contract replay. It isn't
required by any current test.

### 12. Test environment

```
                 ┌──────────────── fakegitlab/ ───────────────────────┐
 scenarios/*.yaml│ scenario.py  load + validate + resolve inheritance │
 (or your dir)   │ api.py       GitLab v4 routes, pagination, search  │
                 │ ratelimits.py per-user API and search limits       │
                 │ faults.py    match → delay / replace response      │
                 │ server.py    FakeGitLab: pytest-httpserver wrapper │
                 │              journal, reset, /__admin endpoints    │
                 └──────────────▲─────────────────────▲───────────────┘
                                │ HTTP (loopback)     │ HTTP
       ┌────────────────────────┴───────┐   ┌─────────┴───────────────────┐
       │ pytest (tests/conftest.py)     │   │ docker compose / python -m  │
       │  integration: python-gitlab    │   │ fakegitlab  → developer runs│
       │  e2e: CLI subprocess           │   │ gitlab-harvester -u ... -t  │
       └────────────────────────────────┘   └─────────────────────────────┘
```

Repository layout:

| Path | Purpose |
|---|---|
| `glh/`, `gitlab_harvester.py` | Production code ([Part I](#part-i-package-architecture)) |
| `fakegitlab/` | Fake GitLab package (dev-only; not shipped in the wheel) |
| `fakegitlab/scenarios/` | Built-in datasets: `default`, `empty`, `large`, `flaky`, `ratelimited` |
| `tests/unit/` | Pure unit tests; no HTTP (including the layer rule, `test_architecture.py`) |
| `tests/fakeserver/` | Unit tests of the fake itself (WSGI-level, no socket) |
| `tests/integration/` | Real `python-gitlab` → Fake GitLab |
| `tests/e2e/` | `python -m gitlab_harvester` subprocess → Fake GitLab |
| `tests/contract/` | Opt-in checks against a real GitLab |
| `tests/helpers.py` | JSONL parsing and expectations for the `default` scenario |
| `docker/Dockerfile`, `docker-compose.yml` | Dev images: `fake-gitlab`, `harvester` |
| `.github/workflows/tests.yml` | CI |

### 13. GitLab API contract used by GitlabHarvester

Derived from the engine (`glh/engine/`, `glh/gitlab/`) and the rate-limit probe
(`glh/limits/finder.py`), and verified at the wire level against python-gitlab 8.6.0
(`tests/integration/test_client_contract.py` asserts this exact list):

| # | Request | Called from | Query parameters | Response fields read |
|---|---|---|---|---|
| 1 | `GET /api/v4/user` | `Gitlab.auth()` in `GitLabConnection.connect` (once per token: `_verify_extra_tokens` checks every token after the first) | none | `id`, `username`, `web_url` (python-gitlab compares `web_url` with the base URL and warns on mismatch) |
| 2 | `GET /api/v4/projects` | `ProjectIndexer.fetch_projects` | `page`, `per_page`, `order_by=id`, `sort=desc`; `last_activity_after`/`last_activity_before` with `--index-active-*` | `id`, `web_url`, `path_with_namespace`, `default_branch`, `empty_repo`, `forked_from_project.id`, `created_at`, `last_activity_at` |
| 3 | `GET /api/v4/projects/:id/repository/branches` | `ProjectIndexer.get_branches` (only when index branches mode ≠ `default`) | `page`, `per_page` | `name`, `commit.id` |
| 4 | `GET /api/v4/projects/:id/search` | `SearchEngine.scan_branch` | `scope=blobs`, `search` (the term, plus `filename:<pattern>` / `extension:<ext>` with `--filename` / `--extension`), `ref`, `page`, `per_page=100` | `path`, `startline`, `data` |
| 5 | `GET /api/v4/projects/:id/repository/commits` | `FileChangeChecker.changed` (only with `--file-changed-*`) | `ref_name`, `path`, `since`, `until`, `page=1`, `per_page=1` | non-empty list = changed in the window |
| 6 | `GET /api/v4/projects/:id/repository/files/:file_path/raw` | `GitLabConnection.open_raw_file` for `FileFetcher` (only with `--download-files`), streamed | `ref` (the branch); `file_path` URL-encoded (`/` → `%2F`) | the body (streamed, stops past `--download-max-size`), `Content-Length` if sent |
| 7 | `GET /api/v4/projects` | `ProjectIndexer.first_project_id` (only `-m find-limits` / `--auto-limits` without an index, to pick a project for search probes) | `per_page=20`, `order_by=id`, `sort=desc` | `id`, `empty_repo` |
| 8 | `GET /api/v4/projects` | `LimitFinder` probe of the other API (`-m find-limits`, `--auto-limits`), not paced, no 429 retries | `per_page=1`, `simple=true` | status, `RateLimit-*`, `Retry-After` |
| 9 | `GET /api/v4/projects/:id/search` | `LimitFinder` probe of the search API, not paced, no 429 retries | `scope=blobs`, `search=glhprobe<random hex>`, `per_page=1` | status, `RateLimit-*`, `Retry-After` |
| 10 | `GET /api/v4/projects/:id/search` | `FileLister._paths_by_search` (no term, `--file-listing auto/search`) | `scope=blobs`, `search=filename:<pattern> extension:<ext>` (filters only), `ref`, `page`, `per_page=100` | `path` |
| 11 | `GET /api/v4/projects/:id/repository/tree` | `FileLister._paths_by_tree` (no term, `--file-listing auto/tree`) | `ref`, `recursive=true`, `pagination=keyset`, `per_page=100`, then the `Link: rel="next"` URL (`page_token`) | `type` (`blob`), `path` |

`GET /user` (row 1) also gives the user `id` of every token: tokens of one user
share its rate limits (`GitLabConnection.token_users`, `tokens_per_user`).

Rows 7-9 only run with `-m find-limits` or `--auto-limits`. With `--auto-limits`,
the `LimitAdvisor` (`glh/limits/advisor.py`, headers parsed in
`glh/limits/headers.py`) reads the rate-limit headers of every response:
`RateLimit-Limit` (requests per minute), `RateLimit-Name`, `Retry-After` and
`RateLimit-Reset` (Unix time).

No other requests are made. `projects.get(id, lazy=True)` doesn't hit the API,
and there are no implicit `/version` or `/projects/:id` calls. The test suite fails
on any request to an endpoint the fake doesn't implement (`unmatched_requests()`).

Headers and behavior that matter:

- **Authentication**: python-gitlab sends `PRIVATE-TOKEN: <token>`. An invalid
  token returns `401 {"message": "401 Unauthorized"}` →
  `GitlabAuthenticationError`. With several tokens (`-t "a;b"` / `--token-file`,
  `glh/cli/tokens.py`), each one is authenticated with its own `GET /user` at
  start-up, so a bad token aborts the run before any scanning. Each worker thread is
  bound to one token round-robin (`GitLabConnection.init_worker_client`), so the run
  keeps `tokens × workers` clients (`GitLabConnection.concurrency`). Each client has
  its own session and its own per-client rate-limit budget. `tokens × workers == 1`
  is the inline sequential path. The token values never leave the client: they
  never appear in logs, the session file or the journal.
- **Pagination**: GitLab offset pagination — `X-Page`, `X-Per-Page`, `X-Total`,
  `X-Total-Pages`, `X-Next-Page`, `X-Prev-Page`, `Link` (`rel="next|prev|first|last"`).
  `per_page` is capped at 100. Above 10 000 records GitLab omits `X-Total`,
  `X-Total-Pages` and `rel="last"`, and the fake reproduces this (`instance.count_limit`).
  The harvester passes an explicit `page`, so python-gitlab doesn't follow `Link`.
  The harvester stops at the **first empty page** (projects, branches), or at the
  first page shorter than `per_page` (search). The repository tree (row 11) is the
  exception: it uses keyset pagination and follows `Link: rel="next"`.
- **Ordering**: branches are returned **sorted by name**. Projects follow
  `order_by`/`sort` (GitLab default `created_at desc`).
- **Blob search** (basic search, `Gitlab::FileFinder` over Gitaly `SearchFilesByContent`):
  case-insensitive literal match. Files whose *path* contains the term come first
  (`startline: 1`, `data` = first 1024 bytes of the file). Then content matches:
  `git grep` with 2 lines of context before and after, where overlapping or adjacent
  windows merge and `startline` is the first line of the chunk (context included),
  not the matching line. Each result has `data`, `startline`, `path`, `filename`,
  `basename`, `ref`, `project_id`. A missing `scope`/`search` returns `400`.
  Filters inside the search string are parsed like `Gitlab::Search::Query`:
  `filename:`, `path:`, `extension:` (a `-` prefix negates, only the first fragment
  of each counts, `*` matches any characters, case-insensitive). `filename:` matches
  the *end of the whole path* (`filename:config.yml` also matches `app/myconfig.yml`),
  `extension:` `.<value>` at its end, `path:` anywhere. The rest is the term; a query
  of filters only finds nothing. The harvester re-checks every result path with its
  own, stricter rules (`glh/domain/file_filter.py`: `--filename` matches the file name).
- **Raw files**: `ref` defaults to the default branch; unknown ref →
  `404 Commit Not Found`, missing file → `404 File Not Found`; the body is the file
  as `text/plain`. The harvester streams it (`http_get(..., streamed=True,
  raw=True)`) and closes it early when the size limit is passed. A failed download
  is a warning and never makes the term incomplete.
- **python-gitlab error handling** (defaults):
  - `429` is retried up to 10 times, sleeping `Retry-After` seconds. This happens
    silently; the harvester sees it through a `requests` response hook,
    `RateLimitMonitor.on_response`. With `--index-rpm`/`--search-rpm`/`--jitter`/
    `-A`/`--user-agent-file`, every client session also gets a
    `glh.gitlab.throttling.ThrottledAdapter`. It spaces requests, adds the random
    delay and sets the User-Agent right before they are sent, retries included;
  - `5xx` is **not** retried (`retry_transient_errors=False`);
  - timeouts and connection errors are **not** retried;
  - a non-JSON 2xx body → `GitlabParsingError`.

  All `Gitlab*Error` exceptions derive from `GitlabError`. A per-project/branch
  error is logged with `describe_api_error()`: a one-line `HTTP <code> <reason>`,
  or the exception type for a timeout/network error. The response body is never
  logged, because a real GitLab returns it as a whole HTML page. The full exception
  goes to a separate `self.logger.debug(...)` line (visible with `--debug`), and the
  session `keyword_incomplete` `failures` entries use the same short form.

Reference documentation:
[REST pagination](https://docs.gitlab.com/api/rest/#pagination),
[Projects API](https://docs.gitlab.com/api/projects/#list-all-projects),
[Branches API](https://docs.gitlab.com/api/branches/),
[Search API: project scope `blobs`](https://docs.gitlab.com/api/search/),
[Users API: current user](https://docs.gitlab.com/api/users/).
GitLab's OpenAPI description (`doc/api/openapi/` in the GitLab repository)
covers only part of the REST API. The endpoints above are defined by the
Markdown docs plus the opt-in contract tests.

### 14. Defects found while building the environment

Each one is fixed minimally and pinned by tests (all of them fail on the original code):

| Defect | Effect | Fix | Tests |
|---|---|---|---|
| `fetch_projects` kept `is_completed=True` after a `GitlabError` mid-listing | A partial index looked complete and was silently reused | Set `is_completed=False`; warn when an existing incomplete index is reused | `test_fetch_projects_api_error_marks_index_incomplete`, `test_error_on_intermediate_page_yields_incomplete_index[*]`, `test_failed_project_listing_is_flagged_incomplete` |
| Branch listing returned a cut list as if it were complete on a 5xx/timeout (1.4.4) | A failure on the first page left a project with no branches, so the search skipped it; a later page lost the remaining branches; the index looked complete | `list_branches()` reports completeness; a cut list keeps the default branch; the index gets `is_completed=false`, `branches_incomplete=N` and a warning names the projects | `test_branch_listing_errors_are_isolated_per_project`, `test_branch_listing_timeout_does_not_abort_index`, `test_branches_added_in_memory_keep_the_default_branch_on_errors`, `test_flaky_scenario_completes` |
| `--resume` never skipped anything: `load_done_keywords` read `keyword`, but the harvester writes `term` | Resume re-scanned every keyword | Read `term` (keep `keyword` for compatibility) | `test_reads_keyword_done_records_written_by_harvester`, `test_interrupted_session_resumes_remaining_keywords` |
| Resume checkpoints weren't flushed | After a hard kill, buffered `keyword_done` records were lost | `flush()` after each `keyword_done` | `test_interrupted_session_resumes_remaining_keywords` |
| `--scan-branches default` took the *first indexed* branch. GitLab sorts branches by name, so `develop` was scanned instead of `main` | Default-branch scans missed or mis-attributed findings when the index held several branches | Prefer `default_branch` | `test_default_mode_prefers_default_branch_over_name_order`, `test_default_branch_search_results` |
| `host:port` URLs produced file names with `:` (`127_0_0_1:8080_project_index.jsonl`) | On Windows the index went into an NTFS alternate data stream and `os.replace` crashed (`WinError 87`) | Instance id replaces `:`; the default index name reuses it | `test_instance_id_is_filesystem_safe`, `test_dump_index_with_default_filename` |
| `scan_branch` passed `project=<Project>` to `project.search()` | A stray `project=<class 'gitlab…Project'> => {…}` query parameter on every search | Removed | `test_scan_branch_sends_only_documented_search_parameters`, `test_full_workflow_uses_only_known_endpoints_and_parameters` |
| Hit URLs weren't URL-encoded | Branches like `fix/#42` and paths with spaces produced broken links (`#` became a fragment) | `quote()` branch and path | `test_special_character_links_are_url_encoded`, `test_hit_links_resolve_to_file_and_line` |
| A read timeout or connection error in a branch/search request aborted the whole run | One slow project killed a multi-hour scan | Catch `requests.RequestException` like `GitlabError` in per-project calls | `test_search_timeout_skips_branch_and_continues`, `test_branch_listing_timeout_does_not_abort_index` |
| `from datetime import UTC` (3.11+) while `requires-python >= 3.10` | Import error on Python 3.10 | `UTC = timezone.utc` | CI matrix (3.10) |
| On a TLS certificate error, the client silently retried with verification disabled | A man-in-the-middle certificate was accepted and the token sent to it | No automatic fallback; explicit `--ca-bundle FILE` or `--insecure` (warned on every run) | `tests/integration/test_tls.py` |
| With `--workers`, the status line showed the last *finished* project, and python-gitlab waited on HTTP 429 without output | A slow last project (many result pages, rate limits) looked like a hung scan with a ticking progress bar | `ActiveTasks` (`glh/engine/workers.py`): the status line shows the running searches with page and elapsed time; `Still searching …` lines after 5 minutes; a throttled 429 warning | `test_status_line_shows_the_running_task_not_the_last_finished_one`, `test_rate_limit_waits_are_reported` |
| A term was marked `keyword_done` even when some of its searches failed (5xx, 429, 401, timeout, network) | `--resume` skipped it, so the failed projects were never searched | Such terms get `keyword_incomplete`, the summary says `completed: false`; 403/404 stay permanent skips | `test_partial_success_when_one_project_fails[*]`, `test_failed_term_is_not_a_resume_checkpoint`, `test_failed_term_is_reported_and_resumed` |

Observed behavior that was intentionally **not** changed (documented by tests):

- The dedup SQLite store is never committed, so every dedup run is independent
  (`test_dedup_runs_are_independent_even_with_the_same_sqlite_path`).
- An invalid token or an unreachable server ends the CLI with exit code 1 (since
  1.4.1 with one line naming the cause instead of a traceback).
- After `--resume`, the `summary.hits` record counts only hits of the resumed part.
- Branch/project listing makes one extra request for the terminating empty page.

### 15. Known limitations of the emulation

The fake is a **stub server**, not GitLab. Passing tests means GitlabHarvester
works with *this model* of the API. It does **not** guarantee compatibility with
every (or a future) GitLab version. Use the contract tests
(`tests/contract`) against a real instance to re-validate the model.

- Only the endpoints in §13 (plus `GET /version` and `GET /projects/:id`) exist.
- Repository history is not modeled: every file has exactly one commit, at its
  `updated_at` (default: the project's `last_activity_at`); the commits endpoint
  supports `ref_name`, `path`, `since`, `until` and pagination only.
  Everything else returns `404` and is reported as *unmatched*.
- No permissions model: every valid token sees every project. `visibility` is informational.
- Search approximates **basic** search: literal, case-insensitive, per-line, path
  matches first, 2 context lines (`instance.search_context_lines`,
  `instance.search_path_matches`), with the `filename:`, `path:` and `extension:`
  filters of basic search. Not modeled: advanced (Elasticsearch/Zoekt) syntax and
  its filter semantics (advanced search matches `filename:` against the file name),
  binary files, and result limits.
- Raw files: no `X-Gitlab-*` metadata headers (a header must be latin-1, refs and
  paths may be any Unicode), no `lfs` parameter, no `HEAD` requests.
  Sources: `lib/gitlab/file_finder.rb` in GitLab and
  `internal/gitaly/service/repository/search_files.go` in Gitaly.
- Keyset pagination (`pagination=keyset`) exists only for the repository tree;
  every other list uses offset pagination.
- Project list filters: only `search`, `archived`, `order_by`, `sort`. Branch
  list: only `search` (with `^`/`$`) and `sort=name_desc`.
- Rate limits (`fakegitlab/ratelimits.py`) model the two GitLab limits that matter
  here: `throttle_authenticated_api` (every request) and the search API limit. Both
  count per user over fixed windows aligned to the clock. GitLab's other throttles
  and its exact counting algorithms are not modeled.
- Repository contents are static per scenario: no commits, tags or history.
