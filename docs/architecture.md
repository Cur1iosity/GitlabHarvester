# Fake GitLab: research, design and API contract

This document records **why** the GitlabHarvester test environment looks the way it
does. For day-to-day usage see [testing.md](testing.md).

- [1. Goals](#1-goals)
- [2. Survey of existing tools](#2-survey-of-existing-tools)
- [3. Decision](#3-decision)
- [4. Architecture](#4-architecture)
- [5. GitLab API contract used by GitlabHarvester](#5-gitlab-api-contract-used-by-gitlabharvester)
- [6. Defects found while building the environment](#6-defects-found-while-building-the-environment)
- [7. Known limitations of the emulation](#7-known-limitations-of-the-emulation)

## 1. Goals

- Run GitlabHarvester, including its real CLI, against a **virtual GitLab REST API v4**.
  No real GitLab, no PostgreSQL or Redis, and no patching of `python-gitlab` internals.
- Serve **two modes** from one implementation and one dataset:
  - a long-running server for manual development (Docker Compose or plain Python);
  - an in-process server for deterministic pytest runs.
- Keep the data **declarative** (YAML/JSON). Support pagination, content search,
  forks, special characters and configurable failures.

## 2. Survey of existing tools

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

## 3. Decision

**`pytest-httpserver` (Werkzeug) as the HTTP layer, plus a thin data-driven
GitLab layer (`fakegitlab/`), plus declarative YAML scenarios.**

- No custom HTTP framework. Threading, request parsing, request log, `clear()`,
  one-shot/ordered handlers and assertions all come from `pytest-httpserver`.
- The GitLab-specific code, about 400 lines, covers only what an off-the-shelf tool
  can't express declaratively: routing for six endpoints, GitLab offset pagination
  headers, blob search over scenario files, and fault rules.
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

## 4. Architecture

```
                 ┌──────────────── fakegitlab/ ───────────────────────┐
 scenarios/*.yaml│ scenario.py  load + validate + resolve inheritance │
 (or your dir)   │ api.py       GitLab v4 routes, pagination, search  │
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
| `glh/`, `gitlab_harvester.py` | Production code (unchanged structure) |
| `fakegitlab/` | Fake GitLab package (dev-only; not shipped in the wheel) |
| `fakegitlab/scenarios/` | Built-in datasets: `default`, `empty`, `large`, `flaky` |
| `tests/unit/` | Pure unit tests; no HTTP |
| `tests/fakeserver/` | Unit tests of the fake itself (WSGI-level, no socket) |
| `tests/integration/` | Real `python-gitlab` → Fake GitLab |
| `tests/e2e/` | `python -m gitlab_harvester` subprocess → Fake GitLab |
| `tests/contract/` | Opt-in checks against a real GitLab |
| `tests/helpers.py` | JSONL parsing and expectations for the `default` scenario |
| `docker/Dockerfile`, `docker-compose.yml` | Dev images: `fake-gitlab`, `harvester` |
| `.github/workflows/tests.yml` | CI |

## 5. GitLab API contract used by GitlabHarvester

Derived from `glh/harvester.py` and verified at the wire level against
python-gitlab 8.6.0 (`tests/integration/test_client_contract.py`
asserts this exact list):

| # | Request | Called from | Query parameters | Response fields read |
|---|---|---|---|---|
| 1 | `GET /api/v4/user` | `Gitlab.auth()` in `_get_gl_client` (and `_verify_extra_tokens`, once per extra token) | none | `username`, `web_url` (python-gitlab compares `web_url` with the base URL and warns on mismatch) |
| 2 | `GET /api/v4/projects` | `fetch_projects` | `page`, `per_page`, `order_by=id`, `sort=desc`; `last_activity_after`/`last_activity_before` with `--index-active-*` | `id`, `web_url`, `path_with_namespace`, `default_branch`, `empty_repo`, `forked_from_project.id`, `created_at`, `last_activity_at` |
| 3 | `GET /api/v4/projects/:id/repository/branches` | `get_branches` (only when index branches mode ≠ `default`) | `page`, `per_page` | `name` |
| 4 | `GET /api/v4/projects/:id/search` | `scan_branch` | `scope=blobs`, `search`, `ref`, `page`, `per_page=100` | `path`, `startline`, `data` |
| 5 | `GET /api/v4/projects/:id/repository/commits` | `_file_changed_in_window` (only with `--file-changed-*`) | `ref_name`, `path`, `since`, `until`, `page=1`, `per_page=1` | non-empty list = changed in the window |

No other requests are made. `projects.get(id, lazy=True)` doesn't hit the API,
and there are no implicit `/version` or `/projects/:id` calls. The test suite fails
on any request to an endpoint the fake doesn't implement (`unmatched_requests()`).

Headers and behavior that matter:

- **Authentication**: python-gitlab sends `PRIVATE-TOKEN: <token>`. An invalid
  token returns `401 {"message": "401 Unauthorized"}` →
  `GitlabAuthenticationError`. With several tokens (`-t "a;b"` / `--token-file`,
  `glh/tokens.py`) each one is authenticated with its own `GET /user` at start-up,
  so a bad token aborts the run before any scanning. Each worker thread is bound to
  one token round-robin (`_init_worker_client`), so the run keeps `tokens × workers`
  clients (`GitlabHarvester.concurrency`), each with its own session and per-client
  rate-limit budget; `tokens × workers == 1` is the inline sequential path. The
  token values never leave the client: not in logs, the session file or the journal.
- **Pagination**: GitLab offset pagination — `X-Page`, `X-Per-Page`, `X-Total`,
  `X-Total-Pages`, `X-Next-Page`, `X-Prev-Page`, `Link` (`rel="next|prev|first|last"`).
  `per_page` is capped at 100. Above 10 000 records GitLab omits `X-Total`,
  `X-Total-Pages` and `rel="last"`, and the fake reproduces this (`instance.count_limit`).
  The harvester passes an explicit `page`, so python-gitlab doesn't follow `Link`.
  The harvester stops at the **first empty page** (projects, branches), or at the
  first page shorter than `per_page` (search).
- **Ordering**: branches are returned **sorted by name**. Projects follow
  `order_by`/`sort` (GitLab default `created_at desc`).
- **Blob search** (basic search, `Gitlab::FileFinder` over Gitaly `SearchFilesByContent`):
  case-insensitive literal match. Files whose *path* contains the term come first
  (`startline: 1`, `data` = first 1024 bytes of the file). Then content matches:
  `git grep` with 2 lines of context before and after, where overlapping or adjacent
  windows merge and `startline` is the first line of the chunk (context included),
  not the matching line. Each result has `data`, `startline`, `path`, `filename`,
  `basename`, `ref`, `project_id`. A missing `scope`/`search` returns `400`.
- **python-gitlab error handling** (defaults):
  - `429` is retried up to 10 times, sleeping `Retry-After` seconds (silently:
    the harvester sees it through a `requests` response hook, `_on_response`);
    with `--index-rpm`/`--search-rpm`/`--jitter`/`-A`/`--user-agent-file` every
    client session also gets a `ratelimit.ThrottledAdapter`, which spaces
    requests, adds the random delay and sets the User-Agent right before they
    are sent (retries included);
  - `5xx` is **not** retried (`retry_transient_errors=False`);
  - timeouts and connection errors are **not** retried;
  - a non-JSON 2xx body → `GitlabParsingError`.
  All `Gitlab*Error` exceptions derive from `GitlabError`. A per-project/branch
  error is logged with `describe_api_error()` — a one-line `HTTP <code> <reason>`
  (or the exception type for a timeout/network error), never the response body,
  which a real GitLab returns as a whole HTML page. The full exception goes to a
  separate `self.logger.debug(...)` line (visible with `--debug`), and the
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

## 6. Defects found while building the environment

Each one is fixed minimally and pinned by tests (all of them fail on the original code):

| Defect | Effect | Fix | Tests |
|---|---|---|---|
| `fetch_projects` kept `is_completed=True` after a `GitlabError` mid-listing | A partial index looked complete and was silently reused | Set `is_completed=False`; warn when an existing incomplete index is reused | `test_fetch_projects_api_error_marks_index_incomplete`, `test_error_on_intermediate_page_yields_incomplete_index[*]`, `test_failed_project_listing_is_flagged_incomplete` |
| `--resume` never skipped anything: `load_done_keywords` read `keyword`, but the harvester writes `term` | Resume re-scanned every keyword | Read `term` (keep `keyword` for compatibility) | `test_reads_keyword_done_records_written_by_harvester`, `test_interrupted_session_resumes_remaining_keywords` |
| Resume checkpoints weren't flushed | After a hard kill, buffered `keyword_done` records were lost | `flush()` after each `keyword_done` | `test_interrupted_session_resumes_remaining_keywords` |
| `--scan-branches default` took the *first indexed* branch. GitLab sorts branches by name, so `develop` was scanned instead of `main` | Default-branch scans missed or mis-attributed findings when the index held several branches | Prefer `default_branch` | `test_default_mode_prefers_default_branch_over_name_order`, `test_default_branch_search_results` |
| `host:port` URLs produced file names with `:` (`127_0_0_1:8080_project_index.jsonl`) | On Windows the index went into an NTFS alternate data stream and `os.replace` crashed (`WinError 87`) | Instance id replaces `:`; the default index name reuses it | `test_instance_id_is_filesystem_safe`, `test_dump_index_with_default_filename` |
| `scan_branch` passed `project=<Project>` to `project.search()` | A stray `project=<class 'gitlab…Project'> => {…}` query parameter on every search | Removed | `test_scan_branch_sends_only_documented_search_parameters`, `test_full_workflow_uses_only_known_endpoints_and_parameters` |
| Hit URLs weren't URL-encoded | Branches like `fix/#42` and paths with spaces produced broken links (`#` became a fragment) | `quote()` branch and path | `test_special_character_links_are_url_encoded`, `test_hit_links_resolve_to_file_and_line` |
| A read timeout or connection error in a branch/search request aborted the whole run | One slow project killed a multi-hour scan | Catch `requests.RequestException` like `GitlabError` in per-project calls | `test_search_timeout_skips_branch_and_continues`, `test_branch_listing_timeout_does_not_abort_index` |
| `from datetime import UTC` (3.11+) while `requires-python >= 3.10` | Import error on Python 3.10 | `UTC = timezone.utc` | CI matrix (3.10) |
| On a TLS certificate error, the client silently retried with verification disabled | A man-in-the-middle certificate was accepted and the token sent to it | No automatic fallback; explicit `--ca-bundle FILE` or `--insecure` (warned on every run) | `tests/integration/test_tls.py` |
| With `--workers`, the status line showed the last *finished* project, and python-gitlab waited on HTTP 429 without output | A slow last project (many result pages, rate limits) looked like a hung scan with a ticking progress bar | `ActiveTasks` (`glh/workers.py`): the status line shows the running searches with page and elapsed time; `Still searching …` lines after 5 minutes; a throttled 429 warning | `test_status_line_shows_the_running_task_not_the_last_finished_one`, `test_rate_limit_waits_are_reported` |
| A term was marked `keyword_done` even when some of its searches failed (5xx, 429, 401, timeout, network) | `--resume` skipped it, so the failed projects were never searched | Such terms get `keyword_incomplete`, the summary says `completed: false`; 403/404 stay permanent skips | `test_partial_success_when_one_project_fails[*]`, `test_failed_term_is_not_a_resume_checkpoint`, `test_failed_term_is_reported_and_resumed` |

Observed behavior that was intentionally **not** changed (documented by tests):

- The dedup SQLite store is never committed, so every dedup run is independent
  (`test_dedup_runs_are_independent_even_with_the_same_sqlite_path`).
- An invalid token or an unreachable server ends the CLI with a traceback (exit code 1).
- After `--resume`, the `summary.hits` record counts only hits of the resumed part.
- Branch/project listing makes one extra request for the terminating empty page.

## 7. Known limitations of the emulation

The fake is a **stub server**, not GitLab. Passing tests means GitlabHarvester
works with *this model* of the API. It does **not** guarantee compatibility with
every (or a future) GitLab version. Use the contract tests
(`tests/contract`) against a real instance to re-validate the model.

- Only the endpoints in §5 (plus `GET /version` and `GET /projects/:id`) exist.
- Repository history is not modeled: every file has exactly one commit, at its
  `updated_at` (default: the project's `last_activity_at`); the commits endpoint
  supports `ref_name`, `path`, `since`, `until` and pagination only.
  Everything else returns `404` and is reported as *unmatched*.
- No permissions model: every valid token sees every project. `visibility` is informational.
- Search approximates **basic** search: literal, case-insensitive, per-line, path
  matches first, 2 context lines (`instance.search_context_lines`,
  `instance.search_path_matches`). Not modeled: the `filename:`, `path:` and
  `extension:` filters that real basic search accepts inside the term, advanced
  (Elasticsearch/Zoekt) syntax, binary files, and result limits.
  Sources: `lib/gitlab/file_finder.rb` in GitLab and
  `internal/gitaly/service/repository/search_files.go` in Gitaly.
- Only offset pagination; keyset pagination (`pagination=keyset`) is not modeled.
- Project list filters: only `search`, `archived`, `order_by`, `sort`. Branch
  list: only `search` (with `^`/`$`) and `sort=name_desc`.
- Rate limiting exists only as configured fault rules; there is no real throttling.
- Repository contents are static per scenario: no commits, tags or history.
