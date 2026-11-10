# GitlabHarvester usage

Complete reference for the CLI. For a short introduction see the [README](../README.md).

- [How it works](#how-it-works)
- [Connection](#connection)
- [Configuration file](#configuration-file)
- [Project index](#project-index)
- [Branches](#branches)
- [Forks](#forks)
- [Time filters](#time-filters)
- [Search terms](#search-terms)
- [Parallel requests](#parallel-requests)
- [Sessions and resume](#sessions-and-resume)
- [Post-processing](#post-processing)
- [Progress output](#progress-output)
- [Output formats](#output-formats)
- [Option reference](#option-reference)

## How it works

A search run has two phases:

1. **Index.** GitlabHarvester lists every project visible to the token and writes a
   JSONL *project index*: id, URL, default branch, fork relation, timestamps, and
   optionally the branch names. The index is built once and reused by later runs.
2. **Scan.** For every search term, every project in the index and every selected
   branch, it calls GitLab's blob search API (`/projects/:id/search?scope=blobs`).
   Hits are streamed to a JSONL *session* file as they are found.

Repositories are never cloned, and memory use doesn't grow with the instance size.

## Connection

```bash
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -s password
```

- The token needs the `read_api` scope. Only projects visible to the token are searched.
- `--proxy http://127.0.0.1:8080` routes API traffic through a proxy (a scheme is added if missing).
- `--timeout 60` is the per-request timeout in seconds.
- If TLS verification fails, the tool retries once with verification disabled.
- `--log-level ERROR|WARN|INFO`, `--debug`, and `--log-file path.log` control logging.
  The log file also gets a summary of every run, see [Run journal](#run-journal).
- Rate limiting (HTTP 429) is retried automatically according to `Retry-After`.
  Errors on a single project or branch are logged, and the run continues.

## Configuration file

Every option can be stored in an INI file and passed with `-c/--config`.
[config.example.ini](../config.example.ini) lists all of them with their values and defaults:

```bash
cp config.example.ini config.ini        # config.ini is git-ignored
gitlab-harvester -c config.ini
gitlab-harvester -c config.ini -s token --forks skip --no-resume
```

```ini
[connection]
url = https://gitlab.example.com
token = env:GITLAB_TOKEN

[search]
scan-branches = all
forks = branch-diff
started-from = 2024-06-01
terms =
    password
    api_key
```

- Keys are the long option names (`index-branches` for `--index-branches`; `_` works too).
  Sections only group keys, and each key may appear once.
- Precedence: command-line argument, then the config file, then the built-in default.
  - `-s` or `-f` on the command line replaces `search`, `terms-file` and `terms` from the file.
  - `--session` or `--session-file` replaces the other one from the file.
  - `-b` replaces `index-branches` and `scan-branches` from the file.
  - On/off options have a `--no-` form (`--no-resume`, `--no-dump-projects`, `--no-debug`,
    `--no-sort-keys`, `--no-normalize-hits`) to switch off a value set in the file.
- `terms` lists search terms one per line, as an alternative to `terms-file`.
- `token = env:NAME` reads the token from an environment variable, so the file holds no secret.
- Relative paths in the file (`index-file`, `terms-file`, `session-file`, `log-file`,
  `input-file`, `output-file`, `sqlite-path`) are resolved against the file's directory.
  Paths given on the command line stay relative to the working directory.
- An empty value means "not set". Comments go on their own lines: text after a value is
  part of the value. `%` has no special meaning.
- Values are validated like command-line arguments. An unknown key or an invalid value
  stops the run before any API request, naming the file, the section and the key.
- The session `meta` record stores the config path (`"config"`).

## Project index

The index is created automatically on the first search. To build or refresh it explicitly:

```bash
gitlab-harvester -u ... -t ... -m dump-index                          # rebuild the index only
gitlab-harvester -u ... -t ... -s password --dump-projects            # rebuild, then search
gitlab-harvester -u ... -t ... -s password --index-file acme.jsonl    # custom location
```

- Default file name: `<host>_project_index.jsonl` in the current directory, for
  example `gitlab_example_com_project_index.jsonl` (`host:port` becomes `host_port`).
- An existing index is reused as is. Options that affect the index
  (`--index-branches`, `--batch-size`) apply only when it is (re)built.
- If listing fails midway, the index is saved with `"is_completed": false`, and
  later runs warn about it. Rebuild with `--dump-projects`.
- `-bs/--batch-size` (default 100, GitLab's maximum) is the page size for project listing.

## Branches

Two independent settings:

| Option | Controls | Values |
|---|---|---|
| `--index-branches` | which branch names are stored in the index | `default` (no extra API calls), `all`, `N` |
| `--scan-branches` | which indexed branches are searched | `default`, `all`, `N` |
| `-b/--branches` | shortcut that sets both | same |

```bash
gitlab-harvester -u ... -t ... -s password -b all                                  # every branch
gitlab-harvester -u ... -t ... -s password --index-branches all --scan-branches 5  # default + 4 others
```

- Only branches present in the index can be scanned. An index built with
  `--index-branches default` holds just the default branch, so `--scan-branches all`
  has no effect until the index is rebuilt with more branches.
- `N` always includes the default branch. The others follow GitLab's order (by name).
- Indexing branches costs one API call per page of branches per project
  (`--branches-per-page`, default 100).

## Forks

```bash
gitlab-harvester -u ... -t ... -s password -b all --forks branch-diff
```

| Mode | Behavior |
|---|---|
| `include` (default) | forks are scanned like regular projects |
| `skip` | forks are not scanned |
| `branch-diff` | forks: default branch, base branches, and branches missing in the upstream |
| `all-branches` | forks: every indexed branch, regardless of `--scan-branches` |

- `branch-diff` avoids re-scanning branches a fork inherited from its upstream.
  Base branches are always scanned and can be changed with
  `--fork-diff-bases main,master,develop,dev`.
- If the upstream isn't in the index (for example, it isn't visible to the
  token), the fork is scanned with the regular `--scan-branches` rules.

## Time filters

Three levels can be limited to a time window. `DATE` is an ISO 8601 date or datetime
(`2024-06-01`, `2024-06-01T12:00`, `2024-06-01T12:00:00+03:00`); without an offset it
means UTC. Every bound is optional.

| Level | After | Before | How it works |
|---|---|---|---|
| Index build | `--index-active-after` | `--index-active-before` | GitLab API filter on `/projects` (`last_activity_after/before`): projects outside the window are not even listed, so a smaller index is built faster |
| Projects of the index | `--active-after` (alias `--started-from`) | `--active-before` | indexed projects whose `last_activity_at` is outside the window are skipped without API calls |
| Files with hits | `--file-changed-after` | `--file-changed-before` | a hit is kept only if a commit in that branch changed its file inside the window (commits API) |
| **All three** | `--time-after` | `--time-before` | shortcuts that set the bound on every level |

```bash
# One window for everything: index, projects and files
gitlab-harvester -u ... -t ... -f words.txt --time-after 2024-06-01 --time-before 2024-06-30 --dump-projects

# A full index once, then searches of different periods over it
gitlab-harvester -u ... -t ... -m dump-index
gitlab-harvester -u ... -t ... -f words.txt --active-after 2024-06-01
gitlab-harvester -u ... -t ... -f words.txt --active-after 2024-06-01 --file-changed-after 2024-06-01

# Inventory of projects untouched since 2023 (index only)
gitlab-harvester -u ... -t ... -m dump-index --index-active-before 2023-01-01 --index-file stale.jsonl
```

- A specific option overrides `--time-after/--time-before`; a command-line option
  overrides the config file. The start must not be later than the end.
- **Index build.** The window is stored in the index `meta` record
  (`last_activity_after`, `last_activity_before`). An existing index is reused as is,
  so a run that asks for another window (or none) gets a warning: the index may miss
  projects. Rebuild it with `--dump-projects`. GitLab compares strictly (`>`/`<`).
- **Projects of the index.** Bounds are inclusive. Projects without `last_activity_at`
  (for example, from an old index) are always scanned. GitLab updates
  `last_activity_at` on pushes and other project activity, at most once per hour, and
  some events (for example, creating a branch or tag in the web UI) may not update it:
  take the dates with a margin. Secrets in skipped projects are **not** reported.
- **Files with hits.** GitLab's blob search has no date filter, so after a branch
  search every file with hits is checked with
  `GET /projects/:id/repository/commits?ref_name=BRANCH&path=FILE&since=…&until=…`
  (one request per project, branch and file, cached across terms; `Search finished`
  shows the number of file checks). "Changed in the window" means at least one commit
  in that branch touched the file then; the matched line itself may be older. If a
  check fails, the hits are kept and a warning is logged.
- The `Search plan` line reports both directions, e.g.
  `(skipped: 1 empty, 1 inactive since 2024-05-01, 5 active after 2024-06-02)` and
  `files changed 2024-03-01..2024-06-04`. The session `meta` record stores the windows.

## Search terms

```bash
gitlab-harvester -u ... -t ... -s 'api_key'
gitlab-harvester -u ... -t ... -f words.txt
```

`words.txt` has one term per line. Empty lines and lines starting with `#` are
ignored. Each term is passed to GitLab search unchanged; how it's matched
(basic or advanced search, case sensitivity) depends on the GitLab instance.

## Parallel requests

```bash
gitlab-harvester -u ... -t ... -f words.txt -b all --workers 8
```

`-w/--workers N` (1-64, default 1) runs up to N API requests at a time. Use it only
when the instance has no API rate limits: N workers send about N times more requests
per second, which also means N times more load and noise in the GitLab logs.
HTTP 429 responses are still retried according to `Retry-After`, but under a rate
limit more workers mostly produce more 429s, not more speed.

How the work is split:

- **Search.** Every (term, project, branch) pair is one task: all result pages of
  one branch search. Tasks come from one shared queue, and a free worker always
  takes the next one. A large fork with many branches or a slow repository
  doesn't leave the other workers idle, as a fixed split of the index would.
- **Project listing** fetches pages ahead in parallel and writes them in order.
  If a page fails, the index keeps the pages before it (`"is_completed": false`),
  as in a sequential run.
- **Branch listing** (`--index-branches all|N`) lists branches of several projects
  at once; the index keeps its order.

What stays the same:

- The results: the same hits, the same index, the same `keyword_done` checkpoints in
  term order, so `--resume` works as usual. Hit records in the session file appear
  in completion order instead of index order.
- Only the main thread writes files and progress; every worker has its own
  connection (python-gitlab client).
- `--workers 1` is the sequential mode: no threads at all.

## Sessions and resume

| Option | Session file |
|---|---|
| none | `results/<host>_session_<UTC timestamp>.jsonl` |
| `--session audit` | `audit.jsonl` in the current directory |
| `--session-file path/audit.jsonl` | the given path (parent directories are created) |

After each term, a checkpoint (`keyword_done`) is written and flushed. To continue
an interrupted run, repeat the command with `--resume` and the same session file:

```bash
gitlab-harvester -u ... -t ... -f words.txt --session audit
gitlab-harvester -u ... -t ... -f words.txt --session audit --resume
```

- Completed terms are skipped. The term that was in progress is searched again,
  so its hits may appear twice; run `dedup` afterwards.
- New records are appended after a `resume` marker. The final `summary` counts
  hits of the resumed part only.

## Post-processing

Post-processing modes work offline and don't need `-u` or `-t`.

```bash
gitlab-harvester -m dedup   --input-file audit.jsonl --output-file clean.jsonl
gitlab-harvester -m convert --input-file clean.jsonl --output-file clean.json
```

**dedup** removes hits whose snippet (`data`) has already been seen anywhere in the
file: across branches, forks and terms. A hit record left without hits is dropped,
and control records are kept.

| Option | Meaning |
|---|---|
| `--hash-algo blake2b\|sha1\|sha256` | hash used as the dedup key (default `blake2b`) |
| `--no-normalize-hits` | compare snippets exactly; by default whitespace is collapsed |
| `--sqlite-path seen.sqlite` | location of the temporary hash store (default `<output>.seen.sqlite`) |

**convert** turns a JSONL file (or concatenated pretty-printed JSON objects) into a
single JSON array. `--sort-keys` sorts object keys.

### In the same run: --post-process

```bash
gitlab-harvester -u ... -t ... -f words.txt --session audit --post-process dedup,convert
gitlab-harvester -u ... -t ... -f words.txt --session audit --post-process dedup,convert --final-only
```

`--post-process` runs the steps on the session file right after a finished search:

| Steps | Files |
|---|---|
| `dedup,convert` | `audit.jsonl`, `audit.deduped.jsonl`, `audit.deduped.converted.json` |
| `dedup` | `audit.jsonl`, `audit.deduped.jsonl` |
| `convert` | `audit.jsonl`, `audit.converted.json` |

- Steps always run in the order dedup, then convert (`convert,dedup` means the same):
  dedup reads JSONL, convert produces a JSON array.
- The dedup and convert options above (`--hash-algo`, `--no-normalize-hits`,
  `--sqlite-path`, `--sort-keys`) apply. Without `--sqlite-path` the hash store is a
  temporary file that is deleted afterwards.
- `--final-only` (off by default) keeps only the last file: the session JSONL and the
  intermediate files are deleted. It saves space, but the session can't be resumed or
  post-processed again. Files are deleted only after the search finished and every step
  succeeded: after Ctrl+C or an error everything stays in place.
- The result equals running `-m dedup` and `-m convert` by hand.

## Progress output

Progress goes to stderr; results and final summaries go to stdout.

On a terminal, one status line is redrawn in place and fitted to the window width.
With one term:

```text
Searching 'password' | 3/5 projects (60%) | 21 hits | 0:05 | ETA 0:04 | acme/web-app @ master [2/3]
```

With several terms, the current term (`term`: its projects, the time since it started,
its ETA) and the whole list (`total`: projects x terms, the time since the search
started, the overall ETA) are shown side by side:

```text
Searching 'api_key' (2/3) | term 3/5 projects (60%) 0:02 ETA 0:01 | total 8/15 (53%) 0:07 ETA 0:06 | 21 hits | acme/web-app @ master
```

Percentages are rounded down, so 100% means the work is really finished.

When a phase ends, the status line is replaced by a permanent summary:

```text
Indexed 9 projects from gitlab.example.com in 0.4s
Listed 19 branches of 8 projects in 1.2s
Index: gitlab_example_com_project_index.jsonl (built 2024-06-30 09:12:44 UTC, 3 h ago; 9 projects, branches: all)
Search plan: 2 terms, 5 of 9 projects, 13 branches (skipped: 1 empty, 3 inactive since 2024-06-02)
Term 1/2 'password': 20 hits in 0.2s
Term 2/2 'api_key': 5 hits in 0.1s
Search finished: 2 terms x 5 projects, 25 hits in 0.3s
```

- The `Index` line names the index file and when it was built (`timestamp_utc` of its
  `meta` record, updated by branch listing), so a reused, possibly outdated index is
  easy to spot; it also flags an incomplete index or an index limited to a time window.
  Rebuild it with `--dump-projects`.
- The search counts only projects that are actually scanned. Projects excluded by
  `--started-from`, `--forks skip`, empty repositories, and projects without a branch
  to scan are reported once in the `Search plan` line and never inflate the totals.
- The ETA covers all terms. Branch listing (`--index-branches all|N`) counts only
  non-empty repositories, since empty ones need no API call.
- When stderr is not a terminal (pipe, file, CI), only the permanent lines are
  written, plus a heartbeat line with the current status once a minute during long phases.
- After Ctrl+C or a fatal error, the last status stays on screen to show how far the
  phase got (`| stopped`, or `(interrupted)` in the indexing summary).

## Run journal

With `--log-file` (or `log-file` in the config file), every run appends a summary to
the log file, **whatever `--log-level` is**, so a history of runs builds up:

```text
[10-11-2026 16:39:57][SUMMARY][run 2f3724f3] Run started: gitlab-harvester 0.3.6, mode=search, url=https://gitlab.example.com, cwd=/audits
[10-11-2026 16:39:57][SUMMARY][run 2f3724f3] Options: index-file=idx.jsonl, index-branches=all, batch-size=100, workers=2, dump-projects=False, scan-branches=all, forks=branch-diff, fork-diff-bases=main,master,develop,dev, terms=terms-file words.txt, active=since 2024-06-02, file-changed=since 2024-03-01, session=audit, resume=False, post-process=dedup,convert, final-only=False
[10-11-2026 16:39:57][SUMMARY][run 2f3724f3] Indexed 9 projects from gitlab.example.com in 0.4s
[10-11-2026 16:39:57][SUMMARY][run 2f3724f3] Listed 19 branches of 8 projects in 1.2s
[10-11-2026 16:39:57][SUMMARY][run 2f3724f3] Index: idx.jsonl (built 2026-11-10 13:39:57 UTC, just now; 9 projects, branches: all)
[10-11-2026 16:39:57][SUMMARY][run 2f3724f3] Search plan: 2 terms, 5 of 9 projects, 12 branches (skipped: 1 empty, 3 inactive since 2024-06-02), files changed since 2024-03-01, 2 workers
[10-11-2026 16:39:58][SUMMARY][run 2f3724f3] Term 1/2 'password': 5 projects, 14 hits in 0.2s
[10-11-2026 16:39:58][SUMMARY][run 2f3724f3] Term 2/2 'api_key': 5 projects, 4 hits in 0.1s
[10-11-2026 16:39:58][SUMMARY][run 2f3724f3] Search finished: 2 terms x 5 projects, 18 hits, 17 file checks in 0.2s
[10-11-2026 16:39:58][SUMMARY][run 2f3724f3] Session saved to: audit.jsonl
[10-11-2026 16:39:58][SUMMARY][run 2f3724f3] Done. Keywords: 2 | Hits: 18 | Search time: 0.2s
[10-11-2026 16:39:58][SUMMARY][run 2f3724f3] Post-processing dedup: audit.jsonl -> audit.deduped.jsonl (kept 9 records, dropped 1 duplicate-only hit records)
[10-11-2026 16:39:58][SUMMARY][run 2f3724f3] Post-processing convert: audit.deduped.jsonl -> audit.deduped.converted.json (9 objects)
[10-11-2026 16:39:58][SUMMARY][run 2f3724f3] Final result: audit.deduped.converted.json
[10-11-2026 16:39:58][SUMMARY][run 2f3724f3] Run finished in 0.4s
```

- `[run …]` is a random id per run: it groups the lines of one run even if two runs
  write to the same file at the same time.
- `Run started` names the version, mode, URL, config file and working directory
  (relative paths below are relative to it). `Options` lists the settings that shape
  the run: index and branch modes, forks, time windows, workers, the term source,
  the session and post-processing. The token is never written.
- The index line, the search plan, one line per term (projects, hits, time; with
  several terms), the search summary and every written file follow.
- The last line is `Run finished in …` or `Run failed after …: <reason>` (an error,
  an invalid token, Ctrl+C).
- `-m dedup` and `-m convert` add `Dedup: …` and `Convert: …` lines with their counters.
- Regular log records (warnings, errors, `--log-level INFO` hit lines) go to the same
  file as before, with their level instead of `SUMMARY`.

## Output formats

All files are UTF-8 JSONL: one JSON object per line.

**Project index**: a meta line followed by one line per project:

```json
{"type": "meta", "source": "gitlab_example_com", "timestamp_utc": "...", "projects_count": 1234,
 "elapsed_seconds": 12.3, "order_by": "id", "sort": "desc", "per_page": 100, "is_completed": true, "branches": "all"}
{"id": 101, "web_url": "https://gitlab.example.com/acme/api", "path_with_namespace": "acme/api",
 "default_branch": "main", "empty_repo": false, "forked_from_project": false,
 "created_at": "...", "last_activity_at": "...", "branches": ["develop", "main"]}
```

`forked_from_project` is `{"id": <upstream id>}` for forks and `false` otherwise.

**Session**: one record per line:

| Record | Content |
|---|---|
| `{"type": "meta", ...}` | run parameters: url, index file, branch and fork modes, `started_from`, number of terms |
| `{"term": ..., "result": {...}}` | hits of one term in one project (see below) |
| `{"type": "keyword_done", "term": ..., "hit_counter": N}` | checkpoint after a term; `hit_counter` is cumulative |
| `{"type": "resume", "done_keywords": N, "remaining_keywords": M}` | start of a resumed run |
| `{"type": "summary", "hits": N}` | end of a run |

```json
{"term": "password", "result": {
  "project_id": 101, "web_url": "https://gitlab.example.com/acme/api",
  "created_at": "...", "last_activity_at": "...",
  "project_search_result": [
    {"branch": "main", "branch_search_result": [
      {"url": "https://gitlab.example.com/acme/api/-/tree/main/config/settings.py#L2",
       "data": "DB_HOST = ...\nDB_PASSWORD = ...\n"}]}]}}
```

`url` links to the file and starting line of the snippet. Branch names and paths
are URL-encoded.

## Option reference

| Option | Default | Description |
|---|---|---|
| `-c, --config FILE` | — | read options from an INI file; CLI arguments override it |
| `-u, --url URL` | — | GitLab base URL (`-H/--host` is a deprecated alias) |
| `-t, --token TOKEN` | — | API token (`read_api`) |
| `-p, --proxy URL` | — | HTTP(S) proxy |
| `--timeout SEC` | 60 | per-request timeout |
| `-w, --workers N` | 1 | parallel API requests (1-64); only for instances without rate limits |
| `--time-after DATE`, `--time-before DATE` | — | window for the index, its projects and the files with hits |
| `--index-active-after/--index-active-before DATE` | — | index only projects active in the window (API filter) |
| `--active-after DATE` (`--started-from`), `--active-before DATE` | — | search only indexed projects active in the window |
| `--file-changed-after/--file-changed-before DATE` | — | keep hits only in files changed in the window (commits API) |
| `-m, --mode` | `search` | `search`, `dump-index`, `dedup`, `convert` |
| `-s, --search TERM` | — | single term |
| `-f, --terms-file FILE` | — | file with one term per line |
| `--index-file FILE` | `<host>_project_index.jsonl` | project index location |
| `--dump-projects` | off | rebuild the index before searching |
| `-bs, --batch-size N` | 100 | page size for project listing |
| `-b, --branches MODE` | — | sets `--index-branches` and `--scan-branches` |
| `--index-branches MODE` | `default` | branches stored in the index: `default`, `all`, `N` |
| `--scan-branches MODE` | `default` | branches searched: `default`, `all`, `N` |
| `--branches-per-page N` | 100 | page size for branch listing |
| `--forks MODE` | `include` | `skip`, `include`, `branch-diff`, `all-branches` |
| `--fork-diff-bases LIST` | `main,master,develop,dev` | base branches for `branch-diff` |
| `--started-from DATE` | — | skip projects inactive since DATE |
| `--session NAME` | — | session file `NAME.jsonl` |
| `--session-file FILE` | `results/<host>_session_<ts>.jsonl` | explicit session file |
| `--resume` | off | continue a session, skipping completed terms |
| `--input-file`, `--output-file` | — | files for `dedup` and `convert` |
| `--hash-algo` | `blake2b` | dedup hash |
| `--[no-]normalize-hits` | on | collapse whitespace before comparing hits in dedup (`--no-normalize-hits` = exact) |
| `--sqlite-path FILE` | `<output>.seen.sqlite` | dedup hash store |
| `--sort-keys` | off | sorted keys in `convert` output |
| `--post-process STEPS` | — | after the search: `dedup`, `convert` or `dedup,convert` on the session file |
| `--[no-]final-only` | off | with `--post-process`: keep only the last file |
| `--log-level`, `--debug`, `--log-file` | `WARN` | logging |
| `-V, --version` | | print version |
