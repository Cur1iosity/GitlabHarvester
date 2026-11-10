# GitlabHarvester usage

Complete reference for the CLI. For a short introduction see the [README](../README.md).

- [How it works](#how-it-works)
- [Connection](#connection)
- [Configuration file](#configuration-file)
- [Project index](#project-index)
- [Branches](#branches)
- [Forks](#forks)
- [Activity filter](#activity-filter)
- [Search terms](#search-terms)
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

## Activity filter

```bash
gitlab-harvester -u ... -t ... -f words.txt --started-from 2024-06-01
gitlab-harvester -u ... -t ... -f words.txt --started-from 2024-06-01T12:00:00+03:00
```

- Projects whose `last_activity_at` is earlier than the given date are skipped
  without API calls. GitLab updates this field on pushes and other project
  activity, so a skipped project normally has no repository changes since that date.
- GitLab updates `last_activity_at` at most once per hour, and some events (for
  example, creating a branch or tag in the web UI) may not update it. Set the
  date with a margin, e.g. a day before the previous scan.
- The value is an ISO 8601 date or datetime. Without an offset it means UTC. The bound is inclusive.
- The index isn't filtered: build it once, then search it with different dates.
- Projects without `last_activity_at` (for example, from an old index) are always scanned.
- GitLab's blob search has no date filter. Inside an active project, every file
  of the selected branches is still searched.
- Secrets committed before the date in skipped projects are **not** reported.

## Search terms

```bash
gitlab-harvester -u ... -t ... -s 'api_key'
gitlab-harvester -u ... -t ... -f words.txt
```

`words.txt` has one term per line. Empty lines and lines starting with `#` are
ignored. Each term is passed to GitLab search unchanged; how it's matched
(basic or advanced search, case sensitivity) depends on the GitLab instance.

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

## Progress output

Progress goes to stderr; results and final summaries go to stdout.

On a terminal, one status line is redrawn in place and fitted to the window width:

```text
Searching 'api_key' (2/2) | 3/5 projects | 21 hits | 0:05 | ETA 0:04 | acme/web-app @ master [2/3]
```

When a phase ends, the status line is replaced by a permanent summary:

```text
Indexed 9 projects from gitlab.example.com in 0.4s
Listed 19 branches of 8 projects in 1.2s
Search plan: 2 terms, 5 of 9 projects, 13 branches (skipped: 1 empty, 3 inactive since 2024-06-02)
Term 1/2 'password': 20 hits in 0.2s
Term 2/2 'api_key': 5 hits in 0.1s
Search finished: 2 terms x 5 projects, 25 hits in 0.3s
```

- The search counts only projects that are actually scanned. Projects excluded by
  `--started-from`, `--forks skip`, empty repositories, and projects without a branch
  to scan are reported once in the `Search plan` line and never inflate the totals.
- The ETA covers all terms. Branch listing (`--index-branches all|N`) counts only
  non-empty repositories, since empty ones need no API call.
- When stderr is not a terminal (pipe, file, CI), only the permanent lines are
  written, plus a heartbeat line with the current status once a minute during long phases.
- After Ctrl+C or a fatal error, the last status stays on screen to show how far the
  phase got (`| stopped`, or `(interrupted)` in the indexing summary).

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
| `--log-level`, `--debug`, `--log-file` | `WARN` | logging |
| `-V, --version` | | print version |
