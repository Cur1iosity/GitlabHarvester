# GitlabHarvester usage

Complete reference for the CLI. For a short introduction see the [README](../README.md).

- [How it works](#how-it-works)
- [Connection](#connection)
- [Configuration file](#configuration-file)
- [Project index](#project-index)
  - [Only some projects: --project-filter](#only-some-projects---project-filter)
- [Branches](#branches)
- [Forks](#forks)
- [Time filters](#time-filters)
- [Search terms](#search-terms)
  - [Only some files: --filename, --extension](#only-some-files---filename---extension)
  - [Without a term: every file by name](#without-a-term-every-file-by-name)
- [Downloading the files with hits](#downloading-the-files-with-hits---download-files)
- [Parallel requests](#parallel-requests)
- [Request rate limits](#request-rate-limits)
- [Finding the rate limits (experimental)](#finding-the-rate-limits--m-find-limits---auto-limits-experimental)
- [Sessions and resume](#sessions-and-resume)
- [Post-processing](#post-processing)
  - [Everything in one archive: --to-zip](#everything-in-one-archive---to-zip)
- [Progress output](#progress-output)
- [Run journal](#run-journal)
- [Output formats](#output-formats)
- [Option reference](#option-reference)

## How it works

A search run has two phases:

1. **Index.** GitlabHarvester lists every project visible to the token and writes a
   JSONL *project index*: id, URL, default branch, fork relation, timestamps, and
   optionally the branch names. The index is built once and reused by later runs.
2. **Scan.** For every search term, every project in the index and every selected
   branch, it calls GitLab's blob search API (`/projects/:id/search?scope=blobs`).
   Hits are streamed to a JSONL *session* file as they are found. The search can be
   limited to some files (`--filename`, `--extension`), and the files with hits can be
   saved one by one (`--download-files`).

Repositories are never cloned, and memory use doesn't grow with the instance size.

## Connection

```bash
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -s password
```

- The token needs the `read_api` scope. Only projects visible to the token are searched.
- **Several tokens at once.** `-t "tok1;tok2;tok3"` (separated by `;`), or
  `--token-file FILE` with one token per line (`#` comments and blank lines skipped),
  runs every token in parallel: each gets its own pool of `--workers` clients and its
  own server-side rate-limit budget, so the layering is `token -> workers per token ->
  rpm per worker`. Handy when an instance rate-limits per user and you hold several
  accounts' tokens. Every token is authenticated at start-up, so a bad one stops the run
  before any scanning (`Token #2 of 3 failed to authenticate …`). Duplicate tokens are
  dropped. Only projects visible to a given token are searched by that token; with no
  permission model differences, identical visibility means identical results. The two
  options exclude each other, and tokens are never written to logs, the session or the
  journal (only their count is).
- `--proxy http://127.0.0.1:8080` routes API traffic through a proxy (a scheme is added if missing).
- `--timeout 60` is the per-request timeout in seconds.
- User-Agent: by default python-gitlab's own (`python-gitlab/<version>`) is sent.
  `-A/--user-agent "Mozilla/5.0 (...)"` sends one fixed string with every request;
  `--user-agent-file agents.txt` reads one User-Agent per line (blank lines and
  `#` comments are skipped) and gives every request one chosen at random. The two
  options exclude each other. Strings must be Latin-1 without control characters
  (an invalid line is reported with its number before the run starts).
- TLS certificates are always verified, and verification is never turned off
  automatically. For a private CA, pass its PEM bundle with `--ca-bundle ca.pem`. To
  connect without verification, add `--insecure` explicitly: every run then warns that
  the token goes to an unverified server. Without either option, a certificate error
  stops the run before the token is sent.
- `--log-level ERROR|WARN|INFO`, `--debug`, and `--log-file path.log` control logging.
  The log file also gets a summary of every run, see [Run journal](#run-journal).
- Rate limiting (HTTP 429) is retried automatically according to `Retry-After`.
  An error on a single project or branch (an unreachable project, a GitLab 500,
  a timeout) is logged as a concise one-line warning — `HTTP 500 Internal Server
  Error` and the project/branch, not the server's HTML error page — and the scan
  moves on. The full error, body included, is logged only with `--debug`. A
  branch that failed with a retryable error keeps its term out of the
  `keyword_done` checkpoint, so `--resume` searches it again.

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
  `token = a;b` or `token-file = tokens.txt` run several tokens in parallel (see [Connection](#connection)).
- Relative paths in the file (`index-file`, `terms-file`, `session-file`, `log-file`,
  `input-file`, `output-file`, `sqlite-path`, `token-file`) are resolved against the file's directory.
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
- While an index is being built, a tip in turquoise above the status line says how
  to reuse it (`--index-file <file>`, found automatically from the same directory;
  `--dump-projects` rebuilds). It disappears when the index is done, so it never
  stays in the scrollback. It needs a terminal with ANSI colors (on Windows the
  console's VT mode is switched on); elsewhere it isn't shown. `NO_COLOR` turns the
  color off.

### Only some projects: --project-filter

```bash
gitlab-harvester -u ... -t ... -f words.txt --project-filter k8s            # paths containing k8s
gitlab-harvester -u ... -t ... -f words.txt --project-filter 'infra/*,*-k8s'
```

`--project-filter PATTERNS` searches only the indexed projects whose path
(`group/subgroup/project`) matches one of the comma-separated patterns,
case-insensitively:

| Pattern | Matches |
|---|---|
| `k8s` (no `*`/`?`) | a substring anywhere: `infra/k8s-deploy`, `k8s/charts`, `team/my-k8s` |
| `infra/*` | the whole path: everything under the `infra` group, subgroups included |
| `*-k8s` | paths ending with `-k8s` |
| `*/api-servic?` | `?` is one character |

- It works on the existing index at search time; the index itself stays complete,
  so each search can pick other projects without rebuilding it. Filtered projects
  cost no API request.
- The search plan counts them: `(skipped: 7 not matching --project-filter k8s, ...)`.
- It combines with the other filters (`--active-after`, `--forks skip`, file filters).
  Fork upstreams are still resolved against the whole index for `--forks branch-diff`.
- The session `meta` stores it (`"project_filter"`), the run journal records it, and
  `--resume` with another filter warns.

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

### Only some files: --filename, --extension

```bash
gitlab-harvester -u ... -t ... -s password --extension py              # .py, py and *.py are the same
gitlab-harvester -u ... -t ... -s password --filename settings.py      # an exact name, extension included
gitlab-harvester -u ... -t ... -f words.txt --filename '*.env'         # a mask
gitlab-harvester -u ... -t ... -s token --filename 'config*' --extension yml
```

| Option | Matches | Examples |
|---|---|---|
| `--filename PATTERN` | the file name: an exact name, **which may include the extension**, or a **mask with `*`** (any characters) | `settings.py`, `.env`, `Dockerfile`, `*.env`, `config*`, `docker-compose*.yml`, `*secret*`; with `/` the end of the path: `config/*.yml` |
| `--extension EXT` | the file name ends with `.EXT` | `py`, `.py`, `*.py` (the same), `tar.gz` |

- Both are case-insensitive; with both, a file must match both. `*` is the only
  wildcard (`?` and `[` are literal). No spaces.
- GitLab does the filtering: the harvester sends `password filename:*.env` as the
  search string (the code search `filename:`/`extension:` filters, supported by
  basic and advanced search). The term in the session stays `password`.
- Every result is re-checked on the client, by the same rules as above. That keeps
  the session exact where GitLab is looser (basic search matches `filename:` against
  the end of the whole path, so `filename:config.yml` also returns `myconfig.yml`)
  or ignores a filter.
- With a term the filters narrow its search. Without one they collect files by
  name instead, see below.
- With `--file-changed-*`, the name check runs first, so files outside the filter
  never cost a commits request.
- The session `meta` records `filename` and `extension`. `--resume` with other
  filters warns: the terms already done were searched with the old ones.

### Without a term: every file by name

```bash
# Download every .env file of the instance, to search it offline
gitlab-harvester -u ... -t ... -b all --filename '*.env' --download-files --to-zip
gitlab-harvester -u ... -t ... --extension tf --project-filter infra/* --download-files
```

With `--filename`/`--extension` but no term (no `-s`, `-f` or `terms`), the run
collects every file whose name passes the filters: one hit per file (an empty
`data`, a `.../-/blob/<branch>/<path>` URL), downloaded with `--download-files`.
The session term is the filter string, e.g. `filename:*.env` (so `--resume`,
`--output-separated` and the download directory `filename_.env/files/` work as
usual).

How the files of a branch are found depends on GitLab's search backend, so
`--file-listing` chooses:

| `--file-listing` | How | Works on |
|---|---|---|
| `search` | the search API with the filters only (`search=filename:*.env`) | backends that take such queries (advanced search); basic search usually returns nothing or an error |
| `tree` | the repository tree API, recursive (one request per 100 entries, `--index-rpm`) | any GitLab |
| `auto` (default) | the search first; a branch with no results or an error is listed by the tree, until the search has found files once (then it is trusted) or rejected the query (then only trees are used) | any GitLab |

- The switch is printed once (`File listing: the search API takes filter-only queries
  here; using it` / `... rejects ...; listing repository trees instead`), and the
  search summary counts the branches per method (`files listed: 12 branches by
  search, 7 branches by tree`).
- The tree costs no search requests, so it isn't held back by GitLab's low search
  rate limit, but a huge repository takes many pages. `--file-changed-*` and
  `--project-filter` apply as usual.

## Downloading the files with hits: --download-files

```bash
gitlab-harvester -u ... -t ... -s password --download-files --session audit
# -> audit.jsonl
#    password/files/acme_backend_api-service_main_20261117093000_password_config_settings.py
gitlab-harvester -u ... -t ... -f words.txt --extension yml --download-files --download-max-size 2M
```

Why: a hit is a few lines around the match. With the whole file on disk you can:
- **read the whole document**: the connection string next to the password, the
  host it is for, the other keys in the same `.env`;
- **hand the files to a secret scanner** for a detailed look, offline and without
  more API requests, e.g. [TruffleHog](https://github.com/trufflesecurity/trufflehog):

  ```bash
  trufflehog filesystem results/password/files --no-verification
  ```

  Without `--no-verification`, TruffleHog checks the secrets it finds against the
  services they belong to, which is a request from your machine to each of them;
- keep the evidence: `--to-zip` packs the session, the results and the files into
  one archive.

Every file that produced a hit is saved into the term's `files` directory next to
the session: `<dir>/<term>/files/` (`results/<term>/files/` with the default session
location), created on the first download. The name is

```
<project>_<branch>_<timestamp>_<term>_<path>
```

with `/` in the project and the path replaced by `_`, so it ends with the original
file name and extension; the timestamp is the run's start (UTC, the same as in a
default session name). The term directory is named like the term, sanitized for the
file system (see `--output-separated` below). Unsafe characters become `_`, long parts
are shortened (the path keeps its end), and a taken name gets `~2`, `~3`, … before
the extension; existing files are never overwritten.

- Every hit of a downloaded file gets a `"file"` key with the local path.
- `--download-max-size SIZE` (default `10M`; bytes or `k`, `M`, `G`; `0` = no limit)
  skips bigger files: by `Content-Length` before any data is read, else as soon as
  the stream passes the limit. They are counted in the summary.
- One request per file (`GET /projects/:id/repository/files/:path/raw?ref=<branch>`),
  counted by `--index-rpm`. Files are streamed to `<name>.part` and renamed when
  complete, so memory stays constant and a broken download leaves nothing behind.
- A file found by several terms is downloaded once and copied locally for the other
  terms; another branch or project is another file.
- A failed download is a warning (`Could not download <path> from <project> @
  <branch> (HTTP 500 ...)`): the hits stay in the session without a `"file"` key, and
  the term still counts as done (the search itself missed nothing).
- The `Results` block at the end has a `downloaded` row: `12 files (340 KiB) in
  results/<term>/files`, then copies, files skipped by size and failed downloads,
  one per line.
- The copies are as sensitive as the repositories they come from.

## Parallel requests

```bash
gitlab-harvester -u ... -t ... -f words.txt -b all --workers 8
```

`-w/--workers N` (1-64, default 1) runs up to N API requests at a time. Use it only
when the instance has no API rate limits: N workers send about N times more requests
per second, which also means N times more load and noise in the GitLab logs.
HTTP 429 responses are still retried according to `Retry-After`, but under a rate
limit more workers mostly produce more 429s, not more speed. These waits are
visible without flooding the log:

- the first 429 of a run is one warning (endpoint, wait, what to do about it);
- after that the 429s are only counted: the status line ends with `HTTP 429 x190`
  (off a terminal, in the heartbeat line every minute), and the waiting task shows
  `rate limited (HTTP 429), retry in …`;
- the `Results` block at the end has a `rate limit` row: `190 HTTP 429 responses,
  retried after 12:30 of waits in total (all workers)` (in the run journal too);
- with `--debug` the warning repeats at most once a minute with the count so far.

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
- `--workers 1` with one token is the sequential mode: no threads at all.

### Several tokens: `--workers` is per token

`--workers` counts **per token**. With several tokens (`-t "a;b"` or `--token-file`,
see [Connection](#connection)) the run keeps `tokens × workers` clients busy at once,
each worker bound to one token for the whole run (round-robin, so every token gets an
equal share of threads):

```bash
# 3 tokens x 2 workers each = 6 concurrent clients, each paced to 20 search req/min
gitlab-harvester -u ... -t "$T1;$T2;$T3" -f words.txt -b all --workers 2 --search-rpm 20
```

- Tasks come from the one shared queue, so the tokens load-balance themselves: if one
  token hits a rate limit (429) its workers wait while the others keep taking tasks.
- Because the `--*-rpm` limits are per worker (per client), every token has its own
  independent budget. Three tokens at `--search-rpm 20 --workers 2` send up to
  `3 × 2 × 20 = 120` search requests a minute, 40 per account — useful against an
  instance that limits each user separately.
- The search plan names it: `parallel  3 tokens x 2 workers = 6 clients` and
  `rate limit  search 20/min per worker`; the run journal records the token count
  (`tokens=3 inline` / `tokens=file t.txt`) and the session `meta` stores it (`"tokens"`).

## Request rate limits

```bash
gitlab-harvester -u ... -t ... -f words.txt --workers 4 --search-rpm 20 --index-rpm 300
```

Client-side limits on how many requests **one worker** sends per minute, to keep
the traffic low or to stay under the instance's rate limits instead of collecting
HTTP 429 responses:

| Option | Limits | Default |
|---|---|---|
| `--search-rpm N` | search API requests (`/projects/:id/search`, one per result page of a branch search) | 0 = no limit |
| `--index-rpm N` | every other API request: project and branch listing, file-change checks (`--file-changed-*`), the login check | 0 = no limit |
| `--rpm N` | shortcut: sets both | |

There are two budgets because GitLab limits the search API separately and usually
much lower than the rest of the API. A specific option overrides `--rpm`
(`--rpm 300 --search-rpm 20`), with the same precedence as the time filters:
specific option on the command line > `--rpm` on the command line > specific key
in the config file > `rpm` in the config file.

- The limits are **per worker**: every worker has its own connection and budget, so
  `--workers 4 --search-rpm 20` sends up to 80 search requests a minute. For an
  instance-wide limit of L requests a minute, use about L / workers. Don't know L?
  [`-m find-limits` or `--auto-limits`](#finding-the-rate-limits--m-find-limits---auto-limits-experimental)
  measure it.
- Requests are spaced evenly (one every 60/N seconds, counted from the start of the
  previous one), so there are no bursts at the start of a minute.
- Retries after HTTP 429 go through the same limit.
- The search plan names the limits (`rate limit  search 20/min, other API 300/min per
  worker`); the run journal records them too.

### Random delay: --jitter

```bash
gitlab-harvester -u ... -t ... -f words.txt --jitter 0.01-0.05
```

`--jitter RANGE` waits a random time before every API request, drawn anew for each
request, so the requests don't come at a fixed rhythm:

| Value | Delay before each request |
|---|---|
| `0.03` | 0 to 0.03 s |
| `0.01-0.05` | 0.01 to 0.05 s |
| `10ms-50ms` | the same, in milliseconds (`ms` and `s` suffixes) |
| `0` or not set | none (default) |

- It applies to every request (search and the rest), in every worker, retries
  after HTTP 429 included.
- It adds to the `--*-rpm` spacing: two requests of one worker are at least
  `60/rpm` seconds plus the jitter apart, so the jitter never pushes the rate above
  a limit. Without a limit it slows the scan by about the mean delay per request
  (`0.01-0.05`: about 30 ms each).
- The search plan line shows it (`..., jitter 0.01-0.05s`), and so does the run journal.

## Finding the rate limits: -m find-limits, --auto-limits (experimental)

> **Experimental.** The probe, its suggestions and the limiter during a run are new:
> their behavior, output and options may change in future releases. Check the
> suggested values before relying on them, and please report results that look
> wrong. Every run that uses them says so in its first lines and in the run journal.

```bash
# Measure only: print the settings, the command line and the config keys
gitlab-harvester -m find-limits -u https://gitlab.example.com -t "$GITLAB_TOKEN"

# Measure, offer the settings, then search (and watch the search for HTTP 429)
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt --auto-limits
```

GitLab rate-limits the search API separately from the rest of the API, and most
limits count **per user**: two tokens of one user share one budget. The limits are
instance settings you usually can't see, so the harvester can measure them:

1. **One request.** If GitLab announces the limit of the API in `RateLimit-*`
   headers on a successful response, that is the answer, with no load at all
   (the other API only: on a search response those headers describe the general
   API throttle).
2. **Requests at a growing parallelism** (1, 2, 4, … up to 16 threads, not paced
   and not retried) until GitLab answers **HTTP 429**. Its `RateLimit-Limit`, if
   sent, is the limit. Without it the probe waits for the window to reset
   (`Retry-After`) and counts **one full window from its start**: the requests that
   pass are the limit, and the time to the next 429 plus its `Retry-After` is the
   window length. A long `Retry-After` (more than 1.5 minutes) means an hourly
   window.
3. **No 429 within the default budget** (search API: 60 requests, other API: 300):
   the probe goes on deeper, up to `--probe-max` requests (default 600), to find a
   higher limit or the throughput really available. It stops early when a whole
   minute passed without a 429, and reports "no rate limit found up to ~N req/min"
   — with "server throughput limit" when more threads stopped raising the rate.

Then it suggests settings:

- the target is `--probe-margin` (default 0.85) of the limit — or of the measured
  throughput when there is no limit, to keep the load reasonable — for all threads
  of one user together;
- `--workers` is as many as needed to reach it at the measured latency (more only
  waste the budget), and the rpm of each worker is the target split over
  `workers x tokens of that user`;
- options set explicitly (command line or config file) are kept, with a warning
  when they exceed a found limit.

```text
Rate limits at https://gitlab.example.com (token #1)
  other API   ~2,000 requests per minute per user (GitLab headers, throttle_authenticated_api)
              1 request, latency 0.08s
  search API  ~30 requests per minute per user (HTTP 429, full window counted)
              61 requests, up to 2 parallel, peak ~410 req/min, latency 0.42s, budget back in 0:58

Suggested settings
  workers     1
  index-rpm   1700 per worker
  search-rpm  25 per worker

Next run
  command      gitlab-harvester -u https://gitlab.example.com -t '<TOKEN>' --auto-limits --workers 1 --index-rpm 1700 --search-rpm 25
  config file  workers = 1
               index-rpm = 1700
               search-rpm = 25
  budget back  in about 58.0s (the probe used it up)
```

The printed command never shows the token (`<TOKEN>`); neither does the run journal.

**`--auto-limits`** does the same before a search: only the search API when the
project index already exists (given with `--index-file` or found under its default
name), both APIs when it has to be built (`--dump-projects` or no index yet);
`--probe-apis` picks them by hand. `-m dump-index --auto-limits` measures the other
API only.

- On a terminal it asks `Apply ... to this run? [Y/n]`; without one (CI, redirected
  output) it prints the command and exits without searching.
- With `--workers` and the rpm options of the measured APIs all set, nothing is
  measured: the run is only watched (so the printed command, which has them all,
  starts at once).
- Before the search starts it waits for the rate-limit windows the probe used up to
  reset, so the scan doesn't begin with 429s.

**During the run**, every HTTP 429 is checked against the requests of that user
that passed before it (or the `RateLimit-Limit` GitLab sent). When the run goes
faster than the limit, the limiter proposes a lower `--search-rpm` / `--index-rpm`
per worker **without stopping the scan**:

```text
[Limiter] HTTP 429 on search API: ~30 requests per minute passed before HTTP 429: --search-rpm no limit -> 6. Apply? [Y]es / [N]o / ignore: 17s
```

- `Y` (or Enter) applies the limits at once to every worker; `N` drops the proposal
  (only a clearly lower one comes back).
- No answer within 20 seconds: the scan goes on unchanged and the status line starts
  with **`[Limiter: L]`**: there is a proposal; press **`L`** to see it again.
- Less than a minute of history gives a *preliminary* proposal; a full minute later
  a lower one may follow. Right after a change the limiter waits a minute before
  proposing again (429s of requests sent before say nothing about the new pace).
- Without a terminal the proposal is a warning in the log, and nothing changes.
- At the end the run prints the limits to start the next run with, or the proposal
  left unanswered; the run journal records every change.

`Y`, `N` and `L` also work with a Russian keyboard layout (the same keys: `Н`, `Т`,
`Д`). The number of workers of a running scan can't change, only their pace.

> The probe provokes HTTP 429 on purpose and sends up to `--probe-max` requests per
> API in a short time: on a monitored instance this is visible. Run it when that is
> acceptable, or set `--workers` and the rpm options yourself.

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
- A term is **completed** only if all its searches succeeded. If a search failed with
  an error that may hide hits (HTTP 5xx, 429 after the retries, 401, a timeout, a
  connection error, an invalid response), the run continues, but the term gets a
  `keyword_incomplete` record (with the failed searches) instead of `keyword_done`,
  the `summary` says `"completed": false`, and the `Results` block has an `INCOMPLETE`
  row (the terms) followed by a line to repeat the command with `--resume`, which
  then searches those terms again. 403 and 404 (no access, project or
  branch gone) can't be fixed by retrying: such projects are skipped with a warning and
  don't keep the term open.
- `--final-only` doesn't delete the session JSONL of an incomplete search, so it can
  still be resumed.
- New records are appended after a `resume` marker. The final `summary` counts
  hits of the resumed part only.

### One file per term: --output-separated

```bash
gitlab-harvester -u ... -t ... -f words.txt --session audit --output-separated
# -> audit.jsonl (full session) + password/audit.jsonl, api_key/audit.jsonl, ...
```

With several search terms, `--output-separated` also writes each term's hits to its
own file in a directory per term next to the session, `<dir>/<term>/<session>.jsonl`
(the same directory that holds the term's `files/` with `--download-files`), so you
can triage one kind of finding at a time. It needs more than one term (with a single
term it is ignored with a notice).

```
results/
  <host>_session_<ts>.jsonl          the session: every term, --resume checkpoints
  password/
    <host>_session_<ts>.jsonl        --output-separated: the hits of "password"
    files/                           --download-files: the files with hits
  api_key/
    ...
```

- The session file itself is still written in full — the per-term files are an extra
  view of it, each a valid session-hit file (`{"term", "result"}` lines), so
  `-m dedup` / `-m convert` work on them too.
- Only terms that produced at least one hit get a file. The split runs after the
  search over the whole session, so with `--resume` the files cover every run.
- The term directory name is sanitized for the file system: characters other than
  letters, digits, `.`, `-` and `_` become `_` (so a term like `api/key` or
  `BEGIN RSA PRIVATE KEY` is safe on Windows, macOS and Linux and can't escape the
  session's directory), the name is shortened, and terms that would collide get a
  numeric suffix.
- It combines with `--post-process`: the per-term split happens first, so `--final-only`
  (which deletes the session) still leaves the per-term files.

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

### Everything in one archive: --to-zip

```bash
gitlab-harvester -u ... -t ... -f words.txt -b all --output-separated --download-files \
    --post-process dedup --to-zip
# -> results/<host>_session_<ts>.zip
```

After a long run the results are many files: the session, the post-processing
outputs, a directory per term with its hits and the downloaded files. `--to-zip`
packs them into one ZIP next to the session, `<dir>/<session>.zip`, with the same
layout inside:

```text
audit.zip
├── audit.jsonl                  the session (unless --final-only removed it)
├── audit.deduped.jsonl          --post-process outputs left on disk
├── password/
│   ├── audit.jsonl              --output-separated
│   └── files/…                  --download-files
└── api_key/…
```

- It runs last: after the search, `--output-separated` and `--post-process`, so with
  `--final-only` the archive holds the final file and the downloaded files.
- Only this session's files go in, not everything in the directory: the default
  `results/` is shared by all sessions. The downloaded files are the ones the
  session's hits point to (their `"file"` key), so after `--resume` the files of the
  earlier runs are in it too. A file outside the session's directory goes under
  `external/`.
- The original files stay in place (the session is still needed for `--resume`);
  an archive of the same session from an earlier run is replaced.
- Files are compressed one at a time (constant memory, ZIP64 for archives over
  4 GiB) into `<session>.zip.part`, renamed when complete: an interrupted run leaves
  no half-written archive. If the archive can't be written (e.g. the disk is full),
  the run ends with an error and the results are unchanged.
- The `Results` block has an `archive` row: `results/....zip (14 files, 16.7 KiB ->
  7.2 KiB), packed in 0.4s`; the run journal records it, and the session `meta` has
  `"to_zip": true`.

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

The last part is the search running right now with the page being fetched and how
long it has been running. With `--workers` it is the longest-running search, and
`(+N running)` counts the others:

```text
Searching 'password' | 7/8 projects (87%) | 7 hits | 14:31 | ETA 2:04 | acme/monorepo @ main, page 37, 12:10 (+1 running)
```

The last searches of a scan can run long after all the others are done (a huge
repository has many result pages, and GitLab runs the search again for every
page; rate limits add waits). With `--workers`, a search still running after
5 minutes gets a permanent line, repeated every 5 minutes (also in the run journal):

```text
Still searching 'password' in acme/monorepo @ main (page 37): running for 10:00
```

A run starts with the banner and the command as you typed it (bold blue on a
terminal; tokens shown as `<TOKEN>`, a proxy password as `***`), so warnings and
everything else come after it. When a phase ends, the status line is replaced by a
permanent line; facts that belong together are shown as a block, one fact per row:

```text
$ gitlab-harvester -u https://gitlab.example.com -t '<TOKEN>' -f words.txt -b all --started-from 2024-06-02 --download-files --to-zip
Indexed 9 projects from gitlab.example.com in 0.4s
Listed 19 branches of 8 projects in 1.2s

Index
  file      gitlab_example_com_project_index.jsonl
  built     2024-06-30 09:12:44 UTC (3 h ago)
  projects  9
  branches  all

Search plan
  terms      2
  projects   5 of 9
  skipped    1 empty
             3 inactive since 2024-06-02
  branches   13
  downloads  results/<term>/files (max 10 MiB each)

Term 1/2 'password': 5 projects, 20 hits in 0.2s
Term 2/2 'api_key': 5 projects, 5 hits in 0.1s
Search finished: 2 terms x 5 projects, 25 hits in 0.3s
Packing the results into results/gitlab_example_com_session_20240630091300.zip ...

Results
  hits         25
  terms        2
  search time  0.3s
  session      results/gitlab_example_com_session_20240630091300.jsonl
  downloaded   21 files (64 KiB) in results/<term>/files
               4 copied locally (same file, another term)
  archive      results/gitlab_example_com_session_20240630091300.zip (24 files, 70 KiB -> 22 KiB), packed in 0.1s
```

- The `Index` block names the index file and when it was built (`timestamp_utc` of
  its `meta` record, updated by branch listing), so a reused, possibly outdated index
  is easy to spot; it also flags an incomplete index (`status`) or an index limited
  to a time window (`active`). Rebuild it with `--dump-projects`.
- The `Search plan` block lists only what applies: file filters, `files changed`,
  `downloads`, `parallel`, `rate limit`, `jitter`, `user agent` rows appear with
  their options.
- The search counts only projects that are actually scanned. Projects excluded by
  `--project-filter`, `--started-from`, `--forks skip`, empty repositories, and
  projects without a branch to scan are listed once under `skipped` (one reason per
  line) and never inflate the totals.
- The `Results` block (stdout) collects what the run produced: hits, terms, time,
  the session, then — with their options — `term files`, `downloaded`,
  `post-process`, `removed`, `final result`, `archive`, `rate limit`, `limiter` and
  `INCOMPLETE`. `-m dump-index` ends with a `Results` block too (`index`), `-m dedup`
  and `-m convert` with `Dedup` / `Convert` blocks.
- The ETA covers all terms. Branch listing (`--index-branches all|N`) counts only
  non-empty repositories, since empty ones need no API call.
- When stderr is not a terminal (pipe, file, CI), only the permanent lines are
  written, plus a heartbeat line with the current status once a minute during long phases.
- After Ctrl+C or a fatal error, the last status stays on screen to show how far the
  phase got (`| stopped`, or `(interrupted)` in the indexing summary).

Extras on the status line, only while they matter:

| Shown | When | Meaning |
|---|---|---|
| a turquoise `Tip: …` line above it | while the project index is built | how to reuse the index next time (`--index-file`); gone when the index is done |
| `\| HTTP 429 x190` at the end | after the first HTTP 429 | rate-limited responses so far (also in the heartbeat lines off a terminal); the run ends with a `Rate limit:` summary |
| `[Limiter: L]` in front | `--auto-limits` (experimental) has a proposal you haven't answered | press `L` to see it again |
| `[Limiter] … Apply? [Y]es / [N]o / ignore: 17s` instead of it | `--auto-limits` proposes new limits after HTTP 429 | answer without stopping the scan; no answer keeps the limits |

The tip needs a terminal with ANSI colors (on Windows the console's VT mode is
switched on); `NO_COLOR` turns the color off.

## Run journal

With `--log-file` (or `log-file` in the config file), every run appends a summary to
the log file, **whatever `--log-level` is**, so a history of runs builds up:

```text
[10-11-2026 16:39:57][SUMMARY][run 2f3724f3] Run started: gitlab-harvester 0.3.6, mode=search, url=https://gitlab.example.com, cwd=/audits
[10-11-2026 16:39:57][SUMMARY][run 2f3724f3] Command: gitlab-harvester -u https://gitlab.example.com -t <TOKEN> -f words.txt -b all --forks branch-diff --started-from 2024-06-02 --file-changed-after 2024-03-01 -w 2 --session audit --post-process dedup,convert --log-file audits.log
[10-11-2026 16:39:57][SUMMARY][run 2f3724f3] Options: index-file=idx.jsonl, index-branches=all, batch-size=100, workers=2, dump-projects=False, scan-branches=all, forks=branch-diff, fork-diff-bases=main,master,develop,dev, terms=terms-file words.txt, active=since 2024-06-02, file-changed=since 2024-03-01, session=audit, resume=False, post-process=dedup,convert, final-only=False
[10-11-2026 16:39:57][SUMMARY][run 2f3724f3] Indexed 9 projects from gitlab.example.com in 0.4s
[10-11-2026 16:39:57][SUMMARY][run 2f3724f3] Listed 19 branches of 8 projects in 1.2s
[10-11-2026 16:39:57][SUMMARY][run 2f3724f3] Index: file idx.jsonl; built 2026-11-10 13:39:57 UTC (just now); projects 9; branches all
[10-11-2026 16:39:57][SUMMARY][run 2f3724f3] Search plan: terms 2; projects 5 of 9; skipped 1 empty, 3 inactive since 2024-06-02; branches 12; files changed since 2024-03-01; parallel 2 workers
[10-11-2026 16:39:58][SUMMARY][run 2f3724f3] Term 1/2 'password': 5 projects, 14 hits in 0.2s
[10-11-2026 16:39:58][SUMMARY][run 2f3724f3] Term 2/2 'api_key': 5 projects, 4 hits in 0.1s
[10-11-2026 16:39:58][SUMMARY][run 2f3724f3] Search finished: 2 terms x 5 projects, 18 hits, 17 file checks in 0.2s
[10-11-2026 16:39:58][SUMMARY][run 2f3724f3] Post-processing dedup: audit.jsonl -> audit.deduped.jsonl (kept 9 records, dropped 1 duplicate-only hit records)
[10-11-2026 16:39:58][SUMMARY][run 2f3724f3] Post-processing convert: audit.deduped.jsonl -> audit.deduped.converted.json (9 objects)
[10-11-2026 16:39:58][SUMMARY][run 2f3724f3] Results: hits 18; terms 2; search time 0.2s; session audit.jsonl; post-process dedup: kept 9 records, dropped 1 duplicate-only hit records, convert: 9 objects; final result audit.deduped.converted.json
[10-11-2026 16:39:58][SUMMARY][run 2f3724f3] Run finished in 0.4s
```

- `[run …]` is a random id per run: it groups the lines of one run even if two runs
  write to the same file at the same time.
- `Run started` names the version, mode, URL, config file and working directory
  (relative paths below are relative to it). `Command` is the command line as typed
  (tokens as `<TOKEN>`). `Options` lists the settings that shape
  the run: index and branch modes, forks, time windows, workers, the term source,
  the session and post-processing. The token is never written.
- The index, the search plan, one line per term (projects, hits, time; with
  several terms), the search summary and the results follow. A block of the console
  output is one line here (`Search plan: terms 2; projects 5 of 9; ...`), so it stays
  easy to grep.
- The last line is `Run finished in …` or `Run failed after …: <reason>` (an error,
  an invalid token, Ctrl+C).
- `-m dedup` and `-m convert` add `Dedup: …` and `Convert: …` lines with their counters
  (`Dedup: input s.jsonl; output d.jsonl; kept 8 records; ...`).
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
| `{"type": "meta", ...}` | run parameters: url, index file, branch and fork modes, `started_from`, `filename`, `extension`, `download_files`, number of terms |
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
are URL-encoded. With `--download-files`, a hit whose file was saved also has
`"file": "results/password/files/<name>"`, the local copy.

## Option reference

| Option | Default | Description |
|---|---|---|
| `-c, --config FILE` | — | read options from an INI file; CLI arguments override it |
| `-u, --url URL` | — | GitLab base URL (`-H/--host` is a deprecated alias) |
| `-t, --token TOKEN` | — | API token(s) (`read_api`); `;`-separated tokens run in parallel |
| `--token-file FILE` | — | file with one token per line; each runs in parallel like `-t` |
| `-p, --proxy URL` | — | HTTP(S) proxy |
| `--timeout SEC` | 60 | per-request timeout |
| `--ca-bundle FILE` | system CAs | CA bundle (PEM) for the GitLab TLS certificate |
| `--[no-]insecure` | off | disable TLS verification explicitly (never automatic) |
| `-w, --workers N` | 1 | parallel API requests per token (1-64); only for instances without rate limits |
| `--[no-]auto-limits` | off | *experimental*: measure the rate limits before the run, offer settings, propose lower limits after HTTP 429 during it |
| `--probe-apis APIS` | auto | *experimental*: APIs to measure: `index`, `search`, `index,search` |
| `--probe-max N` | 600 | *experimental*: most requests per measured API (default budget first, then deeper) |
| `--probe-margin SHARE` | 0.85 | *experimental*: share of a found limit the suggested settings use (0.1-1 or `85%`) |
| `--rpm N` | 0 | shortcut for `--index-rpm` and `--search-rpm` |
| `--index-rpm N` | 0 | max non-search API requests per minute per worker, file downloads included (0 = no limit) |
| `--search-rpm N` | 0 | max search API requests per minute per worker (0 = no limit) |
| `--jitter RANGE` | off | random delay before every request: `MAX` or `MIN-MAX` seconds (`0.03`, `0.01-0.05`, `10ms-50ms`) |
| `-A, --user-agent STRING` | python-gitlab's | fixed User-Agent of every request |
| `--user-agent-file FILE` | | one User-Agent per line; a random one for every request |
| `--time-after DATE`, `--time-before DATE` | — | window for the index, its projects and the files with hits |
| `--index-active-after/--index-active-before DATE` | — | index only projects active in the window (API filter) |
| `--active-after DATE` (`--started-from`), `--active-before DATE` | — | search only indexed projects active in the window |
| `--file-changed-after/--file-changed-before DATE` | — | keep hits only in files changed in the window (commits API) |
| `-m, --mode` | `search` | `search`, `dump-index`, `find-limits` (experimental), `dedup`, `convert` |
| `-s, --search TERM` | — | single term |
| `-f, --terms-file FILE` | — | file with one term per line |
| `--filename PATTERN` | — | search only files with this name: exact (`settings.py`, extension included) or a mask with `*` (`*.env`, `config*`) |
| `--extension EXT` | — | search only files with this extension (`py`, `.py` and `*.py` are the same) |
| `--file-listing MODE` | `auto` | without a term: find files by `search` (filters only), `tree` or `auto` |
| `--project-filter PATTERNS` | — | search only indexed projects whose path matches: substring (`k8s`) or mask (`infra/*`), comma-separated |
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
| `--[no-]output-separated` | off | with several terms, also write each term's hits to `<term>/<session>.jsonl` |
| `--[no-]download-files` | off | save every file with hits to `<term>/files/` next to the session |
| `--download-max-size SIZE` | `10M` | with `--download-files`: skip bigger files (`500k`, `10M`, `1G`; `0` = no limit) |
| `--input-file`, `--output-file` | — | files for `dedup` and `convert` |
| `--hash-algo` | `blake2b` | dedup hash |
| `--[no-]normalize-hits` | on | collapse whitespace before comparing hits in dedup (`--no-normalize-hits` = exact) |
| `--sqlite-path FILE` | `<output>.seen.sqlite` | dedup hash store |
| `--sort-keys` | off | sorted keys in `convert` output |
| `--post-process STEPS` | — | after the search: `dedup`, `convert` or `dedup,convert` on the session file |
| `--[no-]final-only` | off | with `--post-process`: keep only the last file |
| `--[no-]to-zip` | off | after the run, pack its results into `<session>.zip` next to the session, same layout |
| `--log-level`, `--debug`, `--log-file` | `WARN` | logging |
| `-V, --version` | | print version |
