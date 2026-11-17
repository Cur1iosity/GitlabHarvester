# GitlabHarvester use cases

Typical scenarios and which options fit them. For the full option reference see
[usage.md](usage.md).

- [1. First runs: terms, sessions, reports](#1-first-runs-terms-sessions-reports)
- [2. Search only in specific files: --filename, --extension](#2-search-only-in-specific-files---filename---extension)
- [3. Save the files with hits for deeper analysis: --download-files](#3-save-the-files-with-hits-for-deeper-analysis---download-files)
- [4. Every file by name, without a term](#4-every-file-by-name-without-a-term)
- [5. Only some projects: --project-filter](#5-only-some-projects---project-filter)
- [6. Export the project inventory only](#6-export-the-project-inventory-only)
- [7. Forks: scan them or not](#7-forks-scan-them-or-not)
- [8. Only fresh findings: time filters](#8-only-fresh-findings-time-filters)
- [9. Parallel requests: --workers](#9-parallel-requests---workers)
- [10. Red team: several tokens against a per-user rate limit](#10-red-team-several-tokens-against-a-per-user-rate-limit)
- [11. Baseline and re-scans](#11-baseline-and-re-scans)
- [12. Deduplicated JSON report in one run: --post-process](#12-deduplicated-json-report-in-one-run---post-process)
- [13. History of runs in a log file](#13-history-of-runs-in-a-log-file)
- [14. Optional: options from a config file](#14-optional-options-from-a-config-file)

All examples pass the options on the command line; that is the main way to run the tool.
They expect the token in an environment variable: `export GITLAB_TOKEN=...`.

## 1. First runs: terms, sessions, reports

```bash
# One term in the default branch of every project
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -s password

# A list of terms (one per line, # starts a comment) in all branches, as a named session.
# --dump-projects rebuilds the index so it holds all branch names.
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt -b all --dump-projects --session audit

# Interrupted? The same command with --resume (and without --dump-projects) continues
# after the last finished term and reuses the index
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt -b all --session audit --resume

# Remove duplicate hits and export as a JSON array
gitlab-harvester -m dedup   --input-file audit.jsonl --output-file clean.jsonl
gitlab-harvester -m convert --input-file clean.jsonl --output-file clean.json
```

- The first run builds the project index (`<host>_project_index.jsonl`); later runs
  reuse it. Branch options (`-b`) take effect when the index is built, so add
  `--dump-projects` after changing them.
- The session file (`audit.jsonl`) gets every hit as soon as it is found, plus a
  checkpoint after every finished term: that is what `--resume` continues from.
- Searching a list of terms? Add `--output-separated` to also get one file per term
  in a directory per term next to the session (`password/audit.jsonl`,
  `api_key/audit.jsonl`, …), so each kind of finding can be triaged on its own. See [usage.md](usage.md#one-file-per-term---output-separated).
- dedup and convert can also run right after the search: see
  [section 12](#12-deduplicated-json-report-in-one-run---post-process).

## 2. Search only in specific files: --filename, --extension

Some secrets live in well-known files: `.env`, `settings.py`, `application.yml`,
`*.tfvars`, CI files. Narrowing the search to them cuts the noise from docs, tests
and vendored code, and makes every result page smaller.

```bash
# "password" only in Python files (the dot is optional: py, .py and *.py are the same)
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -s password --extension py

# A list of terms only in .env files of all branches
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt -b all --filename '*.env'

# An exact file name, with its extension
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -s DB_PASSWORD --filename settings.py

# A mask: docker-compose.yml, docker-compose.prod.yml, ...
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -s password --filename 'docker-compose*.yml'

# Both: config.yml, config.prod.yml, but not config.json
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -s token --filename 'config*' --extension yml

# A file in a given directory (a pattern with / matches the end of the path)
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -s secret --filename 'k8s/*.yaml'
```

- `--filename` takes an exact name (it may include the extension: `settings.py`,
  `.env`, `Dockerfile`) or a mask where `*` matches any characters (`*.env`,
  `config*`, `*secret*`). It matches the file name, not a directory, case-insensitively.
- GitLab does the filtering (the options become `filename:`/`extension:` in the
  search string), so you get fewer results pages; the harvester re-checks every
  result, so the session holds only the files you asked for even on an instance
  that ignores a filter.
- With a term the filter narrows its search. Without a term it collects every
  matching file instead ([section 4](#4-every-file-by-name-without-a-term)).
- Combine with `--download-files` to keep a copy of each matching file
  ([section 3](#3-save-the-files-with-hits-for-deeper-analysis---download-files)).

## 3. Save the files with hits for deeper analysis: --download-files

A hit is a snippet with a couple of lines of context. To look at the whole file
later (run a secret scanner over it, grep for related values, diff branches,
attach it to a report), let the harvester save every file with hits.

```bash
# Every file with "password" in it, at most 10 MiB each (the default limit)
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -s password --download-files --session audit
# -> audit.jsonl
#    password/files/acme_api_main_20261117093000_password_config_settings.py ...

# Config files of all branches for a list of terms, one directory per term,
# each with the term's hits and its files; skip anything bigger than 2 MiB
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt -b all \
  --extension yml --download-files --download-max-size 2M --output-separated
# -> results/<host>_session_<ts>.jsonl
#    results/password/<host>_session_<ts>.jsonl
#    results/password/files/...
#    results/api_key/...

# Then analyze the copies offline, e.g. with a secret scanner
trufflehog filesystem results/password/files
```

- Files go to `<term>/files/` next to the session (`results/<term>/files/` by
  default), named `<project>_<branch>_<timestamp>_<term>_<path>`, so the name keeps
  the original file name and extension and says where it came from.
- Every hit of a downloaded file gets a `"file"` key with the local path, so a report
  links each finding to its copy.
- `--download-max-size` (default `10M`, `0` = no limit) skips big files (build
  artifacts, dumps, binaries) without downloading them.
- One API request per file (counted by `--index-rpm`); a file found by several terms
  is downloaded once and copied locally for the other terms. A failed download is a
  warning: the hits stay in the session, and the term still counts as done.
- The copies are as sensitive as the repository: keep the results directory private.

After a long run the results are many files. `--to-zip` packs them into one archive
next to the session, with the same layout inside, ready to hand over or move to an
analysis box:

```bash
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt -b all \
  --download-files --output-separated --post-process dedup --session audit --to-zip
# -> audit.zip: audit.jsonl, audit.deduped.jsonl, password/audit.jsonl, password/files/..., api_key/...
```

Only this session's files go in (other sessions in `results/` are left out); the
originals stay in place, so the session can still be resumed. Details:
[usage.md](usage.md#everything-in-one-archive---to-zip).

## 4. Every file by name, without a term

Sometimes the term isn't known yet: you want every `.env`, every `*.tfvars`, every
`application.yml` of the instance, to grep and scan them offline. Give the file
filters without any term (no `-s`, `-f` or `terms`): every matching file becomes one
hit, and `--download-files` saves it.

```bash
# Every .env file in all branches, downloaded and packed into one archive
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -b all --filename '*.env' \
  --download-files --to-zip --session envs
# -> envs.jsonl (term "filename:*.env"), filename_.env/files/..., envs.zip

# Terraform variables of the infra projects only, listed through the repository tree
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" --extension tfvars \
  --project-filter 'infra/*' --file-listing tree --download-files

# Then search the copies offline
trufflehog filesystem filename_.env/files
grep -rn "AWS_SECRET" filename_.env/files
```

- The session term is the filter string (`filename:*.env`), so `--resume`,
  `--output-separated` and `--to-zip` work as for a term.
- How the files of a branch are found depends on GitLab's search backend, so
  `--file-listing` chooses: `search` (the search API with the filters only — works
  where the backend takes such queries, e.g. advanced search), `tree` (the
  repository tree: any GitLab, one request per 100 entries) or `auto` (the default:
  the search first, the tree where it finds nothing or fails). The run says which
  one it settled on, and the search summary counts the branches per method.
- The tree costs no search requests, so GitLab's low search rate limit doesn't hold
  it back; a huge repository takes many tree pages, though. Narrow the projects with
  `--project-filter` and the time with `--active-after` when you can.
- Every matching file is downloaded (up to `--download-max-size` each): on a big
  instance that is a lot of data, and it is as sensitive as the repositories.

Details: [usage.md](usage.md#without-a-term-every-file-by-name).

## 5. Only some projects: --project-filter

The index holds every project the token can see; a search often concerns only some
of them — the Kubernetes repositories, one group, the infrastructure code.
`--project-filter` picks them from the existing index at search time: no new index,
no requests for the others.

```bash
# Every project with "k8s" anywhere in its path (infra/k8s-deploy, k8s/charts, team/my-k8s)
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt --project-filter k8s

# A whole group with its subgroups, plus projects ending with -k8s
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt -b all \
  --project-filter 'infra/*,*-k8s'
```

- Patterns are comma-separated and case-insensitive; one matching is enough.
  Without `*`/`?` a pattern is a substring; with them it must match the whole
  `group/subgroup/project` path.
- The search plan counts the others: `(skipped: 412 not matching --project-filter k8s, ...)`.
- One full index serves many narrow searches: build it once (`-m dump-index`), then
  run each search with its own filter. It combines with the time and file filters.

Details: [usage.md](usage.md#only-some-projects---project-filter).

## 6. Export the project inventory only

Use `-m dump-index` to get a list of all projects visible to the token without
searching anything, for example for an asset inventory, to estimate the size of a
scan, or to find empty, stale or forked repositories.

```bash
# Projects only (one request per 100 projects)
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -m dump-index --index-file inventory.jsonl

# Projects with all branch names (one more listing per non-empty project)
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -m dump-index --index-branches all --index-file inventory.jsonl

# As a JSON array, e.g. for jq or a spreadsheet import
gitlab-harvester -m convert --input-file inventory.jsonl --output-file inventory.json
```

Each line holds `id`, `web_url`, `path_with_namespace`, `default_branch`,
`empty_repo`, `forked_from_project`, `created_at`, `last_activity_at` and, if
requested, `branches`. The first line is a `meta` record: `projects_count`, the
build time, and `is_completed` (false if the listing of projects or of some
project's branches stopped on an API error; `branches_incomplete` counts the latter).

The same file serves later searches: pass it with `--index-file` and it is reused
as is (add `--dump-projects` to rebuild it). While an index is being built, a
turquoise tip above the status line says exactly that, and disappears when the index
is done. With `--project-filter` each search can then pick its own part of it
([section 5](#5-only-some-projects---project-filter)).

## 7. Forks: scan them or not

GitLab blob search looks at the current files of a branch. A fork is a separate
repository with its own branches, so a secret can live only there:

- someone forked the project and committed credentials to their copy;
- the fork kept a file that the upstream has since removed (the fork stopped
  syncing before the cleanup);
- experiments and work-in-progress branches often exist only in personal forks.

On the other hand, most branches of a fork are identical to the upstream. Scanning
them finds the same hits again, multiplies the number of API requests and makes the
report longer without new information.

| Goal | Option |
|---|---|
| Thorough audit, every copy of every file | `--forks all-branches` (with `--index-branches all`) |
| Good coverage without duplicates (recommended for audits) | `--forks branch-diff` (with `--index-branches all`) |
| Treat forks like any other project | `--forks include` (default) |
| Fast pass over original projects only, or forks are out of scope | `--forks skip` |

```bash
# Recommended: all branches of originals; for forks the default branch, the
# base branches and only the branches that differ from the upstream.
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt -b all --forks branch-diff --dump-projects

# Originals only
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt --forks skip
```

`branch-diff` compares every fork branch with the upstream branch of the same
name by the commit it points at: a branch is skipped only when both point at the
same commit, so a leak committed to a fork's copy of `feature/auth` is still found.
It needs an index with branches (`--index-branches all` or `N`); with the default
index it scans only the fork's default branch. An index built before 1.4.4 has no
commits and is compared by branch names (the `Search plan` says so); rebuild it
with `--dump-projects`. `--fork-diff-bases` (default
`main,master,develop,dev`) lists branches that are always scanned in forks,
because a fork often changes exactly those. Deduplication afterwards
(`-m dedup`) removes hits that still repeat across forks and branches.

## 8. Only fresh findings: time filters

Use `--started-from DATE` (alias of `--active-after`) when only recent changes matter: a regular re-scan after
a full baseline, a check after an incident, or a review of what changed during a
sprint. Projects without activity since the date are skipped without any API
request, which on large instances with many abandoned repositories saves most of
the time.

```bash
# Projects with activity since June 1st (midnight UTC)
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt --started-from 2024-06-01

# Since a moment in a given time zone
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt --started-from 2024-06-01T09:00:00+03:00
```

The `Search plan` line shows how many projects were left out:
`5 of 9 projects ... (skipped: 1 empty, 3 inactive since 2024-06-02)`.

A closed time range and the other levels:

```bash
# Index only projects active in June (GitLab filters the listing: a smaller, faster index)
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -m dump-index \
  --index-active-after 2024-06-01 --index-active-before 2024-06-30 --index-file june.jsonl

# Search a full index for projects active in June only
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt --active-after 2024-06-01 --active-before 2024-06-30

# Only hits in files that were changed in June (one commits API request per file with hits)
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt --file-changed-after 2024-06-01 --file-changed-before 2024-06-30

# All three at once
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt --time-after 2024-06-01 --time-before 2024-06-30 --dump-projects
```

The file filter narrows the report to files touched in the period, which is usually
what a "what leaked this month" review needs; the matched line itself may be older
than the change. An index built with a window holds only those projects: later runs
reuse it with a warning, so rebuild it (`--dump-projects`) before a full scan.
See [usage.md](usage.md#time-filters) for all details.

Keep in mind:

- `--started-from` works per **project**, by `last_activity_at`. Inside an active project
  every file of the selected branches is searched, including old ones; add
  `--file-changed-after` to keep only hits in files changed since the date.
- A secret committed long ago into a project that has been quiet since then is
  **not** reported. Run a full scan once as a baseline, then use `--started-from`
  for the re-scans.
- GitLab updates `last_activity_at` at most once per hour, and some events (for
  example, creating a branch or tag in the web UI) may not update it. Take the
  date with a margin, e.g. a day before the previous scan.

## 9. Parallel requests: --workers

`-w/--workers N` sends up to N API requests at a time and speeds up project
listing, branch listing and search almost N times. It is appropriate when the
instance has **no API rate limits** (often the case on self-managed GitLab) and the
scan has to finish quickly.

```bash
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt -b all --workers 8
```

The price grows in the same proportion:

- **Traffic and load.** N workers produce about N times more requests per second.
  Blob search is expensive for GitLab (Gitaly runs `git grep`), so many workers
  can noticeably load the instance.
- **Noise.** The API logs, monitoring, and IDS/WAF see N times more requests in
  the same time. In engagements where staying unnoticed matters, keep the default
  `--workers 1`.
- **Rate limits.** With a limit in place, more workers mostly mean more HTTP 429
  responses and waits (`Retry-After` is obeyed), not more speed. 5xx responses
  under load are logged and the affected branch is skipped.

Start with a small number (4) and increase gradually. Watch for 5xx warnings and
for rate limiting: the first HTTP 429 of a run is one warning, then the status line
counts them (`| HTTP 429 x190`) and the `Results` block ends with `rate limit  190 HTTP 429
responses, retried after 12:30 of waits in total` (`--debug` repeats the warning
instead). The results are the same as with one worker; only the order of
hit records in the session file differs. Details: [usage.md](usage.md#parallel-requests).

Under a known rate limit, or to keep the traffic low, cap the requests per minute
**per worker** instead: `--search-rpm` for search requests (GitLab limits them
separately and usually lower), `--index-rpm` for all other requests, `--rpm` for
both (a specific option overrides it):

```bash
# Search limit of 30 a minute: 2 workers x 15
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt -b all --workers 2 --search-rpm 15

# Low and slow: one worker, at most 10 requests a minute of any kind
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt --rpm 10

# No fixed rhythm: a random 0.5-3 s pause before every request, on top of the limit
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt --rpm 10 --jitter 0.5-3
```

Don't know the limit? Measure it (experimental): `-m find-limits` prints the `--workers`,
`--index-rpm` and `--search-rpm` to use, `--auto-limits` measures before the search,
offers the settings and, during the scan, proposes lower limits after HTTP 429
without stopping it (`[Limiter: L]` in the status line, `L` shows the proposal).
The probe provokes 429 on purpose, so it is noisy:

```bash
gitlab-harvester -m find-limits -u https://gitlab.example.com -t "$GITLAB_TOKEN"
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt -b all --auto-limits
```

Details: [usage.md](usage.md#finding-the-rate-limits--m-find-limits---auto-limits-experimental).

`--jitter` draws a new delay for every request, so the traffic doesn't come at the
fixed interval that `--rpm` alone produces (easy to spot in logs).

The User-Agent is the other obvious marker: by default every request says
`python-gitlab/<version>`. Send a browser string instead, fixed or a random one
per request from a file (one per line, `#` comments allowed):

```bash
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt --user-agent-file agents.txt --rpm 10 --jitter 0.5-3
```

All requests still carry the same token, so the User-Agent changes how the
traffic looks in logs, not whose requests they are.

Details: [usage.md](usage.md#request-rate-limits).

## 10. Red team: several tokens against a per-user rate limit

On an engagement you often end up with tokens from several accounts — phished,
pulled from a CI job, found in a dotfile, or simply shared across the team for the
assessment. When the instance rate-limits **per user** (GitLab's default for the
search API), one token caps your speed no matter how many `--workers` you add: the
extra workers just collect HTTP 429s. Spreading the same scan over several tokens
multiplies the budget, because each account is throttled on its own.

Pass the tokens with `-t` separated by `;`, or keep them in a file with
`--token-file` (one per line, `#` comments allowed — nicer than a long, shell-logged
command line):

```bash
# Three operators' tokens, 2 workers each = 6 concurrent clients.
# Each token is held to 20 search requests/min, so 60/min total, 20 per account.
gitlab-harvester -u https://gitlab.example.com -t "$T1;$T2;$T3" \
  -f words.txt -b all --forks branch-diff --workers 2 --search-rpm 20 --session engagement

# The same from a file kept out of the shell history
printf '%s\n' "$T1" "$T2" "$T3" > tokens.txt      # or hand-edit it
gitlab-harvester -u https://gitlab.example.com --token-file tokens.txt \
  -f words.txt -b all --forks branch-diff --workers 2 --search-rpm 20 --session engagement
```

The layering is `token -> workers per token -> rpm per worker`:

- `--workers` counts **per token**, so the run keeps `tokens × workers` clients busy
  (here `3 × 2 = 6`). The search plan line confirms it: `... 3 tokens x 2 workers =
  6 clients, rate limit: search 20/min per worker`.
- Every token has its **own** client-side budget (the `--*-rpm` limits are per client),
  so `--search-rpm 20` means 20/min *for each account*. Set it from the instance's
  per-user limit, not the total — three accounts stay under the radar individually
  while the scan runs three times faster.
- GitLab counts most rate limits **per user**, not per token: two tokens of the same
  account share one server-side budget and gain nothing. Use tokens of different
  accounts; `-m find-limits` (experimental) groups the tokens by user and says so.
- Tasks come from one shared queue, so the tokens balance themselves: if one account
  trips a 429 and waits, the others keep taking work instead of stalling the scan.

Operational notes for an engagement:

- Every token is checked at start-up; a revoked or mistyped one aborts the run before
  any scanning (`Token #2 of 3 failed to authenticate …`), so you don't burn half a
  scan on a dead token. Duplicate tokens are dropped.
- Tokens are **never** written to the session file, the log or the run journal — only
  their count (`tokens=3 inline`). The session stays safe to hand over as evidence.
- Each token sees only what its account can see. Overlapping accounts give the same
  findings faster; accounts in different groups also widen coverage. Deduplicate
  afterwards (`-m dedup`, [section 12](#12-deduplicated-json-report-in-one-run---post-process))
  to collapse the repeats.
- This stacks with the noise controls from [section 9](#9-parallel-requests---workers):
  `--jitter`, `--user-agent-file` and the rpm limits apply per client, so each token's
  traffic is paced and disguised on its own. Note that all requests from one token
  still carry that token — rotating User-Agents changes how the traffic *looks*, not
  *whose* it is.

```bash
# Low and slow across three tokens: each account trickles requests, with jitter
# and a rotating User-Agent, so no single account stands out.
gitlab-harvester -u https://gitlab.example.com --token-file tokens.txt \
  -f words.txt -b all --rpm 10 --jitter 0.5-3 --user-agent-file agents.txt --session quiet
```

## 11. Baseline and re-scans

```bash
# 1. Baseline: everything, fresh index with all branches (parallel if the instance allows it)
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt \
  --index-file gitlab_index.jsonl -b all --forks branch-diff --dump-projects --workers 4 --session baseline
gitlab-harvester -m dedup --input-file baseline.jsonl --output-file baseline.clean.jsonl

# 2. Every week: refresh the index, search only projects active since the previous run
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt \
  --index-file gitlab_index.jsonl -b all --forks branch-diff --dump-projects --started-from 2024-06-24 --session week-26

# 3. Interrupted? Repeat the command with the same session and --resume (without --dump-projects)
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt \
  --index-file gitlab_index.jsonl -b all --forks branch-diff --started-from 2024-06-24 --session week-26 --resume
```

## 12. Deduplicated JSON report in one run: --post-process

The same secret usually shows up many times: in every branch, in every fork, for
several terms. Instead of running `-m dedup` and `-m convert` after the search, ask
for them in the search command:

```bash
# Keep everything: the raw session, the deduplicated JSONL and the JSON report
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt -b all --forks branch-diff \
  --session audit --post-process dedup,convert
# -> audit.jsonl, audit.deduped.jsonl, audit.deduped.converted.json

# Keep only the final JSON report (saves space)
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt -b all --forks branch-diff \
  --session audit --post-process dedup,convert --final-only
# -> audit.deduped.converted.json
```

When to keep all files (the default):

- the raw session is the evidence: every place where a secret occurs, including
  duplicates in other branches and forks, is what has to be cleaned up;
- the session can still be resumed (`--resume`) or post-processed again with other
  options (`--no-normalize-hits`, another `--hash-algo`).

When `--final-only` fits: large scans where only the report matters, automated runs
that hand one file to another tool, or little disk space. The original JSONL is
deleted, so the run can't be resumed or deduplicated differently later. Nothing is
deleted if the search is interrupted or a step fails.

Only one step is fine too: `--post-process dedup` (JSONL without duplicates) or
`--post-process convert` (a JSON array of the raw session).

## 13. History of runs in a log file

Pass the same `--log-file` to every run. Whatever `--log-level` is, each run appends
a summary: options, index file and its build time, search plan, projects, hits and
time per term, written files, total duration and outcome.

```bash
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt -b all \
  --started-from 2024-06-01 --session june --log-file audits.log

# Later: how long did the searches take, with which options, and what did they find?
grep -E "Options:|Search plan:|Search finished:|Run (finished|failed)" audits.log
grep "Term " audits.log            # hits and time per term over all runs
grep "run 2f3724f3" audits.log     # everything about one run
```

The run id (`[run 2f3724f3]`) ties together the lines of one run. Use it to compare
filters (`--forks`, time windows, `--workers`) against duration and number of hits.
Details: [usage.md](usage.md#run-journal).

## 14. Optional: options from a config file

Any of the options above can also be put into an INI file and passed with
`-c/--config FILE`. Options given on the command line override the values from the file:

```bash
gitlab-harvester -c audit.ini
gitlab-harvester -c audit.ini --forks skip --started-from 2024-06-24
```

[config.example.ini](../config.example.ini) in the repository lists every option with
its values and defaults. The file format and precedence rules are described in
[usage.md](usage.md#configuration-file).
