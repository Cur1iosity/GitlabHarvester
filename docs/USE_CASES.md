# GitlabHarvester use cases

Typical scenarios and which options fit them. For the full option reference see
[usage.md](usage.md).

- [1. Export the project inventory only](#1-export-the-project-inventory-only)
- [2. Forks: scan them or not](#2-forks-scan-them-or-not)
- [3. Only fresh findings: time filters](#3-only-fresh-findings-time-filters)
- [4. Parallel requests: --workers](#4-parallel-requests---workers)
- [5. Baseline and re-scans](#5-baseline-and-re-scans)
- [6. Deduplicated JSON report in one run: --post-process](#6-deduplicated-json-report-in-one-run---post-process)
- [7. History of runs in a log file](#7-history-of-runs-in-a-log-file)
- [8. Optional: options from a config file](#8-optional-options-from-a-config-file)

All examples pass the options on the command line; that is the main way to run the tool.

## 1. Export the project inventory only

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
build time, and `is_completed` (false if the listing stopped on an API error).

The same file serves later searches: pass it with `--index-file` and it is reused
as is (add `--dump-projects` to rebuild it).

## 2. Forks: scan them or not

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
# base branches and only the branches that the upstream doesn't have.
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt -b all --forks branch-diff --dump-projects

# Originals only
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt --forks skip
```

`branch-diff` compares branch *names* with the upstream, so it needs an index
with branches (`--index-branches all` or `N`); with the default index it scans
only the fork's default branch. `--fork-diff-bases` (default
`main,master,develop,dev`) lists branches that are always scanned in forks,
because a fork often changes exactly those. Deduplication afterwards
(`-m dedup`) removes hits that still repeat across forks and branches.

## 3. Only fresh findings: time filters

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

## 4. Parallel requests: --workers

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

Start with a small number (4), watch the warnings for 429 and 5xx responses, and
increase gradually. Under a known rate limit, cap the requests instead:
`--search-rpm` / `--index-rpm` (or `--rpm` for both) set requests per minute per
worker, e.g. `--workers 2 --search-rpm 15` for a search limit of 30 a minute. The results are the same as with one worker; only the order of
hit records in the session file differs. Details: [usage.md](usage.md#parallel-requests).

## 5. Baseline and re-scans

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

## 6. Deduplicated JSON report in one run: --post-process

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

## 7. History of runs in a log file

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

## 8. Optional: options from a config file

Any of the options above can also be put into an INI file and passed with
`-c/--config FILE`. Options given on the command line override the values from the file:

```bash
gitlab-harvester -c audit.ini
gitlab-harvester -c audit.ini --forks skip --started-from 2024-06-24
```

[config.example.ini](../config.example.ini) in the repository lists every option with
its values and defaults. The file format and precedence rules are described in
[usage.md](usage.md#configuration-file).
