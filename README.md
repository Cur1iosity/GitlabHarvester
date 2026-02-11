# GitlabHarvester

**Global term search across an entire GitLab instance — especially useful for GitLab CE.**

GitLab Community Edition does not provide instance‑wide code search the way GitLab EE can.  
**GitlabHarvester** fills this gap: it builds a lightweight **Instance Project Index (JSONL/NDJSON)** and performs term search across repositories **without cloning** them.

The tool is conceptually similar to utilities like *gitlab-finder* (Node.js), but implemented in modern Python with streaming output, branch planning and resumable sessions.

---

## Why this tool matters

- GitLab CE → no global code search  
- Web UI search → limited and unreliable  
- Cloning thousands of repos → slow & disk heavy  

**GitlabHarvester** lets you search the whole instance using only the API.

---

## Features

- ✅ **Instance‑wide keyword search** for GitLab CE  
- ✅ **No cloning required** — API based  
- ✅ **Project Index (JSONL/NDJSON)** for repeatable runs  
- ✅ Branch strategies:
  - `default` — scan only default branch (fast)
  - `all` — scan all indexed branches
  - `N` — scan up to N branches
- ✅ Fork strategies (explained below)
- ✅ **Session output + resume**
- ✅ Low memory footprint

---

## Requirements

- Python **3.11+**
- GitLab token with **read_api** permissions

---

## Installation

### Using pipx (recommended)
```bash
git clone https://github.com/Cur1iosity/GitlabHarvester.git
cd GitlabHarvester
pipx install .
```

or

```bash
pipx install git+https://github.com/Cur1iosity/GitlabHarvester.git
```

After that you can run the tool directly:

```bash
gitlab-harvester --help
```

### Classic pip install
```bash
git clone https://github.com/Cur1iosity/GitlabHarvester.git
cd GitlabHarvester
pip install .
```

or

```bash
pip install git+https://github.com/Cur1iosity/GitlabHarvester.git
```

---

## Quick Start (the index builds automatically)

You **do not need to build the project index manually**.  
When you run a search, the index is created on the fly if it does not exist.

### Search a single keyword

```bash
gitlab-harvester -H https://gitlab.example.com -t $TOKEN --search "password"
```

### Search using a file with keywords

```bash
gitlab-harvester -H https://gitlab.example.com -t $TOKEN --terms-file keywords.txt
```

### Build only the index (optional)

This step is useful only if you want to prepare the index in advance:

```bash
gitlab-harvester -H https://gitlab.example.com -t $TOKEN --dump-only
```

---

## Branch control

There are two independent controls:

- `--index-branches` — what branches are stored in the index  
- `--scan-branches` — what branches are actually scanned

### Examples

```bash
# Index only default branches, but scan up to 10
gitlab-harvester -H ... -t ... --scan-branches 10
```

```bash
# Store all branches and scan all
gitlab-harvester -H ... -t ... --index-branches all --scan-branches all
```

Shorthand:

```bash
gitlab-harvester -H ... -t ... --branches 10
```

---

## Fork strategies (important)

```bash
--forks skip|include|branch-diff|all-branches
```

### What they mean

- **skip**  
  Forked projects are completely ignored.  
  Good when forks are mostly duplicates and noise.

- **include**  
  Forks are treated like normal projects.  
  Simple and predictable but may rescan identical branches.

- **branch-diff** (recommended)  
  Smart mode:
  - always scans fork default branch  
  - scans base branches (`main, master, develop, dev`)  
  - scans only **branches unique to the fork** compared to upstream  
  → best signal/noise ratio.

- **all-branches**  
  Scan every branch of every fork — most exhaustive and slowest.

### Example

```bash
gitlab-harvester -H ... -t ...   --terms-file keywords.txt   --forks branch-diff   --fork-diff-bases main,master,develop,dev
```

---

## Session & resume

Results are written to JSONL session files.

```bash
gitlab-harvester -H ... -t ... --terms-file keywords.txt --session audit_run
```

Resume:

```bash
gitlab-harvester -H ... -t ... --terms-file keywords.txt --session-file audit_run.jsonl --resume
```

---

## Output

- **Project Index (JSONL)** — metadata + project entries  
- **Session file (JSONL)** — hits + checkpoints

---

## Usage
```bash
gitlab-harvester --help

usage: gitlab-harvester [-h] -H HOST -t TOKEN [-bs BATCH_SIZE] [--index-file INDEX_FILE] [--dump-projects] [--dump-only] [-b BRANCHES] [--index-branches INDEX_BRANCHES] [--scan-branches SCAN_BRANCHES]
                    [--branches-per-page BRANCHES_PER_PAGE] [--forks {skip,include,branch-diff,all-branches}] [--fork-diff-bases FORK_DIFF_BASES] [-s SEARCH | -f TERMS_FILE] [--session SESSION |
                    --session-file SESSION_FILE] [-o OUTPUT] [--resume]

Collect and use an Instance Project Index from a GitLab instance.

options:
  -h, --help            show this help message and exit
  -H, --host HOST       GitLab host (e.g., gitlab.example.com).
  -t, --token TOKEN     GitLab token with read_api permissions.
  -bs, --batch-size BATCH_SIZE
                        Projects per page for GitLab API requests (default: 100).
  --index-file INDEX_FILE
                        Path to Instance Project Index file (JSONL/NDJSON). Defaults to instance-specific name.
  --dump-projects       Rebuild the Instance Project Index even if it already exists.
  --dump-only           Only build the Instance Project Index and exit.
  -b, --branches BRANCHES
                        Shorthand for setting both --index-branches and --scan-branches.
  --index-branches INDEX_BRANCHES
                        Branch depth for building the Project Index: 'default' (store only default branch), 'all' (store all), or N limit.
  --scan-branches SCAN_BRANCHES
                        Branch scope for scanning: omit -> scan default only; 'all' -> scan all branches from index; N -> scan up to N branches (default + N-1).
  --branches-per-page BRANCHES_PER_PAGE
                        Branches per page for GitLab API requests (default: 100).
  --forks {skip,include,branch-diff,all-branches}
                        How to handle forked projects during search: skip (ignore forks), include (treat as regular projects), branch-diff (scan only base + unique branches vs upstream), all-branches (scan
                        every branch of forks).
  --fork-diff-bases FORK_DIFF_BASES
                        Comma-separated list of branch names always scanned in forks when --forks=branch-diff (default: main,master,develop,dev).
  -s, --search SEARCH   Single search term.
  -f, --terms-file TERMS_FILE
                        File with search terms (one per line).
  --session SESSION     Session name for results output (writes <name>.jsonl).
  --session-file SESSION_FILE
                        Explicit path for session results file (JSONL).
  -o, --output OUTPUT   Output file for results (optional).
  --resume              Resume search using an existing session file (if supported).
```

## Useful notes

### Deduplicate results (context unique)

Search across forks and mirrors often produces context duplicates — identical file fragments that appear in multiple repositories or branches.
Removing them is useful when:

you only need to confirm the fact of presence of a secret/keyword,

the same leaked token appears in dozens of forks,

you want to reduce a 1–5 GB session file to a human-reviewable size.

The dedup script keeps only one record per unique content, while preserving the original JSONL structure.

What it does:

- hashes normalized search content,
- keeps the first occurrence,
- drops identical matches from other projects/branches.

Run:
```bash
python scripts/dedup.py \
  --input session_20250312.jsonl \
  --output session_20250312_dedup.jsonl
```

Options:

--no-normalize — treat content strictly (no whitespace normalization)

--sqlite /path/db.sqlite — external store for very large files.

**This is not classic deduplication by location — different repositories are preserved, but identical content matches are unified.**

### Convert JSONL to JSON

Session files are stored as JSONL for streaming and resume support.
For manual analysis you may want a single JSON document.

Run:
```
python scripts/convert_jsonl_to_json.py \
  --input session_20250312_dedup.jsonl \
  --output session_20250312.json
 ```

The converter produces a compact minified JSON.
For readable formatting use jq:

```bash
jq . session_20250312.json > session_20250312_pretty.json
```
Why convert:
- easier browsing in editors,
- compatibility with SIEM/ETL tools,
- convenient diff between sessions.

## Security note

Use only on GitLab instances where you have authorization.

---

## License

MIT
