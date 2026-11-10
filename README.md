<div align="center">

# GitlabHarvester

[![PyPI](https://img.shields.io/pypi/v/gitlab-harvester)](https://pypi.org/project/gitlab-harvester/)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/github/license/Cur1iosity/GitlabHarvester)

</div>

Search for keywords and secrets across every repository of a GitLab instance through the API,
without cloning. Useful on GitLab CE, which has no instance-wide code search.

## Install

```bash
pipx install gitlab-harvester    # or: pip install gitlab-harvester
```

Requires Python 3.10+ and a GitLab token with the `read_api` scope.

## Quick start

```bash
export GITLAB_TOKEN=...

# Search one term in the default branch of every project
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -s password

# Search a list of terms in all branches, skipping branches forks share with their upstream.
# --dump-projects rebuilds the index so it includes all branch names.
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt -b all --forks branch-diff --dump-projects --session audit

# Search only repositories with activity on or after a date, e.g. a weekly re-scan.
# Projects inactive since then are skipped without API calls; in active ones every file is searched.
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt -b all --started-from 2024-06-01 --session since-june

# Continue after an interruption (reuses the index)
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -f words.txt -b all --forks branch-diff --session audit --resume

# Optional: options can also come from a config file (see config.example.ini); CLI arguments override it
gitlab-harvester -c config.ini -s token

# Remove duplicate hits and export as a JSON array
gitlab-harvester -m dedup   --input-file audit.jsonl --output-file clean.jsonl
gitlab-harvester -m convert --input-file clean.jsonl --output-file clean.json
```

More scenarios, and when to use which options (index-only export, fork strategies,
fresh findings only, parallel requests, baseline and re-scans):
**[docs/USE_CASES.md](docs/USE_CASES.md)**.

The first run builds a project index (`<host>_project_index.jsonl`), and later runs reuse it.
Branch options take effect when the index is built; add `--dump-projects` after changing them.
Hits are written to a JSONL session file as they are found.

Common options:

| Option | Purpose |
|---|---|
| `-b, --branches default\|all\|N` | branches to index and search |
| `--forks include\|skip\|branch-diff\|all-branches` | how forks are handled |
| `--time-after DATE`, `--time-before DATE` | limit the index, its projects and the files with hits to a time window |
| `--started-from 2024-06-01` | search only indexed projects with activity since the date |
| `-w, --workers N` | parallel API requests, for instances without rate limits |
| `-m dump-index`, `--dump-projects` | build or rebuild the project index |
| `--session NAME`, `--resume` | name a session and continue it later |
| `-c, --config FILE` | read options from an INI file ([config.example.ini](config.example.ini)) |

See [docs/usage.md](docs/usage.md) for every option, branch and fork strategies, and the output formats,
and [docs/USE_CASES.md](docs/USE_CASES.md) for typical scenarios.

## Development

```bash
git clone https://github.com/Cur1iosity/GitlabHarvester.git && cd GitlabHarvester
pip install -r requirements-dev.txt -e .
pytest
```

The tests and local runs use a bundled Fake GitLab API, so they need no real instance:

```bash
python -m fakegitlab
gitlab-harvester -u http://127.0.0.1:8080 -t dev-token -s password -b all
```

Details: [docs/testing.md](docs/testing.md), [docs/architecture.md](docs/architecture.md).

## License

MIT. Use only on GitLab instances you are authorized to scan.
