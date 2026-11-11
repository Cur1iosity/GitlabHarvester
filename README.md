<div align="center">

# GitlabHarvester

[![Tests](https://img.shields.io/github/actions/workflow/status/Cur1iosity/GitlabHarvester/tests.yml?branch=main&event=push&label=tests)](https://github.com/Cur1iosity/GitlabHarvester/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/gitlab-harvester)](https://pypi.org/project/gitlab-harvester/)
[![Python](https://img.shields.io/pypi/pyversions/gitlab-harvester)](https://pypi.org/project/gitlab-harvester/)
[![License](https://img.shields.io/github/license/Cur1iosity/GitlabHarvester)](LICENSE)
[![Downloads](https://static.pepy.tech/badge/gitlab-harvester)](https://pepy.tech/projects/gitlab-harvester)
[![Last commit](https://img.shields.io/github/last-commit/Cur1iosity/GitlabHarvester/main)](https://github.com/Cur1iosity/GitlabHarvester/commits/main/)

</div>

**GitlabHarvester** is a lightweight tool built to install in a minute and show impact fast.
It searches every repository of a GitLab instance for keywords and secrets through the API,
without cloning, including GitLab CE, which has no instance-wide code search.

- **Red team engagements.** One token, the whole instance: credentials, internal hosts
  and pivots hiding in the code. Loud and fast or low and slow, your call: rate limits,
  jitter and User-Agent rotation keep the noise and the signature under control.
- **Penetration tests.** Instance-wide discovery of credentials, tokens and keys as part
  of the assessment.
- **Blue teams and security research.** Secret hunting and hygiene audits: a quick first
  look, full baselines, regular re-scans of recent activity, deduplicated reports, and a
  history of runs in the log file.
- **Developers, analysts and architects.** Not for secrets, but for code: fast search
  across a large codebase, even on GitLab CE.

<p align="center">
  <img src="https://raw.githubusercontent.com/Cur1iosity/GitlabHarvester/demo-assets/demo.gif"
       alt="GitlabHarvester run: project index, search plan, per-term progress and results" width="900">
</p>

## Install

```bash
pipx install gitlab-harvester    # or: pip install gitlab-harvester
```

Requires Python 3.10+ and a GitLab token with the `read_api` scope.

## Quick start

Search one term in the default branch of every project:

```bash
export GITLAB_TOKEN = "your-token-here"
gitlab-harvester -u https://gitlab.example.com -t "$GITLAB_TOKEN" -s password
```

The first run builds a project index (`<host>_project_index.jsonl`), and later runs reuse it.
Hits are written to a JSONL session file as they are found.

Lists of terms, all branches and forks, fresh findings only, resuming, parallel requests
and rate limits, deduplicated reports, config files:
**[docs/USE_CASES.md](docs/USE_CASES.md)**.

## Common options

| Option | Purpose |
|---|---|
| `-b, --branches default\|all\|N` | branches to index and search |
| `--forks include\|skip\|branch-diff\|all-branches` | how forks are handled |
| `--time-after DATE`, `--time-before DATE` | limit the index, its projects and the files with hits to a time window |
| `--started-from 2024-06-01` | search only indexed projects with activity since the date |
| `-w, --workers N` | parallel API requests, for instances without rate limits |
| `--rpm N`, `--index-rpm N`, `--search-rpm N` | requests per minute per worker: all, non-search, search |
| `--jitter 0.01-0.05` | random delay before every request (seconds, or `10ms-50ms`) |
| `-A STRING`, `--user-agent-file FILE` | fixed User-Agent, or a random one from the file for every request |
| `-m dump-index`, `--dump-projects` | build or rebuild the project index |
| `--session NAME`, `--resume` | name a session and continue it later |
| `--post-process dedup,convert`, `--final-only` | deduplicate and convert the session right after the search |
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
Debian/Kali packaging readiness: [docs/packaging.md](docs/packaging.md).

## License

MIT. Use it only on GitLab instances you are authorized to work with: your own, your
organization's, or those within the scope of an agreed engagement.
