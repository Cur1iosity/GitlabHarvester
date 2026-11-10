# Development & testing with the Fake GitLab

GitlabHarvester ships a **Fake GitLab REST API v4** (`fakegitlab/`) for local
development and automated tests. It needs no real GitLab, no database and no
real tokens. Background and design rationale: [architecture.md](architecture.md).

- [Quick start](#quick-start)
- [Running the Fake GitLab](#running-the-fake-gitlab)
- [Using the real CLI against it](#using-the-real-cli-against-it)
- [Scenarios (test data)](#scenarios-test-data)
- [Fault injection](#fault-injection)
- [Diagnostics: request journal & admin API](#diagnostics-request-journal--admin-api)
- [Running the tests](#running-the-tests)
- [Writing tests](#writing-tests)
- [Extending the Fake GitLab](#extending-the-fake-gitlab)
- [Keeping the contract up to date](#keeping-the-contract-up-to-date)
- [CI](#ci)

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt -e .

pytest                                            # unit + integration + e2e (~1 min)

python -m fakegitlab                              # Fake GitLab on http://127.0.0.1:8080
gitlab-harvester -u http://127.0.0.1:8080 -t dev-token -s password -b all
```

## Running the Fake GitLab

**Plain Python** (fastest; no Docker):

```bash
python -m fakegitlab --scenario default --port 8080
python -m fakegitlab --list-scenarios
python -m fakegitlab --scenario path/to/my-scenario.yaml --port 0   # random port
```

Options can also be set through environment variables: `FAKE_GITLAB_HOST`,
`FAKE_GITLAB_PORT`, `FAKE_GITLAB_SCENARIO`, `FAKE_GITLAB_EXTERNAL_URL`,
`FAKE_GITLAB_LOG_LEVEL`. Stop it with `Ctrl+C`. Every request is logged to
stderr; requests to unimplemented endpoints are logged as `UNMATCHED`.

**Docker Compose**:

```bash
mkdir -p .dev/work .dev/scenarios
docker compose up -d --build --wait fake-gitlab        # http://127.0.0.1:8080
FAKE_GITLAB_SCENARIO=large docker compose up -d --wait fake-gitlab   # another dataset
docker compose logs -f fake-gitlab                     # request log
docker compose --profile cli down                      # stop
```

`make fake-up`, `make fake-logs` and `make fake-down` do the same. Built-in
scenarios are bind-mounted, so editing a YAML file only needs
`POST /__admin/reset` (or a container restart), not a rebuild. Put private
scenarios into `.dev/scenarios/` (git-ignored).

**Credentials**: the URL is wherever the server listens. Valid tokens are
defined per scenario. All built-in scenarios accept `dev-token`;
`default` also accepts `readonly-token`. Any other token gets `401`.

## Using the real CLI against it

On the host:

```bash
gitlab-harvester -u http://127.0.0.1:8080 -t dev-token -m dump-index --index-branches all
gitlab-harvester -u http://127.0.0.1:8080 -t dev-token -f terms.txt -b all --forks branch-diff --session audit
gitlab-harvester -m dedup --input-file audit.jsonl --output-file clean.jsonl
```

Inside Docker (output lands in `.dev/work/`):

```bash
docker compose run --rm harvester -s password -b all --session-file s.jsonl
make cli ARGS="-s password --forks skip"
```

The `harvester` service is preconfigured with `GLH_URL=http://fake-gitlab:8080`
and `GLH_TOKEN=dev-token`.

## Scenarios (test data)

Scenarios live in `fakegitlab/scenarios/*.yaml`. Extra directories can be
added with `FAKE_GITLAB_SCENARIO_PATH` (`os.pathsep`-separated); those are searched first.
All data is artificial. "Secrets" use a `FAKE-…` marker and intentionally match
no real token formats.

| Scenario | Content |
|---|---|
| `default` | 9 projects: regular, forks, empty repo, special characters (see below) |
| `empty` | valid token, no projects |
| `large` | `default` + 250 generated projects with 3 branches each (pagination, performance) |
| `flaky` | `default` + 429 with `Retry-After`, 503 on branches, a slow search, malformed JSON |

### Default scenario

| ID | Project | Branches (default **bold**) | Purpose |
|---|---|---|---|
| 101 | `acme/backend/api-service` | develop, feature/login-v2, **main**, release/1.0+hotfix | Several branches; the same finding in every branch |
| 102 | `acme/backend/payments` | **main** | Matches only `FAKE-token` |
| 103 | `acme/frontend/web-app` | fix/#42-login, **master**, ünïcode-ветка | Special characters in branches, paths (`docs/setup guide.md`) and terms (`p@ss w0rd!`, `$SECRET_VAR`, `"quoted"`, `ключ`) |
| 104 | `acme/empty-repo` | — | Empty repository (`empty_repo: true`, `default_branch: null`) |
| 105 | `sandbox/notes` | **main** | No matches for any test term |
| 201 | `alice/api-service` | alice/experiment, develop, feature/login-v2, **main** | Fork of 101: one fork-unique branch; `feature/login-v2` identical to upstream |
| 202 | `bob/web-app-fork` | feature/bob, **master** | Fork of 103 with a unique branch |
| 203 | `carol/orphan-fork` | carol/wip, develop, **main** | Fork of a project that isn't visible (`forked_from_project.id = 999`) |
| 301 | `ops/infra/terraform/modules` | **main** | Deep namespace; several matches in one file (2 result chunks) |

Reference results for `password` (asserted by the e2e tests):

| CLI options | Hits | Distinct snippets after `dedup` |
|---|---|---|
| default (`--branches default`) | 9 | — |
| `-b all --forks include` / `all-branches` | 29 | 8 |
| `-b all --forks branch-diff` | 26 | — |
| `-b all --forks skip` | 14 | — |

With `--started-from` (filter on `last_activity_at`; see the table above for dates:
101 → 2024-06-01 12:00Z, 102 → 05-20, 103 → 06-15, 104 → 02-01, 105 → 02-03,
201 → 06-02, 202 → 06-03, 203 → 06-04, 301 → 06-05):

| `-s password --started-from …` | Active projects | Hits |
|---|---|---|
| `2024-06-02` | 5 of 9 (103, 201, 202, 203, 301) | 7 |
| `2024-06-03T00:00:00+03:00` | 4 of 9 | 5 |
| `2030-01-01` | 0 of 9 | 0 |

`tests/helpers.py` keeps these expectations in one place.

### Scenario format

```yaml
name: my-scenario
description: What this dataset is for.
extends: default                # optional: start from another scenario
remove_projects: [105]          # optional, with extends

instance:                       # all optional
  external_url: null            # base for web_url/Link (default: request Host)
  default_per_page: 20
  max_per_page: 100
  count_limit: 10000            # above it X-Total/X-Total-Pages are omitted
  search_context_lines: 2       # Gitaly git grep context before/after a match
  search_path_matches: true     # also return files whose path contains the term

users:
  - {id: 1, username: harvester-bot, tokens: [dev-token]}

projects:
  - id: 500                     # same id as in the base scenario = replace
    path_with_namespace: team/sub/app
    default_branch: main        # default: first listed branch; null if no branches
    visibility: private
    created_at: "2024-01-01T00:00:00.000Z"
    forked_from: 101            # or {id: 999, path_with_namespace: hidden/x} (invisible upstream)
    branches:
      main:
        files:
          "config/app.yml": |
            password: FAKE-...
          "deploy/old.env":       # a mapping sets the file's last change time
            updated_at: "2024-01-20T10:00:00.000Z"   # default: the project's last_activity_at
            content: |
              DB_PASSWORD=change-me
      develop:
        inherit: main           # copy files of another branch …
        files: {extra.txt: "…"} # … then add/override
        delete: [config/app.yml]
      feature/x:
        inherit: "101:main"     # branch of another project (typical for forks)

generate:                       # deterministic bulk projects
  - count: 100
    start_id: 2000
    project:
      path_with_namespace: "bulk/svc-{n:03d}"     # {n} = 1..count, {id} = project id
      branches: {main: {files: {"a.txt": "token {n}\n"}}}   # literal braces: {{ }}

faults: []                      # see below
```

The loader validates the document: unique ids, existing `default_branch`,
resolvable `inherit` (no cycles), known `forked_from`, and known `instance` keys.
Errors name the offending project.

## Fault injection

Rules can be declared in a scenario (`faults:`), added in tests
(`fake_gitlab.add_fault({...})`) or added at runtime
(`POST /__admin/faults`). They're evaluated in order; delays add up, and the
first rule with a response wins.

```yaml
- name: projects-page-2-fails
  match:
    method: GET
    path: "^/api/v4/projects$"      # regex on the raw (still URL-encoded) path
    query: {page: "2"}              # exact match; "*" = parameter present
    headers: {PRIVATE-TOKEN: "*"}
  after: 0                          # let the first N matching requests through
  times: 1                          # apply N times (default: forever)
  response:
    status: 429                     # 401/403/404/429/500/502/503 …
    headers: {Retry-After: "0"}
    json: {message: "Retry later"}
    # body: "<html>not json</html>" # raw body (malformed JSON, HTML error pages)
    # delay: 1.5                    # delay only (no status) = slow but successful
```

Useful patterns:

| Need | Rule |
|---|---|
| Error on an intermediate page | `query: {page: "2"}` + `status: 500` |
| Rate limit with recovery | `status: 429`, `headers: {Retry-After: "0"}`, `times: 1` |
| Client timeout | `response: {delay: 3}` + harvester `--timeout 1` |
| Malformed JSON | `status: 200`, `body: "{broken"` |
| Token revoked mid-run | `match: {path: "/search$"}`, `after: 5`, `status: 401` |

Delays are interruptible: `reset()`/`stop()` releases pending delayed requests
immediately, so tests never wait out a long delay.

## Diagnostics: request journal & admin API

`/__admin/*` endpoints are not part of GitLab and are not journaled.

| Endpoint | Action |
|---|---|
| `GET /__admin/health` | Liveness probe |
| `GET /__admin/requests` | Request journal: method, path, query, headers (tokens redacted), status, endpoint, applied faults, duration |
| `DELETE /__admin/requests` | Clear the journal |
| `POST /__admin/reset` | Reload the current scenario, restore its faults, clear the journal |
| `GET /__admin/scenario` | Current scenario, token, available scenarios |
| `POST /__admin/scenario` `{"name": "large"}` | Switch scenario (implies reset) |
| `GET/POST/DELETE /__admin/faults` | List / add / clear fault rules |

```bash
curl -s localhost:8080/__admin/requests | python -m json.tool
curl -s -X POST localhost:8080/__admin/scenario -d '{"name": "flaky"}'
curl -s -X POST localhost:8080/__admin/faults \
     -d '{"match": {"path": "/projects/101/search$"}, "response": {"status": 503}}'
```

In tests, use `fake_gitlab.requests`, `fake_gitlab.api_requests(endpoint, path=regex)`
and `fake_gitlab.unmatched_requests()` instead.

## Running the tests

| Command | What runs |
|---|---|
| `pytest` | unit + integration + e2e (contract tests excluded) |
| `pytest -m unit` | `tests/unit` + `tests/fakeserver`: no sockets, ~2 s |
| `pytest -m integration` | real python-gitlab → in-process Fake GitLab |
| `pytest -m e2e` | `python -m gitlab_harvester` subprocesses → Fake GitLab |
| `pytest -m contract tests/contract` | optional, real GitLab (see below) |
| `pytest -k resume -vv` | anything matching a name |

Markers are assigned automatically from the directory. The `make test*` targets
are thin aliases.

Guarantees built into `tests/conftest.py`:

- **No real network.** In-process tests fail immediately on a connection to a
  non-loopback address, and proxy variables are removed. CLI subprocesses only
  ever get the fake's URL.
- **Isolation.** One server per session; `reset()` before each test (scenario,
  faults, journal, ad-hoc handlers). Exceptions raised inside the fake fail the
  test that caused them.
- **No long waits.** `no_retry_sleep` turns python-gitlab's `Retry-After` sleeps
  into recorded values. Timeout tests use `timeout=1` with a 3 s delay.
- **Cleanup.** All files are created under pytest's `tmp_path`. Nothing is
  written to the working tree.

## Writing tests

```python
import pytest

@pytest.mark.scenario("default")           # optional; "default" is the default
def test_something(fake_gitlab, make_harvester, run_cli, tmp_path, no_retry_sleep):
    fake_gitlab.add_fault({"match": {"path": "/projects/301/search$"},
                           "response": {"status": 500, "json": {"message": "500"}}})

    glh = make_harvester()                 # GitlabHarvester bound to the fake
    ...
    proc = run_cli("-u", fake_gitlab.url, "-t", fake_gitlab.token, "-s", "password",
                   "--session-file", "s.jsonl", check=True)   # cwd = tmp_path
    session = Session.load(tmp_path / "s.jsonl")              # tests/helpers.py
    assert [r.arg("ref") for r in fake_gitlab.api_requests("project_search")]
```

- Inline datasets: `fake_gitlab.reset({"extends": "default", "projects": [...]})`.
- One-off raw responses:
  `fake_gitlab.httpserver.expect_oneshot_request("/api/v4/user").respond_with_json(...)`
  (takes precedence over the data-driven API).
- Unit tests that need a client-like object without HTTP: see the stubs in
  `tests/unit/test_harvester_offline.py`.

## Extending the Fake GitLab

**New endpoint** (when GitlabHarvester starts using one):

1. Add a route to `GitLabApi._routes` in `fakegitlab/api.py`, and an
   `_ep_<name>(self, request, base_url, user, **path_params)` method. Use
   `self._paginate(...)` for list endpoints and `ApiError(status, message)` for errors.
2. If needed, add a serializer that only produces fields real GitLab returns.
3. Add WSGI-level tests in `tests/fakeserver/test_fake_api.py` and extend
   `EXPECTED_ENDPOINTS` in `tests/integration/test_client_contract.py`.
4. Add a contract check in `tests/contract/test_real_gitlab.py`.
5. Update the tables in [architecture.md §5](architecture.md#5-gitlab-api-contract-used-by-gitlabharvester).

**New scenario**: drop a YAML file into `fakegitlab/scenarios/` (shared) or
`.dev/scenarios/` (private). Prefer `extends: default` plus a few projects or
faults over copying data. If tests depend on its numbers, put the expectations
in `tests/helpers.py`.

## Keeping the contract up to date

When GitLab or python-gitlab changes:

1. **python-gitlab upgrade**: bump the pin in `requirements-dev.txt` and run
   `pytest -m integration`. `test_full_workflow_uses_only_known_endpoints_and_parameters`
   fails if the library starts sending different requests or parameters.
2. **GitLab behavior**: run the contract suite against a real instance with a
   read-only token:

   ```bash
   export GLH_CONTRACT_URL=https://gitlab.example.com GLH_CONTRACT_TOKEN=...   # read_api
   export GLH_CONTRACT_PROJECT=group/project GLH_CONTRACT_TERM=README
   pytest -m contract tests/contract -v
   ```

   It checks the response fields and pagination headers the harvester relies
   on. It also fails if the fake emits fields that real GitLab doesn't.
3. Adjust `fakegitlab/api.py` serializers or behavior, then the
   documentation in [architecture.md](architecture.md).

The contract job in CI runs only on manual dispatch with repository secrets
(`GLH_CONTRACT_*`), and it never blocks the main pipeline.

## CI

`.github/workflows/tests.yml` runs on every pull request and push to `main`/`master`:

| Job | Matrix | Content |
|---|---|---|
| `unit` | Ubuntu + Windows × Python 3.10–3.14 | `pytest -m unit` |
| `integration` | Ubuntu + Windows × Python 3.10, 3.14 | `pytest -m integration`, `pytest -m e2e` |
| `docker` | Ubuntu | `docker compose up --wait`, real CLI in the `harvester` container, check of the output files |
| `contract` | manual only | `pytest -m contract` against secrets-configured GitLab (non-blocking) |
| `demo gif` (`demo-gif.yml`) | published release; manual | records the README demo GIF with VHS and force-pushes it to the `demo-assets` branch |

Dependencies are pinned in `requirements-dev.txt`. Every job runs the same
commands documented above, so a CI failure reproduces locally with
`pip install -r requirements-dev.txt -e . && pytest -m <layer>`.
