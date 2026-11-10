# Packaging for Debian and Kali

GitlabHarvester is kept ready to be packaged for Kali Linux and Debian with
dh-python/pybuild. The upstream repository doesn't ship a `debian/` directory:
packaging lives in the distribution's repository (for Kali,
`gitlab.com/kalilinux/packages/<package>`). Upstream guarantees what a package build
needs: the tests and the build pass with the distribution's `python3-*` packages
only, without network.

## What CI checks

`.github/workflows/debian.yml` runs on every pull request and push to `main`/`dev`,
for `kalilinux/kali-rolling` and `debian:testing`. It builds
`packaging/debian/Dockerfile` (all Python dependencies from apt) and runs
`packaging/debian/check.sh` in a container with `--network none`:

1. the whole test suite (`python3 -m pytest`) with the distribution's packages;
2. the sdist and wheel with the distribution's build tools (`python3 -m build --no-isolation`);
3. the wheel installed over the system packages, and `pip check`: the versions shipped by
   the distribution satisfy the requirements in `pyproject.toml`;
4. `gitlab-harvester -V` and `gitlab-harvester -h` from the installed package.

Run it locally:

```bash
docker build -f packaging/debian/Dockerfile --build-arg BASE=kalilinux/kali-rolling -t glh-kali .
docker run --rm --network none -v "$PWD:/src:ro" glh-kali
```

## Dependencies

| `pyproject.toml` | Debian/Kali package | Kali rolling / Debian testing | Debian 13 (trixie) |
|---|---|---|---|
| `python-gitlab>=8.0.0` | `python3-gitlab` | 8.0.0 | 4.9.0: too old |
| `requests>=2.32.0` | `python3-requests` | 2.34.2 | 2.32.3 |
| tests: `pytest` | `python3-pytest` | 9.1.1 | 8.3.5 |
| tests: `pytest-httpserver` (Werkzeug) | `python3-pytest-httpserver`, `python3-werkzeug` | 1.1.3, 3.1.9 | 1.1.3, 3.1.3 |
| tests: `PyYAML` | `python3-yaml` | 6.0.3 | 6.0.2 |
| tests: `trustme` | `python3-trustme` | 1.3.0 | 1.2.1 |
| build: `setuptools>=77` | `python3-setuptools` | 84 | 78.1.1 |

Versions as checked in November 2026. Debian 13 (trixie) can't take the package as
is: its `python3-gitlab` is older than the required 8.0.0.

## Notes for the package

- **Source:** package a tagged release from the GitHub tag tarball
  (`https://github.com/Cur1iosity/GitlabHarvester/tags`). It contains the tests and
  the Fake GitLab they need; the PyPI sdist is meant for installation.
- **Build:** pyproject-based setuptools build, so the usual pybuild rules work:

  ```make
  #!/usr/bin/make -f
  export PYBUILD_NAME = gitlab-harvester

  %:
  	dh $@ --with python3 --buildsystem=pybuild
  ```

- **Build-Depends:** `debhelper-compat (= 13), dh-python, pybuild-plugin-pyproject,
  python3-all, python3-setuptools, python3-gitlab, python3-requests, python3-pytest,
  python3-pytest-httpserver, python3-werkzeug, python3-yaml, python3-trustme`.
  **Depends:** `${python3:Depends}, ${misc:Depends}` (`python3-gitlab`, `python3-requests`).
- **Tests during the build:** pytest picks up its configuration from `pyproject.toml`.
  Tests use only the loopback interface (a local Fake GitLab, a local HTTPS server with
  a throwaway CA) and fail fast on any other address, so they work without network.
  Tests that need a real GitLab (`-m contract`) are deselected by default.
- **autopkgtest:** a smoke test is enough to start with:

  ```
  Test-Command: gitlab-harvester -h
  Restrictions: superficial
  ```

- **Not shipped in the package:** `fakegitlab/`, `tests/`, `docs/` (the wheel contains
  only `glh/` and `gitlab_harvester.py`).
- There is no man page yet; `gitlab-harvester -h` is the full option reference.
