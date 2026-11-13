# README demo GIF

The README shows a GIF recorded with [VHS](https://github.com/charmbracelet/vhs) in a
container: `pipx install gitlab-harvester`, then the real CLI against the bundled Fake GitLab
(artificial data only) served as `https://gitlab.example.com`. Nothing is sent to a real GitLab.
`setup.sh` (sourced, not recorded) issues a certificate from a throwaway private CA and trusts it via
`REQUESTS_CA_BUNDLE`, so TLS is really verified and the recorded command needs no TLS flags.

`pipx install` runs for real, but offline: the image builds wheels of this checkout and its
dependencies, and pip is pointed at them (`PIP_NO_INDEX`, `PIP_FIND_LINKS`). So the GIF shows
the version of the checkout, not whatever is on PyPI at recording time.

| File | Purpose |
|---|---|
| `demo.tape` | what is typed; waits for the output (`Wait /done!/`, `Wait /Done\. Keywords/`) instead of fixed pauses |
| `demo.yaml` | Fake GitLab scenario: the default dataset plus ~90 generated projects (~100 total, hundreds of hits) with small response delays, so the scan looks substantial and the progress line stays readable |
| `setup.sh` | hidden setup: private CA and certificate, HTTPS Fake GitLab, term list, token |
| `Dockerfile` | VHS image with pipx, a local wheel directory for GitlabHarvester, and the Fake GitLab |

## Where the GIF lives

The GIF is **not** stored in `dev` or `main`. `.github/workflows/demo-gif.yml` records it for
every published release (and when run by hand from the Actions tab) and force-pushes it to the
`demo-assets` branch as a single commit (`demo.gif` plus a short README). The README embeds
`https://raw.githubusercontent.com/Cur1iosity/GitlabHarvester/demo-assets/demo.gif`, which works
on GitHub and on PyPI. So:

- the GIF always shows the released version;
- the working branches never get bot commits: no pull after CI, no conflicts in a binary file;
- the repository history doesn't grow with every recording.

A run started by hand records the selected branch: run it on `main` to refresh the GIF of the
current release, e.g. after changing the tape.

## Record locally

To preview changes to the tape or the console output (from the repository root):

```bash
docker build -f docs/demo/Dockerfile -t gitlab-harvester/demo .

# Linux/macOS: the container runs as root, so hand the output back to your user
docker run --rm -v "$PWD/docs:/vhs" -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  --entrypoint sh gitlab-harvester/demo -c 'vhs demo/demo.tape && chown -R "$HOST_UID:$HOST_GID" demo/out'

# Windows (Docker Desktop doesn't keep root ownership on the host)
docker run --rm -v "${PWD}/docs:/vhs" gitlab-harvester/demo demo/demo.tape   # PowerShell
MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD/docs:/vhs" gitlab-harvester/demo demo/demo.tape   # Git Bash
```

The GIF is written to `docs/demo/out/demo.gif`, which is git-ignored: local recordings never
touch what the README shows. The scan of ~100 projects takes roughly 15 s on its own (about
600 search requests), so the whole clip runs ~20-25 s; most of the length now comes from the
dataset, not the delays. Tune the `demo.yaml` delays and the final `Sleep` in `demo.tape` to
taste, or lower the generated `count` for a shorter clip.
