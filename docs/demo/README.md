# README demo GIF

`docs/assets/demo.gif` is recorded with [VHS](https://github.com/charmbracelet/vhs) in a
container: `pipx install gitlab-harvester`, then the real CLI against the bundled Fake GitLab
(artificial data only) served as `http://gitlab.example.com`. Nothing is sent to a real GitLab.

`pipx install` runs for real, but offline: the image builds wheels of this checkout and its
dependencies, and pip is pointed at them (`PIP_NO_INDEX`, `PIP_FIND_LINKS`). So the GIF shows
the version being released, not whatever is on PyPI at recording time.

| File | Purpose |
|---|---|
| `demo.tape` | what is typed; waits for the output (`Wait /done!/`, `Wait /Done\. Keywords/`) instead of fixed pauses |
| `demo.yaml` | Fake GitLab scenario: the default dataset plus small response delays, so the progress line is visible |
| `Dockerfile` | VHS image with pipx, a local wheel directory for GitlabHarvester, and the Fake GitLab |
| `needs-rebuild.sh` | CI: decides whether a push needs a new GIF |

Re-record it after changing the console output (from the repository root):

```bash
docker build -f docs/demo/Dockerfile -t gitlab-harvester/demo .
docker run --rm -v "$PWD/docs:/vhs" gitlab-harvester/demo demo/demo.tape
# Windows PowerShell: -v "${PWD}/docs:/vhs"; Git Bash: prefix with MSYS_NO_PATHCONV=1
```

The GIF is written to `docs/assets/demo.gif`. Aim for about 15 seconds: tune the
delays in `demo.yaml` and the final `Sleep` in `demo.tape`.

## In CI

`.github/workflows/demo-gif.yml` re-records the GIF automatically on pushes to `dev`
when the version in `pyproject.toml` changed or `docs/demo/` changed
(`needs-rebuild.sh` decides; other pushes finish in seconds). It commits the new
GIF back to `dev` as `github-actions[bot]` (`docs: regenerate demo GIF for vX.Y.Z`),
and it reaches `main` with the usual `dev -> main` pull request. The GIF is also kept
as a run artifact. Run it by hand from the Actions tab (`workflow_dispatch`) after
changing the console output without a version bump.

After pushing a version bump, pull `dev` before the next commit: the bot's commit
arrives a few minutes later.
