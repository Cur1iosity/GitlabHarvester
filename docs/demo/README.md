# README demo GIF

`docs/assets/demo.gif` is recorded with [VHS](https://github.com/charmbracelet/vhs):
the real CLI runs against the bundled Fake GitLab (artificial data only) served as
`http://gitlab.example.com` inside a container. Nothing is sent to a real GitLab.

| File | Purpose |
|---|---|
| `demo.tape` | what is typed and how long each step is shown (size, font, theme) |
| `demo.yaml` | Fake GitLab scenario: the default dataset plus small response delays, so the progress line is visible |
| `Dockerfile` | VHS image with GitlabHarvester and the Fake GitLab installed |

Re-record it after changing the console output (from the repository root):

```bash
docker build -f docs/demo/Dockerfile -t gitlab-harvester/demo .
docker run --rm -v "$PWD/docs:/vhs" gitlab-harvester/demo demo/demo.tape
# Windows PowerShell: -v "${PWD}/docs:/vhs"; Git Bash: prefix with MSYS_NO_PATHCONV=1
```

The GIF is written to `docs/assets/demo.gif`. Aim for 10-15 seconds: tune the
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
