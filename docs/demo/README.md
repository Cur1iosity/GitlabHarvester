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
