# Image that records docs/assets/demo.gif with VHS (https://github.com/charmbracelet/vhs).
# Build context: repository root. See docs/demo/README.md.
#
# The recording shows `pipx install gitlab-harvester`. It installs the package
# from a local wheel directory built from this checkout (not from PyPI), so the
# GIF always shows the version being released.
FROM ghcr.io/charmbracelet/vhs:v0.12.1

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3-venv pipx \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /demo-app
COPY requirements-dev.txt pyproject.toml README.md LICENSE gitlab_harvester.py ./
COPY glh ./glh
COPY fakegitlab ./fakegitlab

# Fake GitLab runtime (kept off PATH: the demo uses the pipx-installed CLI).
RUN python3 -m venv /opt/fake \
 && /opt/fake/bin/pip install --no-cache-dir -q -r requirements-dev.txt

# Wheels of GitlabHarvester and its dependencies for the offline `pipx install`.
RUN /opt/fake/bin/pip wheel --no-cache-dir -q --wheel-dir /wheels -c requirements-dev.txt . \
 && rm -rf build *.egg-info

ENV PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/usr/local/bin \
    USE_EMOJI=0

# Prepare pipx's shared libraries (pip) while the network is available, then go offline.
RUN pipx upgrade-shared

ENV PIP_NO_INDEX=1 \
    PIP_FIND_LINKS=/wheels
WORKDIR /vhs
