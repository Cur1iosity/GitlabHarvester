# Image that records docs/assets/demo.gif with VHS (https://github.com/charmbracelet/vhs).
# Build context: repository root. See docs/demo/README.md.
FROM ghcr.io/charmbracelet/vhs:v0.12.1

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3-venv \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /demo-app
COPY requirements-dev.txt pyproject.toml README.md LICENSE gitlab_harvester.py ./
COPY glh ./glh
COPY fakegitlab ./fakegitlab
RUN python3 -m venv /opt/glh \
 && /opt/glh/bin/pip install --no-cache-dir -q -r requirements-dev.txt . \
 && rm -rf build *.egg-info

ENV PATH=/opt/glh/bin:$PATH \
    PYTHONPATH=/demo-app
WORKDIR /vhs
