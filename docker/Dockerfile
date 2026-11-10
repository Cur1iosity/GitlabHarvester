# syntax=docker/dockerfile:1
#
# Development images for GitlabHarvester (build context: repository root).
#
#   fake-gitlab : the Fake GitLab REST API v4 (python -m fakegitlab)
#   harvester   : the real GitlabHarvester CLI, preconfigured for fake-gitlab
#
# Versions are pinned through requirements-dev.txt; the base image tag is pinned
# to a Python minor release on Debian trixie.

ARG PYTHON_IMAGE=python:3.14-slim-trixie

FROM ${PYTHON_IMAGE} AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements-dev.txt ./
RUN pip install -r requirements-dev.txt

# ---------------------------------------------------------------- fake-gitlab
FROM base AS fake-gitlab
COPY fakegitlab ./fakegitlab
RUN useradd --system --uid 10001 fake
USER fake
ENV FAKE_GITLAB_HOST=0.0.0.0 \
    FAKE_GITLAB_PORT=8080 \
    FAKE_GITLAB_SCENARIO=default
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=10 \
  CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8080/__admin/health', timeout=2)" || exit 1
ENTRYPOINT ["python", "-m", "fakegitlab"]

# ------------------------------------------------------------------ harvester
FROM base AS harvester
COPY pyproject.toml README.md LICENSE gitlab_harvester.py ./
COPY glh ./glh
RUN pip install --no-deps . && useradd --system --uid 10001 --create-home harvester \
 && mkdir /work && chown harvester /work
USER harvester
WORKDIR /work
ENV GLH_URL=http://fake-gitlab:8080 \
    GLH_TOKEN=dev-token
# Exec form with a tiny shell wrapper so URL/token come from the environment
# while extra CLI arguments are appended verbatim.
ENTRYPOINT ["sh", "-c", "exec gitlab-harvester -u \"$GLH_URL\" -t \"$GLH_TOKEN\" \"$@\"", "gitlab-harvester"]
CMD ["--help"]
