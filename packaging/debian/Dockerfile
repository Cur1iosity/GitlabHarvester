# Debian/Kali packaging check image (see docs/packaging.md).
#
# Every Python dependency comes from the distribution (python3-*), exactly as in a
# Debian/Kali package build with dh-python/pybuild: no pip, no PyPI.
#   docker build -f packaging/debian/Dockerfile --build-arg BASE=kalilinux/kali-rolling -t glh-debian .
#   docker run --rm --network none -v "$PWD:/src:ro" glh-debian
ARG BASE=kalilinux/kali-rolling
FROM ${BASE}

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      python3 \
      python3-venv \
      python3-setuptools \
      python3-build \
      python3-wheel \
      python3-gitlab \
      python3-requests \
      python3-pytest \
      python3-pytest-httpserver \
      python3-werkzeug \
      python3-yaml \
      python3-trustme \
 && rm -rf /var/lib/apt/lists/*

COPY packaging/debian/check.sh /usr/local/bin/glh-debian-check
RUN chmod +x /usr/local/bin/glh-debian-check
CMD ["glh-debian-check"]
