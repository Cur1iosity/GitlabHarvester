#!/bin/sh
# Debian/Kali packaging check, run inside packaging/debian/Dockerfile with the
# source mounted read-only at /src and, like a package build, without network.
#
# 1. The test suite passes with the distribution's python3-* packages.
# 2. The sdist and wheel build with the distribution's build tools (no isolation, no PyPI).
# 3. The installed package's requirements are satisfied by those packages (pip check).
# 4. The installed console script runs (what an autopkgtest smoke test does).
set -eu

src=${1:-/src}
work=$(mktemp -d)
cp -a "$src/." "$work/src"
cd "$work/src"
rm -rf build dist ./*.egg-info .venv

echo "== distribution"
sed -n 's/^PRETTY_NAME=//p' /etc/os-release
python3 --version
dpkg-query -W -f '${Package} ${Version}\n' \
    python3-gitlab python3-requests python3-pytest python3-pytest-httpserver \
    python3-werkzeug python3-yaml python3-trustme python3-setuptools python3-build

echo "== tests (offline, distribution packages only)"
python3 -m pytest -q -p no:cacheprovider

echo "== build sdist and wheel (no isolation)"
python3 -m build --no-isolation --outdir "$work/dist" .
ls -l "$work/dist"

echo "== install over the system packages and check requirements"
python3 -m venv --system-site-packages "$work/venv"
"$work/venv/bin/pip" install --no-index --no-deps --disable-pip-version-check -q "$work"/dist/*.whl
"$work/venv/bin/pip" check --disable-pip-version-check

echo "== smoke test of the installed CLI"
"$work/venv/bin/gitlab-harvester" -V
"$work/venv/bin/gitlab-harvester" -h > /dev/null
echo "OK"
