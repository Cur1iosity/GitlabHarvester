#!/usr/bin/env sh
# Decide whether docs/assets/demo.gif must be re-recorded for a push.
#
# Usage: docs/demo/needs-rebuild.sh <base-commit>
# Prints "run=true|false", "version=X.Y.Z" and "reason=..." lines (for $GITHUB_OUTPUT).
#
# The GIF shows the tool version in the banner and real timings, so it is
# re-recorded only when the version in pyproject.toml changed or the demo
# sources (docs/demo/) changed, not on every push.
set -eu

base="${1:-}"
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' pyproject.toml | head -n 1)
echo "version=${version}"

if [ -z "$base" ] || [ "$base" = "0000000000000000000000000000000000000000" ] \
   || ! git cat-file -e "${base}^{commit}" 2>/dev/null; then
    echo "run=true"
    echo "reason=no usable base commit"
    exit 0
fi

old_version=$(git show "${base}:pyproject.toml" 2>/dev/null | sed -n 's/^version = "\(.*\)"$/\1/p' | head -n 1)
if [ "$old_version" != "$version" ]; then
    echo "run=true"
    echo "reason=version ${old_version:-?} -> ${version}"
    exit 0
fi

if [ -n "$(git diff --name-only "$base" HEAD -- docs/demo)" ]; then
    echo "run=true"
    echo "reason=demo sources changed"
    exit 0
fi

echo "run=false"
echo "reason=version ${version} unchanged, demo sources unchanged"
