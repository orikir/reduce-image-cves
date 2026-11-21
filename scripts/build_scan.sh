#!/usr/bin/env bash
# Build one candidate (Dockerfile.<NAME>), check it starts, then scan + compare it with the baseline.
# Usage (inside the work folder): bash build_scan.sh NAME [TAG]
#   TAG defaults to cvework/<folder>:<NAME>. VERSION_CMD (e.g. "redis-server --version") is run in the new
#   image as a quick smoke check. Build log: summaries/build-<NAME>.log
set -euo pipefail
NAME=${1:?usage: build_scan.sh NAME [TAG]}
TAG=${2:-cvework/$(basename "$PWD" | tr 'A-Z' 'a-z'):$NAME}
S=$(cd "$(dirname "$0")" && pwd)
DOCKER=${DOCKER:-docker}
[ -f "Dockerfile.$NAME" ] || { echo "no Dockerfile.$NAME here"; exit 1; }
sed -i 's/\r$//' "Dockerfile.$NAME"   # files edited on Windows break RUN lines with CRLF

echo "building $TAG from Dockerfile.$NAME ..."
if ! $DOCKER build --progress=plain -f "Dockerfile.$NAME" -t "$TAG" . > "summaries/build-$NAME.log" 2>&1; then
  grep -nE 'ERROR|error:|Errors were|E: ' "summaries/build-$NAME.log" | head -20
  tail -25 "summaries/build-$NAME.log"; exit 1
fi
if [ -n "${VERSION_CMD:-}" ]; then
  echo "smoke: $($DOCKER run --rm "$TAG" $VERSION_CMD 2>&1 | head -1)"
fi
bash "$S/scan.sh" "$TAG" "$NAME"
