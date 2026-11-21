#!/usr/bin/env bash
# Scan an image, summarize it, and compare it with the baseline - always the same way.
# Usage (inside the work folder): bash scan.sh IMAGE NAME
#   NAME=baseline  -> scans/baseline.json (refuses to overwrite; FORCE=1 to rescan, e.g. after a DB update)
#   NAME=<other>   -> scans/<NAME>.json + summaries/compare-<NAME>.txt against the baseline
# After the baseline exists the grype DB is frozen (GRYPE_DB_AUTO_UPDATE=false) so every scan uses the
# same vulnerability data. UPDATE_DB=1 lets it update - then rescan the baseline too (FORCE=1).
set -euo pipefail
IMAGE=${1:?usage: scan.sh IMAGE NAME}; NAME=${2:?usage: scan.sh IMAGE NAME}
S=$(cd "$(dirname "$0")" && pwd)
DOCKER=${DOCKER:-docker}
mkdir -p scans summaries
OUT="scans/$NAME.json"

if [ "$NAME" = baseline ] && [ -s "$OUT" ] && [ "${FORCE:-0}" != 1 ]; then
  echo "refusing to overwrite $OUT (it is the reference for every comparison). FORCE=1 to rescan."; exit 1
fi
if [ -s scans/baseline.json ] && [ "${UPDATE_DB:-0}" != 1 ]; then export GRYPE_DB_AUTO_UPDATE=false; fi

grype "$IMAGE" -o json > "$OUT.tmp" 2> "summaries/$NAME.grype.log" || { tail -20 "summaries/$NAME.grype.log"; rm -f "$OUT.tmp"; exit 1; }
mv "$OUT.tmp" "$OUT"
python3 "$S/summarize_scan.py" "$OUT" --csv "summaries/$NAME.csv" > "summaries/$NAME.txt"
SIZE=$($DOCKER image inspect --format '{{.Size}}' "$IMAGE" 2>/dev/null || echo "")
[ -n "$SIZE" ] && echo "Docker image size: $SIZE bytes ($((SIZE / 1000000)) MB uncompressed - use this one in the report)" >> "summaries/$NAME.txt"
sed -n '1,/^Packages by/p' "summaries/$NAME.txt" | sed '$d'
[ -n "$SIZE" ] && tail -1 "summaries/$NAME.txt"

if [ "$NAME" != baseline ] && [ -s scans/baseline.json ]; then
  python3 "$S/summarize_scan.py" --compare scans/baseline.json "$OUT" > "summaries/compare-$NAME.txt"
  echo "---- vs baseline (summaries/compare-$NAME.txt)"
  sed -n '1,/^Removed:/p' "summaries/compare-$NAME.txt"
fi
