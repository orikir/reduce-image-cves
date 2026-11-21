#!/usr/bin/env bash
# Step 6 helper: scan candidate base images and rank them (fewest Critical, then High, then total).
# Usage (inside the work folder): bash scan_bases.sh IMAGE [IMAGE ...]
#   e.g. bash scan_bases.sh debian:bookworm-slim alpine:3.22 gcr.io/distroless/base-debian12 cgr.dev/chainguard/wolfi-base
# Writes scans/bases/<image>.json and summaries/bases.tsv. Uses the frozen DB once a baseline exists.
set -uo pipefail
[ $# -ge 1 ] || { echo "usage: scan_bases.sh IMAGE [IMAGE ...]"; exit 2; }
S=$(cd "$(dirname "$0")" && pwd)
DOCKER=${DOCKER:-docker}
mkdir -p scans/bases summaries
[ -s scans/baseline.json ] && [ "${UPDATE_DB:-0}" != 1 ] && export GRYPE_DB_AUTO_UPDATE=false
files=()
for img in "$@"; do
  f="scans/bases/$(printf '%s' "$img" | sed 's#[/:@]#_#g').json"
  if $DOCKER pull -q "$img" >/dev/null 2>&1 && grype "$img" -o json > "$f" 2>/dev/null; then
    files+=("$f"); echo "scanned $img"
  else echo "FAILED  $img (pull or scan error)"; rm -f "$f"; fi
done
[ ${#files[@]} -gt 0 ] || exit 1
python3 "$S/summarize_scan.py" "${files[@]}" --oneline | tee summaries/bases.tsv | column -t -s $'\t'
echo
echo "Remember: a bare base has no app yet. Prefer the same libc as the original (glibc vs musl) unless tests prove otherwise,"
echo "and a 0-CVE static/distroless result can mean the libraries are just invisible to the scanner."
