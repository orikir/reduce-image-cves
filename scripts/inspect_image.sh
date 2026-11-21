#!/usr/bin/env bash
# Step 1: identify the image. Pulls it, records digest/OS/size/config/history, counts packages and maps
# what the app really loads (ldd) to the packages that own it.
# Usage (inside the work folder): bash inspect_image.sh IMAGE [BINARY ...]
#   BINARY defaults to the first word of the image's Cmd/Entrypoint that is not a shell script.
# Writes: summaries/image-info.txt, summaries/history.txt, summaries/runtime-deps.txt, summaries/packages.txt
set -euo pipefail
IMAGE=${1:?usage: inspect_image.sh IMAGE [BINARY ...]}; shift
DOCKER=${DOCKER:-docker}
mkdir -p summaries

$DOCKER pull -q "$IMAGE" >/dev/null
fmt() { $DOCKER image inspect --format "$1" "$IMAGE"; }
DIGEST=$(fmt '{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}')
{
  echo "image:       $IMAGE"
  echo "digest:      ${DIGEST:-<none: local image>}   (pin the baseline to this)"
  echo "image id:    $(fmt '{{.Id}}')"
  echo "size:        $(fmt '{{.Size}}') bytes ($(( $(fmt '{{.Size}}') / 1000000 )) MB, uncompressed)"
  echo "arch:        $(fmt '{{.Os}}/{{.Architecture}}')"
  echo "user:        $(fmt '{{if .Config.User}}{{.Config.User}}{{else}}<root>{{end}}')"
  echo "entrypoint:  $(fmt '{{json .Config.Entrypoint}}')"
  echo "cmd:         $(fmt '{{json .Config.Cmd}}')"
  echo "workdir:     $(fmt '{{.Config.WorkingDir}}')"
  echo "volumes:     $(fmt '{{json .Config.Volumes}}')"
  echo "ports:       $(fmt '{{json .Config.ExposedPorts}}')"
  echo "healthcheck: $(fmt '{{json .Config.Healthcheck}}')"
  echo "env:"; fmt '{{range .Config.Env}}  {{.}}{{"\n"}}{{end}}'
  echo "os-release:"
  $DOCKER run --rm --entrypoint cat "$IMAGE" /etc/os-release 2>/dev/null | grep -E '^(PRETTY_NAME|ID|VERSION_ID)=' | sed 's/^/  /' \
    || echo "  <no cat in image: read the distro field from the grype scan>"
} | tee summaries/image-info.txt

# Build steps, oldest first (use them to rebuild a Dockerfile if none is available)
$DOCKER history --no-trunc --format '{{.CreatedBy}}' "$IMAGE" | tac > summaries/history.txt
echo "history:     summaries/history.txt ($(wc -l < summaries/history.txt) layers)"

# Default binaries: entrypoint + cmd words that are executables (not scripts)
if [ $# -eq 0 ]; then
  set -- $(fmt '{{range .Config.Entrypoint}}{{.}} {{end}}{{range .Config.Cmd}}{{.}} {{end}}')
fi

# Everything below runs inside the image with its own sh, fed on stdin (no quoting games).
if ! $DOCKER run --rm --entrypoint sh "$IMAGE" -c 'exit 0' >/dev/null 2>&1; then
  echo "runtime deps: image has no shell; use 'syft $IMAGE' for the inventory" | tee summaries/runtime-deps.txt
  exit 0
fi
$DOCKER run --rm -i --entrypoint sh "$IMAGE" -s -- "$@" > summaries/runtime-deps.txt 2>&1 <<'IN' || true
owner() {   # file -> owning package (usrmerge: resolve symlinks first, try /usr and / variants)
  f=$(readlink -f "$1" 2>/dev/null || echo "$1")
  for c in "$f" "${f#/usr}" "/usr$f"; do
    if command -v dpkg >/dev/null 2>&1; then o=$(dpkg -S "$c" 2>/dev/null | head -1 | cut -d: -f1)
    elif command -v apk >/dev/null 2>&1; then o=$(apk info --who-owns "$c" 2>/dev/null | sed -n 's/.* is owned by //p' | head -1)
    elif command -v rpm >/dev/null 2>&1; then o=$(rpm -qf "$c" 2>/dev/null | grep -v 'not owned' | head -1)
    else o=""; fi
    [ -n "$o" ] && { echo "$o"; return; }
  done
  echo "<not from a package>"
}
echo "# binaries and the shared libraries they load (ldd cannot see dlopen'ed libs: tests must cover those)"
for b in "$@"; do
  p=$(command -v "$b" 2>/dev/null) || continue
  case "$(head -c 2 "$p" 2>/dev/null)" in '#!') echo "SCRIPT $p (interpreter: $(head -1 "$p" | cut -c3-)) -> $(owner "$p")"
    echo "  commands it calls (check each is still present in a slim image):"
    # words at command position (after start/indent, ; & | ( exec then do) plus absolute /bin paths
    { grep -v '^[[:space:]]*#' "$p" | grep -oE '(^|[;&|([:space:]]|exec |then |do )[a-z][a-z0-9_.-]+' | grep -oE '[a-z][a-z0-9_.-]+$'
      grep -v '^[[:space:]]*#' "$p" | grep -oE '/(usr/)?(local/)?s?bin/[a-z0-9_.-]+'; } | sort -u \
      | while read -r c; do r=$(command -v "$c" 2>/dev/null) || continue
          case "$r" in /*) echo "    $c -> $r [$(owner "$r")]";; esac; done
    continue;; esac
  echo "BIN $p -> $(owner "$p")"
  if command -v ldd >/dev/null 2>&1; then
    ldd "$p" 2>/dev/null | awk '/=>/ && $3 ~ /^\// {print $3} /^\t\/[^ ]+ \(/ {print $1}' | while read -r l; do
      echo "  lib $l -> $(owner "$l")"
    done
  else echo "  (no ldd in image)"; fi
done
echo
if command -v dpkg-query >/dev/null 2>&1; then echo "# installed: $(dpkg-query -W | wc -l) deb packages"
elif command -v apk >/dev/null 2>&1; then echo "# installed: $(apk info 2>/dev/null | wc -l) apk packages"
elif command -v rpm >/dev/null 2>&1; then echo "# installed: $(rpm -qa | wc -l) rpm packages"; fi
IN
cat summaries/runtime-deps.txt
$DOCKER run --rm --entrypoint sh "$IMAGE" -c \
  'dpkg-query -W -f="\${Package}\t\${Version}\t\${Essential}\t\${Priority}\n" 2>/dev/null || apk info -v 2>/dev/null || rpm -qa 2>/dev/null' \
  > summaries/packages.txt 2>/dev/null || true
echo "packages:    summaries/packages.txt ($(wc -l < summaries/packages.txt) lines)"
