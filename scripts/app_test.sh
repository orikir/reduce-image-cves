#!/usr/bin/env bash
# Repeatable smoke tests for a container image. Run the SAME script, with the
# SAME settings, against the original and the hardened image, then diff the TSVs.
#
# Usage: IMAGE=myapp:orig LABEL=original ./app_test.sh
#        IMAGE=myapp:slim LABEL=final    ./app_test.sh
#        python3 compare_tests.py tests/original.tsv tests/final.tsv   # regressions / flaky -> exit 1
#
# Bind-mounted test files (certs, configs) must live under $HOME if docker is a snap (it can't see /tmp).
#
# Settings (env vars):
#   IMAGE        image to test (required); pin by digest when possible
#   LABEL        name for the result file (default: sanitized IMAGE)
#   RUNS         how many full runs; all must pass (default 3)
#   PORT         container port the app listens on (default 8080; empty = no HTTP)
#   HEALTH_PATH  readiness URL path (default /health)
#   READY_TIMEOUT seconds to wait for readiness (default 60)
#   RUN_ARGS     extra args for docker run (env, volumes, ...)
#   EXPECT_VERSION  expected substring of the version output (optional)
#   VERSION_CMD  command inside the container that prints the version (optional)
set -uo pipefail

: "${IMAGE:?set IMAGE}"
LABEL="${LABEL:-$(printf '%s' "$IMAGE" | tr -c 'A-Za-z0-9._-' '_')}"   # printf: echo's newline would become a trailing _
RUNS="${RUNS:-3}"
PORT="${PORT-8080}"
HEALTH_PATH="${HEALTH_PATH:-/health}"
READY_TIMEOUT="${READY_TIMEOUT:-60}"
RUN_ARGS="${RUN_ARGS:-}"
OUT_DIR="${OUT_DIR:-tests}"
mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/$LABEL.tsv"
: > "$OUT"

CID=""
HOST_PORT=""
cleanup() { [ -n "$CID" ] && docker rm -f "$CID" >/dev/null 2>&1; CID=""; }
trap cleanup EXIT INT TERM

# record RUN CHECK RESULT DETAIL
record() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" | tee -a "$OUT"; }

# check RUN NAME EXPECTED ACTUAL -> exact comparison, never "looks fine"
check() {
  if [ "$3" = "$4" ]; then record "$1" "$2" PASS "$4"
  else record "$1" "$2" FAIL "expected=[$3] actual=[$4]"; FAILED=1; fi
}

http() { curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${HOST_PORT}$1"; }

start() {
  local name="cvetest-${LABEL}-$$-$1"
  local pub=""; [ -n "$PORT" ] && pub="-p 127.0.0.1::${PORT}"
  # shellcheck disable=SC2086
  CID=$(docker run -d --name "$name" $pub $RUN_ARGS "$IMAGE") || return 1
  [ -n "$PORT" ] && HOST_PORT=$(docker port "$CID" "$PORT" | head -n1 | sed 's/.*://')
  return 0
}

# Poll until ready, never a fixed sleep.
wait_ready() {
  local deadline=$((SECONDS + READY_TIMEOUT))
  while [ $SECONDS -lt $deadline ]; do
    [ "$(docker inspect -f '{{.State.Running}}' "$CID" 2>/dev/null)" = "true" ] || return 1
    if [ -z "$PORT" ]; then return 0; fi
    [ "$(http "$HEALTH_PATH")" = "200" ] && return 0
    sleep 1
  done
  return 1
}

run_once() {
  local r=$1
  FAILED=0
  start "$r" || { record "$r" start FAIL "docker run failed"; return 1; }
  if wait_ready; then record "$r" ready PASS "<=${READY_TIMEOUT}s"
  else record "$r" ready FAIL "not ready in ${READY_TIMEOUT}s: $(docker logs --tail 5 "$CID" 2>&1 | tr '\n\t' '  ')"; cleanup; return 1; fi

  # --- Generic checks -------------------------------------------------------
  if [ -n "${VERSION_CMD:-}" ] && [ -n "${EXPECT_VERSION:-}" ]; then
    local v; v=$(docker exec "$CID" sh -c "$VERSION_CMD" 2>&1 || docker run --rm --entrypoint "${VERSION_CMD%% *}" "$IMAGE" ${VERSION_CMD#* } 2>&1)
    case "$v" in *"$EXPECT_VERSION"*) check "$r" version ok ok ;; *) check "$r" version "$EXPECT_VERSION" "$v" ;; esac
  fi
  [ -n "$PORT" ] && check "$r" health_200 200 "$(http "$HEALTH_PATH")"
  check "$r" still_running true "$(docker inspect -f '{{.State.Running}}' "$CID")"
  check "$r" restarts 0 "$(docker inspect -f '{{.RestartCount}}' "$CID")"

  # --- App-specific checks: ADD YOURS HERE ----------------------------------
  # Cover what a smaller base tends to break. Examples:
  # check "$r" main_feature 200 "$(http /api/items)"
  # check "$r" body '{"status":"ok"}' "$(curl -s --max-time 5 http://127.0.0.1:$HOST_PORT/status)"
  # check "$r" outbound_tls 200 "$(http /selftest/tls)"      # CA certs present
  # check "$r" dns ok "$(docker exec $CID getent hosts example.com >/dev/null && echo ok)"
  # check "$r" write_tmp ok "$(docker exec $CID sh -c 'touch /tmp/x && echo ok')"
  # check "$r" user 10001 "$(docker exec $CID id -u)"

  # Graceful shutdown: should stop on SIGTERM well within 10 s.
  local t0=$SECONDS
  docker stop -t 10 "$CID" >/dev/null 2>&1
  local took=$((SECONDS - t0))
  if [ $took -lt 10 ]; then record "$r" graceful_stop PASS "${took}s"; else record "$r" graceful_stop FAIL "${took}s (killed?)"; FAILED=1; fi
  check "$r" no_errors_in_log 0 "$(docker logs "$CID" 2>&1 | grep -ciE 'panic|segfault|fatal|no such file|not found' || true)"
  cleanup
  return $FAILED
}

TOTAL_FAIL=0
for r in $(seq 1 "$RUNS"); do
  run_once "$r" || TOTAL_FAIL=$((TOTAL_FAIL + 1))
done

echo "---"
echo "$IMAGE: $((RUNS - TOTAL_FAIL))/$RUNS runs passed. Results: $OUT"
if [ $TOTAL_FAIL -gt 0 ] && [ $TOTAL_FAIL -lt "$RUNS" ]; then
  echo "FLAKY: some runs passed and some failed. Fix the test or the app before trusting the result."
fi
[ $TOTAL_FAIL -eq 0 ]
