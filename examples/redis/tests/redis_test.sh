#!/usr/bin/env bash
# Repeatable functional test for a redis image.
# Usage: IMAGE=redis:7-bookworm LABEL=original RUNS=3 bash tests/redis_test.sh
# Writes tests/<LABEL>.tsv (run, check, result, detail). Exit 0 only if every check passed in every run.
set -uo pipefail
IMAGE=${IMAGE:?set IMAGE}
LABEL=${LABEL:?set LABEL}
RUNS=${RUNS:-3}
EXPECT_VERSION=${EXPECT_VERSION:-7.4.12}
EXPECT_UID=${EXPECT_UID:-999}
READY_TIMEOUT=${READY_TIMEOUT:-30}
HERE=$(cd "$(dirname "$0")" && pwd)
OUT="$HERE/$LABEL.tsv"
TAG="cvetest-$LABEL-$$"
CERTS=$(mktemp -d "$HOME/cvetest-certs.XXXXXX")   # snap docker cannot see /tmp
printf 'run\tcheck\tresult\tdetail\n' > "$OUT"
FAILS=0

cleanup() {
  docker rm -f $(docker ps -aq --filter "name=$TAG") >/dev/null 2>&1 || true
  docker volume rm -f "$TAG-vol" >/dev/null 2>&1 || true
  docker network rm "$TAG-net" >/dev/null 2>&1 || true
  rm -rf "$CERTS"
}
trap cleanup EXIT

record() { # run check ok(0/1) detail
  local r=PASS; [ "$3" -eq 0 ] || { r=FAIL; FAILS=$((FAILS+1)); }
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$r" "$4" >> "$OUT"
  printf '  %-4s %-26s %s  %s\n' "$r" "$2" "" "$4"
}
cli() { docker exec "$1" redis-cli "${@:2}" 2>&1 | tr -d '\r'; }
wait_ready() { # container -> 0 when PING answers PONG
  local i
  for i in $(seq 1 $((READY_TIMEOUT*5))); do
    [ "$(cli "$1" ping)" = "PONG" ] && return 0
    [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = "true" ] || return 1
    sleep 0.2
  done
  return 1
}
eq() { [ "$1" = "$2" ]; }

# Throw-away TLS material (readable by uid 999 inside the container):
# trusted CA + server cert (SAN localhost/127.0.0.1) + client cert, and a rogue CA + rogue client
# cert for the negative tests.
(
  cd "$CERTS" || exit 1
  openssl req -x509 -new -nodes -newkey rsa:2048 -days 1 -keyout ca.key -out ca.crt -subj "/CN=Redis Test CA"
  openssl req -x509 -new -nodes -newkey rsa:2048 -days 1 -keyout rogue-ca.key -out rogue-ca.crt -subj "/CN=Rogue CA"
  printf "subjectAltName=DNS:localhost,DNS:redis,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" > server.ext
  openssl req -new -nodes -newkey rsa:2048 -keyout server.key -out server.csr -subj "/CN=localhost"
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 -extfile server.ext -out server.crt
  printf "extendedKeyUsage=clientAuth\n" > client.ext
  openssl req -new -nodes -newkey rsa:2048 -keyout client.key -out client.csr -subj "/CN=redis-client"
  openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 -extfile client.ext -out client.crt
  openssl req -new -nodes -newkey rsa:2048 -keyout rogue-client.key -out rogue-client.csr -subj "/CN=rogue-client"
  openssl x509 -req -in rogue-client.csr -CA rogue-ca.crt -CAkey rogue-ca.key -CAcreateserial -days 1 -extfile client.ext -out rogue-client.crt
) >/dev/null 2>&1 || { echo "certificate generation failed"; exit 1; }
chmod 0755 "$CERTS"; chmod 0644 "$CERTS"/*

# helpers for TLS checks
rejected() { case "$1" in *PONG*) return 1;; *) return 0;; esac; }   # pass when no PONG came back
handshake() { # host-port extra-openssl-args... -> negotiated protocol, empty if handshake failed
  local port=$1; shift
  timeout 10 openssl s_client -brief -connect "127.0.0.1:$port" -CAfile "$CERTS/ca.crt" -verify_return_error \
    -cert "$CERTS/client.crt" -key "$CERTS/client.key" "$@" </dev/null 2>&1 | awk -F': ' '/^Protocol version/ {print $2}'
}

docker network create "$TAG-net" >/dev/null

echo "Testing $IMAGE ($LABEL), $RUNS runs"
for run in $(seq 1 "$RUNS"); do
  echo "run $run"
  C="$TAG-$run"
  docker volume rm -f "$TAG-vol" >/dev/null 2>&1

  # 1 version string
  v=$(docker run --rm "$IMAGE" redis-server --version 2>&1)
  case "$v" in *"v=$EXPECT_VERSION "*) record "$run" version 0 "$EXPECT_VERSION";; *) record "$run" version 1 "$v";; esac

  # 2 start with default CMD and become ready (poll, no fixed sleep)
  docker run -d --name "$C" --network "$TAG-net" --network-alias redis-svc -v "$TAG-vol:/data" "$IMAGE" >/dev/null
  if wait_ready "$C"; then record "$run" startup_ready 0 "PONG"; else record "$run" startup_ready 1 "$(docker logs "$C" 2>&1 | tail -3)"; continue; fi

  # 3 server process runs as the unprivileged redis user
  uid=$(docker top "$C" -eo pid,uid,comm | awk '$3 ~ /redis-server/ {print $2; exit}')
  [ "$uid" = "redis" ] && uid=$EXPECT_UID
  eq "$uid" "$EXPECT_UID"; record "$run" runs_as_uid_999 $? "uid=$uid"

  # 4 core data types
  r1=$(cli "$C" set k1 hello); r2=$(cli "$C" get k1)
  eq "$r1|$r2" "OK|hello"; record "$run" set_get $? "$r1 $r2"
  cli "$C" del n >/dev/null; for i in 1 2 3; do cli "$C" incr n >/dev/null; done
  eq "$(cli "$C" get n)" "3"; record "$run" incr $? "n=$(cli "$C" get n)"
  cli "$C" del l >/dev/null; cli "$C" rpush l a b c >/dev/null
  eq "$(cli "$C" lrange l 0 -1 | tr '\n' ',')" "a,b,c,"; record "$run" list $? "$(cli "$C" lrange l 0 -1 | tr '\n' ' ')"
  cli "$C" hset h f1 v1 f2 v2 >/dev/null
  eq "$(cli "$C" hget h f2)" "v2"; record "$run" hash $? "f2=$(cli "$C" hget h f2)"
  cli "$C" zadd z 1 one 2 two >/dev/null
  eq "$(cli "$C" zrange z 0 -1 | tr '\n' ',')" "one,two,"; record "$run" sorted_set $? ""
  cli "$C" set e x EX 100 >/dev/null; t=$(cli "$C" ttl e)
  [ "$t" -gt 0 ] 2>/dev/null; record "$run" expire_ttl $? "ttl=$t"
  cli "$C" set k2 first >/dev/null; cli "$C" set k2 updated >/dev/null
  eq "$(cli "$C" get k2)" "updated"; record "$run" update_key $? "$(cli "$C" get k2)"
  eq "$(cli "$C" exists k2)" "1"; record "$run" exists $? "exists=$(cli "$C" exists k2)"
  cli "$C" append k2 " world" >/dev/null
  eq "$(cli "$C" get k2)" "updated world"; record "$run" append $? "$(cli "$C" get k2)"
  cli "$C" set counter 10 >/dev/null; cli "$C" incr counter >/dev/null; cli "$C" decr counter >/dev/null; cli "$C" decr counter >/dev/null
  eq "$(cli "$C" get counter)" "9"; record "$run" decr $? "counter=$(cli "$C" get counter)"
  cli "$C" del k2 >/dev/null
  eq "$(cli "$C" exists k2)" "0"; record "$run" del $? "exists=$(cli "$C" exists k2)"
  cli "$C" sadd s apple banana orange >/dev/null
  eq "$(cli "$C" sismember s apple)|$(cli "$C" sismember s grape)|$(cli "$C" scard s)" "1|0|3"; record "$run" sets $? "scard=$(cli "$C" scard s)"
  # key really expires: EX 1, then poll until GET returns nil (max 5 s, no fixed sleep)
  cli "$C" set tmp v EX 1 >/dev/null; gone=1
  for i in $(seq 1 50); do [ -z "$(cli "$C" get tmp)" ] && { gone=0; break; }; sleep 0.1; done
  record "$run" expired_key_nil $gone "after $((i*100))ms"
  n=$(cli "$C" dbsize)
  eq "$n" "8"; record "$run" dbsize $? "dbsize=$n (k1 n l h z e counter s)"

  # 5 Lua scripting
  eq "$(cli "$C" eval "return redis.call('get', KEYS[1])" 1 k1)" "hello"; record "$run" lua_eval $? ""

  # 6 allocator is jemalloc (same as official build)
  a=$(cli "$C" info memory | awk -F: '/^mem_allocator/ {print $2}')
  case "$a" in jemalloc*) record "$run" jemalloc 0 "$a";; *) record "$run" jemalloc 1 "$a";; esac

  # 7 DNS + network: a second container resolves the service name and connects
  p=$(docker run --rm --network "$TAG-net" "$IMAGE" redis-cli -h redis-svc ping 2>&1 | tr -d '\r')
  eq "$p" "PONG"; record "$run" dns_network_client $? "$p"

  # 8 /data is writable by the runtime user (RDB save)
  s=$(cli "$C" save)
  eq "$s" "OK"; record "$run" save_rdb $? "$s"
  eq "$(cli "$C" ping)" "PONG"; record "$run" final_ping $? "PONG"

  # 9 graceful shutdown on SIGTERM in < 10 s, exit code 0
  t0=$(date +%s%N); docker stop -t 10 "$C" >/dev/null; t1=$(date +%s%N)
  ms=$(( (t1-t0)/1000000 )); ec=$(docker inspect -f '{{.State.ExitCode}}' "$C")
  { [ "$ms" -lt 10000 ] && [ "$ec" = "0" ]; }; record "$run" graceful_stop $? "${ms}ms exit=$ec"
  docker logs "$C" 2>&1 | grep -q "ready to exit"; record "$run" shutdown_log $? "ready to exit"
  ! docker logs "$C" 2>&1 | grep -qiE "fatal|segfault|crashed|Bad file format"; record "$run" no_errors_in_log $? ""
  docker rm "$C" >/dev/null

  # 10 persistence: a new container on the same volume sees the data
  docker run -d --name "$C-b" -v "$TAG-vol:/data" "$IMAGE" >/dev/null
  if wait_ready "$C-b"; then
    eq "$(cli "$C-b" get k1)|$(cli "$C-b" hget h f1)" "hello|v1"; record "$run" persistence_restart $? "k1=$(cli "$C-b" get k1)"
  else record "$run" persistence_restart 1 "not ready"; fi
  docker rm -f "$C-b" >/dev/null

  # 11 option-style args (entrypoint prepends redis-server) + AOF works
  docker run -d --name "$C-c" "$IMAGE" --appendonly yes --maxmemory 10mb >/dev/null
  if wait_ready "$C-c"; then
    m=$(cli "$C-c" config get maxmemory | tail -1); ao=$(cli "$C-c" config get appendonly | tail -1)
    cli "$C-c" set a 1 >/dev/null
    eq "$m|$ao" "10485760|yes"; record "$run" args_and_aof $? "maxmemory=$m appendonly=$ao"
  else record "$run" args_and_aof 1 "not ready: $(docker logs "$C-c" 2>&1 | tail -2)"; fi
  docker rm -f "$C-c" >/dev/null

  # 12 TLS (BUILD_TLS=yes + libssl at runtime): TLS-only, client certificates required (Redis default)
  docker run -d --name "$C-t" -v "$CERTS:/tls:ro" -p 127.0.0.1::6380 "$IMAGE" redis-server --port 0 --tls-port 6380 \
    --tls-cert-file /tls/server.crt --tls-key-file /tls/server.key --tls-ca-cert-file /tls/ca.crt >/dev/null
  TLS_CLI="redis-cli --tls -p 6380 --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key"
  ok=1
  for i in $(seq 1 $((READY_TIMEOUT*5))); do
    p=$(docker exec "$C-t" $TLS_CLI ping 2>&1 | tr -d '\r')
    [ "$p" = "PONG" ] && { ok=0; break; }
    [ "$(docker inspect -f '{{.State.Running}}' "$C-t")" = "true" ] || break
    sleep 0.2
  done
  record "$run" tls_ping $ok "${p:-$(docker logs "$C-t" 2>&1 | tail -2)}"
  if [ $ok -eq 0 ]; then
    docker exec "$C-t" $TLS_CLI set tls-key tls-value >/dev/null 2>&1
    g=$(docker exec "$C-t" $TLS_CLI get tls-key 2>&1 | tr -d '\r')
    eq "$g" "tls-value"; record "$run" tls_set_get $? "$g"
    # negative tests: every one of these connections must be refused
    r=$(timeout 10 docker exec "$C-t" redis-cli -p 6379 ping 2>&1); rejected "$r"; record "$run" tls_plaintext_port_disabled $? "$(echo $r | head -c 60)"
    r=$(timeout 10 docker exec "$C-t" redis-cli -p 6380 ping 2>&1); rejected "$r"; record "$run" tls_plaintext_client_rejected $? "$(echo $r | head -c 60)"
    r=$(timeout 10 docker exec "$C-t" redis-cli --tls -p 6380 --cacert /tls/ca.crt ping 2>&1); rejected "$r"; record "$run" tls_no_client_cert_rejected $? "$(echo $r | head -c 60)"
    r=$(timeout 10 docker exec "$C-t" redis-cli --tls -p 6380 --cacert /tls/ca.crt --cert /tls/rogue-client.crt --key /tls/rogue-client.key ping 2>&1)
    rejected "$r"; record "$run" tls_rogue_client_cert_rejected $? "$(echo $r | head -c 60)"
    r=$(timeout 10 docker exec "$C-t" redis-cli --tls -p 6380 --cacert /tls/rogue-ca.crt --cert /tls/client.crt --key /tls/client.key ping 2>&1)
    rejected "$r"; record "$run" tls_untrusted_server_rejected $? "$(echo $r | head -c 60)"
    # protocol versions, from the host straight to the server's OpenSSL
    hp=$(docker port "$C-t" 6380/tcp | head -1); hp=${hp##*:}
    pv=$(handshake "$hp" -tls1_3); eq "$pv" "TLSv1.3"; record "$run" tls13_handshake $? "${pv:-failed}"
    pv=$(handshake "$hp" -tls1_2); eq "$pv" "TLSv1.2"; record "$run" tls12_handshake $? "${pv:-failed}"
    pv=$(handshake "$hp" -tls1_1 -cipher "DEFAULT:@SECLEVEL=0"); [ -z "$pv" ]; record "$run" tls11_rejected $? "${pv:-refused}"
    p=$(docker exec "$C-t" $TLS_CLI ping 2>&1 | tr -d '\r'); eq "$p" "PONG"; record "$run" tls_final_ping $? "$p"
  fi
  docker rm -f "$C-t" >/dev/null
done

echo "$LABEL: $FAILS failed checks -> $OUT"
[ "$FAILS" -eq 0 ]
