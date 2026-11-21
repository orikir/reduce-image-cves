
#!/bin/bash

ORIGINAL="${ORIGINAL:-redis:7-bookworm}"
SECURED="${SECURED:-redis-secure:alpine-v3}"

FAILURES=0
RESULTS_FILE="redis-test-results.txt"

run_tests() {
    IMAGE="$1"
    LABEL="$2"
    CONTAINER="redis-test"

    echo ""
    echo "========================================"
    echo "Testing: $LABEL"
    echo "Image: $IMAGE"
    echo "========================================"

    docker rm -f "$CONTAINER" >/dev/null 2>&1

    if ! docker run -d --name "$CONTAINER" "$IMAGE" >/dev/null; then
        echo "ERROR: Failed to start $IMAGE"
        FAILURES=$((FAILURES + 1))
        return
    fi

    sleep 2

    check() {
        NAME="$1"
        ACTUAL="$2"
        EXPECTED="$3"

        if [ "$ACTUAL" = "$EXPECTED" ]; then
            echo "PASS: $NAME"
            echo "$LABEL | $NAME | PASS" >> "$RESULTS_FILE"
        else
            echo "FAIL: $NAME"
            echo "Expected: [$EXPECTED]"
            echo "Actual:   [$ACTUAL]"
            echo "$LABEL | $NAME | FAIL" >> "$RESULTS_FILE"
            FAILURES=$((FAILURES + 1))
        fi
    }

    # Connectivity
    RESULT=$(docker exec "$CONTAINER" redis-cli --raw PING)
    check "PING" "$RESULT" "PONG"

    # Basic operations
    docker exec "$CONTAINER" redis-cli SET test-key hello >/dev/null
    RESULT=$(docker exec "$CONTAINER" redis-cli --raw GET test-key)
    check "SET / GET" "$RESULT" "hello"

    docker exec "$CONTAINER" redis-cli SET test-key updated >/dev/null
    RESULT=$(docker exec "$CONTAINER" redis-cli --raw GET test-key)
    check "Update key" "$RESULT" "updated"

    RESULT=$(docker exec "$CONTAINER" redis-cli --raw EXISTS test-key)
    check "EXISTS" "$RESULT" "1"

    docker exec "$CONTAINER" redis-cli APPEND test-key " world" >/dev/null
    RESULT=$(docker exec "$CONTAINER" redis-cli --raw GET test-key)
    check "APPEND" "$RESULT" "updated world"

    # Numeric operations
    docker exec "$CONTAINER" redis-cli SET counter 10 >/dev/null
    docker exec "$CONTAINER" redis-cli INCR counter >/dev/null
    RESULT=$(docker exec "$CONTAINER" redis-cli --raw GET counter)
    check "INCR" "$RESULT" "11"

    docker exec "$CONTAINER" redis-cli DECR counter >/dev/null
    RESULT=$(docker exec "$CONTAINER" redis-cli --raw GET counter)
    check "DECR" "$RESULT" "10"

    # Delete
    docker exec "$CONTAINER" redis-cli DEL test-key >/dev/null
    RESULT=$(docker exec "$CONTAINER" redis-cli --raw EXISTS test-key)
    check "DEL" "$RESULT" "0"

    # Lists
    docker exec "$CONTAINER" redis-cli RPUSH mylist first second third >/dev/null
    RESULT=$(docker exec "$CONTAINER" redis-cli --raw LRANGE mylist 0 -1 | paste -sd ' ' -)
    check "Lists" "$RESULT" "first second third"

    # Sets
    docker exec "$CONTAINER" redis-cli SADD myset apple banana orange >/dev/null
    RESULT=$(docker exec "$CONTAINER" redis-cli --raw SISMEMBER myset apple)
    check "Sets" "$RESULT" "1"

    # Hashes
    docker exec "$CONTAINER" redis-cli HSET user:1 name Alice age 30 >/dev/null
    RESULT=$(docker exec "$CONTAINER" redis-cli --raw HGET user:1 name)
    check "Hashes" "$RESULT" "Alice"

    # TTL
    docker exec "$CONTAINER" redis-cli SET temporary-key value EX 5 >/dev/null
    RESULT=$(docker exec "$CONTAINER" redis-cli --raw TTL temporary-key)

    if [[ "$RESULT" =~ ^[1-5]$ ]]; then
        echo "PASS: TTL"
        echo "$LABEL | TTL | PASS" >> "$RESULTS_FILE"
    else
        echo "FAIL: TTL (remaining: $RESULT)"
        echo "$LABEL | TTL | FAIL" >> "$RESULTS_FILE"
        FAILURES=$((FAILURES + 1))
    fi

    echo "Waiting for expiration..."
    sleep 6

    RESULT=$(docker exec "$CONTAINER" redis-cli --raw GET temporary-key)
    check "Expired key returns nil" "$RESULT" ""

    # Persistence
    docker exec "$CONTAINER" redis-cli SET persist-key saved-value >/dev/null
    RESULT=$(docker exec "$CONTAINER" redis-cli --raw SAVE)
    check "RDB SAVE" "$RESULT" "OK"

    # Database size
    RESULT=$(docker exec "$CONTAINER" redis-cli --raw DBSIZE)
    if [[ "$RESULT" =~ ^[1-9][0-9]*$ ]]; then
        echo "PASS: DBSIZE"
        echo "$LABEL | DBSIZE | PASS" >> "$RESULTS_FILE"
    else
        echo "FAIL: DBSIZE"
        echo "$LABEL | DBSIZE | FAIL" >> "$RESULTS_FILE"
        FAILURES=$((FAILURES + 1))
    fi

    # Final health check
    RESULT=$(docker exec "$CONTAINER" redis-cli --raw PING)
    check "Final PING" "$RESULT" "PONG"

    docker rm -f "$CONTAINER" >/dev/null
    echo "Container removed."
}

# ---------------------------------------------------------------
# TLS tests
# ---------------------------------------------------------------
# Throw-away test certificates, generated on the host with openssl.
# The "rogue" CA is not trusted by Redis and is used for negative tests.
CERTS_DIR="$(pwd)/tls-test-certs"
TLS_CONTAINER="redis-tls-test"

generate_certs() {
    if ! command -v openssl >/dev/null; then
        echo "ERROR: openssl is needed on the host to generate test certificates"
        exit 1
    fi

    rm -rf "$CERTS_DIR"
    mkdir -p "$CERTS_DIR"
    (
        cd "$CERTS_DIR" || exit 1

        # Trusted CA and a rogue (untrusted) CA
        openssl req -x509 -new -nodes -newkey rsa:2048 -days 1 \
            -keyout ca.key -out ca.crt -subj "/CN=Redis Test CA"
        openssl req -x509 -new -nodes -newkey rsa:2048 -days 1 \
            -keyout rogue-ca.key -out rogue-ca.crt -subj "/CN=Rogue CA"

        # Server certificate (signed by the trusted CA)
        printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" > server.ext
        openssl req -new -nodes -newkey rsa:2048 \
            -keyout server.key -out server.csr -subj "/CN=localhost"
        openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
            -days 1 -extfile server.ext -out server.crt

        # Client certificates: one trusted, one signed by the rogue CA
        printf "extendedKeyUsage=clientAuth\n" > client.ext
        openssl req -new -nodes -newkey rsa:2048 \
            -keyout client.key -out client.csr -subj "/CN=redis-client"
        openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
            -days 1 -extfile client.ext -out client.crt
        openssl req -new -nodes -newkey rsa:2048 \
            -keyout rogue-client.key -out rogue-client.csr -subj "/CN=rogue-client"
        openssl x509 -req -in rogue-client.csr -CA rogue-ca.crt -CAkey rogue-ca.key \
            -CAcreateserial -days 1 -extfile client.ext -out rogue-client.crt

        # Test-only keys: readable by the non-root redis user in the container
        chmod 755 .
        chmod 644 ./*.key ./*.crt
    ) >/dev/null 2>&1 || { echo "ERROR: certificate generation failed"; exit 1; }
}

pass_or_fail() {
    NAME="$1"
    OK="$2"
    DETAIL="$3"

    if [ "$OK" = "yes" ]; then
        echo "PASS: $NAME"
        echo "$LABEL | $NAME | PASS" >> "$RESULTS_FILE"
    else
        echo "FAIL: $NAME"
        [ -n "$DETAIL" ] && echo "Actual:   [$DETAIL]"
        echo "$LABEL | $NAME | FAIL" >> "$RESULTS_FILE"
        FAILURES=$((FAILURES + 1))
    fi
}

# A connection that must be refused: it passes when the command does NOT return PONG
check_rejected() {
    NAME="$1"
    ACTUAL="$2"

    if [[ "$ACTUAL" == *PONG* ]]; then
        pass_or_fail "$NAME" "no" "$ACTUAL"
    else
        pass_or_fail "$NAME" "yes"
    fi
}

# Run openssl s_client from the host and print the negotiated protocol (empty if the handshake failed)
tls_handshake_protocol() {
    PORT="$1"
    shift
    timeout 10 openssl s_client -brief -connect "127.0.0.1:$PORT" \
        -CAfile "$CERTS_DIR/ca.crt" -verify_return_error \
        -cert "$CERTS_DIR/client.crt" -key "$CERTS_DIR/client.key" "$@" \
        </dev/null 2>&1 | awk -F': ' '/^Protocol version/ {print $2}'
}

run_tls_tests() {
    IMAGE="$1"
    LABEL="$2"

    echo ""
    echo "========================================"
    echo "TLS testing: $LABEL"
    echo "Image: $IMAGE"
    echo "========================================"

    docker rm -f "$TLS_CONTAINER" >/dev/null 2>&1

    # TLS only: plain-text port disabled, client certificates required (Redis default)
    if ! docker run -d --name "$TLS_CONTAINER" \
        -v "$CERTS_DIR":/tls:ro \
        -p 127.0.0.1::6380 \
        "$IMAGE" redis-server \
            --port 0 \
            --tls-port 6380 \
            --tls-cert-file /tls/server.crt \
            --tls-key-file /tls/server.key \
            --tls-ca-cert-file /tls/ca.crt >/dev/null; then
        echo "ERROR: Failed to start $IMAGE with TLS"
        FAILURES=$((FAILURES + 1))
        return
    fi

    sleep 2

    TLS_CLI="redis-cli --tls -p 6380 --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key"
    HOST_PORT=$(docker port "$TLS_CONTAINER" 6380/tcp | head -1)
    HOST_PORT="${HOST_PORT##*:}"

    # Positive tests
    RESULT=$(docker exec "$TLS_CONTAINER" $TLS_CLI --raw PING 2>&1)
    check "TLS PING" "$RESULT" "PONG"

    docker exec "$TLS_CONTAINER" $TLS_CLI SET tls-key tls-value >/dev/null 2>&1
    RESULT=$(docker exec "$TLS_CONTAINER" $TLS_CLI --raw GET tls-key 2>&1)
    check "TLS SET / GET" "$RESULT" "tls-value"

    # Negative tests: each connection must be refused
    RESULT=$(timeout 10 docker exec "$TLS_CONTAINER" redis-cli -p 6379 PING 2>&1)
    check_rejected "Plain-text port disabled" "$RESULT"

    RESULT=$(timeout 10 docker exec "$TLS_CONTAINER" redis-cli -p 6380 PING 2>&1)
    check_rejected "Plain-text client on TLS port rejected" "$RESULT"

    RESULT=$(timeout 10 docker exec "$TLS_CONTAINER" \
        redis-cli --tls -p 6380 --cacert /tls/ca.crt PING 2>&1)
    check_rejected "Client without certificate rejected" "$RESULT"

    RESULT=$(timeout 10 docker exec "$TLS_CONTAINER" \
        redis-cli --tls -p 6380 --cacert /tls/ca.crt \
        --cert /tls/rogue-client.crt --key /tls/rogue-client.key PING 2>&1)
    check_rejected "Client certificate from untrusted CA rejected" "$RESULT"

    RESULT=$(timeout 10 docker exec "$TLS_CONTAINER" \
        redis-cli --tls -p 6380 --cacert /tls/rogue-ca.crt \
        --cert /tls/client.crt --key /tls/client.key PING 2>&1)
    check_rejected "Untrusted server certificate rejected by client" "$RESULT"

    # Protocol checks from the host (tests the server's OpenSSL directly)
    RESULT=$(tls_handshake_protocol "$HOST_PORT" -tls1_3)
    check "TLS 1.3 handshake" "$RESULT" "TLSv1.3"

    RESULT=$(tls_handshake_protocol "$HOST_PORT" -tls1_2)
    check "TLS 1.2 handshake" "$RESULT" "TLSv1.2"

    RESULT=$(tls_handshake_protocol "$HOST_PORT" -tls1_1 -cipher "DEFAULT:@SECLEVEL=0")
    if [ -z "$RESULT" ]; then
        pass_or_fail "TLS 1.1 rejected" "yes"
    else
        pass_or_fail "TLS 1.1 rejected" "no" "$RESULT"
    fi

    # Server is still healthy after the failed handshakes
    RESULT=$(docker exec "$TLS_CONTAINER" $TLS_CLI --raw PING 2>&1)
    check "Final TLS PING" "$RESULT" "PONG"

    docker rm -f "$TLS_CONTAINER" >/dev/null
    echo "TLS container removed."
}

cleanup() {
    docker rm -f redis-test "$TLS_CONTAINER" >/dev/null 2>&1
    rm -rf "$CERTS_DIR"
}
trap cleanup EXIT

# Reset results
: > "$RESULTS_FILE"

generate_certs

# Run identical tests
run_tests "$ORIGINAL" "ORIGINAL"
run_tls_tests "$ORIGINAL" "ORIGINAL"
run_tests "$SECURED" "SECURED"
run_tls_tests "$SECURED" "SECURED"

# Summary
echo ""
echo "========================================"
echo "COMPARISON SUMMARY"
echo "========================================"

echo ""
echo "Original image:"
grep "^ORIGINAL" "$RESULTS_FILE"

echo ""
echo "Secured image:"
grep "^SECURED" "$RESULTS_FILE"

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "ALL TESTS PASSED ON BOTH IMAGES!"
else
    echo "$FAILURES TEST(S) FAILED."
fi

echo "========================================"
echo "Full results saved to $RESULTS_FILE"
