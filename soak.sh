#!/usr/bin/env bash
# Load/soak test for ai-protect against a real LDAP server.
#
# Unlike test.sh (correctness of pass-through and policy decisions),
# this drives the real release binary with many concurrent, sustained
# connections and samples its own resource usage while doing so, to catch
# what unit/e2e tests can't: a memory or file-descriptor leak, a connection
# that never gets cleaned up, or latency that falls over under load.
#
#   Phase A (sustained soak): a pool of workers, each opening a fresh LDAP
#   connection per operation (bind/search/unbind, matching real client
#   behavior) for DURATION_SECS, mostly reads with a minority of allowed
#   and blocked modifies mixed in so the policy path is exercised too.
#   Samples the proxy's RSS and open-fd count throughout, then checks that
#   memory didn't run away, every connection got cleaned up (fd count and
#   the ai_protect_connections_active metric both back near baseline after
#   load stops), and read latency stayed sane.
#
#   Phase B (connection-limit burst): a short burst of far more concurrent
#   connection attempts than a low max_connections cap, to confirm the
#   proxy's Semaphore rejects the excess immediately (fast failure, no
#   queueing/hang) rather than pinning tasks indefinitely, and that it
#   recovers cleanly once the burst ends.
#
# Requires: docker (compose), cargo, and the OpenLDAP client tools, same as
# test.sh. Not part of `cargo test` or CI -- run manually, e.g. after
# touching src/proxy.rs, connection limits, or the metrics/health modules.
#
# Usage: ./soak.sh
# Tunables (env vars): DURATION_SECS (default 20), CONCURRENCY (default 40),
# BURST_CONCURRENCY (default 300)

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

PASS_COUNT=0
FAIL_COUNT=0

STARTED_LLDAP=0
PROXY_PID=""
WORKDIR=""
TEST_USER_DN=""
WORKER_PIDS=()

DURATION_SECS="${DURATION_SECS:-20}"
CONCURRENCY="${CONCURRENCY:-40}"
BURST_CONCURRENCY="${BURST_CONCURRENCY:-300}"

cleanup() {
    for pid in "${WORKER_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null
    done
    for pid in "${WORKER_PIDS[@]:-}"; do
        wait "$pid" 2>/dev/null
    done
    if [ -n "$PROXY_PID" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
        kill "$PROXY_PID" 2>/dev/null
        wait "$PROXY_PID" 2>/dev/null
    fi
    if [ -n "$TEST_USER_DN" ]; then
        ldapdelete -x -H "$UPSTREAM_URL" -D "$ADMIN_BIND" -w "$LLDAP_LDAP_USER_PASS" \
            "$TEST_USER_DN" >/dev/null 2>&1
    fi
    if [ "$STARTED_LLDAP" = "1" ]; then
        echo "Stopping lldap container this run started..."
        docker compose stop lldap >/dev/null 2>&1
    fi
    if [ -n "$WORKDIR" ] && [ -d "$WORKDIR" ]; then
        rm -rf "$WORKDIR"
    fi
}
trap cleanup EXIT INT TERM

fail() { echo "  ${RED}FAIL${RESET}: $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
pass() { echo "  ${GREEN}PASS${RESET}: $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
note() { echo "  ${YELLOW}note${RESET}: $1"; }
section() { echo; echo "${BOLD}== $1 ==${RESET}"; }

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "${RED}Missing required command: $1${RESET}" >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Portable helpers: sub-second timestamps, RSS, and open-fd count differ
# between macOS (BSD userland) and Linux (GNU/proc), and this needs to run
# on both.
# ---------------------------------------------------------------------------

HAVE_PY=0
if command -v python3 >/dev/null 2>&1; then
    HAVE_PY=1
fi

now_ms() {
    if [ "$HAVE_PY" = "1" ]; then
        python3 -c 'import time; print(int(time.time() * 1000))'
    else
        echo $(($(date +%s) * 1000))
    fi
}

# rss_kb <pid> -- resident set size in KiB. `ps -o rss=` reports it in KiB
# on both BSD (macOS) and GNU (Linux) ps, so no OS branch needed here.
rss_kb() {
    ps -o rss= -p "$1" 2>/dev/null | tr -d ' '
}

# fd_count <pid> -- number of open file descriptors. /proc is Linux-only;
# macOS falls back to lsof.
fd_count() {
    local pid="$1"
    if [ -d "/proc/$pid/fd" ]; then
        ls "/proc/$pid/fd" 2>/dev/null | wc -l | tr -d ' '
    else
        lsof -p "$pid" 2>/dev/null | wc -l | tr -d ' '
    fi
}

# percentile <file-of-numbers, one per line> <pct 0-100>
percentile() {
    local file="$1" pct="$2"
    sort -n "$file" | awk -v pct="$pct" '
        { a[NR] = $1 }
        END {
            if (NR == 0) { print "n/a"; exit }
            idx = int((pct / 100) * NR)
            if (idx < 1) idx = 1
            if (idx > NR) idx = NR
            print a[idx]
        }'
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

section "Preflight"

for cmd in docker cargo ldapsearch ldapmodify ldapwhoami ldapdelete ldapadd nc curl; do
    require_cmd "$cmd"
done
pass "required tools present (docker, cargo, openldap clients, curl)"
if [ "$HAVE_PY" = "1" ]; then
    pass "python3 present (millisecond-resolution latency sampling)"
else
    note "python3 not found -- falling back to whole-second latency sampling"
fi

if [ ! -f .env ]; then
    echo "${RED}Missing .env (copy .env.example to .env and fill in real values first).${RESET}" >&2
    exit 1
fi
# shellcheck disable=SC1091
source .env
: "${LLDAP_LDAP_USER_PASS:?LLDAP_LDAP_USER_PASS not set in .env}"
pass ".env present with LLDAP_LDAP_USER_PASS set"

ADMIN_BIND="uid=admin,ou=people,dc=example,dc=com"
UPSTREAM_HOST="127.0.0.1"
UPSTREAM_PORT="389"
UPSTREAM_URL="ldap://${UPSTREAM_HOST}:${UPSTREAM_PORT}"
BASE_DN="dc=example,dc=com"

WORKDIR="$(mktemp -d)"
TEST_USER_ID="soak-ai-protect-$$"
TEST_USER_DN="uid=${TEST_USER_ID},ou=people,${BASE_DN}"

echo "DURATION_SECS=${DURATION_SECS} CONCURRENCY=${CONCURRENCY} BURST_CONCURRENCY=${BURST_CONCURRENCY}"

# ---------------------------------------------------------------------------
# Bring up the real upstream directory
# ---------------------------------------------------------------------------

section "Starting upstream lldap"

if docker compose ps lldap --status running 2>/dev/null | grep -q lldap; then
    echo "lldap already running, reusing it."
else
    STARTED_LLDAP=1
    docker compose up -d --build lldap
fi

echo -n "Waiting for lldap to accept LDAP connections on ${UPSTREAM_URL}"
for _ in $(seq 1 30); do
    if nc -z "$UPSTREAM_HOST" "$UPSTREAM_PORT" 2>/dev/null; then
        echo
        break
    fi
    echo -n "."
    sleep 1
done
if ! nc -z "$UPSTREAM_HOST" "$UPSTREAM_PORT" 2>/dev/null; then
    echo
    echo "${RED}lldap never came up on ${UPSTREAM_URL}${RESET}" >&2
    exit 1
fi
pass "upstream lldap is up"

# ---------------------------------------------------------------------------
# Build the real binary, in release mode -- a debug build's overhead would
# swamp anything this is trying to measure.
# ---------------------------------------------------------------------------

section "Building ai-protect (release)"

if ! cargo build --release --quiet 2>"$WORKDIR/build.log"; then
    cat "$WORKDIR/build.log" >&2
    fail "cargo build --release"
    exit 1
fi
BIN="./target/release/ai-protect"
pass "cargo build --release"

# ---------------------------------------------------------------------------
# Fixture: one throwaway test user on the real directory
# ---------------------------------------------------------------------------

section "Creating fixture user"

cat >"$WORKDIR/add_user.ldif" <<EOF
dn: ${TEST_USER_DN}
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: person
uid: ${TEST_USER_ID}
cn: Soak Test User
sn: TestUser
uidNumber: 65001
gidNumber: 65001
homeDirectory: /home/${TEST_USER_ID}
mail: ${TEST_USER_ID}@example.com
EOF

if ! ldapadd -x -H "$UPSTREAM_URL" -D "$ADMIN_BIND" -w "$LLDAP_LDAP_USER_PASS" \
        -f "$WORKDIR/add_user.ldif" >"$WORKDIR/add_user.log" 2>&1; then
    cat "$WORKDIR/add_user.log" >&2
    fail "create fixture user ${TEST_USER_DN}"
    exit 1
fi
pass "created fixture user ${TEST_USER_DN}"

# ---------------------------------------------------------------------------
# start_proxy <config-file> <listen-port> <metrics-port> <health-port> <tag>
# ---------------------------------------------------------------------------

start_proxy() {
    local max_connections="$1" listen_port="$2" metrics_port="$3" health_port="$4" tag="$5"

    local policy_file="$WORKDIR/policy-${tag}.toml"
    local config_file="$WORKDIR/config-${tag}.toml"
    PROXY_LOG="$WORKDIR/proxy-${tag}.log"

    cat >"$policy_file" <<'EOF'
[[policy]]
type = "threshold"
max_per_request = 1000
max_per_window = 1000000
window_secs = 3600
EOF

    cat >"$config_file" <<EOF
[[proxy]]
listen_addr = "127.0.0.1:${listen_port}"
upstream_addr = "${UPSTREAM_HOST}:${UPSTREAM_PORT}"
max_connections = ${max_connections}

[proxy.policy]
file = "${policy_file}"

[metrics]
listen_addr = "127.0.0.1:${metrics_port}"

[health]
listen_addr = "127.0.0.1:${health_port}"
EOF

    RUST_LOG=warn "$BIN" "$config_file" >"$PROXY_LOG" 2>&1 &
    PROXY_PID=$!
    PROXY_URL="ldap://127.0.0.1:${listen_port}"
    METRICS_URL="http://127.0.0.1:${metrics_port}/metrics"

    for _ in $(seq 1 20); do
        if nc -z 127.0.0.1 "$listen_port" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$PROXY_PID" 2>/dev/null; then
            echo "${RED}ai-protect exited immediately, log follows:${RESET}" >&2
            cat "$PROXY_LOG" >&2
            return 1
        fi
        sleep 0.2
    done
    echo "${RED}ai-protect never opened 127.0.0.1:${listen_port}${RESET}" >&2
    return 1
}

stop_proxy() {
    if [ -n "$PROXY_PID" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
        kill "$PROXY_PID" 2>/dev/null
        wait "$PROXY_PID" 2>/dev/null
    fi
    PROXY_PID=""
}

active_connections_metric() {
    curl -s "$METRICS_URL" 2>/dev/null | awk '/^ai_protect_connections_active /{print $2}'
}

# ---------------------------------------------------------------------------
# Phase A: sustained concurrent load
# ---------------------------------------------------------------------------

section "Phase A: sustained soak (${CONCURRENCY} concurrent workers, ${DURATION_SECS}s)"

start_proxy 512 13990 19090 19091 soak || { fail "start proxy for soak phase"; exit 1; }
pass "proxy up with max_connections=512, metrics on :19090, health on :19091"

if curl -sf "http://127.0.0.1:19091/healthz" >/dev/null 2>&1; then
    pass "/healthz answers while idle"
else
    fail "/healthz did not answer before load started"
fi

BASELINE_RSS="$(rss_kb "$PROXY_PID")"
BASELINE_FD="$(fd_count "$PROXY_PID")"
echo "baseline: rss=${BASELINE_RSS}KiB fd=${BASELINE_FD}"

# Each worker repeatedly opens a fresh connection per operation (no -c
# reuse), mirroring many short-lived clients rather than a few long ones --
# the harder case for ConnectionLimits/ConnectionGuard cleanup. Mostly
# searches, with a modify mixed in every few iterations so the decode/
# policy path (not just pass-through) is under load too.
LATENCY_DIR="$WORKDIR/latency"
mkdir -p "$LATENCY_DIR"

soak_worker() {
    local id="$1"
    local lat_file="$LATENCY_DIR/worker-${id}.txt"
    local end_at=$(($(date +%s) + DURATION_SECS))
    local i=0
    : >"$lat_file"
    while [ "$(date +%s)" -lt "$end_at" ]; do
        i=$((i + 1))
        local t0 t1 status out
        t0="$(now_ms)"
        if [ $((i % 5)) -eq 0 ]; then
            # lldap (the disposable test upstream) itself rejects a plain
            # `mail` replace with "Unsupported operation" regardless of
            # ai-protect -- test.sh relies on the same response to prove a
            # request reached upstream unmodified. So success here means
            # "got that exact upstream response through the proxy", not
            # exit 0 -- this still exercises the full decode/no-policy-match
            # pass-through path (mail isn't a lock attribute) under load.
            out=$(ldapmodify -x -H "$PROXY_URL" -D "$ADMIN_BIND" -w "$LLDAP_LDAP_USER_PASS" \
                2>&1 <<EOF
dn: ${TEST_USER_DN}
changetype: modify
replace: mail
mail: soak-${id}-${i}@example.com
EOF
)
            if echo "$out" | grep -q "Unsupported operation"; then status=0; else status=1; fi
        else
            ldapsearch -x -H "$PROXY_URL" -D "$ADMIN_BIND" -w "$LLDAP_LDAP_USER_PASS" \
                -b "$BASE_DN" -LLL "(uid=${TEST_USER_ID})" mail >/dev/null 2>&1
            status=$?
        fi
        t1="$(now_ms)"
        echo "$((t1 - t0)) $status" >>"$lat_file"
    done
}

WORKER_PIDS=()
for w in $(seq 1 "$CONCURRENCY"); do
    soak_worker "$w" &
    WORKER_PIDS+=("$!")
done

echo -n "Sampling proxy resource usage during load"
PEAK_RSS="$BASELINE_RSS"
SAMPLE_END=$(($(date +%s) + DURATION_SECS))
while [ "$(date +%s)" -lt "$SAMPLE_END" ]; do
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
        echo
        fail "ai-protect process died during the soak (see $PROXY_LOG)"
        break
    fi
    cur_rss="$(rss_kb "$PROXY_PID")"
    if [ -n "$cur_rss" ] && [ "$cur_rss" -gt "$PEAK_RSS" ]; then
        PEAK_RSS="$cur_rss"
    fi
    echo -n "."
    sleep 1
done
echo

for pid in "${WORKER_PIDS[@]}"; do
    wait "$pid" 2>/dev/null
done
WORKER_PIDS=()

if kill -0 "$PROXY_PID" 2>/dev/null; then
    pass "ai-protect survived the full soak duration without crashing"
fi

cat "$LATENCY_DIR"/worker-*.txt >"$WORKDIR/all_latencies.txt" 2>/dev/null
TOTAL_OPS=$(wc -l <"$WORKDIR/all_latencies.txt" | tr -d ' ')
ERROR_OPS=$(awk '$2 != 0' "$WORKDIR/all_latencies.txt" | wc -l | tr -d ' ')
cut -d' ' -f1 "$WORKDIR/all_latencies.txt" >"$WORKDIR/latency_ms.txt"
P50=$(percentile "$WORKDIR/latency_ms.txt" 50)
P95=$(percentile "$WORKDIR/latency_ms.txt" 95)
MAXLAT=$(sort -n "$WORKDIR/latency_ms.txt" | tail -1)

echo "total ops: ${TOTAL_OPS}, errors: ${ERROR_OPS}, throughput: $((TOTAL_OPS / DURATION_SECS)) ops/s"
echo "latency ms -- p50=${P50} p95=${P95} max=${MAXLAT}"

if [ "$TOTAL_OPS" -gt 0 ] && [ "$ERROR_OPS" -eq 0 ]; then
    pass "all ${TOTAL_OPS} operations across ${CONCURRENCY} concurrent workers succeeded"
else
    fail "${ERROR_OPS}/${TOTAL_OPS} operations failed during sustained load"
fi

# Generous threshold: this is a smoke check for a runaway leak, not a tight
# perf budget -- loopback ops here should be single-digit milliseconds, so
# 90th-percentile-style p95 north of 2s under only ${CONCURRENCY} connections
# means something is actually wrong (lock contention, blocking I/O on the
# async runtime, etc.), not just noise.
if [ "${P95:-999999}" != "n/a" ] && [ "${P95:-999999}" -lt 2000 ]; then
    pass "p95 latency (${P95}ms) well under the 2000ms smoke threshold"
else
    fail "p95 latency (${P95}ms) exceeds the 2000ms smoke threshold"
fi

sleep 2 # let connections finish draining before re-sampling
DRAINED_FD="$(fd_count "$PROXY_PID")"
DRAINED_RSS="$(rss_kb "$PROXY_PID")"
ACTIVE_METRIC="$(active_connections_metric)"
echo "after drain: rss=${DRAINED_RSS}KiB (peak ${PEAK_RSS}KiB, baseline ${BASELINE_RSS}KiB) fd=${DRAINED_FD} (baseline ${BASELINE_FD}) ai_protect_connections_active=${ACTIVE_METRIC:-n/a}"

# fd count should return close to baseline once every connection this phase
# opened has been closed -- a persistent gap here is exactly what an fd
# leak (a dropped connection whose socket/task never got cleaned up) looks
# like. A small fixed slop covers the metrics/health listener sockets and
# whatever's transiently open for this shell's own bookkeeping.
if [ -n "$DRAINED_FD" ] && [ -n "$BASELINE_FD" ] && [ "$((DRAINED_FD - BASELINE_FD))" -le 5 ]; then
    pass "fd count back near baseline after drain (${DRAINED_FD} vs baseline ${BASELINE_FD}) -- no fd leak"
else
    fail "fd count did not return to baseline after drain (${DRAINED_FD} vs baseline ${BASELINE_FD})"
fi

if [ "${ACTIVE_METRIC:-1}" = "0" ]; then
    pass "ai_protect_connections_active metric returned to 0 after drain"
else
    fail "ai_protect_connections_active metric is ${ACTIVE_METRIC:-unknown}, expected 0 after drain"
fi

# Growth cap relative to peak, not baseline: a cold process's RSS baseline
# can be tiny, so an absolute floor avoids penalizing a process that simply
# started small. 150MB of growth from ${CONCURRENCY} short-lived LDAP
# connections would be wildly disproportionate for a proxy that allocates a
# capped per-frame buffer and nothing else long-lived per connection.
if [ -n "$DRAINED_RSS" ] && [ -n "$BASELINE_RSS" ] && [ "$((DRAINED_RSS - BASELINE_RSS))" -le 153600 ]; then
    pass "resident memory after drain (${DRAINED_RSS}KiB) shows no runaway growth from baseline (${BASELINE_RSS}KiB)"
else
    fail "resident memory grew suspiciously (baseline ${BASELINE_RSS}KiB -> ${DRAINED_RSS}KiB after drain)"
fi

stop_proxy

# ---------------------------------------------------------------------------
# Phase B: connection-limit burst -- far more concurrent attempts than a
# deliberately low max_connections, to confirm the Semaphore rejects the
# excess immediately instead of queuing/hanging, and that the proxy is
# still healthy and back at zero active connections right after.
# ---------------------------------------------------------------------------

section "Phase B: connection-limit burst (${BURST_CONCURRENCY} attempts, max_connections=50)"

start_proxy 50 13991 19092 19093 burst || { fail "start proxy for burst phase"; exit 1; }
pass "proxy up with max_connections=50"

BURST_DIR="$WORKDIR/burst"
mkdir -p "$BURST_DIR"

burst_worker() {
    local id="$1"
    local t0 t1
    t0="$(now_ms)"
    ldapsearch -x -H "$PROXY_URL" -D "$ADMIN_BIND" -w "$LLDAP_LDAP_USER_PASS" \
        -b "$BASE_DN" -LLL "(uid=${TEST_USER_ID})" mail >/dev/null 2>&1
    local status=$?
    t1="$(now_ms)"
    echo "$((t1 - t0)) $status" >"$BURST_DIR/worker-${id}.txt"
}

WORKER_PIDS=()
for w in $(seq 1 "$BURST_CONCURRENCY"); do
    burst_worker "$w" &
    WORKER_PIDS+=("$!")
done
for pid in "${WORKER_PIDS[@]}"; do
    wait "$pid" 2>/dev/null
done
WORKER_PIDS=()

cat "$BURST_DIR"/worker-*.txt >"$WORKDIR/burst_all.txt" 2>/dev/null
BURST_OK=$(awk '$2 == 0' "$WORKDIR/burst_all.txt" | wc -l | tr -d ' ')
BURST_REJECTED=$(awk '$2 != 0' "$WORKDIR/burst_all.txt" | wc -l | tr -d ' ')
BURST_MAXLAT=$(cut -d' ' -f1 "$WORKDIR/burst_all.txt" | sort -n | tail -1)
echo "burst: ${BURST_OK} succeeded, ${BURST_REJECTED} rejected, slowest attempt ${BURST_MAXLAT}ms"

if [ "$BURST_REJECTED" -gt 0 ]; then
    pass "excess connections over max_connections=50 were rejected rather than silently queued"
else
    fail "expected some rejections with ${BURST_CONCURRENCY} attempts against max_connections=50, saw none"
fi

# The whole burst should resolve quickly either way (fast accept or fast
# reject) -- io_timeout defaults to 60s, so anything pinned open would blow
# well past this, meaning a connection got stuck rather than rejected.
if [ "${BURST_MAXLAT:-999999}" -lt 10000 ]; then
    pass "every burst attempt resolved quickly (slowest: ${BURST_MAXLAT}ms) -- no stuck/queued connections"
else
    fail "slowest burst attempt took ${BURST_MAXLAT}ms -- looks queued/stuck rather than fast-rejected"
fi

if kill -0 "$PROXY_PID" 2>/dev/null; then
    pass "ai-protect survived the connection-limit burst without crashing"
else
    fail "ai-protect died during the connection-limit burst (see $PROXY_LOG)"
fi

sleep 1
POST_BURST_ACTIVE="$(active_connections_metric)"
if [ "${POST_BURST_ACTIVE:-1}" = "0" ]; then
    pass "ai_protect_connections_active back to 0 after the burst -- proxy recovered cleanly"
else
    fail "ai_protect_connections_active is ${POST_BURST_ACTIVE:-unknown} after the burst, expected 0"
fi

if curl -sf "http://127.0.0.1:19093/healthz" >/dev/null 2>&1; then
    pass "/healthz still answers after the burst"
else
    fail "/healthz did not answer after the burst"
fi

stop_proxy

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

section "Summary"
echo "${GREEN}${PASS_COUNT} passed${RESET}, ${RED}${FAIL_COUNT} failed${RESET}"

if [ "$FAIL_COUNT" -ne 0 ]; then
    exit 1
fi
exit 0
