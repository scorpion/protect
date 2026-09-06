#!/usr/bin/env bash
# Full end-to-end test for ai-protect against a real LDAP server.
#
# Brings up the lldap container from compose.yaml as a real upstream
# directory, builds and runs the actual ai-protect binary (not mocks) in
# front of it, and drives it with the system `ldapsearch`/`ldapmodify`/
# `ldapwhoami`/`ldappasswd` tools to prove, over the wire:
#
#   1. Non-modify traffic (bind, search, the password-modify extended op)
#      passes through untouched, in both directions.
#   2. A ModifyRequest touching an unrelated attribute is never evaluated
#      by policy and always reaches upstream, no matter how many are sent.
#   3. A ModifyRequest touching a known lock attribute is forwarded while
#      under threshold, and blocked by the proxy itself once it would
#      exceed max_per_request or the identity's sliding window -- and that
#      every decision (allow and block) is written to the audit log.
#
# Requires: docker (compose), cargo, and the OpenLDAP client tools
# (ldapsearch/ldapmodify/ldapwhoami/ldappasswd).
#
# Usage: ./test.sh

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"

# ---------------------------------------------------------------------------
# Setup / teardown
# ---------------------------------------------------------------------------

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

PASS_COUNT=0
FAIL_COUNT=0

STARTED_LLDAP=0
PROXY_PID=""
WORKDIR=""
TEST_USER_DN=""

cleanup() {
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

fail() {
    echo "  ${RED}FAIL${RESET}: $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

pass() {
    echo "  ${GREEN}PASS${RESET}: $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

section() {
    echo
    echo "${BOLD}== $1 ==${RESET}"
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "${RED}Missing required command: $1${RESET}" >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

section "Preflight"

for cmd in docker cargo ldapsearch ldapmodify ldapwhoami ldappasswd ldapdelete ldapadd nc; do
    require_cmd "$cmd"
done
pass "required tools present (docker, cargo, openldap clients)"

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
TEST_USER_ID="e2e-ai-protect-$$"
TEST_USER_DN="uid=${TEST_USER_ID},ou=people,${BASE_DN}"

# ai-protect writes its structured JSON audit log to ./logs/ldap.log
# (relative to its own cwd, which is this repo's root throughout this
# script) regardless of which [[proxy]] entry is running -- reset it here
# so the "Structured JSON audit log" check below verifies what this run
# actually produced, not a stale file left over from an earlier run.
rm -f logs/ldap.log

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

if ! ldapwhoami -x -H "$UPSTREAM_URL" -D "$ADMIN_BIND" -w "$LLDAP_LDAP_USER_PASS" >/dev/null 2>&1; then
    echo "${RED}Could not bind to upstream lldap as ${ADMIN_BIND}. Check LLDAP_LDAP_USER_PASS in .env.${RESET}" >&2
    exit 1
fi
pass "upstream lldap is up and admin bind works"

# ---------------------------------------------------------------------------
# Build the real binary
# ---------------------------------------------------------------------------

section "Building ai-protect"

if ! cargo build --quiet 2>"$WORKDIR/build.log"; then
    cat "$WORKDIR/build.log" >&2
    fail "cargo build"
    exit 1
fi
BIN="./target/debug/ai-protect"
pass "cargo build"

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
cn: E2E Test User
sn: TestUser
uidNumber: 65000
gidNumber: 65000
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
# Helpers
# ---------------------------------------------------------------------------

# start_proxy <policy-toml-contents> <listen-port> -> writes PROXY_PID, PROXY_URL, PROXY_LOG
start_proxy() {
    local policy_contents="$1"
    local port="$2"
    local tag="$3"

    local policy_file="$WORKDIR/policy-${tag}.toml"
    local config_file="$WORKDIR/config-${tag}.toml"
    PROXY_LOG="$WORKDIR/proxy-${tag}.log"

    printf '%s\n' "$policy_contents" >"$policy_file"
    cat >"$config_file" <<EOF
[[proxy]]
listen_addr = "127.0.0.1:${port}"
upstream_addr = "${UPSTREAM_HOST}:${UPSTREAM_PORT}"

[proxy.policy]
file = "${policy_file}"
EOF

    RUST_LOG=info "$BIN" "$config_file" >"$PROXY_LOG" 2>&1 &
    PROXY_PID=$!
    PROXY_URL="ldap://127.0.0.1:${port}"

    for _ in $(seq 1 20); do
        if nc -z 127.0.0.1 "$port" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$PROXY_PID" 2>/dev/null; then
            echo "${RED}ai-protect exited immediately, log follows:${RESET}" >&2
            cat "$PROXY_LOG" >&2
            return 1
        fi
        sleep 0.2
    done
    echo "${RED}ai-protect never opened 127.0.0.1:${port}${RESET}" >&2
    return 1
}

stop_proxy() {
    if [ -n "$PROXY_PID" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
        kill "$PROXY_PID" 2>/dev/null
        wait "$PROXY_PID" 2>/dev/null
    fi
    PROXY_PID=""
}

# ---------------------------------------------------------------------------
# 1. Transparent pass-through: bind, search, and the password-modify
#    extended op (a non-ModifyRequest, so the connector never even looks
#    at it) must behave identically through the proxy as direct to upstream.
# ---------------------------------------------------------------------------

section "Pass-through of non-modify operations"

start_proxy '
[[policy]]
type = "threshold"
max_per_request = 5
max_per_window = 5
window_secs = 60
' 13890 passthrough || { fail "start proxy for pass-through tests"; exit 1; }

if ldapwhoami -x -H "$PROXY_URL" -D "$ADMIN_BIND" -w "$LLDAP_LDAP_USER_PASS" >/dev/null 2>&1; then
    pass "bind through proxy succeeds"
else
    fail "bind through proxy failed"
fi

proxy_search=$(ldapsearch -x -H "$PROXY_URL" -D "$ADMIN_BIND" -w "$LLDAP_LDAP_USER_PASS" \
    -b "$BASE_DN" -LLL "(uid=${TEST_USER_ID})" mail 2>&1)
direct_search=$(ldapsearch -x -H "$UPSTREAM_URL" -D "$ADMIN_BIND" -w "$LLDAP_LDAP_USER_PASS" \
    -b "$BASE_DN" -LLL "(uid=${TEST_USER_ID})" mail 2>&1)
if [ "$proxy_search" = "$direct_search" ] && [ -n "$proxy_search" ]; then
    pass "search results through proxy match direct-to-upstream search"
else
    fail "search through proxy diverged from direct upstream search"
fi

if ldappasswd -x -H "$PROXY_URL" -D "$ADMIN_BIND" -w "$LLDAP_LDAP_USER_PASS" \
        -s "E2eProxyPass!1" "$TEST_USER_DN" >/dev/null 2>&1 \
    && ldapwhoami -x -H "$PROXY_URL" -D "$TEST_USER_DN" -w "E2eProxyPass!1" >/dev/null 2>&1; then
    pass "password-modify extended op through proxy genuinely succeeds (rebind with new password works)"
else
    fail "password-modify extended op through proxy did not take effect"
fi

stop_proxy

# ---------------------------------------------------------------------------
# 2. Per-request cap: with max_per_request=0, a single lock-attribute
#    modify must be blocked by ai-protect itself before ever reaching
#    upstream, while an unrelated attribute still passes through.
# ---------------------------------------------------------------------------

section "Per-request blast-radius cap"

start_proxy '
[[policy]]
type = "threshold"
max_per_request = 0
max_per_window = 1000
window_secs = 120
' 13891 per_request || { fail "start proxy for per-request test"; exit 1; }

cat >"$WORKDIR/mod_lock_single.ldif" <<EOF
dn: ${TEST_USER_DN}
changetype: modify
replace: userAccountControl
userAccountControl: 514
EOF
lock_out=$(ldapmodify -x -H "$PROXY_URL" -D "$ADMIN_BIND" -w "$LLDAP_LDAP_USER_PASS" \
    -f "$WORKDIR/mod_lock_single.ldif" 2>&1)
if echo "$lock_out" | grep -q "exceeds per-request limit 0"; then
    pass "lock-attribute modify blocked by ai-protect (never reached upstream) with the expected reason"
else
    fail "expected a per-request-limit rejection from ai-protect, got: $lock_out"
fi

cat >"$WORKDIR/mod_unrelated_single.ldif" <<EOF
dn: ${TEST_USER_DN}
changetype: modify
replace: mail
mail: unrelated@example.com
EOF
unrelated_out=$(ldapmodify -x -H "$PROXY_URL" -D "$ADMIN_BIND" -w "$LLDAP_LDAP_USER_PASS" \
    -f "$WORKDIR/mod_unrelated_single.ldif" 2>&1)
if echo "$unrelated_out" | grep -q "Unsupported operation"; then
    pass "unrelated-attribute modify still reached upstream under the same (maximally strict) policy"
else
    fail "expected unrelated attribute to reach upstream unaffected, got: $unrelated_out"
fi

if grep -q 'action blocked.*blast radius 1 exceeds per-request limit 0' "$PROXY_LOG"; then
    pass "block decision was audit-logged with the correct reason"
else
    fail "did not find the expected audit log entry for the per-request block"
fi

stop_proxy

# ---------------------------------------------------------------------------
# 3. Sliding window: N lock-attribute modifies over one connection (one
#    identity) are forwarded upstream; the (N+1)th is blocked by ai-protect.
#    An equal number of unrelated-attribute modifies over the same window
#    must never be blocked.
# ---------------------------------------------------------------------------

section "Per-identity sliding window"

WINDOW_LIMIT=3
start_proxy "
[[policy]]
type = \"threshold\"
max_per_request = 1000
max_per_window = ${WINDOW_LIMIT}
window_secs = 120
" 13892 window || { fail "start proxy for window test"; exit 1; }

# All records below are sent over a single ldapmodify connection (one bind,
# one TCP peer address), which is what ai-protect's Identity is keyed on.
{
    for i in $(seq 1 $((WINDOW_LIMIT + 1))); do
        cat <<EOF
dn: ${TEST_USER_DN}
changetype: modify
replace: nsAccountLock
nsAccountLock: TRUE

EOF
    done
} >"$WORKDIR/mod_lock_burst.ldif"

burst_out=$(ldapmodify -x -c -H "$PROXY_URL" -D "$ADMIN_BIND" -w "$LLDAP_LDAP_USER_PASS" \
    -f "$WORKDIR/mod_lock_burst.ldif" 2>&1)

forwarded_count=$(echo "$burst_out" | grep -c "Unsupported operation")
blocked_count=$(echo "$burst_out" | grep -c "would exceed window limit ${WINDOW_LIMIT}")

if [ "$forwarded_count" -eq "$WINDOW_LIMIT" ]; then
    pass "first ${WINDOW_LIMIT} lock-attribute modifies in the burst were forwarded to upstream"
else
    fail "expected ${WINDOW_LIMIT} modifies forwarded to upstream, saw ${forwarded_count}. Output:
$burst_out"
fi

if [ "$blocked_count" -eq 1 ]; then
    pass "the (${WINDOW_LIMIT}+1)th lock-attribute modify in the burst was blocked by ai-protect"
else
    fail "expected exactly 1 window-limit rejection, saw ${blocked_count}. Output:
$burst_out"
fi

{
    for i in $(seq 1 $((WINDOW_LIMIT + 2))); do
        cat <<EOF
dn: ${TEST_USER_DN}
changetype: modify
replace: mail
mail: unrelated-burst-${i}@example.com

EOF
    done
} >"$WORKDIR/mod_unrelated_burst.ldif"

unrelated_burst_out=$(ldapmodify -x -c -H "$PROXY_URL" -D "$ADMIN_BIND" -w "$LLDAP_LDAP_USER_PASS" \
    -f "$WORKDIR/mod_unrelated_burst.ldif" 2>&1)
unrelated_forwarded=$(echo "$unrelated_burst_out" | grep -c "Unsupported operation")
if [ "$unrelated_forwarded" -eq $((WINDOW_LIMIT + 2)) ]; then
    pass "unrelated-attribute modifies are immune to the lock-attribute window (all $((WINDOW_LIMIT + 2)) reached upstream)"
else
    fail "expected all unrelated modifies to reach upstream unaffected, saw ${unrelated_forwarded}/$((WINDOW_LIMIT + 2))"
fi

allow_logged=$(grep -c "action allowed" "$PROXY_LOG")
block_logged=$(grep -c "action blocked" "$PROXY_LOG")
if [ "$allow_logged" -ge "$WINDOW_LIMIT" ] && [ "$block_logged" -ge 1 ]; then
    pass "both allow and block decisions from the burst were audit-logged (${allow_logged} allowed, ${block_logged} blocked)"
else
    fail "audit log missing expected allow/block entries (${allow_logged} allowed, ${block_logged} blocked)"
fi

stop_proxy

# ---------------------------------------------------------------------------
# 4. Structured JSON audit log: every proxy instance above shares one
#    ./logs/ldap.log (see the reset near the top of this script), so by now
#    it should hold both an allow and a block decision as single-line JSON
#    objects with fields flattened to the top level (not nested under
#    "fields"), which is what a log shipper/SIEM expects to parse.
# ---------------------------------------------------------------------------

section "Structured JSON audit log"

if [ -s logs/ldap.log ]; then
    pass "logs/ldap.log was written to"
else
    fail "logs/ldap.log is missing or empty"
fi

first_line=$(head -n1 logs/ldap.log)
if echo "$first_line" | grep -Eq '^\{.*"timestamp":"[^"]+".*"level":"[A-Z]+".*\}$'; then
    pass "logs/ldap.log lines are JSON objects with the expected fields"
else
    fail "first line of logs/ldap.log doesn't look like JSON: $first_line"
fi

if grep -q '"message":"action allowed"' logs/ldap.log \
        && grep -q '"message":"action blocked"' logs/ldap.log \
        && grep -q '"reason":' logs/ldap.log; then
    pass "logs/ldap.log captured both allow and block decisions with flattened fields"
else
    fail "logs/ldap.log missing expected allow/block/reason fields"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

section "Summary"
echo "${GREEN}${PASS_COUNT} passed${RESET}, ${RED}${FAIL_COUNT} failed${RESET}"

if [ "$FAIL_COUNT" -ne 0 ]; then
    exit 1
fi
exit 0
