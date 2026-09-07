#!/usr/bin/env bash
# Interactive setup: interrogates the real upstream directory server this
# ai-protect instance will front, and writes config.toml + policies/ldap.toml
# (both gitignored, not tracked -- see config.example.toml and
# policies/ldap.example.toml) tailored to what it finds, instead of a plain
# copy of the templates with placeholder values.
#
# What it does, all read-only against the upstream:
#   - checks TCP reachability on the chosen port
#   - reads rootDSE (namingContexts, vendorName, supportedExtension, ...) to
#     guess the backend (AD / OpenLDAP / 389 DS) and whether StartTLS /
#     RFC 3062 Password Modify are advertised
#   - if TLS is in play, fetches the upstream certificate to help you decide
#     server_name/ca_file, without asking you to already know them
# It never writes to the directory, and any bind DN/password you give it for
# the rootDSE query is used in-memory only -- never written to config.toml.
#
# Requires: ldapsearch (OpenLDAP client tools), nc, openssl, awk.
#
# Usage: ./setup.sh

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

ok()      { echo "  ${GREEN}✓${RESET} $1"; }
warn()    { echo "  ${YELLOW}!${RESET} $1"; }
err()     { echo "  ${RED}✗${RESET} $1" >&2; }
section() { echo; echo "${BOLD}== $1 ==${RESET}"; }

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "Missing required command: $1"
        exit 1
    fi
}

# ask <var-name> <prompt> [default]
ask() {
    local __var="$1" __prompt="$2" __default="${3-}" __reply
    if [ -n "$__default" ]; then
        read -r -p "$__prompt [$__default]: " __reply </dev/tty
        __reply="${__reply:-$__default}"
    else
        read -r -p "$__prompt: " __reply </dev/tty
    fi
    printf -v "$__var" '%s' "$__reply"
}

# ask_secret <var-name> <prompt>
ask_secret() {
    local __var="$1" __prompt="$2" __reply
    read -r -s -p "$__prompt: " __reply </dev/tty
    echo
    printf -v "$__var" '%s' "$__reply"
}

# confirm <prompt> [default: y|n] -> 0 (true) for yes
confirm() {
    local prompt="$1" default="${2:-y}" reply hint
    [ "$default" = "y" ] && hint="Y/n" || hint="y/N"
    read -r -p "$prompt [$hint]: " reply </dev/tty
    reply="${reply:-$default}"
    [[ "$reply" =~ ^[Yy] ]]
}

backup_if_exists() {
    local f="$1"
    if [ -f "$f" ]; then
        local bak
        bak="${f}.bak.$(date +%Y%m%d%H%M%S)"
        cp "$f" "$bak"
        warn "existing $f backed up to $bak"
    fi
}

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT INT TERM

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

section "Preflight"

for cmd in ldapsearch nc openssl awk; do
    require_cmd "$cmd"
done
ok "required tools present (ldapsearch, nc, openssl, awk)"

if [ ! -e /dev/tty ]; then
    err "setup.sh is interactive and needs a terminal (no /dev/tty available)."
    exit 1
fi

echo
echo "This will interrogate a live upstream LDAP server (read-only: rootDSE"
echo "and a TLS handshake, nothing is modified) and then write config.toml +"
echo "policies/ldap.toml. Existing copies of either are backed up first."

# ---------------------------------------------------------------------------
# Upstream connection details
# ---------------------------------------------------------------------------

section "Upstream directory"

ask UPSTREAM_HOST "Upstream LDAP host" "127.0.0.1"

echo
echo "Connection type on that host:"
echo "  1) Plaintext LDAP"
echo "  2) LDAPS -- implicit TLS"
echo "  3) Plaintext LDAP that upgrades via StartTLS"
ask CONN_CHOICE "Choice" "1"

case "$CONN_CHOICE" in
    2) DEFAULT_PORT=636; UPSTREAM_TLS_MODE="ldaps" ;;
    3) DEFAULT_PORT=389; UPSTREAM_TLS_MODE="starttls" ;;
    *) DEFAULT_PORT=389; UPSTREAM_TLS_MODE="plain" ;;
esac
ask UPSTREAM_PORT "Upstream LDAP port" "$DEFAULT_PORT"

section "Connectivity"

if nc -z -w 3 "$UPSTREAM_HOST" "$UPSTREAM_PORT" 2>/dev/null; then
    ok "TCP reachable at ${UPSTREAM_HOST}:${UPSTREAM_PORT}"
else
    err "Cannot reach ${UPSTREAM_HOST}:${UPSTREAM_PORT} over TCP from here."
    if ! confirm "Continue anyway (e.g. it's only reachable from where ai-protect itself will run)?" n; then
        exit 1
    fi
fi

case "$UPSTREAM_TLS_MODE" in
    ldaps)    LDAP_URL="ldaps://${UPSTREAM_HOST}:${UPSTREAM_PORT}"; LDAPSEARCH_TLS_OPTS=() ;;
    starttls) LDAP_URL="ldap://${UPSTREAM_HOST}:${UPSTREAM_PORT}";  LDAPSEARCH_TLS_OPTS=(-ZZ) ;;
    *)        LDAP_URL="ldap://${UPSTREAM_HOST}:${UPSTREAM_PORT}";  LDAPSEARCH_TLS_OPTS=() ;;
esac

# ---------------------------------------------------------------------------
# TLS certificate inspection (upstream hop only)
# ---------------------------------------------------------------------------

UPSTREAM_TLS_SERVER_NAME=""
UPSTREAM_TLS_CA_FILE=""
UPSTREAM_TLS_CLIENT_CERT=""
UPSTREAM_TLS_CLIENT_KEY=""

if [ "$UPSTREAM_TLS_MODE" != "plain" ]; then
    section "TLS certificate (upstream)"

    openssl_args=(-connect "${UPSTREAM_HOST}:${UPSTREAM_PORT}" -servername "$UPSTREAM_HOST")
    [ "$UPSTREAM_TLS_MODE" = "starttls" ] && openssl_args+=(-starttls ldap)

    CERT_INFO="$(openssl s_client "${openssl_args[@]}" </dev/null 2>/dev/null \
        | openssl x509 -noout -subject -issuer -dates 2>/dev/null)"

    SELF_SIGNED=""
    if [ -n "$CERT_INFO" ]; then
        echo "$CERT_INFO" | sed 's/^/  /'
        SUBJ_LINE="$(echo "$CERT_INFO" | grep '^subject=')"
        ISSUER_LINE="$(echo "$CERT_INFO" | grep '^issuer=')"
        if [ "$SUBJ_LINE" = "${ISSUER_LINE/issuer=/subject=}" ]; then
            SELF_SIGNED=1
            warn "certificate is self-signed (subject == issuer)"
        fi
    else
        warn "Could not retrieve the upstream certificate (SNI, a required client cert, or an old openssl without -starttls ldap support could all cause this). You'll need to fill in server_name/ca_file yourself below."
    fi

    ask UPSTREAM_TLS_SERVER_NAME "Hostname to validate the upstream cert against (server_name / SNI)" "$UPSTREAM_HOST"

    default_ca_answer="n"; [ -n "$SELF_SIGNED" ] && default_ca_answer="y"
    if confirm "Is the upstream cert signed by an internal/enterprise CA not in the OS trust store?" "$default_ca_answer"; then
        ask UPSTREAM_TLS_CA_FILE "Path to that CA cert (PEM)" "certs/internal-ca.pem"
    fi

    if confirm "Does the upstream require a client certificate (mutual TLS) on this hop?" n; then
        ask UPSTREAM_TLS_CLIENT_CERT "Client cert file (PEM)" "certs/ai-protect-client.pem"
        ask UPSTREAM_TLS_CLIENT_KEY "Client key file (PEM)" "certs/ai-protect-client.key"
    fi
fi

# ---------------------------------------------------------------------------
# rootDSE interrogation
# ---------------------------------------------------------------------------

section "Directory interrogation (rootDSE)"

ROOTDSE_ATTRS=(namingContexts vendorName vendorVersion supportedExtension supportedControl supportedCapabilities)

# Certificate trust for THIS discovery script's own ldapsearch calls is
# deliberately relaxed -- the real trust decision (ca_file above) governs
# what the Rust proxy itself will accept at runtime, not this read-only probe.
[ "$UPSTREAM_TLS_MODE" != "plain" ] && export LDAPTLS_REQCERT=allow

# LDIF continuation lines (RFC 2849) start with a single space; unfold them
# before parsing so a wrapped namingContexts/vendorName doesn't get cut off.
unfold() {
    awk '{
        if ($0 ~ /^ /) { line = line substr($0, 2) }
        else { if (line != "") print line; line = $0 }
    } END { if (line != "") print line }'
}

BIND_ARGS=()
USED_CREDS=0

try_rootdse() {
    # ${arr[@]+"${arr[@]}"} instead of a bare "${arr[@]}": bash 3.2 (macOS's
    # default /bin/bash) treats expanding an empty array as an unset
    # variable under `set -u` otherwise.
    ldapsearch -x -H "$LDAP_URL" ${LDAPSEARCH_TLS_OPTS[@]+"${LDAPSEARCH_TLS_OPTS[@]}"} ${BIND_ARGS[@]+"${BIND_ARGS[@]}"} \
        -s base -b "" -LLL "${ROOTDSE_ATTRS[@]}" 2>"$WORKDIR/rootdse.err" | unfold
}

ROOTDSE_OUT="$(try_rootdse)"
if [ -z "$ROOTDSE_OUT" ]; then
    warn "Anonymous rootDSE query returned nothing ($(head -n1 "$WORKDIR/rootdse.err" 2>/dev/null))."
    if confirm "Retry with a bind DN/password (common for servers that reject anonymous binds, e.g. Active Directory)?" y; then
        ask BIND_DN "Bind DN"
        ask_secret BIND_PW "Bind password"
        BIND_ARGS=(-D "$BIND_DN" -w "$BIND_PW")
        USED_CREDS=1
        ROOTDSE_OUT="$(try_rootdse)"
    fi
fi

get_attr() {
    local want
    want="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]'):"
    echo "$ROOTDSE_OUT" | awk -v want="$want" '
        { lc = tolower($0)
          if (index(lc, want) == 1) { sub(/^[^:]+:[ ]?/, ""); print } }'
}

VENDOR_GUESS="unknown -- ai-protect detects the right lock attribute across AD/OpenLDAP/389 DS at runtime regardless"
SUPPORTS_STARTTLS=0
SUPPORTS_PWDMODIFY=0
NAMING_CONTEXTS=""

if [ -z "$ROOTDSE_OUT" ]; then
    err "Could not read rootDSE even with credentials. Continuing with generic defaults."
else
    ok "rootDSE retrieved$([ "$USED_CREDS" = 1 ] && echo " (authenticated)")"
    if [ "$USED_CREDS" = 1 ]; then
        warn "the bind DN/password above were used only for this query and are not written to any generated file"
    fi

    NAMING_CONTEXTS="$(get_attr namingContexts)"
    VENDOR_NAME="$(get_attr vendorName)"
    SUPPORTED_EXT="$(get_attr supportedExtension)"
    SUPPORTED_CAPS="$(get_attr supportedCapabilities)"

    echo "$SUPPORTED_EXT" | grep -q '1\.3\.6\.1\.4\.1\.1466\.20037' && SUPPORTS_STARTTLS=1
    echo "$SUPPORTED_EXT" | grep -q '1\.3\.6\.1\.4\.1\.4203\.1\.11\.1' && SUPPORTS_PWDMODIFY=1

    if echo "$SUPPORTED_CAPS" | grep -q '1\.2\.840\.113556\.1\.4\.800' || echo "$VENDOR_NAME" | grep -qi "microsoft"; then
        VENDOR_GUESS="Active Directory"
    elif echo "$VENDOR_NAME" | grep -qiE "389|red hat|fedora"; then
        VENDOR_GUESS="389 Directory Server"
    elif echo "$VENDOR_NAME" | grep -qi "openldap"; then
        VENDOR_GUESS="OpenLDAP"
    elif [ -z "$VENDOR_NAME" ]; then
        VENDOR_GUESS="OpenLDAP (likely -- vendorName is unset, which is OpenLDAP's out-of-the-box default)"
    else
        VENDOR_GUESS="unknown (vendorName: ${VENDOR_NAME})"
    fi

    echo "  Naming contexts : $(echo "$NAMING_CONTEXTS" | paste -sd, -)"
    echo "  Vendor guess    : $VENDOR_GUESS"
    echo "  StartTLS        : $([ "$SUPPORTS_STARTTLS" = 1 ] && echo yes || echo 'not advertised')"
    echo "  Password Modify : $([ "$SUPPORTS_PWDMODIFY" = 1 ] && echo yes || echo 'not advertised (still passed through untouched if used)')"

    if [ "$UPSTREAM_TLS_MODE" = "plain" ] && [ "$SUPPORTS_STARTTLS" = 1 ]; then
        warn "this server advertises StartTLS support -- consider re-running and choosing option 3 to encrypt this hop"
    fi
fi

# ---------------------------------------------------------------------------
# Proxy listener (client-facing side)
# ---------------------------------------------------------------------------

section "Proxy listener"

ask LISTEN_ADDR "Address ai-protect listens on for clients" "127.0.0.1:3890"

LISTEN_TLS_MODE="plain"
LISTEN_CERT=""; LISTEN_KEY=""; LISTEN_CLIENT_CA=""

if confirm "Should ai-protect itself terminate TLS for connecting clients (LDAPS on $LISTEN_ADDR)?" n; then
    LISTEN_TLS_MODE="ldaps"
    ask LISTEN_CERT "Server cert file (PEM) for clients" "certs/server.pem"
    ask LISTEN_KEY "Server key file (PEM) for clients" "certs/server.key"
    if confirm "Require mutual TLS from clients (only accept certs signed by a given CA)?" n; then
        ask LISTEN_CLIENT_CA "Client CA file (PEM)" "certs/agent-ca.pem"
    fi
elif confirm "Accept plaintext from clients but allow a StartTLS upgrade mid-session?" n; then
    LISTEN_TLS_MODE="starttls"
    ask LISTEN_CERT "Server cert file (PEM) for clients" "certs/server.pem"
    ask LISTEN_KEY "Server key file (PEM) for clients" "certs/server.key"
fi

# ---------------------------------------------------------------------------
# Upstream load balancing
# ---------------------------------------------------------------------------

EXTRA_UPSTREAMS=""
UPSTREAM_STRATEGY="round_robin"

section "Upstream load balancing"

if confirm "Do you have more than one upstream replica to load-balance across?" n; then
    ask EXTRA_UPSTREAMS "Additional upstream host:port entries, comma-separated" ""
    if [ -n "$EXTRA_UPSTREAMS" ]; then
        echo "Load-balancing strategy: 1) round_robin  2) random  3) least_connections"
        ask STRAT_CHOICE "Choice" "1"
        case "$STRAT_CHOICE" in
            2) UPSTREAM_STRATEGY="random" ;;
            3) UPSTREAM_STRATEGY="least_connections" ;;
            *) UPSTREAM_STRATEGY="round_robin" ;;
        esac
    fi
fi

# ---------------------------------------------------------------------------
# Observability
# ---------------------------------------------------------------------------

section "Observability"

ENABLE_METRICS=0; METRICS_ADDR="127.0.0.1:9090"
if confirm "Enable a Prometheus /metrics endpoint?" y; then
    ENABLE_METRICS=1
    ask METRICS_ADDR "Metrics listen address" "$METRICS_ADDR"
fi

ENABLE_HEALTH=0; HEALTH_ADDR="127.0.0.1:9091"
if confirm "Enable /healthz + /readyz endpoints for orchestrator probes?" y; then
    ENABLE_HEALTH=1
    ask HEALTH_ADDR "Health listen address" "$HEALTH_ADDR"
fi

# ---------------------------------------------------------------------------
# Policy thresholds
# ---------------------------------------------------------------------------

section "Policy thresholds"

echo "Starting threshold preset for account-lock/unlock + password-reset"
echo "traffic (hand-tune policies/ldap.toml afterwards as needed):"
echo "  1) Conservative -- max 5/request, 20/window over 60s"
echo "  2) Moderate (recommended default) -- max 10/request, 50/window over 60s"
echo "  3) Permissive -- max 25/request, 200/window over 60s"
echo "  4) Custom"
ask PRESET "Choice" "2"
case "$PRESET" in
    1) MAX_PER_REQUEST=5;  MAX_PER_WINDOW=20;  WINDOW_SECS=60 ;;
    3) MAX_PER_REQUEST=25; MAX_PER_WINDOW=200; WINDOW_SECS=60 ;;
    4)
        ask MAX_PER_REQUEST "max_per_request" "10"
        ask MAX_PER_WINDOW "max_per_window" "50"
        ask WINDOW_SECS "window_secs" "60"
        ;;
    *) MAX_PER_REQUEST=10; MAX_PER_WINDOW=50; WINDOW_SECS=60 ;;
esac

INCLUDE_GLOBAL_BACKSTOP=0
if confirm "Add the recommended global backstop entry (catches identity-churn abuse a per-identity budget alone can't)?" y; then
    INCLUDE_GLOBAL_BACKSTOP=1
    ask GLOBAL_MAX_PER_WINDOW "Global window budget (set well above expected legitimate aggregate traffic)" "$((MAX_PER_WINDOW * 80))"
    ask GLOBAL_WINDOW_SECS "Global window_secs" "$WINDOW_SECS"
fi

INCLUDE_STRICT_DCR=0
if confirm "Add the recommended stricter entry for delete/create/rename (irreversible ops)?" y; then
    INCLUDE_STRICT_DCR=1
    ask STRICT_DCR_MAX_PER_WINDOW "delete/create/rename window budget" "5"
    ask STRICT_DCR_WINDOW_SECS "delete/create/rename window_secs" "60"
fi

section "Policy state persistence"

echo "  1) None -- in-memory only, resets on restart (default)"
echo "  2) SQLite file -- survives restart, shareable over a common volume"
echo "  3) Valkey/Redis -- shared across hosts with no shared disk"
ask STATE_CHOICE "Choice" "1"
STATE_DB_MODE="none"
case "$STATE_CHOICE" in
    2)
        STATE_DB_MODE="sqlite"
        ask STATE_DB_PATH "SQLite file path" "db.sqlite"
        ;;
    3)
        STATE_DB_MODE="valkey"
        ask STATE_DB_URL "Valkey/Redis URL" "redis://127.0.0.1:6379"
        ask STATE_DB_PREFIX "Key prefix" "ai_protect:threshold"
        STATE_DB_USER=""; STATE_DB_PASS=""
        if confirm "Does it require auth?" y; then
            ask STATE_DB_USER "Username" "ai-protect"
            ask_secret STATE_DB_PASS "Password"
        fi
        ;;
esac

# ---------------------------------------------------------------------------
# Write config.toml
# ---------------------------------------------------------------------------

section "Writing files"

UPSTREAM_ADDRS="\"${UPSTREAM_HOST}:${UPSTREAM_PORT}\""
if [ -n "$EXTRA_UPSTREAMS" ]; then
    IFS=',' read -ra EXTRA_ARR <<< "$EXTRA_UPSTREAMS"
    for addr in "${EXTRA_ARR[@]}"; do
        addr="$(echo "$addr" | xargs)"
        [ -n "$addr" ] && UPSTREAM_ADDRS="${UPSTREAM_ADDRS}, \"${addr}\""
    done
fi

CFG="$WORKDIR/config.toml"
{
    echo "# Generated by setup.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ") from a live"
    echo "# interrogation of ${UPSTREAM_HOST}:${UPSTREAM_PORT} (detected: ${VENDOR_GUESS})."
    echo "# Gitignored, not tracked -- see config.example.toml for full field docs."
    echo
    echo "[[proxy]]"
    echo "listen_addr = \"${LISTEN_ADDR}\""
    echo "upstream_addrs = [${UPSTREAM_ADDRS}]"
    [ -n "$EXTRA_UPSTREAMS" ] && echo "upstream_strategy = \"${UPSTREAM_STRATEGY}\""

    if [ "$UPSTREAM_TLS_MODE" != "plain" ]; then
        echo
        echo "[proxy.upstream_tls]"
        echo "server_name = \"${UPSTREAM_TLS_SERVER_NAME}\""
        [ -n "$UPSTREAM_TLS_CA_FILE" ] && echo "ca_file = \"${UPSTREAM_TLS_CA_FILE}\""
        [ "$UPSTREAM_TLS_MODE" = "starttls" ] && echo "starttls = true"
        if [ -n "$UPSTREAM_TLS_CLIENT_CERT" ]; then
            echo
            echo "[proxy.upstream_tls.client_cert]"
            echo "cert_file = \"${UPSTREAM_TLS_CLIENT_CERT}\""
            echo "key_file = \"${UPSTREAM_TLS_CLIENT_KEY}\""
        fi
    fi

    if [ "$LISTEN_TLS_MODE" = "ldaps" ]; then
        echo
        echo "[proxy.listen_tls]"
        echo "cert_file = \"${LISTEN_CERT}\""
        echo "key_file = \"${LISTEN_KEY}\""
        [ -n "$LISTEN_CLIENT_CA" ] && echo "client_ca_file = \"${LISTEN_CLIENT_CA}\""
    elif [ "$LISTEN_TLS_MODE" = "starttls" ]; then
        echo
        echo "[proxy.listen_starttls]"
        echo "cert_file = \"${LISTEN_CERT}\""
        echo "key_file = \"${LISTEN_KEY}\""
    fi

    echo
    echo "[proxy.policy]"
    echo "file = \"policies/ldap.toml\""

    if [ "$ENABLE_METRICS" = 1 ]; then
        echo
        echo "[metrics]"
        echo "listen_addr = \"${METRICS_ADDR}\""
    fi

    if [ "$ENABLE_HEALTH" = 1 ]; then
        echo
        echo "[health]"
        echo "listen_addr = \"${HEALTH_ADDR}\""
    fi
} > "$CFG"

POL="$WORKDIR/ldap.toml"
{
    echo "# Generated by setup.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")."
    echo "# Gitignored, not tracked -- see policies/ldap.example.toml for full field docs."
    echo
    echo "[[policy]]"
    echo "type = \"threshold\""
    echo "max_per_request = ${MAX_PER_REQUEST}"
    echo "max_per_window = ${MAX_PER_WINDOW}"
    echo "window_secs = ${WINDOW_SECS}"

    case "$STATE_DB_MODE" in
        sqlite)
            echo "state_db = \"${STATE_DB_PATH}\""
            ;;
        valkey)
            echo
            echo "[policy.state_db]"
            echo "url = \"${STATE_DB_URL}\""
            echo "key_prefix = \"${STATE_DB_PREFIX}\""
            [ -n "$STATE_DB_USER" ] && echo "username = \"${STATE_DB_USER}\""
            [ -n "$STATE_DB_PASS" ] && echo "password = \"${STATE_DB_PASS}\""
            ;;
    esac

    if [ "$INCLUDE_GLOBAL_BACKSTOP" = 1 ]; then
        echo
        echo "[[policy]]"
        echo "type = \"threshold\""
        echo "scope = \"global\""
        echo "max_per_request = ${MAX_PER_REQUEST}"
        echo "max_per_window = ${GLOBAL_MAX_PER_WINDOW}"
        echo "window_secs = ${GLOBAL_WINDOW_SECS}"
    fi

    if [ "$INCLUDE_STRICT_DCR" = 1 ]; then
        echo
        echo "[[policy]]"
        echo "type = \"threshold\""
        echo "operations = [\"delete\", \"create\", \"rename\"]"
        echo "max_per_request = 1"
        echo "max_per_window = ${STRICT_DCR_MAX_PER_WINDOW}"
        echo "window_secs = ${STRICT_DCR_WINDOW_SECS}"
    fi
} > "$POL"

backup_if_exists config.toml
backup_if_exists policies/ldap.toml
mv "$CFG" config.toml
mv "$POL" policies/ldap.toml
ok "wrote config.toml"
ok "wrote policies/ldap.toml"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

section "Summary"

echo "Detected upstream vendor : ${VENDOR_GUESS}"
echo "Upstream TLS mode        : ${UPSTREAM_TLS_MODE}"
echo "Client-facing TLS mode   : ${LISTEN_TLS_MODE}"
echo
echo "Next steps:"
echo "  1. Review config.toml and policies/ldap.toml -- any paths above"
echo "     (certs/*, state_db) need to actually exist before running."
echo "  2. RUST_LOG=info cargo run"
echo
echo "ai-protect will then listen on ${LISTEN_ADDR} and proxy to ${UPSTREAM_HOST}:${UPSTREAM_PORT}."
