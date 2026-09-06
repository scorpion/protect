# Installing and running ai-protect

This walks through getting `ai-protect` running in front of a real
directory: building it, writing its two config files, turning on TLS,
and wiring up logging, metrics, and health checks for production use.

If you just want to see it work end-to-end against a disposable test
directory first, jump to [Try it locally](#try-it-locally) below.

## Requirements

- A 64-bit Linux, macOS, or Windows host to run `ai-protect` on.
- Either the [Rust toolchain](https://rustup.rs) (2024 edition) to build
  from source, or Docker to build/run the container image.
- Network access from `ai-protect`'s host to your real directory server,
  and from your clients to `ai-protect`'s host.
- If you're terminating TLS on either hop: PEM-encoded certificates/keys
  for that hop, and, for mutual TLS, a CA bundle to validate client or
  upstream certificates against.

## Getting a binary

**From source:**

```sh
git clone <this repository>
cd ai-protect
cargo build --release
# binary is at target/release/ai-protect
```

**With Docker** (no local Rust toolchain needed):

```sh
docker build -f docker/rust/Dockerfile -t ai-protect .
```

The image builds the release binary in one stage and copies it into a
minimal Debian runtime image in another — configuration and certificates
are mounted in at runtime rather than baked into the image (see
[Running](#running) below), and the container runs as an unprivileged
user.

## Configuring

`ai-protect` reads two TOML files, neither of which ships with real
values (a real deployment's addresses, thresholds, and secrets shouldn't
live in version control). Start from the tracked templates:

```sh
cp config.example.toml config.toml
cp policies/ldap.example.toml policies/ldap.toml
```

`ai-protect` fails fast at startup with a message pointing at the
matching `*.example.toml` if either file is missing, so you can't
accidentally run with silently-empty config.

### `config.toml` — network and process config

Each `[[proxy]]` table is one independent listener: where it accepts
client connections (`listen_addr`), where it forwards to
(`upstream_addr`), and which policy file governs it. Most deployments
need exactly one `[[proxy]]` entry; a single process can run more than
one if you need to front multiple directories, or the same directory on
more than one address, side by side.

```toml
[[proxy]]
listen_addr = "127.0.0.1:3890"
upstream_addr = "127.0.0.1:389"

[proxy.policy]
file = "policies/ldap.toml"
```

Every field beyond that — TLS on either hop, connection limits, I/O
timeouts, shutdown grace period — is optional and documented inline in
[config.example.toml](../config.example.toml), which is the authoritative
schema reference. A few highlights:

- **`max_connections`** (default 1024) caps concurrent client
  connections; anything over the cap is rejected immediately rather than
  queued, so a connection flood degrades predictably instead of piling up
  memory.
- **`io_timeout_secs`** (default 60) bounds every individual read/write
  on either hop, TLS handshakes included, and doubles as an idle-connection
  timeout — a client or upstream that goes quiet for longer than this gets
  disconnected.
- **`shutdown_timeout_secs`** (default 30) is how long a graceful
  shutdown (see [Stopping and restarting](#stopping-and-restarting) below)
  waits for in-flight connections to finish on their own before cutting
  them off.

### `policies/ldap.toml` — what to block

An ordered list of `[[policy]]` tables. Today there's one policy type,
`"threshold"`, which encodes "a few accounts at once is fine, thousands
isn't" as two independent caps:

```toml
[[policy]]
type = "threshold"
max_per_request = 10    # a single request touching more than this many
                         # accounts is blocked outright
max_per_window = 50     # total accounts one identity can affect within...
window_secs = 60        # ...this many seconds, before it's blocked
```

Full behavior — what counts as "affecting an account," how identity is
determined, what a blocked client sees — is in
[LDAP.md](LDAP.md#the-threshold-policy). Pick starting numbers based on
your normal peak legitimate usage (a bulk HR sync, an offboarding batch)
plus headroom, then tighten once you've watched real traffic in the audit
log for a while.

By default, policy state (which identities have done what, recently)
lives only in memory and resets on restart. If you need it to survive a
restart, or to be shared across more than one `ai-protect` instance
behind a load balancer, see
[Sharing policy state across restarts or instances](#sharing-policy-state-across-restarts-or-instances)
below.

## Running

```sh
./target/release/ai-protect                    # loads ./config.toml
./target/release/ai-protect other-config.toml   # load config from elsewhere
```

Logging is silent by default. Turn it on with `RUST_LOG`:

```sh
RUST_LOG=info ./target/release/ai-protect
```

With logging on, output goes to both stdout (for a terminal, `docker
logs`, or the systemd journal) and `./logs/ldap.log` (structured JSON,
one event per line) — point a log shipper or SIEM at the latter. Neither
rotates itself; put `logrotate` (with `copytruncate`) or an equivalent in
front of `logs/ldap.log` in any long-running deployment. See
[Reading the audit log](LDAP.md#reading-the-audit-log) for what the
events actually contain.

Once it's running, point an LDAP client at `listen_addr` instead of your
real directory. Everything works exactly as before, except requests that
trip your policy come back rejected instead of reaching the directory.

### With Docker

```sh
docker run --rm \
  -p 3890:3890 \
  -v "$PWD/config.toml:/app/config.toml:ro" \
  -v "$PWD/policies:/app/policies:ro" \
  -e RUST_LOG=info \
  ai-protect
```

Mount `certs/` the same way if your config references certificate files.
The container writes `./logs` relative to its `/app` working directory —
mount that too (`-v "$PWD/logs:/app/logs"`) if you want log files to
persist outside the container's lifetime.

### Enabling TLS

Each hop — client-facing and upstream — is independently plaintext or
TLS. To have `ai-protect` itself terminate LDAPS for incoming clients,
add to a `[[proxy]]` entry:

```toml
[proxy.listen_tls]
cert_file = "certs/server.pem"
key_file = "certs/server.key"
# client_ca_file = "certs/agent-ca.pem"   # uncomment to require client certs (mTLS)
```

To connect to an upstream directory over LDAPS instead of plaintext:

```toml
[proxy.upstream_tls]
server_name = "dc01.corp.example.com"   # for SNI + certificate validation
# ca_file = "certs/internal-ca.pem"     # if signed by an internal CA
```

If either side speaks RFC 4511 StartTLS on a plaintext port rather than
dedicated implicit-TLS port, use `[proxy.listen_starttls]` (client-facing)
or add `starttls = true` under `[proxy.upstream_tls]` (upstream) instead
— `ai-protect` negotiates the upgrade itself before continuing. Full
field-by-field detail is in
[config.example.toml](../config.example.toml).

### Metrics and health checks

Both are opt-in and off by default — add the relevant table to
`config.toml` only if you use them:

```toml
[metrics]
listen_addr = "127.0.0.1:9090"   # Prometheus text format at /metrics

[health]
listen_addr = "127.0.0.1:9091"   # /healthz (liveness), /readyz (readiness)
```

`/metrics` exposes connection counts, allow/block rates, upstream connect
latency, and TLS handshake failures — one endpoint covering every
`[[proxy]]` entry in the process. `/healthz` always answers `200` while
the process is up; `/readyz` flips to `503` the moment a graceful
shutdown is requested (ahead of the drain finishing), so a load balancer
or orchestrator stops routing new connections here without waiting out
the shutdown grace period.

**Neither endpoint authenticates its caller.** Bind both to `localhost`
or a private network reachable only by your metrics/orchestration
systems — never to the same address your directory clients connect on.

### Sharing policy state across restarts or instances

By default, a threshold policy's "who's done what recently" bookkeeping
lives only in memory and starts empty on every restart. Two backends make
it persistent instead, both configured on the `[[policy]]` entry in
`policies/ldap.toml`, and both a pure availability enhancement — if the
backend can't be reached at startup, `ai-protect` logs a warning and
falls back to in-memory-only behavior rather than refusing to start:

- **A local SQLite file** (`state_db = "db.sqlite"`) — survives a
  restart of a single instance, or is approximately shared between
  multiple instances that all have access to the same file (a shared
  volume, not a network path).
- **A Valkey or Redis server** (`state_db = { url = "redis://host:6379",
  key_prefix = "..." }`) — for multiple instances spread across hosts
  with no shared filesystem, e.g. behind a load balancer. A local Valkey
  for testing this is one `docker compose --profile ha up -d valkey` away
  (see [compose.yaml](../compose.yaml)).

Never point two different `[[policy]]` entries at the same SQLite file
or Valkey `key_prefix` — state isn't tagged by which policy wrote it, so
they'd corrupt each other's windows. See
[ARCHITECTURE.md](../ARCHITECTURE.md#sqlite-backed-policy-state) for the
full consistency model if you're deploying this in HA.

## Changing thresholds without downtime

Editing `policies/ldap.toml` and sending the running process `SIGHUP`
reloads every `[[proxy]]` entry's policy file in place — new thresholds
apply to new connections immediately, with no dropped connections and no
restart:

```sh
kill -HUP $(pgrep ai-protect)
```

Network settings (`listen_addr`, `upstream_addr`, TLS, connection limits)
are read once at startup and need a restart to change — only the policy
file hot-reloads.

## Stopping and restarting

`SIGTERM` or `SIGINT` (Ctrl-C) triggers a graceful shutdown: `ai-protect`
immediately stops accepting *new* connections, but gives in-flight ones
up to `shutdown_timeout_secs` (default 30s) to finish on their own before
forcibly closing whatever's left. This is what makes it safe to restart
during a rolling deploy without hard-cutting active client sessions.

## Try it locally

To see `ai-protect` working end-to-end without touching a real directory,
[compose.yaml](../compose.yaml) brings up a disposable
[lldap](https://github.com/lldap/lldap) server as a stand-in:

```sh
cp .env.example .env   # fill in the secrets described in the file's comments
docker compose up -d lldap
cargo run               # loads config.toml, proxies to the lldap container
```

Or run the full scripted check, which brings the test directory up,
builds and runs the real binary in front of it, and drives it with the
standard OpenLDAP command-line tools (`ldapsearch`/`ldapmodify`/
`ldapwhoami`/`ldappasswd`) to confirm pass-through and blocking both work
over the wire:

```sh
./test.sh    # requires docker, cargo, and the OpenLDAP client tools
```

## Troubleshooting

- **"config file ... (copy config.example.toml to get started)"** — one
  of the two config files is missing; see [Configuring](#configuring)
  above.
- **Startup succeeds but every client connection is refused** — check
  `max_connections` hasn't already been reached, and that nothing else is
  bound to `listen_addr`.
- **A request is blocked that you expected to pass (or vice versa)** —
  the audit log records the identity, operation, target, and block reason
  for every decision; see
  [Reading the audit log](LDAP.md#reading-the-audit-log) to interpret it,
  and [The threshold policy](LDAP.md#the-threshold-policy) to adjust the
  limits that produced it.
- **TLS handshake failures** — confirm `server_name`/certificate SANs
  match, and that `ca_file` points at the actual issuing CA if it's not
  in your OS trust store; failures are also counted in the
  `ai_protect_tls_handshake_failures_total` metric, labeled by which hop
  failed, if metrics are enabled.

For anything not covered here, the full system design — including
current known limitations — is in
[ARCHITECTURE.md](../ARCHITECTURE.md) and [TODO.md](../TODO.md) in the
repository root.
