# Architecture

## Purpose

`ai-protect` is an inline TCP proxy for directory-service protocols (LDAP
today). It sits between a client and the real directory server, and its job
is narrow: catch bulk, high-blast-radius account operations — the kind an
over-eager automated caller (an AI agent, a misconfigured script, a
compromised credential) issues — and block them before they reach the real
directory, while leaving every other operation untouched.

It is not an LDAP implementation, a directory, or a general firewall. It
decodes only the specific operations it needs to make a policy decision
about, and forwards everything else as opaque bytes.

## Request lifecycle

```
 client                    ai-protect                      upstream LDAP
   |                            |                                  |
   |---- TCP connect ---------->|                                  |
   |<=== TLS handshake ========>| (only if [proxy.listen_tls] set) |
   |                            |----- TCP connect --------------->|
   |                            |<==== TLS handshake ==============| (only if [proxy.upstream_tls] set)
   |                            |                                  |
   |==== frame (BER) =========>| read_frame()                     |
   |                            |   |                               |
   |                            |   v                               |
   |                            | connector.decode(frame)          |
   |                            |   |                               |
   |                            |   +-- None (not actionable) -------+--> forward verbatim
   |                            |   |                               |
   |                            |   +-- Some(Action) ---> evaluate_all(policies)
   |                            |                              |
   |                            |                    Allow ---+---> forward verbatim
   |                            |                              |
   |                            |                    Block  --+
   |                            |                              |
   |<== build_rejection() ======|<-----------------------------+
   |   (UnwillingToPerform)     |
   |                            |
   |                            |         audit::log_decision() (every decision, both outcomes)
   |                            |
   |<==== upstream responses ===|<== relayed verbatim, upstream -> client, no decoding =========|
```

Two directions of the connection are driven concurrently by
[`proxy::handle_connection`](src/proxy.rs) via `tokio::select!`:

- **client → upstream**: every frame is decoded; only frames that decode to
  an `Action` are evaluated by policy. Everything else — binds, searches,
  unrelated modifies — is forwarded without being parsed at all.
- **upstream → client**: relayed verbatim in both cases. The proxy never
  inspects or alters directory responses, only outbound requests.

The connection ends (and both directions are torn down) when either side
closes, hits an I/O error, or a decode error occurs.

TLS, where configured, is negotiated once up front on each hop and is
otherwise invisible to this loop: `read_frame`/`decode`/relaying all operate
on a `MaybeTlsStream` (plain or TLS) exactly as they would on a bare
`TcpStream` — see [Transport](#transport-plaintext-or-tls) below.

## Component pipeline: Connector → Action → Policy → Decision

The system is built around one seam: a normalized `Action` type
([src/core/action.rs](src/core/action.rs)) that decouples "what wire
protocol is this" from "should this be allowed."

```
   raw bytes            Connector             Action                Policy engine           Decision
 ┌───────────┐      ┌───────────────┐    ┌──────────────┐      ┌────────────────────┐    ┌───────────┐
 │ LDAP frame│ ───> │ LdapConnector │ ─> │ backend: str  │ ──>  │ evaluate_all(       │ -> │  Allow    │
 │ (BER)     │      │  ::decode()   │    │ operation:    │      │   [ThresholdPolicy] │    │  or       │
 └───────────┘      └───────────────┘    │  OperationKind│      │ )                   │    │  Block{   │
                                          │ target: String│      └────────────────────┘    │   reason }│
                                          │ blast_radius  │                                 └───────────┘
                                          └──────────────┘
```

- **Connector** is a trait ([`Connector`](src/core/connector.rs):
  `connect_upstream`/`read_frame`/`decode`/`build_rejection`) that
  [src/proxy.rs](src/proxy.rs) is written against as `Arc<dyn Connector>` —
  it has no compile-time knowledge of LDAP or any other specific backend.
  [`LdapConnector`](src/connector/ldap.rs) is the only implementation today,
  and owns everything protocol-specific: BER framing (`read_frame`), message
  decoding (`rasn`/`rasn-ldap`), recognizing which attributes represent an
  account-lock across different directory schemas (`LOCK_ATTRIBUTES` covers
  AD's `userAccountControl`, OpenLDAP's `pwdAccountLockedTime`, 389 DS's
  `nsAccountLock`, and `shadowExpire`), recognizing every `DelRequest`/
  `AddRequest` unconditionally (removing or creating an entry outright is
  already high-blast-radius, and — unlike `Modify` — there's no cheap
  attribute-level filter to narrow it further without querying the
  directory, which this proxy deliberately never does), recognizing an
  `ExtendedRequest` for the RFC 3062 Password Modify OID specifically (a
  bulk password reset is disruptive the same way a bulk lock is — both
  leave the affected users unable to log in — so it's decoded via a
  hand-rolled `PasswdModifyRequestValue` type, since `rasn-ldap` only models
  core LDAP operations, not this extended operation's payload; every other
  extended request, including StartTLS, passes through unrecognized here),
  and building a well-formed rejection response (`build_rejection`) whose
  variant matches the request it's rejecting (`ModifyResponse`/
  `DelResponse`/`AddResponse`/`ExtendedResp`) in that same protocol. Nothing
  outside the `connector/ldap` module needs to know LDAP exists.
  `connect_upstream` returns a boxed `DuplexStream` (any `AsyncRead +
  AsyncWrite + Send + Unpin`) so the proxy loop's `tokio::io::split`/relay
  code is written once regardless of which connector or transport is
  underneath.
- **Action** is the seam. It says *what* is being attempted
  (`OperationKind`: `AccountLock`, `Delete`, `Create`, or `PasswordReset`),
  *what* it targets (`target`), and *how big* it is (`blast_radius`) —
  nothing about how it was expressed on the wire. Today `blast_radius` is
  always `1` (one object per modify/delete/add/password-reset), but the
  field exists so a future connector recognizing a bulk operation (e.g. an
  LDAP extended-op batch, or a REST API's array payload) can report a
  number greater than one without changing anything downstream.
- **Policy** ([src/core/policy.rs](src/core/policy.rs)) is pure decision
  logic: `fn evaluate(&self, action: &Action, ctx: &PolicyContext) ->
  Decision`. Policies don't know about sockets, frames, or LDAP result
  codes — only `Action` and `Identity`. `evaluate_all` runs the configured
  list in order and short-circuits on the first `Block`, so the caller
  always gets one authoritative decision.
- **Decision** is `Allow` or `Block { reason }`. The proxy is responsible
  for turning that back into protocol terms (forward the original frame, or
  ask the connector to synthesize a rejection); policies never see raw
  bytes.

This separation is the main thing to preserve when extending the system:
*a new backend is a new connector, not a change to policy; a new rule is a
new policy, not a change to any connector.*

## Transport: plaintext or TLS

Each hop — client-facing and upstream — independently negotiates plaintext
or TLS, controlled by two optional config tables (`[proxy.listen_tls]`,
`[proxy.upstream_tls]`; see [Configuration](#configuration)). Two small
modules make this an orthogonal concern that neither the connector's framing
logic nor the proxy loop needs to branch on:

- [`net::MaybeTlsStream`](src/core/net.rs) is a thin enum (`Plain(TcpStream)` /
  `Tls(T)`) implementing `AsyncRead`/`AsyncWrite` by delegating to whichever
  variant is active. `LdapConnector::connect_upstream` and the listener's
  accept loop both return/wrap this type, so `read_frame`, `handle_connection`,
  and the two relay functions are written once against "an async
  duplex stream" and don't know or care whether TLS is underneath.
- [`tls::UpstreamTls`](src/core/tls.rs) builds a `rustls` `ClientConfig` and
  performs the client-side LDAPS handshake against `upstream_addr`,
  validating the upstream's certificate against a configured `server_name`
  (required since directory certs are issued for hostnames, not the IP in
  `upstream_addr`) and trusting either the OS store or a configured
  `ca_file`. When the upstream itself requires mutual TLS, an optional
  client cert/key pair (`[proxy.upstream_tls.client_cert]`) is presented
  during the handshake instead of `with_no_client_auth()`.
  [`tls::ListenTls`](src/core/tls.rs) builds a `ServerConfig` from a
  cert/key pair and performs the server-side handshake for clients
  connecting to `listen_addr`. Both are `Option`al and independent: ai-protect
  can terminate LDAPS for clients while speaking plaintext LDAP upstream, do
  the reverse, both, or neither.

`ListenTls` supports mutual TLS on the client-facing hop: when
`[proxy.listen_tls].client_ca_file` is set, it builds a
`WebPkiClientVerifier` from that CA instead of `with_no_client_auth()`,
requiring every connecting client to present a certificate signed by it
before the handshake completes — the proxy then authenticates *which*
agent is connecting rather than just trusting whoever can reach the
socket. Rejection (no certificate, or one not signed by `client_ca_file`)
surfaces as a failed or immediately-terminated handshake; the connection
is dropped and logged like any other connection-setup error, never
forwarded upstream. This is authentication only — it doesn't yet feed into
`Identity` or per-client policy; identity is derived from the LDAP bind DN
where available, not the mTLS client certificate (see
[Identity](#identity)).

Both hops can also negotiate TLS mid-session via RFC 4511 StartTLS instead
of dialing implicit TLS (LDAPS) from the first byte — for directories and
clients standardized on the plaintext LDAP port plus StartTLS rather than a
dedicated LDAPS port:

- **Client-facing**: `[proxy.listen_starttls]` (same shape as
  `[proxy.listen_tls]` — `cert_file`/`key_file`, optional `client_ca_file`
  for mTLS) accepts plaintext connections and, in `proxy::serve`, peeks the
  first frame off each one. `Connector::upgrade_request` — a
  protocol-specific hook with a default no-op impl, so only a connector
  that supports this needs to implement it — decides whether that frame is
  an upgrade request; `LdapConnector`'s impl recognizes the StartTLS OID
  (`1.3.6.1.4.1.1466.20037`) and builds the confirming `ExtendedResponse`.
  The proxy sends that response over the still-plaintext socket, then runs
  the same `ListenTls::accept` handshake implicit TLS uses, and only then
  starts relaying. A frame that isn't an upgrade request is fed into the
  ordinary per-frame pipeline instead of being lost, so a client that never
  asks for StartTLS is relayed exactly as before — the upgrade is
  opportunistic, never required. Ignored if `[proxy.listen_tls]` is also
  set, since an already-encrypted connection has no plaintext phase to
  upgrade from.
- **Upstream**: `LdapConnector::with_starttls(true)` (config:
  `[proxy.upstream_tls].starttls`) makes `connect_upstream` dial the
  upstream in plaintext, send its own StartTLS `ExtendedRequest`, wait for
  a success `ExtendedResponse`, and only then run the same
  `UpstreamTls::connect` handshake implicit TLS uses. No effect unless
  `upstream_tls` is also set, since StartTLS only decides *when* to start
  the handshake, not with what parameters.

Either mechanism ends by handing off to the exact same `ListenTls`/
`UpstreamTls` handshake code implicit TLS uses, so mutual TLS, trust
stores, and SNI validation all work identically regardless of how the
handshake was triggered.

**TLS version floor**: both hops are built via `rustls` with its `tls12`
feature enabled ([`Cargo.toml`](Cargo.toml)), so the negotiated range is
TLS 1.2–1.3 (rustls never supports anything older, so 1.2 is already the
practical floor regardless of this feature flag). This is a deliberate
compatibility decision, not an oversight: Active Directory — one of the
three directories this proxy targets — only gained TLS 1.3 support for
LDAPS in Windows Server 2022, so a large share of real deployments (2016,
2019, older 389 DS/OpenLDAP builds) speak TLS 1.2 only. Dropping the
`tls12` feature would silently lock those out. Revisit this once TLS 1.3
is ubiquitous across supported directory versions; either hop can be
tightened independently by removing `tls12` from the `rustls`/
`tokio-rustls` feature lists.

## Connection limits & timeouts

[`proxy::ConnectionLimits`](src/proxy.rs) bounds two things a slow-loris
client or a hung upstream could otherwise use to pin the process
indefinitely:

- **Concurrent connections** (`max_connections`, default 1024): a
  `Semaphore` sized to this limit gates the accept loop. A connection that
  can't acquire a permit is closed immediately rather than queued — no
  unbounded backlog of waiting tasks.
- **Per-I/O timeout** (`io_timeout`, default 60s): every individual
  read/write on both hops — including TLS handshakes — races this deadline
  via `tokio::time::timeout`. Because it applies per operation rather than
  per connection, it also functions as an idle-connection timeout: a client
  or upstream that goes quiet for longer than `io_timeout` gets
  disconnected.

Both are configurable per deployment (`max_connections`/`io_timeout_secs`
per `[[proxy]]` entry, see `config.example.toml`) or programmatically
(`ProxyBuilder::limits`).

## Graceful shutdown

`ai_protect::run`/`run_with_config` install a handler for `SIGTERM`/`SIGINT`
(Unix; `Ctrl-C` only on Windows, since `tokio::signal` has no `SIGTERM`
equivalent there) so a rolling restart or deploy doesn't hard-cut every
in-flight LDAP session the moment the process is asked to stop:

1. The signal fires a `tokio::sync::watch::channel(bool)` shared by every
   `[[proxy]]` entry's `proxy::serve` accept loop.
2. Each loop's `tokio::select!` between `listener.accept()` and the
   shutdown watch stops accepting *new* connections as soon as it observes
   `true` — a late subscriber (or one that's slow to reach this `select!`
   for the first time) still sees the request correctly, since
   `watch::Receiver::wait_for` checks the current value before waiting on
   a change, unlike a bare `changed().await`.
3. Every already-spawned connection task is tracked in a `JoinSet` (not
   fired via a bare `tokio::spawn`) specifically so shutdown can wait on
   it: `serve` gives them up to `ConnectionLimits::shutdown_timeout`
   (`shutdown_timeout_secs` per `[[proxy]]` entry, default 30s) to finish
   on their own — a client or upstream closing the socket, an `io_timeout`,
   or the request/response it's mid-handling completing.
4. Whatever's still running once that grace period elapses is forcibly
   aborted (`JoinSet::shutdown`) rather than left to hang the process.

`run_with_config` waits for every `[[proxy]]` entry to finish this way
before returning `Ok(())`; an entry that instead exits with an error (e.g.
`ProxyError::Accept`) still stops the rest immediately, unchanged from
before graceful shutdown existed. Embedding via `ProxyBuilder` gets the same
mechanism opt-in: `ProxyBuilder::shutdown` takes a `watch::Receiver<bool>`
the caller drives themselves (`run`/`run_with_config`'s OS-signal handling
is specific to those file-driven entry points, not `ProxyBuilder` itself);
without it, `serve` runs forever like before, since the builder's default
receiver is paired with a `Sender` the builder itself holds onto and never
sends on.

## Config hot-reload

`ai_protect::run_with_config` installs a second signal handler alongside the
`SIGTERM`/`SIGINT` one above: `SIGHUP` (Unix only — `tokio::signal` has no
equivalent on Windows, so this is simply unavailable there) re-reads every
`[[proxy]]` entry's policy file and swaps it in without dropping any
connection or restarting the process:

1. `build_proxy` wires each entry's `proxy::serve` up to a
   `tokio::sync::watch::channel(Vec<Arc<dyn Policy>>)` instead of a fixed
   `Vec`, via `ProxyBuilder::policies_reloadable`; `run_with_config` keeps
   the `Sender` half paired with that entry's policy file path.
2. `proxy::serve`'s accept loop reads the receiver fresh
   (`watch::Receiver::borrow().clone()`) for every connection it accepts, the
   same place it already clones `listen_tls`/`connector` once per connection
   — so a reload is visible to new connections without a restart, and (like
   those other per-connection settings) a connection already in flight keeps
   running under whichever policy list was in effect when it was accepted,
   rather than switching mid-session.
3. `reload_policies_on_signal` (spawned by `run_with_config` alongside the
   shutdown-signal task) waits on `SIGHUP`, then calls
   `core::policy::config::load` again for every entry and pushes the result
   through that entry's `Sender`. A read/parse failure for one entry is
   logged and leaves that entry's policies unchanged — it neither stops the
   process nor blocks reloading the others. The task exits once `shutdown`
   is requested, so it doesn't keep `run_with_config`'s `JoinSet` waiting
   forever after every listener has finished draining.
4. `ThresholdPolicy::spawn_background_sync` (used when a `[[policy]]` entry
   sets `state_db`) holds only a `Weak` reference to the policy in its
   background sync task, not an `Arc` — otherwise every reload would leak
   one sync task per superseded `ThresholdPolicy` instance, looping forever
   after nothing else referenced it. The task's next tick fails to `upgrade`
   the `Weak` once the last connection using that instance has closed, and
   exits then instead.

This deliberately covers only what a `[[policy]]` file describes —
thresholds and which policies run, in what order. `listen_addr`,
`upstream_addr`, TLS settings, and connection limits are still read once at
process start and require a restart to change: reloading those in place
would mean rebinding a live listener socket or migrating already-open
connections onto new upstream/TLS settings mid-session, not just swapping
out an in-memory value the way a policy list can be. `ProxyBuilder` exposes
the same mechanism to embedders directly: `ProxyBuilder::policies_reloadable`
takes a `watch::Receiver<Vec<Arc<dyn Policy>>>` the caller drives themselves
(no OS signal handling of its own, matching `ProxyBuilder::shutdown`);
without it, `policy`/`policies` build a fixed list exactly as before.

## Policy: blast-radius thresholding

The only policy implemented, [`ThresholdPolicy`](src/core/policy/threshold.rs),
encodes "4 accounts is fine, 4,000 is not" with two independent checks:

1. **Per-request cap** (`max_per_request`): a single action whose own
   `blast_radius` exceeds the limit is blocked immediately, no history
   needed.
2. **Sliding window** (`max_per_window` over `window`): the bucket the
   window is tracked under accumulates a `VecDeque<Instant>` of past
   allowed actions (one entry per unit of blast radius). Entries older than
   `window` are evicted lazily on each evaluation. An action is blocked if
   admitting it would push the bucket's windowed total over the limit;
   state is only advanced when the action is ultimately allowed (blocked
   actions don't pollute history).

`scope` selects what that bucket *is*:

- `PerIdentity` (the default): one bucket per `Identity`, exactly as
  described above — "4 accounts is fine for this caller, 4,000 is not."
- `Global`: one shared bucket across every identity, ignoring
  `ctx.identity` entirely (bucketed under a fixed internal sentinel key
  instead). Meant to run as a *second* `[[policy]]` entry alongside a
  `PerIdentity` one: since it isn't keyed by identity at all, a caller that
  claims a fresh, unverified bind DN before each batch — resetting a
  `PerIdentity` budget every time (see [Identity](#identity)) — can't reset
  this one too. See `policies/ldap.example.toml` for the two-entry pattern.

State lives in an in-memory `Mutex<HashMap<Identity, VecDeque<Instant>>>`,
always — `evaluate` never does I/O, so admitting or blocking a request
never waits on anything slower than a mutex, regardless of how many
requests per second the process is handling. By default that map is also
the *only* copy: a restart resets it, and it isn't shared across multiple
`ai-protect` instances.

The age-based pruning described above only removes a given identity's own
stale timestamps, and only when that identity is evaluated again — an
identity seen exactly once (a bind DN claimed before one throwaway action,
then never reused) leaves an empty `VecDeque` sitting in the map forever
otherwise, since nothing ever visits it again to notice it's empty. This is
what let an unauthenticated caller grow the map without bound by churning
through a fresh, made-up identity per request, even one that's immediately
blocked (a blocked action still creates the map entry — it just never gets
a timestamp pushed into it). `max_tracked_identities` (config, defaults to
100,000) caps this independently: once reached, admitting a brand-new
identity evicts the tracked identity with the least recently recorded
activity first — see `evict_stalest_until` in
[src/core/policy/threshold.rs](src/core/policy/threshold.rs) — bounding
memory (and `state_db` storage, if configured) to a fixed size regardless
of how many distinct identities a caller churns through.

### SQLite-backed policy state

`state_db` on a `[[policy]]` threshold entry (see
`policies/ldap.example.toml`) selects a [`HistoryStore`](src/core/policy/store/mod.rs)
backend that layers durability and approximate cross-instance sharing on
top of `ThresholdPolicy`'s in-memory history, without touching the hot
path. A bare string (`state_db = "db.sqlite"`) selects
[`SqliteStore`](src/core/policy/store/sqlite.rs), the default backend:

- **Startup**: [`ThresholdPolicy::new`](src/core/policy/threshold.rs) opens
  the SQLite file, prunes rows older than `window`, and loads what's left
  into the in-memory map — so a restart resumes mid-window instead of
  resetting everyone's budget to zero.
- **Steady state**: a background task, one per `ThresholdPolicy`, wakes
  every `flush_interval` (default 2s) and, entirely off the tokio runtime
  (`spawn_blocking`): writes whatever this instance admitted since the
  last tick, deletes rows the window has aged out (safe regardless of
  which instance wrote them), and reads back every remaining row,
  replacing (not merging into) this instance's in-memory entry for each
  identity found. Replacing rather than merging is what keeps a healthy
  instance's own repeatedly-round-tripped events from double-counting
  themselves cycle over cycle.
- **Multi-instance**: two `ai-protect` processes pointed at the same
  `state_db` file each see the other's admitted actions within one
  `flush_interval` of each other — a real, if eventually-consistent,
  shared budget. This only works when both processes can reach the same
  file (shared disk/volume, not a network service) — see "Valkey-backed
  policy state" below for hosts with no shared disk. Two *different*
  threshold policies must never point at the same file — nothing keys a
  row to which policy wrote it, so their windows would prune and observe
  each other's rows.
- **Failure mode**: if the file can't be opened (bad path, permissions,
  disk full), `ThresholdPolicy::new` logs a warning and falls back to pure
  in-memory behavior rather than stopping the proxy from starting — this
  feature is a best-effort enhancement to availability-critical code, not
  a hard dependency.

### Valkey-backed policy state

A table (`state_db = { url = "redis://valkey:6379", key_prefix = "..." }`)
selects [`ValkeyStore`](src/core/policy/store/valkey.rs) instead: a
Redis-protocol-compatible network service (Valkey — <https://valkey.io> —
or Redis itself), for a multi-instance HA deployment spread across hosts
with no shared filesystem. A local instance is available via `docker
compose --profile ha up -d valkey` (see `compose.yaml`).

Each identity's events live in a Valkey sorted set keyed by
`{key_prefix}:history:{identity}`, scored by epoch milliseconds, so pruning
by age (`ZREMRANGEBYSCORE`) and reading survivors back in order (`ZRANGE
... WITHSCORES`) are both native per-identity operations — unlike
`SqliteStore`, which scans/deletes across its one global table every
sync. Identities are discovered with `SCAN` (matching `{key_prefix}:history:*`)
rather than a maintained index, so an instance picks up keys another
instance wrote without either needing to register them anywhere. As with
SQLite, two different threshold policies must use distinct `key_prefix`
values or their windows will prune/observe each other's keys.

The steady-state sync loop is otherwise identical to `SqliteStore`'s
(same `ThresholdPolicy::sync_once`, same `flush_interval`), except the I/O
is a native async round trip via `redis`'s `ConnectionManager` (which
multiplexes over one connection and reconnects automatically) rather than
a blocking call handed to `spawn_blocking`.

One asymmetry with `SqliteStore`: `ValkeyStore::open` only parses the
connection URL — connecting is async, and `ThresholdPolicy::new` is a
synchronous, no-executor-required constructor — so a Valkey-backed policy
cannot warm its in-memory history from existing state at startup the way
a SQLite-backed one does. It starts with empty history and catches up
within one `flush_interval` via the same background task that performs
cross-instance sync. The failure mode is otherwise the same as SQLite's:
an invalid URL (the one failure `open` can detect synchronously) logs a
warning and falls back to pure in-memory behavior.

## Identity

[`Identity`](src/core/identity.rs) is an opaque wrapper around a string
(rather than passing `SocketAddr` around directly) so that policies and
audit logging depend on an abstraction, not a transport detail. A
connection's `Identity` starts as the client's source IP address,
stringified (the ephemeral port is dropped, so it survives reconnects) and
prefixed `ip:` (`Identity::from_peer_addr`), and is replaced with a more
specific one — a bind DN, prefixed `dn:` (`Identity::from_bind_dn`) — only
once that DN is confirmed, not merely claimed. The two prefixes are
disjoint by construction, so a DN crafted to read identically to some
peer's IP-address string (e.g. a bind DN of literally `127.0.0.1`) can
never land in the same `ThresholdPolicy` history bucket as that peer —
they produce `dn:127.0.0.1` and `ip:127.0.0.1` respectively, which are
different `Identity` values.

This confirmation is what [`BindState`](src/proxy.rs) exists for. Two
relay directions run concurrently per connection (`tokio::select!` in
`handle_connection`), and neither alone has enough information to decide
identity safely: the client-facing direction sees the `BindRequest` but not
whether it succeeds; the upstream-facing direction sees the `BindResponse`
but not which DN it answers. `BindState`, shared between them, closes that
gap by correlating the two on LDAP message ID:

1. **Client direction** (`handle_client_frame`): when
   [`Connector::bind_request`](src/core/connector.rs) recognizes a frame as
   a simple (DN + password) `BindRequest` naming a non-empty DN —
   [`LdapConnector::bind_request`](src/connector/ldap.rs) is the one
   implementation — its message ID and claimed DN are staged in
   `BindState.pending`. This is a *claim*, not yet trusted for policy
   purposes; `Identity` doesn't change here.
2. **Upstream direction** (`relay_upstream_responses` →
   `resolve_pending_bind`): every response frame is checked via
   [`Connector::bind_response`](src/core/connector.rs)
   (`LdapConnector::bind_response`). If its message ID matches a pending
   claim, that claim is resolved — removed from `pending` either way, and
   promoted to `BindState.identity` (the connection's actual `Identity`)
   only if the response reports success. A failed or never-answered bind
   leaves identity untouched.

Because promotion only happens on a confirmed success, a caller can't buy a
fresh, empty blast-radius budget by claiming a made-up DN that never
actually authenticates — see the
`unverified_bind_does_not_change_identity_or_reset_budget` test in
[src/proxy.rs](src/proxy.rs). This closes the main gap with pure
address-based identity from the other direction too: two agents behind the
same NAT/egress no longer share one blast-radius budget as long as they
bind under different, real DNs (see the
`bind_dn_becomes_identity_so_same_peer_gets_separate_budgets` test in the
same file). Anonymous binds (empty DN) and SASL binds (the `name` field
isn't password-verified the way it is for a simple bind) are never staged
as claims, leaving the current identity unchanged. A connection that never
binds keeps its address-based identity for its whole lifetime, so
anonymous/unauthenticated traffic behaves exactly as before.

This closes bind-claim verification specifically; it doesn't by itself cap
how many *distinct* identities one attacker can churn through (an
unauthenticated caller can still claim an unbounded number of fresh DNs,
each getting its own empty `PerIdentity` budget once — if ever — it binds
successfully). A `ThresholdScope::Global` policy entry (see
[Policy: blast-radius thresholding](#policy-blast-radius-thresholding))
is the backstop for that: a shared ceiling identity churn can't reset,
regardless of how many identities are involved. `max_tracked_identities`
(see "Policy: blast-radius thresholding" above) separately bounds how many
distinct identities' history the map itself will hold onto, evicting the
least recently active once the cap is reached, so unbounded identity
churn can grow *turnover* in the map but not its size.

## Audit logging

[`audit::log_decision`](src/core/audit.rs) is called once per evaluated action,
for both `Allow` and `Block`, and is intentionally decoupled from policy
logic itself — policies decide, audit only records. It emits structured
`tracing` events (`info` for allow, `warn` for block) carrying identity,
backend, operation, target, blast radius, and (for blocks) the reason. This
is the system's forensic trail: everything a policy blocked, and why, is
recoverable from logs even though the process holds no persistent state
beyond the in-memory threshold window.

`audit::log_decision` itself doesn't know or care where those events end up
— that's [`src/main.rs`](src/main.rs)'s job, as the one place that installs
a `tracing` subscriber (the library entry points never do — see
[Using ai-protect as a library](AGENTS.md#using-ai-protect-as-a-library)).
It installs two output layers sharing one `RUST_LOG`-driven `EnvFilter`, so
verbosity is controlled once for both:

- **stdout**, human-readable text — unchanged from before, for interactive
  use (`RUST_LOG=info cargo run`) and for anything that captures a
  process's stdout as its log (a terminal, `docker logs`, the systemd
  journal).
- **`./logs/ldap.log`**, structured JSON with event fields flattened to the
  top level (not nested under a `"fields"` key) — the machine-parseable
  form of the same events, meant to be tailed by a log shipper (Filebeat,
  Fluentd, Promtail) or rotated by `logrotate`, without needing to scrape
  process output. Written through a `tracing-appender` non-blocking
  writer so a slow or stalled disk write can't back up the async runtime;
  the directory is created on startup if it doesn't exist. The path is
  fixed rather than configurable — a stable, well-known location is more
  useful to point log-shipping config at than one more setting to plumb
  through `Config`.

Both layers see exactly the same events (they're two views of one
subscriber, not two separate logging paths), so nothing is unique to one
side — anything in `logs/ldap.log` is also on stdout and vice versa. Neither
one rotates the file automatically (`tracing_appender::rolling::never`, to
keep the filename exactly `ldap.log` rather than a date-suffixed variant) —
an unbounded deployment needs an external rotator (`logrotate` with
`copytruncate`, or a log-shipping agent that handles rotation itself)
watching that same path.

## Metrics

[`core::metrics`](src/core/metrics.rs) records aggregate counters/gauges/
histograms through the [`metrics`](https://docs.rs/metrics) facade crate,
alongside — not instead of — the per-event audit trail above: audit answers
"what happened and why," metrics answer "how much, how often, how long."
Every recording call (`ConnectionGuard::open`, `record_decision`,
`record_upstream_connect`, `record_tls_handshake_failure`) is a documented
no-op until a recorder is installed, so instrumented call sites in
`proxy.rs` and `connector/ldap.rs` don't need to know or care whether one
is — an embedder using `ProxyBuilder` directly pays nothing for this unless
it installs a recorder itself.

`ai_protect::run_with_config` is the one caller that installs one:
`core::metrics::install_prometheus_exporter`, wired up when the config's
top-level `[metrics]` table is present (see
[Configuration](#configuration)), starts a Prometheus text-format HTTP
listener on `[metrics].listen_addr`, scraped like any other Prometheus
target. It's process-wide, not per `[[proxy]]` entry — every entry shares
one metrics recorder and one `/metrics` endpoint, since `metrics`'s
recorder is itself a process-global singleton (`install` can only succeed
once per process; a second call returns
`BuildError::FailedToSetGlobalRecorder` instead of panicking).

Four things are tracked:

- **Connections** — `ai_protect_connections_active` (gauge) and
  `ai_protect_connections_total` (counter), via a `ConnectionGuard` opened
  when `proxy::serve` spawns a connection's task and dropped when that task
  ends, however it ends (clean finish, error, or shutdown's forced abort) —
  a `Drop` impl rather than an explicit decrement at every return point, so
  the gauge can't drift out of sync with reality.
- **Policy decisions** — `ai_protect_policy_decisions_total`, labeled by
  `decision` (`allow`/`block`), `backend`, and `operation`. Recorded
  alongside `audit::log_decision` at the same call site in
  `proxy::handle_client_frame`, as the aggregate counterpart to audit's
  per-event record.
- **Upstream connect latency** — `ai_protect_upstream_connect_duration_seconds`
  (histogram), timing `Connector::connect_upstream` itself (TCP dial plus,
  when configured, its TLS/StartTLS handshake). This is connection *setup*
  latency, not a per-request round trip: the relay loop forwards both
  directions concurrently without correlating individual request/response
  frames by LDAP message ID (see [Request lifecycle](#request-lifecycle)),
  so there's no existing seam to time an individual request against its
  response without decoding every frame just to do so — connection setup is
  the one discrete, already-measured step available cheaply.
- **TLS handshake failures** — `ai_protect_tls_handshake_failures_total`,
  labeled `hop` — `listen` (implicit TLS on `[proxy.listen_tls]`),
  `listen_starttls` (the client-facing StartTLS upgrade in
  `proxy::maybe_upgrade_to_tls`), or `upstream` (implicit or StartTLS TLS to
  the real directory, in `LdapConnector::connect_upstream`) — covering all
  three points a handshake can happen on either hop (see
  [Transport](#transport-plaintext-or-tls)).

## Health

[`core::health`](src/core/health.rs) is a small hand-rolled HTTP server
(no framework dependency — the only surface is two fixed-response routes
read off the request line) serving `/healthz` (liveness) and `/readyz`
(readiness) for orchestrator probes (k8s `livenessProbe`/`readinessProbe`,
or equivalent). Wired up by `ai_protect::run_with_config` when the config's
top-level `[health]` table is present (see
[Configuration](#configuration)), the same opt-in pattern as `[metrics]`:
one endpoint for the whole process, not per `[[proxy]]` entry, since
readiness is process-wide — graceful shutdown (see
[Graceful shutdown](#graceful-shutdown)) stops every entry together off the
same `watch::channel(bool)`.

`/healthz` always answers `200` for as long as the process is up. `/readyz`
answers `200` until graceful shutdown is requested, then flips to `503`
immediately — before the drain itself finishes — so a load balancer or
service mesh stops routing new connections here without waiting out
`shutdown_timeout`. Critically, `/healthz` must *not* also go quiet during
that drain window: a `SIGTERM`/`SIGINT` can leave in-flight connections
draining for up to `shutdown_timeout` (30s by default), and if the liveness
probe stopped answering for that whole window, the orchestrator would
conclude the process is wedged and kill it outright — the exact outcome
graceful shutdown exists to avoid. So `core::health::serve` never stops
accepting connections on its own; `run_with_config` spawns it and lets
process exit take it down, the same way the installed Prometheus exporter
above is never explicitly stopped either. (`core::health::bind` is a
separate step from `serve` specifically so a bad `[health].listen_addr` —
already in use, unparseable — surfaces as an immediate startup error rather
than only once the first probe hits a dead port.)

## Configuration

Two kinds of TOML file, deliberately kept separate, plus one optional
top-level table:

- [`Config`](src/config.rs) (`config.toml`, template in
  `config.example.toml`) — process-level settings: an array of `[[proxy]]`
  entries, each one an independent listener/upstream/policy triple.
  `Config::load` reads whichever path is given as the first CLI arg,
  defaulting to `config.toml` in the working directory, and fails fast if
  the array is empty (nothing to listen on). Each entry has its own
  `listen_addr`/`upstream_addr`, optional `[proxy.upstream_tls]`
  (`server_name`, optional `ca_file`, optional
  `[proxy.upstream_tls.client_cert]` for mTLS to the upstream, `starttls` to
  negotiate TLS via RFC 4511 StartTLS instead of dialing implicit TLS) and
  `[proxy.listen_tls]` (`cert_file`, `key_file`, optional `client_ca_file`
  for mTLS from clients) tables controlling TLS on each hop, plus
  `[proxy.listen_starttls]` (same shape as `[proxy.listen_tls]`) to accept
  plaintext and let a client upgrade via StartTLS instead (see
  [Transport](#transport-plaintext-or-tls)), and its own `[proxy.policy].file`
  pointing at the policy file to load for that entry specifically —
  `ai_protect::run_with_config` runs every entry concurrently (see
  [Extension points](#extension-points)).
- Policy definitions (one file per `[[proxy]]` entry, e.g.
  `policies/ldap.toml`, template in `policies/ldap.example.toml`) — an
  ordered list of `[[policy]]` tables, each tagged by `type` and parsed by
  [`policy::config::load`](src/core/policy/config.rs) into a `Vec<Arc<dyn
  Policy>>`. The only type today is `"threshold"`, deserializing straight
  into [`ThresholdConfig`](src/core/policy/threshold.rs) (durations are plain
  `window_secs` integers, since TOML has no native duration type).
- Optional top-level `[metrics]` table in `config.toml` (not per `[[proxy]]`
  entry — see [Metrics](#metrics)): just `listen_addr`, the address the
  Prometheus `/metrics` endpoint listens on. Absent by default; a
  deployment that doesn't scrape Prometheus doesn't get a listening socket
  it never uses.
- Optional top-level `[health]` table in `config.toml` (not per `[[proxy]]`
  entry — see [Health](#health)): just `listen_addr`, the address
  `/healthz`/`/readyz` listen on. Absent by default; a deployment with no
  orchestrator probing it doesn't get a listening socket it never uses.

This split exists because policy files are one-per-connector/backend and may
encode deployment-specific thresholds or naming that shouldn't live in the
same file — or necessarily the same commit history — as network config; two
`[[proxy]]` entries in the same `config.toml` are free to point at the same
policy file or two entirely different ones. Both `config.toml` and
everything under `policies/` besides the tracked `*.example.toml` files are
gitignored; `ai_protect::run` fails fast with a message pointing at the
matching example file if either is missing.

Adding a new policy *type* is a Rust change (a `PolicyEntry` variant in
`policy::config` plus the `Policy` impl); adding a new policy *instance* of
an existing type is a config-only change (another `[[policy]]` table).
Adding another listener/upstream pair is likewise config-only — another
`[[proxy]]` entry.

## Extension points

- **New backend protocol** (e.g. a different directory API, or a non-LDAP
  admin surface): add a module under `src/connector/` with a type that
  `impl Connector` (see [src/core/connector.rs](src/core/connector.rs)) —
  its own framing (`read_frame`), decoding (`decode`), and rejection-building
  (`build_rejection`), producing `Action`s for the operations worth policing.
  Hand an `Arc::new(YourConnector::new(...))` to `ProxyBuilder::connector`
  (embedders build and `serve()` their own `ProxyBuilder`s; the config-driven
  path's private `build_proxy` helper in `src/lib.rs`, one call per
  `[[proxy]]` entry, would need a Rust change to select a connector type
  per entry instead of always building an `LdapConnector`). `src/proxy.rs`
  and the policy engine need no changes — this is no longer just a
  convention to follow, it's enforced by `proxy::run`'s signature taking
  `Arc<dyn Connector>`.
- **New policy rule**: implement `Policy` and add it via
  `ProxyBuilder::policy`/`policies` (or `[[policy]]` entries in a policy
  file, which is a config-only change once the `Policy` impl and its
  `PolicyEntry` variant exist — see [Configuration](#configuration)).
  Because `evaluate_all` stops at the first block, place cheap/fast-failing
  policies earlier if ordering matters for performance; place stateful
  policies with care since only `Allow`s should typically advance their
  state (see `ThresholdPolicy`).
- **Embedding ai-protect in another process**: use
  [`ProxyBuilder`](src/builder.rs) directly instead of `ai_protect::run` —
  see the library-usage section of [AGENTS.md](AGENTS.md#using-ai-protect-as-a-library).
  No TOML file is required; a `Connector` and `Policy` list constructed
  in-memory are enough.
- **Multiple upstreams / multiple listeners**: `proxy::run`/`ProxyBuilder`
  still take one `listen_addr` and one connector bound to one upstream each,
  but `Config` is a `Vec<ProxyConfig>` (`[[proxy]]` array-of-tables) and
  `ai_protect::run_with_config` builds one `ProxyBuilder` per entry and
  `serve()`s them concurrently as sibling tasks in a `tokio::task::JoinSet` —
  see [Configuration](#configuration). Embedders using `ProxyBuilder`
  directly (skipping `Config` entirely) get the same effect by spawning
  multiple `serve()` tasks themselves.

## Known gaps (by design, at this stage)

- Persistent/shared threshold history is opt-in and best-effort, not the
  default — set `state_db` per policy (see "SQLite-backed policy state"
  above) or a restart or a second instance still resets/double-budgets it.
- `Identity` is derived from a bind DN confirmed only by its `BindResponse`
  result code (falling back to source address) — see [Identity](#identity)
  — not from an authenticated principal such as a validated mTLS client
  certificate. A caller can still churn through an unbounded number of
  distinct DNs (each gets its own fresh `PerIdentity` budget); a
  `ThresholdScope::Global` backstop bounds the aggregate regardless, and
  `max_tracked_identities` bounds the `Identity`-keyed history map's
  cardinality (evicting the least recently active identity once the cap is
  reached — see [Identity](#identity)).
- Every `[[proxy]]` entry hardcodes `LdapConnector` as its connector; the
  config-driven path (as opposed to `ProxyBuilder`, used directly) can front
  several LDAP upstreams but not a mix of protocols in one process without a
  Rust change to select a connector type per entry.
- One `[[proxy]]` entry's fatal error aborts every other entry in the same
  process (see `run_with_config`) rather than restarting just the failed
  one — there's no per-entry supervision/backoff.
- `./logs/ldap.log` (see [Audit logging](#audit-logging)) is a fixed path
  relative to the process's working directory and never rotates itself —
  it assumes that directory is writable and that something external
  (`logrotate`, a log-shipping agent) bounds the file's size. Neither holds
  automatically in every deployment shape (a read-only container root
  filesystem, an orchestrator that doesn't run `logrotate`).

These aren't oversights to work around silently; they're the next pieces of
this architecture, and changes that touch those areas should extend the
existing seams (`Policy`, connector, `Config`) rather than introduce new
ones.
