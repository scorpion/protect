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
   |                            |   +-- None (not a lock op) -------+--> forward verbatim
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
[`proxy::handle_connection`](src/proxy/mod.rs) via `tokio::select!`:

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
([src/connector/mod.rs](src/connector/mod.rs)) that decouples "what wire
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

- **Connector** ([src/connector/ldap.rs](src/connector/ldap.rs)) owns
  everything protocol-specific: BER framing (`read_frame`), message decoding
  (`rasn`/`rasn-ldap`), recognizing which attributes represent an
  account-lock across different directory schemas (`LOCK_ATTRIBUTES` covers
  AD's `userAccountControl`, OpenLDAP's `pwdAccountLockedTime`, 389 DS's
  `nsAccountLock`, and `shadowExpire`), and building a well-formed rejection
  response (`build_rejection`) in that same protocol. Nothing outside this
  module needs to know LDAP exists.
- **Action** is the seam. It says *what* is being attempted
  (`OperationKind`), *what* it targets (`target`), and *how big* it is
  (`blast_radius`) — nothing about how it was expressed on the wire. Today
  `blast_radius` is always `1` (one object per modify), but the field exists
  so a future connector recognizing a bulk operation (e.g. an LDAP
  extended-op batch, or a REST API's array payload) can report a number
  greater than one without changing anything downstream.
- **Policy** ([src/policy/mod.rs](src/policy/mod.rs)) is pure decision
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

- [`net::MaybeTlsStream`](src/net.rs) is a thin enum (`Plain(TcpStream)` /
  `Tls(T)`) implementing `AsyncRead`/`AsyncWrite` by delegating to whichever
  variant is active. `LdapConnector::connect_upstream` and the listener's
  accept loop both return/wrap this type, so `read_frame`, `handle_connection`,
  and the two relay functions are written once against "an async
  duplex stream" and don't know or care whether TLS is underneath.
- [`tls::UpstreamTls`](src/tls.rs) builds a `rustls` `ClientConfig` and
  performs the client-side LDAPS handshake against `upstream_addr`,
  validating the upstream's certificate against a configured `server_name`
  (required since directory certs are issued for hostnames, not the IP in
  `upstream_addr`) and trusting either the OS store or a configured
  `ca_file`. [`tls::ListenTls`](src/tls.rs) builds a `ServerConfig` from a
  cert/key pair and performs the server-side handshake for clients
  connecting to `listen_addr`. Both are `Option`al and independent: ai-protect
  can terminate LDAPS for clients while speaking plaintext LDAP upstream, do
  the reverse, both, or neither.

Neither direction does mutual TLS (client certificate authentication) —
`ClientConfig`/`ServerConfig` are both built with `with_no_client_auth()`.

Both hops are implicit TLS only (LDAPS on a dedicated port, negotiated
before any LDAP bytes are exchanged) — StartTLS (the RFC 4511 extended
operation that upgrades a plaintext connection on the standard LDAP port
mid-session) is not implemented on either side.

## Policy: blast-radius thresholding

The only policy implemented, [`ThresholdPolicy`](src/policy/threshold.rs),
encodes "4 accounts is fine, 4,000 is not" with two independent checks:

1. **Per-request cap** (`max_per_request`): a single action whose own
   `blast_radius` exceeds the limit is blocked immediately, no history
   needed.
2. **Per-identity sliding window** (`max_per_window` over `window`): each
   identity accumulates a `VecDeque<Instant>` of past allowed actions
   (one entry per unit of blast radius). Entries older than `window` are
   evicted lazily on each evaluation. An action is blocked if admitting it
   would push the identity's windowed total over the limit; state is only
   advanced when the action is ultimately allowed (blocked actions don't
   pollute history).

State is process-local (`Mutex<HashMap<Identity, VecDeque<Instant>>>`) — it
does not survive a restart and is not shared across multiple `ai-protect`
instances. That's acceptable for a single-instance deployment in front of
one directory; a multi-instance deployment would need shared state (e.g.
Redis) for the window to be enforced correctly across instances.

## Identity

[`Identity`](src/identity.rs) is currently just the client's TCP peer
address, stringified. It exists as its own type (rather than passing
`SocketAddr` around directly) so that policies and audit logging depend on
an abstraction, not a transport detail — the intent is for this to become
LDAP-bind-derived (or otherwise credential-derived) identity later without
changing `Policy`, `ThresholdPolicy`, or `audit::log_decision` signatures.
Today it does **not** correlate to a stable principal across reconnects or
distinguish two clients behind the same NAT/address.

## Audit logging

[`audit::log_decision`](src/audit.rs) is called once per evaluated action,
for both `Allow` and `Block`, and is intentionally decoupled from policy
logic itself — policies decide, audit only records. It emits structured
`tracing` events (`info` for allow, `warn` for block) carrying identity,
backend, operation, target, blast radius, and (for blocks) the reason. This
is the system's forensic trail: everything a policy blocked, and why, is
recoverable from logs even though the process holds no persistent state
beyond the in-memory threshold window.

## Configuration

Two independent TOML files, deliberately kept separate:

- [`Config`](src/config.rs) (`config.toml`, template in
  `config.example.toml`) — process-level settings: `[proxy]` listen/upstream
  addresses, optional `[proxy.upstream_tls]` (`server_name`, optional
  `ca_file`) and `[proxy.listen_tls]` (`cert_file`, `key_file`) tables
  controlling TLS on each hop (see [Transport](#transport-plaintext-or-tls)),
  and `[policy].file` pointing at the policy file to load. `Config::load`
  reads whichever path is given as the first CLI arg, defaulting to
  `config.toml` in the working directory.
- Policy definitions (`policies/ldap.toml`, template in
  `policies/ldap.example.toml`) — an ordered list of `[[policy]]` tables,
  each tagged by `type` and parsed by
  [`policy::config::load`](src/policy/config.rs) into a `Vec<Arc<dyn
  Policy>>`. The only type today is `"threshold"`, deserializing straight
  into [`ThresholdConfig`](src/policy/threshold.rs) (durations are plain
  `window_secs` integers, since TOML has no native duration type).

This split exists because policy files are one-per-connector/backend and may
encode deployment-specific thresholds or naming that shouldn't live in the
same file — or necessarily the same commit history — as network config. Both
`config.toml` and everything under `policies/` besides the tracked
`*.example.toml` files are gitignored; `main.rs` fails fast with a message
pointing at the matching example file if either is missing.

Adding a new policy *type* is a Rust change (a `PolicyEntry` variant in
`policy::config` plus the `Policy` impl); adding a new policy *instance* of
an existing type is a config-only change (another `[[policy]]` table).

## Extension points

- **New backend protocol** (e.g. a different directory API, or a non-LDAP
  admin surface): add a module under `src/connector/` that reads its own
  framing and produces `Action`s for the operations worth policing. Wire it
  up in `main.rs` alongside (or instead of) `LdapConnector`. The proxy loop
  and policy engine need no changes as long as the connector exposes
  `decode`/rejection-building analogous to `LdapConnector`'s.
- **New policy rule**: implement `Policy` and add it to the `Vec<Arc<dyn
  Policy>>` built in `main.rs`. Because `evaluate_all` stops at the first
  block, place cheap/fast-failing policies earlier if ordering matters for
  performance; place stateful policies with care since only `Allow`s should
  typically advance their state (see `ThresholdPolicy`).
- **Multiple upstreams / multiple listeners**: not modeled yet.
  `proxy::run` takes one `listen_addr` and one connector bound to one
  `upstream_addr`; supporting several would mean either multiple `run` tasks
  in `main.rs` or extending `Config` to a list and adding a dispatch layer.

## Known gaps (by design, at this stage)

- No persistent/shared state — a restart or a second instance resets
  threshold history.
- No mutual TLS — `[proxy.listen_tls]`/`[proxy.upstream_tls]` cover
  server-side certificates only, not client certificate authentication.
- No StartTLS — only implicit TLS (LDAPS) is supported on either hop, so a
  directory or client that expects to upgrade a plaintext port 389
  connection mid-session isn't accommodated.
- `Identity` is address-based, not credential-based.
- Only one connector/policy-file pair can be wired up at a time; `main.rs`
  doesn't yet dispatch multiple `[policy].file`s for multiple connectors.

These aren't oversights to work around silently; they're the next pieces of
this architecture, and changes that touch those areas should extend the
existing seams (`Policy`, connector, `Config`) rather than introduce new
ones.
