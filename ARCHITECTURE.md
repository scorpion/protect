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
   |                            |----- TCP connect --------------->|
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

[`Config`](src/config.rs) is a single hardcoded `dev_default()` today
(listen on `127.0.0.1:3890`, proxy to `127.0.0.1:389`, threshold of 10 per
request / 50 per 60s window). File-based config (TOML/YAML) is explicitly
noted as not-yet-built in the doc comment — anticipate a config module that
parses into the same `Config` struct rather than a structural change.

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
- No TLS on either the listener or the upstream connection.
- `Identity` is address-based, not credential-based.
- No config file loading — everything is compiled-in via
  `Config::dev_default()`.
- No automated test suite yet.

These aren't oversights to work around silently; they're the next pieces of
this architecture, and changes that touch those areas should extend the
existing seams (`Policy`, connector, `Config`) rather than introduce new
ones.
