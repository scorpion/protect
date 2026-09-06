# AGENTS.md

## What this is

`ai-protect` is a transparent TCP proxy that sits in front of an upstream LDAP
directory (AD, OpenLDAP, 389 DS) and inspects traffic in-flight. It decodes
each client request, normalizes the ones it cares about into a
backend-agnostic `Action`, runs a policy engine over that action, and either
forwards the original frame upstream unmodified or rejects it with a
synthesized LDAP error response. The motivating case is an over-eager
automated caller (an AI agent, a misconfigured script) locking or disabling
accounts in bulk — the proxy is the place that catches "4 accounts is fine,
4,000 is not" before it ever reaches the real directory.

Everything not explicitly decoded is passed straight through, both
directions, byte-for-byte.

## Module map

`src/core/` holds everything shared across connectors and the proxy loop —
the `Action` seam, identity, audit logging, transport (`net`/`tls`), and the
policy engine — as opposed to `src/connector/`, which is protocol-specific
(LDAP today), and `src/proxy/`, which is the connection-handling orchestration.

- [src/main.rs](src/main.rs) — thin binary entry point: reads the config
  path CLI arg and hands off to `ai_protect::run`.
- [src/lib.rs](src/lib.rs) — the library's three public entry points
  (`run`, `run_with_config`, `builder::ProxyBuilder`) covering different
  amounts of "load this from a file" — see its module doc comment and
  [Using ai-protect as a library](#using-ai-protect-as-a-library) below.
  Start here to see how pieces fit together.
- [src/builder.rs](src/builder.rs) — `ProxyBuilder`, the fully-programmatic
  entry point for embedding ai-protect: set a connector and policies you
  already have in memory, no config file required.
- [src/error.rs](src/error.rs) — `Error`, the aggregate error type returned
  by the public entry points above. Each variant wraps a module-local error
  type (`ConfigError`, `PolicyConfigError`, `TlsError`, `ProxyError`) that
  lives next to the code producing it.
- [src/config.rs](src/config.rs) — process configuration, loaded from a TOML
  file (`config.toml` by default, or a path given as the first CLI arg; see
  `config.example.toml` for the schema). Policy definitions are deliberately
  *not* part of this file — `[policy].file` just points at the TOML file
  `policy::config::load` (in `src/core/policy/config.rs`) parses into
  `Vec<Arc<dyn Policy>>`.
- [src/proxy.rs](src/proxy.rs) — the connection loop: accepts a
  client, dials upstream, and relays frames in both directions concurrently
  via `tokio::select!`. Client→upstream frames are decoded and evaluated
  against policy before being forwarded or rejected; upstream→client frames
  pass through untouched. Generic over `Arc<dyn Connector>` — this module
  has no compile-time dependency on LDAP or any other specific backend.
  Also owns `ConnectionLimits`: a `Semaphore` caps concurrent connections
  (anything over `max_connections` is closed immediately instead of
  queued), and every read/write on both hops races an `io_timeout` that
  doubles as an idle-connection timeout — together the mitigation for a
  slow-loris client or a hung upstream pinning a task indefinitely. Also
  peeks the first frame off a still-plaintext connection to
  opportunistically negotiate RFC 4511 StartTLS (`[proxy.listen_starttls]`)
  before falling into the normal per-frame loop.
- [src/core/net.rs](src/core/net.rs) — `MaybeTlsStream`, a thin enum
  (`Plain(TcpStream)` / `Tls(T)`) implementing `AsyncRead`/`AsyncWrite` by
  delegating to whichever variant is active, so `read_frame`, the relay
  loop, and connectors are written once against "an async duplex stream"
  regardless of whether TLS is underneath.
- [src/core/tls.rs](src/core/tls.rs) — `UpstreamTls`/`ListenTls`, building
  `rustls` client/server configs for each hop: implicit TLS (LDAPS), an
  optional custom CA (`ca_file`) instead of the OS trust store, and mutual
  TLS in both directions (`client_ca_file` on the listener via
  `WebPkiClientVerifier`, `client_cert` on the upstream hop). Also logs
  (rather than silently discarding) any error `rustls-native-certs` hits
  loading the OS trust store.
- [src/core/action.rs](src/core/action.rs) — defines `Action` /
  `OperationKind` (`AccountLock`, `Delete`, `Create`, `PasswordReset`), the
  normalized representation a connector produces so the policy engine
  never has to understand a wire protocol.
- [src/core/connector.rs](src/core/connector.rs) — the `Connector` trait
  (`connect_upstream`/`read_frame`/`decode`/`build_rejection`/
  `upgrade_request`/`bind_identity`) that `src/proxy.rs` is written against,
  plus `DuplexStream`, the boxable `AsyncRead + AsyncWrite` object every
  connector's upstream connection is returned as. This is what makes "a
  new backend is a new connector, not a proxy.rs change" literally true
  rather than aspirational. `upgrade_request` and `bind_identity` each
  default to `Ok(None)` ("this protocol has no in-session TLS upgrade" /
  "no identity-establishing request"), so both are opt-in per connector.
- [src/connector/ldap.rs](src/connector/ldap.rs) — the only connector today.
  Reads BER-framed LDAP messages off the wire (`read_frame`), decodes
  `ModifyRequest`s via `rasn`/`rasn-ldap` and flags ones touching a known
  account-lock attribute (`LOCK_ATTRIBUTES`, covering AD/OpenLDAP/389 DS
  schemas) as an `Action`, flags every `DelRequest`/`AddRequest`
  unconditionally (removing/creating an entry outright is already
  high-blast-radius, and unlike `Modify` there's no cheap attribute-level
  filter to narrow it further without querying the directory), and flags an
  `ExtendedRequest` for the RFC 3062 Password Modify OID (a bulk password
  reset is as disruptive as a bulk lock) — decoding its payload via a
  hand-rolled `PasswdModifyRequestValue` type, since `rasn-ldap` doesn't
  model extended-operation payloads. Every other extended request passes
  through `decode` unrecognized. Also builds the matching rejection
  response sent back to a blocked client (`ModifyResponse`/`DelResponse`/
  `AddResponse`/`ExtendedResp`), recognizes RFC 4511 StartTLS extended
  requests (`upgrade_request`, a separate code path from `decode`) so a
  client can upgrade a plaintext connection to TLS mid-session, and
  recognizes a simple `BindRequest` naming a non-empty DN (`bind_identity`)
  so the proxy can key policy/audit identity off that DN instead of the
  peer address. Exposes this as both inherent methods (used directly by its
  own tests) and an `impl Connector`.
- [src/core/policy.rs](src/core/policy.rs) — the `Policy` trait
  (`evaluate(&Action, &PolicyContext) -> Decision`) and `evaluate_all`, which
  runs every configured policy and stops at the first `Block`.
- [src/core/policy/threshold.rs](src/core/policy/threshold.rs) — `ThresholdPolicy`, the
  only policy implemented so far. Blocks a single request whose
  `blast_radius` exceeds `max_per_request`, and separately tracks a sliding
  window of blast radius per `Identity` to block bursts that exceed
  `max_per_window` within `window`. Its history is an in-memory
  `Mutex<HashMap<..>>` on the hot path, always — an optional `state_db`
  (a [`HistoryStore`](src/core/policy/store) backend) is loaded once at
  startup and, if set, kept in sync by a background task (`flush_interval`,
  default 2s) that writes newly-admitted actions and reloads the whole
  store, off the hot path. This is how history survives a restart and is
  approximately shared by multiple `ai-protect` instances pointed at the
  same backend — see "SQLite-backed policy state" and "Valkey-backed
  policy state" below.
- [src/core/policy/store/](src/core/policy/store/) — the `HistoryStore`
  trait `ThresholdPolicy` persists/shares its in-memory history through,
  plus `Anchor` (in `mod.rs`), which round-trips `Instant` (monotonic,
  meaningless across a restart) through epoch milliseconds (portable) and
  back. Two backends implement it: [`sqlite.rs`](src/core/policy/store/sqlite.rs)
  (`SqliteStore`, a local file — the default, no external service needed)
  and [`valkey.rs`](src/core/policy/store/valkey.rs) (`ValkeyStore`, a
  Redis-protocol-compatible network service, for HA across hosts with no
  shared disk — see the `ha` profile in `compose.yaml` for a local one).
- [src/core/policy/config.rs](src/core/policy/config.rs) — TOML schema for policy files
  (`policies/ldap.toml`, one file per connector/backend). An ordered
  `[[policy]]` array, each table tagged by `type` (only `"threshold"` today),
  deserializes into the matching `Policy` impl's config and gets built into
  the `Vec<Arc<dyn Policy>>` `main.rs` hands to the proxy. Adding a new
  `Policy` impl means adding a variant to the `PolicyEntry` enum here, not
  changing the file format.
- [src/core/identity.rs](src/core/identity.rs) — `Identity`, an opaque
  wrapper around a string. Starts as the peer's source IP (port dropped so
  it's stable across reconnects); `proxy::handle_client_frame` replaces it
  mid-connection with the DN from a simple LDAP bind, once one is seen
  (`Connector::bind_identity`).
- [src/core/audit.rs](src/core/audit.rs) — structured `tracing` logging of every policy
  decision (allow or block), independent of the policy logic itself.

## Architecture notes worth knowing before changing things

- **Connector → Action → Policy → Decision** is the core pipeline. A new
  backend (e.g. a different directory protocol, or a non-LDAP admin API)
  means a new `impl Connector` (see `src/core/connector.rs`) that produces
  `Action`s; it should not require touching `src/proxy.rs` or
  `src/core/policy/` — `proxy.rs` only ever sees `Arc<dyn Connector>`. A new
  rule means a new `Policy` impl; it should not require touching any
  connector.
- Policies are pure decision logic — `evaluate_all` stops at the first
  block, so ordering in the `Vec<Arc<dyn Policy>>` passed to
  `ProxyBuilder`/`proxy::run` matters if policies have side effects (like
  `ThresholdPolicy`'s history tracking, which only advances state on an
  `Allow`).
- The proxy relays raw bytes; it only decodes frames it might act on
  (currently LDAP `ModifyRequest`s touching lock attributes, every
  `DelRequest`/`AddRequest`, and `ExtendedRequest`s for the RFC 3062
  Password Modify OID specifically). Anything else — binds, searches,
  unrelated modifies, other extended operations — is forwarded without
  being parsed. Keep that pass-through-by-default behavior when adding
  decoding logic: fail open to "not my concern, forward it" rather than
  trying to understand every operation type.
- `read_frame` implements BER definite-length framing itself (RFC 4511
  §5.1) rather than relying on a higher-level LDAP library for transport
  framing, since the proxy needs raw frame boundaries to forward bytes
  unmodified when a message isn't inspected.
- `Identity` starts peer-address-based and is upgraded to a bind DN once a
  simple LDAP bind is seen on the connection (see `bind_identity`), but
  that DN is never verified against the actual `BindResponse` — the proxy
  doesn't correlate responses per connection. Don't assume it maps to a
  stable, verified principal; a failed bind still moves `Identity` before
  upstream has a chance to reject it.

## Using ai-protect as a library

`ai-protect` is a normal Rust library crate as well as a binary — `main.rs`
is a thin wrapper around it, not a separate thing. Three public entry points
in `src/lib.rs` cover different amounts of "load this from a file":

- `run(config_path)` — fully file-driven, what the binary calls.
- `run_with_config(&Config)` — skip the config file (`Config`'s fields are
  all `pub`) but still load policies from the file `config.policy.file`
  points at.
- `builder::ProxyBuilder` — fully programmatic: give it an `Arc<dyn
  Connector>` and a `Vec<Arc<dyn Policy>>` you built yourself (e.g.
  `LdapConnector::new(...)` and `ThresholdPolicy::new(...)`), no file I/O
  anywhere.

All three return `ai_protect::Error` (`src/error.rs`), a `thiserror` enum
aggregating the module-local error types (`ConfigError`, `PolicyConfigError`,
`TlsError`, `ProxyError`) so a caller can match on what went wrong instead of
only reading a message string. Runtime, per-connection errors deliberately
stay `anyhow::Result` — see the `Connector` trait and `proxy::handle_connection` —
since those are caught and logged per-connection rather than returned to any
caller; typing them wouldn't change any caller's behavior.

## Building and running

`cargo run` needs `config.toml` (and the policy file it points at) to exist —
copy the tracked templates first:

```sh
cp config.example.toml config.toml
cp policies/ldap.example.toml policies/ldap.toml
```

```sh
cargo check          # fast type/borrow check
cargo build           # debug build
cargo run             # loads config.toml (127.0.0.1:3890 -> 127.0.0.1:389
                       # by default), plus the policy file it references
cargo run -- other-config.toml   # load config from a different path
RUST_LOG=info cargo run   # tracing-subscriber reads RUST_LOG; default is silent
```

Both `config.toml` and everything under `policies/` (except the tracked
`*.example.toml` templates) are gitignored, since real deployment values may
be sensitive — see `.gitignore`.

Run the test suite with `cargo test`. If you add behavior, prefer adding
`#[test]`/`#[tokio::test]` coverage alongside it — `ThresholdPolicy` and
`LdapConnector::decode`/`build_rejection` are straightforward to unit test
without a real LDAP server since they operate on plain byte frames /
in-memory state, and `proxy::serve`/`builder::ProxyBuilder` can be driven
end-to-end over real (loopback) TCP/TLS connections, as their existing
tests do.

Run `cargo fmt` and `cargo clippy` before considering a change done; neither
is currently wired into CI (there is no CI config in this repo yet), so
they're on the honor system.

## Conventions

- Rust 2024 edition. The public setup/config surface (config/policy file
  loading, TLS setup, binding, `ProxyBuilder`) returns typed `thiserror`
  errors — see [Using ai-protect as a library](#using-ai-protect-as-a-library).
  Everything else (protocol decoding, the `Connector` trait, per-connection
  runtime code) keeps using `anyhow::Result`, with `.context(...)` on I/O and
  decode calls to keep error messages traceable to what was being attempted.
- `tracing` for logging, not `println!`/`eprintln!`.
- Doc comments on non-obvious structs/functions explain *why*, not what
  (see `read_frame`, `LOCK_ATTRIBUTES`, `evaluate_all`) — match that style
  rather than restating the signature in prose.
- README.md and ARCHITECTURE.md are both filled in; this file, README.md,
  and ARCHITECTURE.md together are the authoritative source of project
  context — keep all three in sync when changing module structure or the
  public API.
