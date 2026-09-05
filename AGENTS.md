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

- [src/main.rs](src/main.rs) — wires up config, connector, and policies, then
  hands off to the proxy loop. Start here to see how pieces fit together.
- [src/config.rs](src/config.rs) — process configuration. Currently a single
  hardcoded `Config::dev_default()`; no file-based config yet.
- [src/proxy/mod.rs](src/proxy/mod.rs) — the connection loop: accepts a
  client, dials upstream, and relays frames in both directions concurrently
  via `tokio::select!`. Client→upstream frames are decoded and evaluated
  against policy before being forwarded or rejected; upstream→client frames
  pass through untouched.
- [src/connector/mod.rs](src/connector/mod.rs) — defines `Action` /
  `OperationKind`, the normalized representation a connector produces so the
  policy engine never has to understand a wire protocol.
- [src/connector/ldap.rs](src/connector/ldap.rs) — the only connector today.
  Reads BER-framed LDAP messages off the wire (`read_frame`), decodes
  `ModifyRequest`s via `rasn`/`rasn-ldap`, and flags ones touching a known
  account-lock attribute (`LOCK_ATTRIBUTES`, covering AD/OpenLDAP/389 DS
  schemas) as an `Action`. Also builds the `UnwillingToPerform` rejection
  response sent back to a blocked client.
- [src/policy/mod.rs](src/policy/mod.rs) — the `Policy` trait
  (`evaluate(&Action, &PolicyContext) -> Decision`) and `evaluate_all`, which
  runs every configured policy and stops at the first `Block`.
- [src/policy/threshold.rs](src/policy/threshold.rs) — `ThresholdPolicy`, the
  only policy implemented so far. Blocks a single request whose
  `blast_radius` exceeds `max_per_request`, and separately tracks a sliding
  window of blast radius per `Identity` to block bursts that exceed
  `max_per_window` within `window`.
- [src/identity.rs](src/identity.rs) — `Identity`, currently just the peer's
  socket address as a string. No auth/bind-based identity yet.
- [src/audit.rs](src/audit.rs) — structured `tracing` logging of every policy
  decision (allow or block), independent of the policy logic itself.

## Architecture notes worth knowing before changing things

- **Connector → Action → Policy → Decision** is the core pipeline. A new
  backend (e.g. a different directory protocol, or a non-LDAP admin API)
  means a new module under `src/connector/` that produces `Action`s; it
  should not require touching `src/policy/`. A new rule means a new
  `Policy` impl; it should not require touching `src/connector/`.
- Policies are pure decision logic — `evaluate_all` stops at the first
  block, so ordering in the `Vec<Arc<dyn Policy>>` built in `main.rs` matters
  if policies have side effects (like `ThresholdPolicy`'s history tracking,
  which only advances state on an `Allow`).
- The proxy relays raw bytes; it only decodes frames it might act on
  (currently just LDAP `ModifyRequest`s touching lock attributes). Anything
  else — binds, searches, unrelated modifies — is forwarded without being
  parsed. Keep that pass-through-by-default behavior when adding decoding
  logic: fail open to "not my concern, forward it" rather than trying to
  understand every operation type.
- `read_frame` implements BER definite-length framing itself (RFC 4511
  §5.1) rather than relying on a higher-level LDAP library for transport
  framing, since the proxy needs raw frame boundaries to forward bytes
  unmodified when a message isn't inspected.
- `Identity` is peer-address-based only; there's no LDAP bind/auth
  correlation yet. Don't assume it maps to a stable principal across
  reconnects.

## Building and running

```sh
cargo check          # fast type/borrow check
cargo build           # debug build
cargo run             # runs against config::Config::dev_default():
                       # listens on 127.0.0.1:3890, proxies to 127.0.0.1:389
RUST_LOG=info cargo run   # tracing-subscriber reads RUST_LOG; default is silent
```

There is no test suite yet (`cargo test` runs zero tests). If you add
behavior, prefer adding `#[test]`/`#[tokio::test]` coverage alongside it —
`ThresholdPolicy` and `LdapConnector::decode`/`build_rejection` are
straightforward to unit test without a real LDAP server since they operate
on plain byte frames / in-memory state.

Run `cargo fmt` and `cargo clippy` before considering a change done; neither
is currently wired into CI (there is no CI config in this repo yet), so
they're on the honor system.

## Conventions

- Rust 2024 edition, `anyhow::Result` for fallible functions outside of
  tightly-scoped protocol decoding, `.context(...)` on I/O and decode calls
  to keep error messages traceable to what was being attempted.
- `tracing` for logging, not `println!`/`eprintln!`.
- Doc comments on non-obvious structs/functions explain *why*, not what
  (see `read_frame`, `LOCK_ATTRIBUTES`, `evaluate_all`) — match that style
  rather than restating the signature in prose.
- README.md and ARCHITECTURE.md exist but are currently empty; this file is
  the authoritative source of project context until those are filled in.
