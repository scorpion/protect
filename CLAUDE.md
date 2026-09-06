# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`ai-protect` is an inline TCP proxy for directory-service protocols (LDAP
today). It sits between a client and the real directory server (AD,
OpenLDAP, 389 DS), decodes only the requests that modify account-lock
attributes, and blocks bulk/high-blast-radius operations — the kind an
over-eager automated caller (an AI agent, a misconfigured script) issues —
via a configurable policy chain before they reach the real directory. Every
other request is forwarded byte-for-byte, untouched; every decision is
logged.

For full design detail beyond what's summarized below, read:
- [AGENTS.md](AGENTS.md) — module map and conventions
- [ARCHITECTURE.md](ARCHITECTURE.md) — request lifecycle, component design, extension points
- [TODO.md](TODO.md) — gap list to a production-ready deployment (what's fixed vs. still open)

## Commands

Setup (config/policy files are gitignored, not tracked — copy templates first):
```sh
cp config.example.toml config.toml
cp policies/ldap.example.toml policies/ldap.toml
```

```sh
cargo check                     # fast type/borrow check
cargo build                     # debug build
cargo run                       # loads config.toml
cargo run -- other-config.toml  # load config from a different path
RUST_LOG=info cargo run         # logging is silent by default; tracing-subscriber reads RUST_LOG
cargo test                      # unit + in-process integration tests
cargo test <name>                # run a single test by name (substring match)
cargo fmt                       # format
cargo clippy                    # lint
./test.sh                       # real end-to-end test: brings up dockerized lldap, runs the real
                                 # binary in front of it, drives it with ldapsearch/ldapmodify/
                                 # ldapwhoami/ldappasswd; requires docker, cargo, OpenLDAP client tools
```

`cargo fmt`/`cargo clippy` are not wired into CI — run them before considering a change done anyway.
CI ([.github/workflows/ci.yaml](.github/workflows/ci.yaml)) runs `cargo build`/`cargo test` on stable, beta, and nightly for every push and PR.

Local upstream for manual testing: `cp .env.example .env` (fill in secrets) then `docker compose up -d lldap`.

## Architecture

Core pipeline, in `src/proxy.rs`'s connection loop (`tokio::select!`, both directions concurrent):

```
Connector.read_frame → Connector.decode → Action → Policy.evaluate_all → Decision (Allow/Block)
```

- **`src/core/connector.rs`** — the `Connector` trait
  (`connect_upstream`/`read_frame`/`decode`/`build_rejection`/
  `upgrade_request`) that `src/proxy.rs` is written against as `Arc<dyn
  Connector>`, with zero compile-time knowledge of LDAP or any specific
  backend. `upgrade_request` has a default no-op impl (`Ok(None)`), so
  only a connector that supports an in-session TLS upgrade (LDAP's
  StartTLS) needs to override it.
- **`src/connector/ldap.rs`** — the only `Connector` impl. Owns BER frame
  parsing (RFC 4511 §5.1, not delegated to a higher-level LDAP library,
  since raw frame boundaries are needed to forward unmodified bytes),
  `rasn`/`rasn-ldap` decoding of `ModifyRequest`s, recognizing
  `LOCK_ATTRIBUTES` across AD/OpenLDAP/389 DS schemas, and building the
  `UnwillingToPerform` rejection sent to a blocked client. Also recognizes
  RFC 4511 StartTLS extended requests (`upgrade_request`) and, via
  `with_starttls`, can negotiate StartTLS itself when dialing the upstream
  instead of using implicit TLS.
- **`src/core/action.rs`** — `Action`/`OperationKind`, the backend-agnostic
  seam: what's attempted, what it targets, and its `blast_radius` (always
  `1` today; exists so a future bulk-op connector can report >1 without any
  downstream change).
- **`src/core/policy.rs`** + **`src/core/policy/threshold.rs`** — the
  `Policy` trait (`evaluate(&Action, &PolicyContext) -> Decision`) and
  `evaluate_all` (stops at first `Block`, so ordering matters for
  stateful/side-effecting policies). `ThresholdPolicy` is the only impl:
  blocks a single request over `max_per_request`, and separately tracks a
  per-`Identity` sliding window (`max_per_window` over `window_secs`) — a
  process-local `Mutex<HashMap<Identity, VecDeque<Instant>>>` that only
  advances on `Allow` (blocked actions don't pollute history). State does
  not survive a restart or span multiple instances.
- **`src/core/identity.rs`** — `Identity` is just the peer's source IP
  (port dropped, stable across reconnects); no auth/bind-derived identity
  yet, so it doesn't distinguish two clients behind the same NAT.
- **`src/core/audit.rs`** — structured `tracing` logging of every policy
  decision (`info` allow / `warn` block), decoupled from policy logic —
  the forensic trail since there's no other persistent state.
- **`src/core/net.rs`** / **`src/core/tls.rs`** — `MaybeTlsStream`
  (`Plain(TcpStream)` / `Tls(T)`) makes TLS-or-not transparent to framing
  and relay code; each hop (`[proxy.listen_tls]`, `[proxy.upstream_tls]`)
  independently and optionally runs LDAPS, with optional mutual TLS
  (`client_ca_file` on the listener, `client_cert` on the upstream hop).
  Either hop can instead start plaintext and upgrade mid-session via RFC
  4511 StartTLS (`[proxy.listen_starttls]`, `[proxy.upstream_tls].starttls`)
  rather than dialing implicit TLS from the first byte.
- **`src/config.rs`** — process config (`config.toml`: listen/upstream
  addrs, TLS tables, `[policy].file` pointer). Deliberately separate from
  policy definitions (`policies/ldap.toml`, parsed by
  `src/core/policy/config.rs` into `Vec<Arc<dyn Policy>>`) since policy
  files are one-per-connector/backend and may have a different change
  cadence than network config. Both files are gitignored; loading fails
  fast with a message pointing at the matching `*.example.toml` if either
  is missing.
- **`src/lib.rs`** / **`src/builder.rs`** — three public entry points
  covering different amounts of "load from a file": `run(config_path)`
  (fully file-driven), `run_with_config(&Config)` (skip the config file,
  still load policy from `config.policy.file`), and `builder::ProxyBuilder`
  (fully programmatic — construct a `Connector` and `Vec<Arc<dyn Policy>>`
  in memory, no file I/O). `src/main.rs` is a thin wrapper calling `run`.
- **`src/error.rs`** — `Error` aggregates module-local typed errors
  (`ConfigError`, `PolicyConfigError`, `TlsError`, `ProxyError`) for the
  public setup/config surface. Per-connection runtime code deliberately
  stays `anyhow::Result` (caught and logged per-connection, never
  returned to a caller, so typing it wouldn't change behavior).

**Extending this system**: a new backend protocol is a new
`src/connector/*.rs` implementing `Connector` — no changes to
`src/proxy.rs` or the policy engine. A new rule is a new `Policy` impl —
no changes to any connector. A new policy *instance* of an existing type
is config-only (`[[policy]]` table); a new policy *type* needs a
`PolicyEntry` variant in `src/core/policy/config.rs`. Keep the
pass-through-by-default behavior when touching decoding: only frames the
system needs to act on get parsed, everything else is forwarded as opaque
bytes.

## Conventions

- `tracing` for logging, never `println!`/`eprintln!`.
- Doc comments on non-obvious structs/functions explain *why*, not what
  (see `read_frame`, `LOCK_ATTRIBUTES`, `evaluate_all`) — match that style.
- `ThresholdPolicy` and `LdapConnector::decode`/`build_rejection` are unit
  tested on plain byte frames/in-memory state without a real LDAP server;
  `proxy::serve`/`ProxyBuilder` are tested end-to-end over real loopback
  TCP/TLS. Prefer the same approach for new behavior.
- AGENTS.md, README.md, and ARCHITECTURE.md are kept in sync with each
  other and treated as authoritative — update all three (plus this file)
  when module structure or the public API changes.
