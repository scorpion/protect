# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`ai-protect` is an inline TCP proxy for directory-service protocols (LDAP
today). It sits between a client and the real directory server (AD,
OpenLDAP, 389 DS), decodes only the requests that modify account-lock
attributes, delete/create an entry outright, or reset a password via
extended operation, and blocks bulk/high-blast-radius operations — the
kind an over-eager automated caller (an AI agent, a misconfigured script)
issues — via a configurable policy chain before they reach the real
directory. Every other request is forwarded byte-for-byte, untouched;
every decision is logged.

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
cargo +nightly fuzz run decode       # fuzz BER message decoding (LdapConnector::decode et al.)
cargo +nightly fuzz run read_frame   # fuzz frame length parsing (read_frame)
                                 # both require a nightly toolchain + `cargo install cargo-fuzz`;
                                 # not part of cargo test or CI, run manually after touching either
                                 # target's code (see fuzz/ and "Fuzzing" in README.md)
```

CI ([.github/workflows/ci.yaml](.github/workflows/ci.yaml)) runs `cargo build`/`cargo test` on stable, beta, and nightly, `cargo fmt --check`/`cargo clippy -D warnings` on stable, and `cargo audit` (RustSec advisory scan) — all for every push and PR. Run `cargo fmt`/`cargo clippy` locally before considering a change done anyway, so CI doesn't catch it first.

Local upstream for manual testing: `cp .env.example .env` (fill in secrets) then `docker compose up -d lldap`.

## Architecture

Core pipeline, in `src/proxy.rs`'s connection loop (`tokio::select!`, both directions concurrent):

```
Connector.read_frame → Connector.decode → Action → Policy.evaluate_all → Decision (Allow/Block)
```

- **`src/proxy.rs`** — the accept loop and per-connection relay. Owns
  `ConnectionLimits`: a `Semaphore` sized to `max_connections` rejects
  anything over the cap immediately instead of queuing it, and every
  read/write on both hops (TLS handshakes included) races an `io_timeout`
  that doubles as an idle-connection timeout — together the mitigation for
  a slow-loris client or a hung upstream pinning a task indefinitely. Also
  peeks the first frame off a still-plaintext connection to opportunistically
  negotiate RFC 4511 StartTLS (`[proxy.listen_starttls]`) before falling
  into the normal per-frame loop.
- **`src/core/connector.rs`** — the `Connector` trait
  (`connect_upstream`/`read_frame`/`decode`/`build_rejection`/
  `upgrade_request`/`bind_identity`) that `src/proxy.rs` is written against
  as `Arc<dyn Connector>`, with zero compile-time knowledge of LDAP or any
  specific backend. `upgrade_request` and `bind_identity` each have a
  default no-op impl (`Ok(None)`), so only a connector that supports an
  in-session TLS upgrade (LDAP's StartTLS) or an identity-establishing
  request (LDAP's bind) needs to override the respective one.
- **`src/connector/ldap.rs`** — the only `Connector` impl. Owns BER frame
  parsing (RFC 4511 §5.1, not delegated to a higher-level LDAP library,
  since raw frame boundaries are needed to forward unmodified bytes),
  `rasn`/`rasn-ldap` decoding of `ModifyRequest`s (recognizing
  `LOCK_ATTRIBUTES` across AD/OpenLDAP/389 DS schemas), `DelRequest`s, and
  `AddRequest`s (the latter two unconditionally, since removing/creating an
  entry outright is already high-blast-radius with no cheap way to narrow
  it further without querying the directory), and building the matching
  `UnwillingToPerform` rejection (`ModifyResponse`/`DelResponse`/
  `AddResponse`) sent to a blocked client. Also decodes the one
  `ExtendedRequest` this proxy polices — RFC 3062 Password Modify — into an
  `Action` (its own hand-rolled `PasswdModifyRequestValue` type, since
  `rasn-ldap` only models core LDAP ops, not this extended operation's
  payload); every other extended request (including StartTLS) is left to
  pass through `decode` unrecognized. Separately recognizes RFC 4511
  StartTLS extended requests (`upgrade_request`) and, via `with_starttls`,
  can negotiate StartTLS itself when dialing the upstream instead of using
  implicit TLS; and recognizes a simple `BindRequest` naming a non-empty DN
  (`bind_identity`) so the proxy can key policy/audit identity off that DN
  instead of the peer address.
- **`src/core/action.rs`** — `Action`/`OperationKind`, the backend-agnostic
  seam: what's attempted, what it targets, and its `blast_radius` (always
  `1` today; exists so a future bulk-op connector can report >1 without any
  downstream change). `OperationKind` covers `AccountLock`, `Delete`,
  `Create`, and `PasswordReset`.
- **`src/core/policy.rs`** + **`src/core/policy/threshold.rs`** — the
  `Policy` trait (`evaluate(&Action, &PolicyContext) -> Decision`) and
  `evaluate_all` (stops at first `Block`, so ordering matters for
  stateful/side-effecting policies). `ThresholdPolicy` is the only impl:
  blocks a single request over `max_per_request`, and separately tracks a
  per-`Identity` sliding window (`max_per_window` over `window_secs`) — a
  process-local `Mutex<HashMap<Identity, VecDeque<Instant>>>` that only
  advances on `Allow` (blocked actions don't pollute history). State does
  not survive a restart or span multiple instances.
- **`src/core/identity.rs`** — `Identity`, an opaque string wrapper. Starts
  as the peer's source IP (port dropped, stable across reconnects);
  `proxy::handle_client_frame` replaces it with the DN from a simple LDAP
  bind once one is seen (`Connector::bind_identity`), so two clients behind
  the same NAT are distinguished as long as they bind under different DNs.
  The bind isn't correlated against its `BindResponse`, so this is
  optimistic — see the caveat in [ARCHITECTURE.md](ARCHITECTURE.md#identity).
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
