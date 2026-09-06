# Enterprise deployment TODO

A gap list between the current state (post-TLS, see [ARCHITECTURE.md](ARCHITECTURE.md))
and something safe to run in front of a production directory. Grouped by
priority; within a group, roughly in the order you'd want to tackle them.

## Critical — security / DoS

- [x] **Unbounded frame allocation.** [`read_frame`](src/connector/ldap.rs)
      trusts the BER length prefix and does `vec![0u8; content_len]` with no
      upper bound — a client can claim a length up to ~4 GiB
      (`u32::MAX`) and force a multi-gigabyte allocation per connection
      before a single byte of content is read. Add a sane max-frame-size cap
      (config or const) and close the connection over it. Fixed: `read_frame`
      now rejects any claimed content length over `MAX_FRAME_CONTENT_LEN`
      (16 MiB) before allocating, returning an error that propagates up and
      closes the connection.
- [x] **No connection limits or timeouts.** The accept loop in
      [`proxy::serve`](src/proxy.rs) spawns an unbounded task per
      connection with no cap on concurrent connections, no idle-connection
      timeout, and no read/write timeout — a slow-loris client or a hung
      upstream pins a task and its memory indefinitely. Fixed: added
      `ConnectionLimits` (`max_connections`, `io_timeout`), configurable via
      `[proxy]` in `config.toml` (`max_connections`, `io_timeout_secs`,
      defaulting to 1024/60s) or `ProxyBuilder::limits`. A `Semaphore` caps
      concurrent connections, closing anything over the limit immediately;
      every read/write on both hops (TLS handshakes included) races against
      `io_timeout`, doubling as an idle timeout.
- [x] **No mutual TLS.** Both `ClientConfig`/`ServerConfig` in
      [`src/core/tls.rs`](src/core/tls.rs) use `with_no_client_auth()`. Right now
      anything that can reach the listener and speak LDAP is trusted equally;
      client certificate auth would let the proxy authenticate *which* agent
      is connecting instead of just trusting its source IP. Fixed: `ListenTls`
      now takes an optional `client_ca_file` (`[proxy.listen_tls].client_ca_file`
      in config) — when set, it builds a `WebPkiClientVerifier` from that CA and
      requires every connecting client to present a certificate signed by it,
      rejecting the handshake otherwise. `UpstreamTls` symmetrically takes an
      optional client cert/key pair (`[proxy.upstream_tls.client_cert]`) to
      present when the upstream itself requires mTLS. This is authentication
      only — `Identity` (see below) is still address-based, not tied to the
      presented certificate.
- [x] **StartTLS unsupported.** Only implicit TLS (LDAPS) is implemented on
      either hop (see updated [ARCHITECTURE.md](ARCHITECTURE.md#transport-plaintext-or-tls)).
      Any environment standardized on port 389 + StartTLS instead of 636
      can't sit behind this proxy today. Fixed: `Connector` gained an
      `upgrade_request` hook (default no-op) that `LdapConnector` implements
      for RFC 4511 StartTLS. Client-facing: `[proxy.listen_starttls]`
      accepts plaintext and `proxy::serve` peeks the first frame off each
      connection, confirming and upgrading in place on a StartTLS request
      and otherwise feeding that frame into the normal pipeline unchanged
      (opportunistic, never required; ignored if `[proxy.listen_tls]` is
      also set). Upstream: `LdapConnector::with_starttls(true)`
      (`[proxy.upstream_tls].starttls`) negotiates StartTLS before handing
      off to the same TLS handshake implicit TLS uses. Both ends reuse
      `ListenTls`/`UpstreamTls`, so mTLS/trust-store/SNI behavior is
      identical regardless of how the handshake was triggered.
- [x] **Native cert-store load errors are swallowed.** [`tls.rs:49`](src/core/tls.rs)
      iterates `rustls_native_certs::load_native_certs().certs` and silently
      discards `.errors` — a partially-broken OS trust store fails open
      instead of being logged. Fixed: each entry in `.errors` is now logged
      via `tracing::warn!` before the successfully-loaded certs are added to
      the trust store.
- [x] **Confirm the TLS version floor.** `rustls`/`tokio-rustls` are built
      with the `tls12` feature enabled alongside 1.3 ([`Cargo.toml`](Cargo.toml)).
      Decide whether TLS 1.2 needs to stay for compatibility with older
      directory servers or should be dropped, and document the decision.
      Decided: keep TLS 1.2. Active Directory (a target directory) only
      supports TLS 1.3 for LDAPS from Windows Server 2022 onward, so most
      real deployments (2016/2019 AD, older 389 DS/OpenLDAP) are TLS-1.2-only
      — dropping it would lock them out. Documented in `Cargo.toml` (comment
      on the `tls12` feature) and [ARCHITECTURE.md](ARCHITECTURE.md#transport-plaintext-or-tls)
      ("TLS version floor").

## High — identity & policy coverage

- [x] **Identity is source-IP-only.** [`Identity::from_peer_addr`](src/core/identity.rs)
      means two agents behind the same NAT/egress (very common for
      containerized/agent-fleet deployments) share one blast-radius budget,
      and a reconnect resets nothing but also proves nothing. Derive identity
      from the LDAP bind DN (or the mTLS client cert CN, once mTLS exists)
      instead — `Identity` is already an opaque type specifically so this
      swap doesn't touch `Policy`/`ThresholdPolicy`/audit signatures. Fixed:
      `Connector` gained a `bind_identity` hook (default no-op, same pattern
      as `upgrade_request`); `LdapConnector::bind_identity` recognizes a
      simple (DN + password) `BindRequest` naming a non-empty DN and
      `proxy::handle_client_frame` swaps the connection's `Identity` to it,
      falling back to (and starting as) the peer address otherwise. Two
      agents behind the same NAT/egress now get separate blast-radius
      budgets as long as they bind under different DNs. Known limitation:
      the bind isn't correlated against its `BindResponse`, so `Identity`
      moves as soon as the request is seen, optimistically — see the
      caveat in [ARCHITECTURE.md](ARCHITECTURE.md#identity). mTLS-cert-CN-
      derived identity remains unimplemented if bind DN coverage isn't
      enough (e.g. SASL-only deployments).
- [x] **Policy only watches `ModifyRequest`.** [`LdapConnector::decode`](src/connector/ldap.rs)
      only turns lock-attribute `Modify` operations into `Action`s. A bulk
      `DelRequest` (mass account deletion) or bulk `AddRequest` (mass account
      creation) is at least as high-blast-radius as a lock and currently
      passes through unpoliced. Decide if "account lock" is the intentional
      v1 scope or if delete/add need equivalent coverage before calling this
      blast-radius protection in general. Fixed: decided delete/add need
      equivalent coverage — `decode` now flags every `DelRequest`/
      `AddRequest` as an `Action` (`OperationKind::Delete`/`Create`)
      unconditionally, since (unlike `Modify`, where most requests are
      mundane attribute edits) removing or creating an entry outright is
      already high-blast-radius, and there's no cheap attribute-level filter
      to narrow it further without querying the directory. `build_rejection`
      now returns the matching response variant (`DelResponse`/
      `AddResponse`) so a blocked client gets a well-formed rejection instead
      of a mismatched `ModifyResponse`. `ThresholdPolicy` needed no changes —
      it's already operation-agnostic, keying only on `blast_radius` and
      `Identity`.
- [x] **`ExtendedRequest` isn't policed.** [`LdapConnector::upgrade_request`](src/connector/ldap.rs)
      now inspects `ExtendedRequest`s, but only to recognize the StartTLS
      OID for the TLS-upgrade handshake — it's not part of the
      `decode`/policy path. Some directories expose account-disable-equivalent
      operations (e.g. RFC 3062 password modify) as extended operations
      rather than `Modify`; those still pass through with no policy
      evaluation at all. Fixed: `decode` now recognizes the RFC 3062
      Password Modify OID specifically (a bulk password reset is as
      disruptive as a bulk lock — both leave affected users unable to log
      in) and turns it into an `Action` (`OperationKind::PasswordReset`),
      decoding the extended operation's opaque payload via a hand-rolled
      `PasswdModifyRequestValue` type (`rasn-ldap` only models core LDAP
      operations, not extended-operation payloads). `build_rejection` returns
      a matching `ExtendedResp` for a blocked one. `upgrade_request` and
      `decode` remain separate, independent code paths — StartTLS is still
      handled only by the former, and this doesn't change that. Every other
      extended operation still passes through unpoliced; RFC 3062 was the
      only one the gap explicitly called out.

## High — reliability & scale

- [x] **Policy state is process-local and in-memory.** [`ThresholdPolicy`](src/core/policy/threshold.rs)
      keeps history in a `Mutex<HashMap<...>>` — a restart resets all
      counters, and running more than one instance for HA silently
      double-budgets every identity. Needs a shared backing store (e.g.
      Redis) before this can run as more than a single process. Fixed: the
      in-memory map stays the hot path unconditionally (`evaluate` never
      does I/O), and an optional `state_db` (SQLite, via the new
      [`HistoryStore`](src/core/policy/store.rs)) layers durability and
      approximate cross-instance sharing on top of it — chosen over Redis
      so this doesn't add an external service dependency for a
      single-binary proxy. `ThresholdPolicy::new` loads existing history
      from `state_db` once at startup (restart durability), and a
      background task per policy wakes every `flush_interval` (default 2s)
      to write newly-admitted actions and reload the whole table, always
      via `spawn_blocking` so a slow disk never stalls a live connection's
      tokio worker. Two instances pointed at the same file converge on a
      shared budget within one `flush_interval` of each other — see
      "SQLite-backed policy state" in [ARCHITECTURE.md](ARCHITECTURE.md#sqlite-backed-policy-state).
      Opt-in (`state_db` unset keeps today's pure in-memory behavior) and
      best-effort (a failure to open it logs a warning and falls back to
      in-memory rather than stopping the proxy from starting). Known
      limitation: this needs a shared filesystem (e.g. a shared volume),
      not a network service — a genuinely distributed deployment across
      hosts with no shared disk still needs something like Redis.
- [ ] **Single connector/listener only.** `ai_protect::run` wires up exactly
      one `LdapConnector` behind one listener; there's no way to front more
      than one directory or protocol from a single deployment (see
      [ARCHITECTURE.md "Multiple upstreams / multiple listeners"](ARCHITECTURE.md#extension-points)).
- [ ] **No config hot-reload.** Changing thresholds, addresses, or TLS
      settings requires a process restart, which currently also hard-drops
      every in-flight connection (see next item).
- [ ] **No graceful shutdown.** There's no `SIGTERM`/`SIGINT` handling in
      [`main.rs`](src/main.rs)/[`lib.rs`](src/lib.rs) (tokio's `signal` feature isn't even enabled
      in [`Cargo.toml`](Cargo.toml)) and no draining of in-flight connections
      — a rolling restart or deploy hard-cuts active LDAP sessions instead of
      finishing them.

## Medium — observability & operations

- [ ] **No metrics.** Only `tracing` logs exist
      ([`audit::log_decision`](src/core/audit.rs)); there's no
      Prometheus/OpenTelemetry counters for allow/block rates, active
      connections, upstream latency, or TLS handshake failures.
- [ ] **No structured log output option.** `tracing_subscriber::fmt::init()`
      in [`main.rs`](src/main.rs) emits human-readable text only; a JSON
      formatter option would make shipping to a SIEM much less painful, and
      the audit trail (this system's stated forensic record, per
      [ARCHITECTURE.md](ARCHITECTURE.md#audit-logging)) is worth making
      easy to ingest.
- [ ] **No health/readiness endpoint** for orchestrator liveness/readiness
      probes (k8s, etc.).
- [ ] **No deployment packaging** — no Dockerfile, systemd unit, or Helm
      chart yet; needed for a repeatable rollout.
- [ ] **No CI pipeline** — no GitHub Actions (or equivalent) running
      `cargo test` / `cargo clippy` / `cargo fmt --check`, and no
      supply-chain scanning (`cargo audit` / `cargo deny`) on dependencies.

## Low — cleanup & polish

- [x] **Unused dependency:** `ldap3` is declared in [`Cargo.toml`](Cargo.toml)
      but nothing in `src/` references it (the LDAP wire protocol work is
      all hand-rolled via `rasn`/`rasn-ldap`). Remove it or document why it's
      there if it's a placeholder for planned work. Fixed: removed from
      `Cargo.toml`/`Cargo.lock`.
- [ ] **No fuzzing of the decode path.** `read_frame` and the `rasn` BER
      decode in [`LdapConnector::decode`](src/connector/ldap.rs) are the only
      code that touches fully untrusted bytes; worth a fuzz target given a
      malformed/adversarial LDAP frame is the most likely place for a panic
      or resource-exhaustion bug (also see the frame-size cap above).
- [ ] **No load/soak testing** to validate behavior (memory, fd count,
      latency) under many concurrent connections or sustained throughput.
