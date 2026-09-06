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
- [ ] **No mutual TLS.** Both `ClientConfig`/`ServerConfig` in
      [`src/core/tls.rs`](src/core/tls.rs) use `with_no_client_auth()`. Right now
      anything that can reach the listener and speak LDAP is trusted equally;
      client certificate auth would let the proxy authenticate *which* agent
      is connecting instead of just trusting its source IP.
- [ ] **StartTLS unsupported.** Only implicit TLS (LDAPS) is implemented on
      either hop (see updated [ARCHITECTURE.md](ARCHITECTURE.md#transport-plaintext-or-tls)).
      Any environment standardized on port 389 + StartTLS instead of 636
      can't sit behind this proxy today.
- [ ] **Native cert-store load errors are swallowed.** [`tls.rs:49`](src/core/tls.rs)
      iterates `rustls_native_certs::load_native_certs().certs` and silently
      discards `.errors` — a partially-broken OS trust store fails open
      instead of being logged.
- [ ] **Confirm the TLS version floor.** `rustls`/`tokio-rustls` are built
      with the `tls12` feature enabled alongside 1.3 ([`Cargo.toml`](Cargo.toml)).
      Decide whether TLS 1.2 needs to stay for compatibility with older
      directory servers or should be dropped, and document the decision.

## High — identity & policy coverage

- [ ] **Identity is source-IP-only.** [`Identity::from_peer_addr`](src/core/identity.rs)
      means two agents behind the same NAT/egress (very common for
      containerized/agent-fleet deployments) share one blast-radius budget,
      and a reconnect resets nothing but also proves nothing. Derive identity
      from the LDAP bind DN (or the mTLS client cert CN, once mTLS exists)
      instead — `Identity` is already an opaque type specifically so this
      swap doesn't touch `Policy`/`ThresholdPolicy`/audit signatures.
- [ ] **Policy only watches `ModifyRequest`.** [`LdapConnector::decode`](src/connector/ldap.rs)
      only turns lock-attribute `Modify` operations into `Action`s. A bulk
      `DelRequest` (mass account deletion) or bulk `AddRequest` (mass account
      creation) is at least as high-blast-radius as a lock and currently
      passes through unpoliced. Decide if "account lock" is the intentional
      v1 scope or if delete/add need equivalent coverage before calling this
      blast-radius protection in general.
- [ ] **No `ExtendedRequest` handling** — some directories expose
      account-disable-equivalent operations (e.g. RFC 3062 password modify)
      as extended operations rather than `Modify`, which this connector
      doesn't inspect at all.

## High — reliability & scale

- [ ] **Policy state is process-local and in-memory.** [`ThresholdPolicy`](src/core/policy/threshold.rs)
      keeps history in a `Mutex<HashMap<...>>` — a restart resets all
      counters, and running more than one instance for HA silently
      double-budgets every identity. Needs a shared backing store (e.g.
      Redis) before this can run as more than a single process.
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

- [ ] **Unused dependency:** `ldap3` is declared in [`Cargo.toml`](Cargo.toml)
      but nothing in `src/` references it (the LDAP wire protocol work is
      all hand-rolled via `rasn`/`rasn-ldap`). Remove it or document why it's
      there if it's a placeholder for planned work.
- [ ] **No fuzzing of the decode path.** `read_frame` and the `rasn` BER
      decode in [`LdapConnector::decode`](src/connector/ldap.rs) are the only
      code that touches fully untrusted bytes; worth a fuzz target given a
      malformed/adversarial LDAP frame is the most likely place for a panic
      or resource-exhaustion bug (also see the frame-size cap above).
- [ ] **No load/soak testing** to validate behavior (memory, fd count,
      latency) under many concurrent connections or sustained throughput.
