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
      does I/O), and an optional `state_db` layers durability and
      approximate cross-instance sharing on top of it via a
      [`HistoryStore`](src/core/policy/store/mod.rs) backend — either
      [`SqliteStore`](src/core/policy/store/sqlite.rs) (a local file,
      chosen as the default so a single-binary proxy doesn't need an
      external service) or [`ValkeyStore`](src/core/policy/store/valkey.rs)
      (a network service — Redis-protocol-compatible, for HA across hosts
      with no shared disk, which SQLite's file-based sharing can't reach).
      `ThresholdPolicy::new` loads existing history from `state_db` once at
      startup (restart durability; a `ValkeyStore` skips this specific step
      since connecting is async — see its doc comment — and catches up on
      the first background sync instead), and a background task per policy
      wakes every `flush_interval` (default 2s) to write newly-admitted
      actions and reload the whole table/keyspace, off the tokio runtime
      either way (`spawn_blocking` for SQLite, a native async round trip
      for Valkey). Two instances pointed at the same file or Valkey
      instance converge on a shared budget within one `flush_interval` of
      each other — see "SQLite-backed policy state" and "Valkey-backed
      policy state" in
      [ARCHITECTURE.md](ARCHITECTURE.md#sqlite-backed-policy-state). Opt-in
      (`state_db` unset keeps today's pure in-memory behavior) and
      best-effort (a failure to open either backend logs a warning and
      falls back to in-memory rather than stopping the proxy from
      starting). A local `valkey` service (`docker compose --profile ha up
      -d valkey`) is available for testing this backend.
- [x] **Single connector/listener only.** `ai_protect::run` wired up exactly
      one `LdapConnector` behind one listener; there was no way to front more
      than one directory or protocol from a single deployment (see
      [ARCHITECTURE.md "Multiple upstreams / multiple listeners"](ARCHITECTURE.md#extension-points)).
      Fixed: `Config` is now `Vec<ProxyConfig>` (`[[proxy]]` array-of-tables
      in `config.toml`), each entry an independent
      listen/upstream/TLS/policy-file quintuple. `ai_protect::run_with_config`
      builds one `ProxyBuilder` per entry and runs all of them concurrently
      as sibling tasks in a `tokio::task::JoinSet`, returning (and aborting
      every other entry) as soon as any one exits — normally only on error,
      mirroring the previous single-listener behavior extended to "any
      listener failing brings down the process." `Config::load` fails fast
      if the array is empty. Each entry still hardcodes `LdapConnector` as
      its connector, so this covers multiple listeners/upstreams for the one
      protocol this proxy already speaks, not yet a mix of protocols in one
      process — see the note in
      [ARCHITECTURE.md "Known gaps"](ARCHITECTURE.md#known-gaps-by-design-at-this-stage).
- [x] **No config hot-reload.** Changing thresholds, addresses, or TLS
      settings requires a process restart. Graceful shutdown (below) means
      that restart no longer hard-drops in-flight connections, but it's
      still a full process stop/start rather than reloading in place. Fixed
      for policy files (thresholds and which policies run, in what order) —
      the highest-churn piece, per this file's own note in `[proxy.policy]`
      about a different change cadence than network config:
      `ai_protect::run_with_config` now installs a `SIGHUP` handler
      (`reload_policies_on_signal`) that re-reads every `[[proxy]]` entry's
      policy file and pushes it through a `watch::channel` `proxy::serve`
      reads fresh for each newly-accepted connection
      (`ProxyBuilder::policies_reloadable`). A connection already in flight
      keeps running under whichever policy list was current when it was
      accepted, the same as `listen_tls`/the connector are captured once per
      connection rather than re-read per frame; a read/parse failure for one
      entry is logged and leaves that entry unchanged rather than stopping
      the process. `ThresholdPolicy`'s background `state_db` sync task was
      changed to hold a `Weak` reference so a policy instance superseded by
      a reload stops syncing (instead of leaking a sync task per reload)
      once nothing references it anymore. See "Config hot-reload" in
      [ARCHITECTURE.md](ARCHITECTURE.md#config-hot-reload). Known
      limitation, by design: `listen_addr`/`upstream_addr`/TLS
      settings/connection limits are still read once at process start and
      need a restart — reloading those in place means rebinding a live
      listener socket or migrating open connections onto new upstream/TLS
      settings mid-session, not just swapping an in-memory value, and was
      judged out of scope for this pass.
- [x] **No graceful shutdown.** There's no `SIGTERM`/`SIGINT` handling in
      [`main.rs`](src/main.rs)/[`lib.rs`](src/lib.rs) (tokio's `signal` feature isn't even enabled
      in [`Cargo.toml`](Cargo.toml)) and no draining of in-flight connections
      — a rolling restart or deploy hard-cuts active LDAP sessions instead of
      finishing them. Fixed: `ai_protect::run_with_config` now installs a
      handler for `SIGTERM`/`SIGINT` (`Ctrl-C` only on Windows — no
      `SIGTERM` equivalent there) that flips a `watch::channel(bool)` shared
      by every `[[proxy]]` entry. `proxy::serve`'s accept loop selects
      between `listener.accept()` and that signal, so it stops taking *new*
      connections the moment shutdown is requested — using
      `watch::Receiver::wait_for` rather than a bare `changed().await` so a
      request that landed before the loop started watching still isn't
      missed. Every already-spawned connection is now tracked in a
      `JoinSet` (previously a bare `tokio::spawn`) specifically so shutdown
      can wait on it: up to a new `shutdown_timeout` (`shutdown_timeout_secs`
      per `[[proxy]]` entry, default 30s, part of `ConnectionLimits`) to
      finish on its own, after which whatever's left is forcibly aborted
      instead of hanging the process. `run_with_config` waits for every
      entry to finish draining before returning `Ok(())`; an entry that
      instead exits with an error still stops the rest immediately, as
      before. `ProxyBuilder::shutdown` exposes the same mechanism to
      embedders opt-in (a caller-driven `watch::Receiver<bool>`, no OS
      signal handling of its own) — see "Graceful shutdown" in
      [ARCHITECTURE.md](ARCHITECTURE.md#graceful-shutdown).

## Medium — observability & operations

- [x] **No metrics.** Only `tracing` logs exist
      ([`audit::log_decision`](src/core/audit.rs)); there's no
      Prometheus/OpenTelemetry counters for allow/block rates, active
      connections, upstream latency, or TLS handshake failures. Fixed:
      [`core::metrics`](src/core/metrics.rs) records exactly those four
      things through the `metrics` facade crate (a no-op until a recorder
      is installed, so `ProxyBuilder` embedders pay nothing unless they opt
      in) — `ai_protect_connections_active`/`_total` via a `ConnectionGuard`
      tied to each connection's task lifetime, `ai_protect_policy_decisions_total`
      (labeled `decision`/`backend`/`operation`) recorded alongside
      `audit::log_decision`, `ai_protect_upstream_connect_duration_seconds`
      timing `Connector::connect_upstream` (connection setup, not a
      per-request round trip — the relay doesn't correlate individual
      request/response frames), and `ai_protect_tls_handshake_failures_total`
      (labeled `hop`: `listen`/`listen_starttls`/`upstream`) covering all
      three handshake points on either side of the proxy.
      `run_with_config` installs a Prometheus text-format `/metrics`
      listener via `core::metrics::install_prometheus_exporter` when the
      new top-level `[metrics]` table (`listen_addr`) is present in
      `config.toml` — one process-wide endpoint, opt-in, covering every
      `[[proxy]]` entry. See "Metrics" in
      [ARCHITECTURE.md](ARCHITECTURE.md#metrics).
- [x] **No structured log output option.** `tracing_subscriber::fmt::init()`
      in [`main.rs`](src/main.rs) emits human-readable text only; a JSON
      formatter option would make shipping to a SIEM much less painful, and
      the audit trail (this system's stated forensic record, per
      [ARCHITECTURE.md](ARCHITECTURE.md#audit-logging)) is worth making
      easy to ingest. Fixed: `main.rs` now installs two `tracing` output
      layers sharing one `RUST_LOG`-driven filter — stdout keeps the
      existing human-readable text (unchanged), and a new
      `tracing-appender` non-blocking writer sends structured JSON (fields
      flattened to the top level, not nested under `"fields"`) to
      `./logs/ldap.log`, created on startup if missing. Every event reaches
      both; nothing is unique to either side. The path is fixed rather
      than config-driven — a stable location to point a log shipper or
      `logrotate` at. Known limitation: the file never rotates itself
      (`rolling::never`, to keep the exact filename `ldap.log`) and the
      path is relative to the process's working directory — an unbounded
      deployment needs an external rotator, and a non-writable/relative
      cwd (e.g. some container setups) needs attention. See "Audit
      logging" in [ARCHITECTURE.md](ARCHITECTURE.md#audit-logging).
- [x] **No health/readiness endpoint** for orchestrator liveness/readiness
      probes (k8s, etc.). Fixed: [`core::health`](src/core/health.rs) is a
      small hand-rolled HTTP server (no framework dependency needed for two
      fixed-response routes) serving `/healthz` and `/readyz`, wired up by
      `run_with_config` when the new top-level `[health]` table
      (`listen_addr`) is present in `config.toml` — one endpoint for the
      whole process, the same opt-in pattern as `[metrics]`. `/healthz`
      always answers `200`; `/readyz` answers `200` until graceful shutdown
      is requested, then `503`, so a load balancer stops routing new
      connections here before the drain itself finishes. `/healthz`
      deliberately keeps answering `200` throughout that drain window
      (`serve` never stops accepting on its own — process exit takes it
      down, same as the installed Prometheus exporter) since a liveness
      probe going quiet mid-drain would get the process killed outright,
      defeating the point of draining. See "Health" in
      [ARCHITECTURE.md](ARCHITECTURE.md#health).
- [x] **No deployment packaging** — no Dockerfile, systemd unit, or Helm
      chart yet; needed for a repeatable rollout. Fixed for the Dockerfile:
      [`docker/rust/Dockerfile`](docker/rust/Dockerfile) is a two-stage
      build — a `rust:1-slim-bookworm` stage compiles the release binary
      (LTO + single codegen unit, per `Cargo.toml`'s `[profile.release]`,
      with dependencies cached in their own layer via a dummy `src/main.rs`
      built before the real source is copied in), copied into a
      `debian:bookworm-slim` runtime stage with just `ca-certificates`
      (needed for `rustls-native-certs` to validate an upstream's LDAPS/
      StartTLS certificate against the OS trust store) and an unprivileged
      user. `config.toml`/`policies/*.toml`/`certs/` are deliberately not
      baked into the image — they're gitignored (secrets, environment-
      specific addresses) — so they're mounted in at runtime instead; see
      "Docker" in [README.md](README.md#docker) for the build/run commands.
      Verified end-to-end: built the image, ran it with a mounted
      `config.toml`/policy file, confirmed the LDAP listener and the new
      `/healthz`/`/readyz` endpoint (see the entry above) both answered
      correctly and `./logs` was created and writable under the
      unprivileged user. `.dockerignore` added alongside it to keep the
      build context small. Known limitation, deliberately out of scope for
      this pass: no systemd unit or Helm chart yet — a container image is
      the one packaging format needed to unblock most orchestrators (k8s,
      Nomad, plain `docker run`) directly; a systemd unit only matters for
      bare-metal/VM rollouts and a Helm chart is only useful once there's a
      real k8s deployment shape (resource limits, probe wiring, secret
      mounting conventions) to template, which hasn't been decided yet.
- [x] **No CI pipeline** — no GitHub Actions (or equivalent) running
      `cargo test` / `cargo clippy` / `cargo fmt --check`, and no
      supply-chain scanning (`cargo audit` / `cargo deny`) on dependencies.
      Fixed: [`.github/workflows/ci.yaml`](.github/workflows/ci.yaml) gained
      two jobs alongside the existing `build_and_test` matrix (stable/beta/
      nightly `cargo build`+`cargo test`, unchanged) — `lint` (stable-only:
      `cargo fmt --all -- --check` and `cargo clippy --all-targets
      --all-features -- -D warnings`, so a warning fails the build the same
      as a test failure) and `security_audit` (`cargo audit` via
      `taiki-e/install-action@cargo-audit`, checking every dependency in
      `Cargo.lock` against the RustSec advisory database). All three jobs
      run on every push and PR; none require new repo permissions or
      secrets beyond the default `GITHUB_TOKEN`.

## Low — cleanup & polish

- [x] **Unused dependency:** `ldap3` is declared in [`Cargo.toml`](Cargo.toml)
      but nothing in `src/` references it (the LDAP wire protocol work is
      all hand-rolled via `rasn`/`rasn-ldap`). Remove it or document why it's
      there if it's a placeholder for planned work. Fixed: removed from
      `Cargo.toml`/`Cargo.lock`.
- [x] **No fuzzing of the decode path.** `read_frame` and the `rasn` BER
      decode in [`LdapConnector::decode`](src/connector/ldap.rs) are the only
      code that touches fully untrusted bytes; worth a fuzz target given a
      malformed/adversarial LDAP frame is the most likely place for a panic
      or resource-exhaustion bug (also see the frame-size cap above). Fixed:
      added a `cargo-fuzz` project at [`fuzz/`](fuzz/) with two targets —
      `read_frame` (BER tag/length framing, driven over a `Cursor` under a
      throwaway `tokio::runtime::Runtime` since `read_frame` is async) and
      `decode` (`LdapConnector::decode`/`upgrade_request`/`bind_identity`/
      `build_rejection`, the four methods that call `rasn::ber::decode` on an
      already-framed message). Both ran clean past ~800K (`decode`) and
      ~2.6M (`read_frame`) executions locally with no crashes. Requires a
      nightly toolchain (`rasn`/BER decoding isn't the constraint —
      `cargo-fuzz`'s libFuzzer instrumentation is), so it's deliberately not
      wired into `cargo test` or CI's stable/beta/nightly matrix; run
      manually via `cargo +nightly fuzz run decode` /
      `cargo +nightly fuzz run read_frame` after touching either target's
      code. See "Fuzzing" in [README.md](README.md#fuzzing).
- [x] **No load/soak testing** to validate behavior (memory, fd count,
      latency) under many concurrent connections or sustained throughput.
      Fixed: [`soak.sh`](soak.sh), following the same real-binary-over-the-
      wire approach as `test.sh` rather than a synthetic benchmark. Phase A
      runs a pool of concurrent workers (default 40) against a release
      build for a sustained duration (default 20s), each opening a fresh
      connection per operation (mostly searches, some modifies) to mirror
      many short-lived clients rather than a few long ones, while sampling
      the proxy's own RSS and open-fd count throughout; it then checks
      memory didn't run away, every connection was cleaned up (fd count and
      the `ai_protect_connections_active` metric both back at baseline/0
      after load stops), and read latency stayed sane. Phase B bursts far
      more concurrent connection attempts (default 300) than a deliberately
      low `max_connections` cap to confirm the `Semaphore` rejects the
      excess immediately rather than queuing/hanging, and that the proxy
      recovers cleanly afterward. Requires the same tools as `test.sh`
      (docker, cargo, OpenLDAP client tools) plus `curl` to scrape
      `/metrics`; like fuzzing, it's a manual check, not wired into `cargo
      test` or CI. See "Load/soak testing" in [README.md](README.md#loadsoak-testing).
