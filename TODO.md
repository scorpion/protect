# Enterprise deployment TODO

A gap list from a follow-up security review (2026-09-06) of the current state
(see [ARCHITECTURE.md](ARCHITECTURE.md)), conducted after the previous round
of hardening (frame-size caps, connection limits/timeouts, mTLS, StartTLS,
graceful shutdown, hot-reload, metrics, health checks, structured logging,
fuzzing — all still in place and not re-litigated here). Grouped by
priority; within a group, roughly in the order you'd want to tackle them.

## Critical — policy bypass & resource exhaustion

- [x] **The blast-radius policy can be bypassed by identity churn.**
      [`LdapConnector::bind_identity`](src/connector/ldap.rs) accepts any DN
      named in a simple `BindRequest` at face value and
      [`proxy::handle_client_frame`](src/proxy.rs) swaps the connection's
      `Identity` to it immediately — it is never correlated against the
      actual `BindResponse` on the reply path (the request and response
      relay loops in `proxy.rs` share no state to do this).
      [`ThresholdPolicy::evaluate`](src/core/policy/threshold.rs) then
      buckets every budget purely per `Identity`, and there is no policy
      type anywhere that enforces a global, identity-independent ceiling.
      The consequence: a caller sends a throwaway `BindRequest` naming a
      fresh, made-up DN before each batch of destructive operations and
      gets a brand-new, empty per-identity budget every time, as long as
      each individual batch stays under `max_per_request`/`max_per_window`
      — completely defeating "4 accounts is fine, 4,000 is not" for exactly
      the "compromised credential" actor named in CLAUDE.md's own threat
      model. [ARCHITECTURE.md#identity](ARCHITECTURE.md#identity) already
      acknowledges the bind is unverified, but only reasons about the
      *write itself* getting rejected upstream afterward — it doesn't
      address that the local forward-or-block decision is made using the
      unverified claimed identity *before* that rejection could ever
      happen. Fix direction: don't trust a claimed identity for policy
      purposes until its `BindResponse` is seen to be `Success` (requires
      correlating request/response by message ID, which the proxy
      currently doesn't do at all); add a global, identity-independent
      aggregate cap as a backstop regardless of how identity is derived.
      Fixed: `bind_identity` is split into `Connector::bind_request`
      (stages a claimed DN, keyed by LDAP message ID, without touching
      identity) and `Connector::bind_response` (reports whether the
      correlated response succeeded); a new connection-scoped `BindState`
      in `src/proxy.rs`, shared between the client- and upstream-facing
      relay directions, resolves a pending claim — promoting `Identity`
      only on confirmed success — the moment the matching `BindResponse` is
      seen. A claimed-but-unverified DN can no longer buy a fresh budget
      (see the `unverified_bind_does_not_change_identity_or_reset_budget`
      test in `src/proxy.rs`). Separately, `ThresholdPolicy` gained a
      `scope` option (`PerIdentity`, the default, or `Global`, one shared
      bucket ignoring identity entirely) so a second `[[policy]]` entry can
      run as the identity-independent aggregate backstop, undefeatable by
      identity churn since it isn't keyed by identity at all — see the
      commented-out example in `policies/ldap.example.toml`. Known
      limitation: this closes *verification* of one claimed identity, not
      the number of distinct identities a caller can churn through — an
      unauthenticated caller can still bind under an unbounded number of
      real, distinct DNs (if it has credentials for them) or unverified
      claims (which now just never promote), each only bounded by the
      `Global` backstop's aggregate ceiling, not a per-caller one. Unbounded
      history-map cardinality and the IP/DN identity-namespace collision
      were tracked as the following two items — both since fixed.
- [x] **Identity namespace collision between peer-IP and bind-DN
      derivation.** [`Identity`](src/core/identity.rs) is one flat,
      un-namespaced string used both for `Identity::from_peer_addr`
      (`"10.0.0.5"`) and for a bind DN
      (`LdapConnector::bind_identity`). A bind DN deliberately crafted to
      equal a real peer's IP-address string collides with that peer's
      budget in `ThresholdPolicy`'s history map, letting an attacker
      pollute or exhaust a legitimate peer's rate limit without ever
      touching that peer's actual connection. Fix direction: prefix/tag
      identity values by their source (`ip:`/`dn:`) so the two derivation
      methods can never collide.
      Fixed: `Identity::from_peer_addr` now formats as `ip:<addr>` and a
      new `Identity::from_bind_dn` (used by the confirmed-bind promotion
      path in `src/proxy.rs`, replacing a bare `Identity(dn)` construction)
      formats as `dn:<dn>` — the two prefixes are disjoint by construction,
      so a DN crafted to read identically to some peer's IP-address string
      (e.g. a bind DN of literally `127.0.0.1`) now produces `dn:127.0.0.1`,
      never colliding with that peer's `ip:127.0.0.1` bucket in
      `ThresholdPolicy`'s history map. See the
      `peer_ip_and_bind_dn_never_collide_even_with_matching_text` test in
      `src/core/identity.rs`.
- [x] **Unbounded identity cardinality enables unauthenticated memory/disk
      exhaustion.** Every actionable request — even one immediately
      blocked by the window check — creates a permanent entry in
      [`ThresholdPolicy`](src/core/policy/threshold.rs)'s
      `Mutex<HashMap<Identity, VecDeque<Instant>>>`
      (`entry(ctx.identity.clone()).or_default()`). Entries are pruned by
      *age* only, never by count, and an `Identity` string has no length
      cap — it can be as large as a single BER frame allows
      (`MAX_FRAME_CONTENT_LEN`, 16 MiB). Combined with the identity-churn
      issue above, an unauthenticated network client with no valid
      credentials at all can grow this map without bound:
      `connect → BindRequest(simple, DN=<random unique string>) →
      DelRequest(anything) → close`, repeated. The same pattern grows the
      optional persistent backends too —
      [`SqliteStore`](src/core/policy/store/sqlite.rs)/
      [`ValkeyStore`](src/core/policy/store/valkey.rs) also only prune by
      age, not by distinct-identity count, so a steady stream of fresh fake
      identities grows the on-disk table / Valkey keyspace forever as well.
      Fix direction: cap identity-string length at ingestion (bind DN, and
      really any DN accepted into `Action.target`), and bound the history
      map's cardinality (LRU eviction or a hard cap with a logged warning)
      independently of the existing age-based pruning.
      Fixed: two independent bounds. (1) A new `cap_dn` helper in
      [`src/connector/ldap.rs`](src/connector/ldap.rs) caps every DN
      extracted from a decoded message (bind DN, and modify/del/add/
      password-modify `Action.target`) at 256 bytes; a DN over that replaces
      itself with a small fixed-shape marker carrying its true length and a
      stable hash of its full content, so oversized DNs stay bounded in size
      without colliding into each other. (2) A new `max_tracked_identities`
      config field on `ThresholdConfig` (default 100,000) hard-caps
      `ThresholdPolicy`'s history map: once reached, admitting a
      never-before-seen identity evicts the tracked identity with the least
      recently recorded activity first (`evict_stalest_until`), applied both
      on the request hot path (`evaluate`) and when folding a `state_db`
      snapshot back in (`sync_once`/`ThresholdPolicy::new`), so the same
      cap holds however history got populated. See
      `caps_tracked_identity_count_by_evicting_the_stalest_one` in
      `src/core/policy/threshold.rs` and
      `cap_dn_bounds_the_size_of_an_oversized_dn` in
      `src/connector/ldap.rs`.

## High

- [x] **No TLS support for the Valkey-backed HA state store.**
      [`Cargo.toml`](Cargo.toml)'s `redis` dependency
      (`features = ["tokio-comp", "connection-manager"]`) enables no
      `tls-*` feature, and no TLS-capable crate appears anywhere in
      `Cargo.lock`'s dependency graph — confirmed by grepping for
      `native-tls`/`rustls-tls` there. A `rediss://` URL in
      [`ValkeyStateDbConfig`](src/core/policy/threshold.rs) will fail at
      runtime; there is currently no way to encrypt the connection between
      `ai-protect` instances and the shared Valkey store carrying
      rate-limit/identity bookkeeping. For a real multi-instance HA
      deployment this likely fails typical enterprise in-transit-encryption
      requirements, and it isn't called out as a limitation anywhere in
      ARCHITECTURE.md's "Valkey-backed policy state" section. Fix
      direction: enable a `tls-*` feature on the `redis` dependency, thread
      an optional CA/cert config through `ValkeyStateDbConfig`, and
      document the `rediss://` scheme.
      Fixed: `Cargo.toml`'s `redis` dependency gained the
      `tokio-rustls-comp` feature (pulls in `tls-rustls`, unifying with the
      `rustls`/`tokio-rustls` versions this crate already depends on for
      LDAPS). `ValkeyStateDbConfig` gained optional `ca_file` and
      `client_cert` (`{ cert_file, key_file }`) fields, mirroring
      `UpstreamTlsConfig`'s shape for the same two cases (internal CA,
      mutual TLS). A new [`ValkeyTlsConfig`](src/core/policy/store/valkey.rs)
      carries these into `ValkeyStore::open`, which now installs the
      process-wide `rustls` crypto provider
      (`core::tls::ensure_crypto_provider`, exposed `pub(crate)` for this)
      before building a client — via plain `redis::Client::open` when no
      CA/cert override is set (a `rediss://` URL still works, validated
      against the OS trust store, exactly like an `upstream_tls` LDAPS hop
      with no `ca_file`), or `redis::Client::build_with_tls` when one is.
      Documented in ARCHITECTURE.md's "Valkey-backed policy state" section
      and `policies/ldap.example.toml`. See
      `parses_state_db_valkey_tls_config` in
      `src/core/policy/threshold.rs` and
      `open_rejects_a_client_cert_without_a_matching_key` in
      `src/core/policy/store/valkey.rs`.

## Medium

- [x] **Unbounded DN/identity string length turns the "logs never rotate"
      limitation into an attacker-controlled disk-fill lever.**
      [`audit::log_decision`](src/core/audit.rs) writes the raw
      `identity`/`target` strings into every log line with no truncation.
      ARCHITECTURE.md's "Known gaps" section already notes
      `logs/ldap.log` never rotates itself, but treats that as an
      operational concern about ordinary traffic volume. Combined with the
      lack of a length cap noted above, an attacker can inflate the disk
      fill rate on demand by repeatedly issuing actionable requests
      carrying near-16-MiB DNs. Fix direction: cap the length of
      identity/target strings actually written to log output, independent
      of (and in addition to) fixing the underlying cardinality issue
      above.
      Fixed: `audit::log_decision` now passes `identity`/`target` through a
      new `truncate_for_log` helper (cap `MAX_LOGGED_FIELD_LEN`, 512 bytes)
      before writing the log line, truncating on a UTF-8 char boundary and
      appending the original byte length. Deliberately independent of
      `connector::ldap::cap_dn`'s 256-byte DN cap — `audit` stays decoupled
      from any specific `Connector`, so it can't assume every
      implementation caps these upstream; this is the last line of defense
      regardless. See `logs_an_oversized_identity_and_target_truncated` and
      `truncate_for_log_does_not_split_a_multi_byte_char` in
      `src/core/audit.rs`.
- [ ] **`/metrics` and `/health` unauthenticated exposure needs to be a
      hard deployment requirement, not just documentation.** Both are
      correctly documented as unauthenticated by design
      ([`config.rs`](src/config.rs)'s doc comments on `MetricsConfig`/
      `HealthConfig`) and off by default, but nothing enforces that a
      deployment binds them to a private/localhost-only interface — it's
      easy to accidentally expose either on a routable address. Fix
      direction: add this as an explicit, checked item in deployment
      docs/runbooks (firewall or network-policy restriction), since the
      code itself can't enforce a network topology decision.

## Low — hardening & process

- [ ] **`Mutex::lock().unwrap()` poisoning is a single point of permanent
      failure in stateful policy/store code.** `ThresholdPolicy.history`,
      `SqliteStore.conn`, and similar shared locks all panic-and-poison on
      an internal panic while held; once poisoned, every future policy
      decision on that instance panics too, silently turning what should
      be a clean rejection into a dropped connection for the rest of the
      process's life. No live panic path is currently known (the BER
      decode/framing code is already fuzzed), but given how central these
      locks are, consider a non-poisoning mutex (e.g. `parking_lot`) as
      defense in depth.
- [ ] **Confirm `cargo audit` is currently clean.** Not independently
      verified in this review (no network install attempted); CI already
      runs it on every push/PR (`security_audit` job in
      [`ci.yaml`](.github/workflows/ci.yaml)) — confirm the latest run is
      green before sign-off. Dependency versions in `Cargo.lock` (rustls
      0.23.43, rasn 0.28.14, rusqlite 0.40.2, tokio 1.53.1) are all recent
      and no open RustSec advisory is known against them as of this
      review, but that wasn't independently re-checked here.
- [ ] **Encryption and persistent state are opt-in, not enforced.** TLS/mTLS
      on both hops and `state_db` persistence are fully implemented but
      off by default — [`config.example.toml`](config.example.toml) ships
      with both commented out. Nothing in the code stops a deployment from
      running fully plaintext/unauthenticated end-to-end, or as a single
      replica with in-memory-only policy state that resets on every
      restart. These need to be explicit go-live checklist items for any
      real deployment, not just available features.
