# Enterprise deployment TODO

A gap list from a full security review (2026-09-06) of the current state
(see [ARCHITECTURE.md](ARCHITECTURE.md)). This pass re-confirmed the
previous rounds of hardening are still in place and working as documented
— frame-size/DN-length caps, connection limits/timeouts, mTLS, StartTLS,
graceful shutdown, hot-reload, metrics, health checks, structured logging
with per-field truncation, fuzzing, bind-response correlation for
`Identity`, `max_tracked_identities` eviction, TLS for the Valkey state
store, non-poisoning `parking_lot` mutexes on every hot shared lock, and a
clean `cargo audit` (1239 advisories checked, 256 crates, no hits) — none
of that is re-litigated below. Grouped by severity; within a group,
roughly in the order you'd want to tackle them.

## Critical — policy bypass & resource exhaustion

- [x] **Unbounded per-connection bind-claim map allows a single connection
      to exhaust process memory.** `BindState.pending`
      (`StdMutex<HashMap<u32, String>>`, [src/proxy.rs:362](src/proxy.rs))
      is populated by `handle_client_frame` every time
      `Connector::bind_request` recognizes a simple `BindRequest`
      ([src/proxy.rs:445-447](src/proxy.rs)), and only ever drained by
      `resolve_pending_bind` when the correlated `BindResponse` arrives
      from the upstream ([src/proxy.rs:387-402](src/proxy.rs)). Nothing
      caps how many distinct message IDs one connection can have staged at
      once. The client and upstream relay directions run independently
      (`tokio::select!` in `handle_connection`), so `ai-protect`'s own
      insert rate is bounded only by how fast one TCP connection can
      deliver bytes — not by how fast the real directory answers binds,
      which is often deliberately slow (password hashing, lockout
      checks). A single pre-authenticated client — reaching `decode`/
      `bind_request` requires no valid credentials at all — can pipeline
      BindRequests continuously without ever reading a response and grow
      this map without bound on one connection, unconstrained by
      `max_connections`, `io_timeout` (a per-op/idle timeout, not a
      connection-lifetime cap), or `max_tracked_identities` (which only
      bounds `ThresholdPolicy`'s history map, a completely separate
      structure). An OOM here takes down every `[[proxy]]` entry in the
      process, not just the offending connection — a full availability
      outage of whatever directory traffic depends on this proxy being up.
      Fix direction: cap `pending`'s size per connection (e.g. drop the
      oldest unresolved claim, or close the connection once a threshold of
      outstanding, unresolved binds is reached).
      Fixed: `handle_client_frame` now stages every claim through a new
      `stage_pending_bind` helper ([src/proxy.rs](src/proxy.rs)) instead of
      inserting directly. Once `pending` reaches a new `MAX_PENDING_BINDS`
      constant (1024) and a genuinely new message ID arrives, it evicts the
      oldest (smallest) message ID first — logged at `warn` — capping
      per-connection memory regardless of how many `BindRequest`s a client
      pipelines without ever reading a response; re-staging under a
      message ID already pending overwrites in place without evicting
      anything. Never triggers in ordinary use, since a well-behaved
      client's claims are drained promptly by `resolve_pending_bind`. See
      `stage_pending_bind_evicts_oldest_message_id_once_at_capacity` and
      `stage_pending_bind_restaging_an_existing_id_does_not_evict` in
      `src/proxy.rs`.
- [x] **`ModifyDNRequest` (RFC 4511 §4.9 — rename/move) is not decoded or
      policed at all.** `LdapConnector::decode`
      ([src/connector/ldap.rs:209-284](src/connector/ldap.rs)) matches
      `ModifyRequest`, `DelRequest`, `AddRequest`, and the Password-Modify
      `ExtendedReq`; every other `ProtocolOp` — including
      `ProtocolOp::ModDnRequest(ModifyDnRequest)`, which `rasn_ldap` fully
      models — falls through the wildcard `_ => Ok(None)` at line 282 and
      is forwarded byte-for-byte, unlogged and unthrottled, exactly like a
      read-only `SearchRequest`/`CompareRequest`. `docs/LDAP.md:27`
      candidly lists "modify-DN" alongside those read-only operations as
      passing through untouched, without flagging it as a residual gap.
      ModifyDN achieves several of the exact outcomes this proxy exists to
      police: moving an account into a "Disabled Users"/quarantine OU is a
      standard Active Directory account-disable workflow, functionally
      equivalent to the `AccountLock` action this proxy already recognizes
      via `userAccountControl`; a bulk rename/relocation can break
      identity lookups for downstream automation as effectively as a bulk
      delete. Because `decode` returns `None`, none of it reaches
      `evaluate_all`, `audit::log_decision`, or the Prometheus counters —
      a bulk ModifyDN campaign leaves zero trace in the one place this
      proxy is supposed to guarantee visibility into. Fix direction:
      decode `ProtocolOp::ModDnRequest` into an `Action` unconditionally
      (a new `OperationKind`, e.g. `Rename`), the same way `Delete`/
      `Create` are handled today — no cheap way to filter "account-like"
      without querying the directory — and add the matching
      `ModifyDnResponse` case to `build_rejection`.
      Fixed: `LdapConnector::decode` ([src/connector/ldap.rs](src/connector/ldap.rs))
      now matches `ProtocolOp::ModDnRequest` unconditionally, the same way
      `DelRequest`/`AddRequest` are handled, producing an `Action` with a
      new `OperationKind::Rename` ([src/core/action.rs](src/core/action.rs))
      and `target` set to the entry's current DN (its post-move name isn't
      known to the proxy, matching how `Delete`/`Create` report the acted-on
      DN). `build_rejection` gained the matching `ModDnResponse` case so a
      blocked rename gets a well-formed `UnwillingToPerform` response
      instead of the request reaching the real directory. `Rename` is also
      wired into `metrics::operation_label` and `docs/LDAP.md`/
      `ARCHITECTURE.md`/`AGENTS.md`/`CLAUDE.md` no longer describe
      modify-DN as an untouched pass-through. See
      `decodes_mod_dn_request_as_rename_action_unconditionally` and
      `build_rejection_for_mod_dn_request_returns_mod_dn_response` in
      `src/connector/ldap.rs`.

## Medium

- [x] **Bulk *unlocking* via a `Delete`-type change to a lock attribute is
      not policed.** The `touches_lock_attribute` closure in
      `LdapConnector::decode`
      ([src/connector/ldap.rs:217-223](src/connector/ldap.rs)) only
      matches `ChangeOperation::Add | ChangeOperation::Replace`; a
      `ChangeOperation::Delete` against the same attribute
      (`pwdAccountLockedTime`, `nsAccountLock`, ...) — which, per the
      code's own comment, "just clears them back to the schema default" —
      is never flagged, at any volume or rate. The asymmetry is reasonable
      for the original threat model (a script *disabling* too many
      accounts), but it leaves the mirror image — mass-*reactivating*
      previously-locked/disabled accounts (e.g. stripping lockout state to
      keep a credential-stuffing run alive against a target set, or
      reviving a batch of dormant/compromised accounts) — completely
      outside policy, blast-radius accounting, and the audit trail, even
      though it's arguably just as security-relevant as the direction this
      proxy already catches. Fix direction: decide deliberately whether a
      `Delete` against a `LOCK_ATTRIBUTES` entry should also produce an
      `Action` (perhaps a distinct `OperationKind::AccountUnlock`, since
      "4 unlocks" and "4 locks" may warrant different limits) rather than
      leaving it as an unexamined side effect of the current filter.
      Fixed: `LdapConnector::decode` ([src/connector/ldap.rs](src/connector/ldap.rs))
      now checks a `ModifyRequest`'s changes against `LOCK_ATTRIBUTES` for
      `Add`/`Replace` (producing `OperationKind::AccountLock`, unchanged)
      and separately for `Delete` (producing a new
      `OperationKind::AccountUnlock`, [src/core/action.rs](src/core/action.rs)),
      so mass-clearing a lock attribute back to its schema default is now
      decoded, policed, and audited exactly like setting one — a `Delete`
      is never silently treated as a no-op the way it was before. Since
      `ThresholdPolicy` polices by `Action` generically rather than by
      operation kind, both are already covered by volume under the
      existing per-identity/global threshold with no policy-engine change
      needed; a deployment wanting a distinct limit for unlocks vs. locks
      would still need `PolicyContext`/config to gain matching on
      `OperationKind`, which remains future work. `AccountUnlock` is wired
      into `metrics::operation_label`, and `docs/LDAP.md`/`ARCHITECTURE.md`/
      `AGENTS.md`/`CLAUDE.md` no longer describe a lock-attribute delete as
      unexamined. See `decodes_lock_attribute_delete_as_account_unlock_action`
      in `src/connector/ldap.rs`.
- [x] **SASL-bound connections never get identity upgraded from source
      IP, likely covering most real traffic on this project's flagship
      target directory.** `LdapConnector::bind_request`
      ([src/connector/ldap.rs:300-310](src/connector/ldap.rs)) returns
      `None` for any `BindRequest` whose `authentication` isn't
      `AuthenticationChoice::Simple` — correctly, since a SASL `name`
      field isn't password-verified the way a simple bind's DN is (see the
      `bind_request_ignores_sasl_bind` test). `Identity` therefore stays
      `ip:<addr>` for the connection's whole lifetime. Active Directory —
      one of the three directories `LOCK_ATTRIBUTES` explicitly targets —
      overwhelmingly uses SASL/GSSAPI (Kerberos) binds for both
      interactive and service-account LDAP traffic in a typical enterprise
      deployment, not simple DN+password binds. In such an environment,
      the bind-verification/per-identity-budget machinery this project
      already invested two Critical-severity fixes in
      (`BindState`/`resolve_pending_bind`/`Identity::from_bind_dn`) may see
      little real traffic to act on: every distinct Kerberos-authenticated
      principal calling through a shared egress (a jump box, a container
      host, a NAT gateway — exactly the shared-egress "AI agent" shape this
      project's own README motivates itself with) is still pooled into one
      `ip:`-keyed `PerIdentity` budget, quietly reintroducing the
      shared-budget problem DN-based identity was built to solve. This
      doesn't let an attacker exceed the aggregate IP-scoped cap, but it
      does mean distinct legitimate principals can false-positive-block
      each other, and a compromised principal's actions are attributed
      only to a shared IP in the audit trail, not to the principal
      responsible. Fix direction: SASL/Kerberos identity isn't carried in
      the LDAP protocol itself in a form a passive proxy can verify
      without GSS-API/keytab integration, so this is unlikely to be a
      quick code fix — but ARCHITECTURE.md/`docs/LDAP.md` should say
      explicitly how much of real-world AD traffic "anonymous binds and
      SASL binds leave the current identity unchanged" actually covers,
      so it's weighed when sizing the `Global` backstop for a
      Kerberos-heavy deployment.
      Fixed: no code change (a passive proxy genuinely can't verify a SASL
      principal without GSS-API/keytab integration, as the fix direction
      notes), but [ARCHITECTURE.md#identity](ARCHITECTURE.md#identity) and
      [docs/LDAP.md](docs/LDAP.md) now say explicitly, in the Identity
      section itself rather than only in a limitations footnote, that AD
      deployments predominantly use SASL/GSSAPI (Kerberos) rather than
      simple binds, so most real AD traffic is expected to stay on
      address-based identity for its whole connection lifetime — pooling
      distinct Kerberos principals behind a shared egress into one
      `PerIdentity` budget and one audit identity — and that sizing a
      `scope = "global"` backstop matters more, not less, in a
      Kerberos-heavy deployment. This also brought `docs/LDAP.md`'s
      "Identity" and "Known limitations" sections (previously describing
      the pre-bind-correlation, no-`Global`-backstop behavior) up to date
      with the mechanics `ARCHITECTURE.md#identity` already documented
      accurately, resolving the doc-staleness item below as a side effect.
- [x] **The hand-rolled `/healthz`/`/readyz` listener has none of the
      per-connection hardening the main proxy path relies on.**
      `core::health::serve`/`handle_connection`
      ([src/core/health.rs:63-103](src/core/health.rs)) hands every
      accepted connection to an unsupervised `tokio::spawn`, and
      `handle_connection`'s single `stream.read(&mut buf).await?` has no
      timeout at all. Contrast with `proxy::serve`/`ConnectionLimits`
      ([src/proxy.rs:41-65](src/proxy.rs),
      [132-231](src/proxy.rs)), which caps concurrent connections with a
      `Semaphore` and races every read/write against `io_timeout`
      specifically to stop a slow-loris client or hung peer from pinning a
      task indefinitely. Docs correctly say `/healthz`/`/metrics` must be
      network-isolated since "nothing here authenticates" requests
      (`config.rs` doc comments, INSTALLATION.md's deployment checklist),
      but the code itself doesn't apply the same defense-in-depth here
      that it applies everywhere else. Anyone who *can* reach this port (a
      misconfigured network policy, a compromised host on the
      orchestrator's segment) can open connections that never send a byte,
      each parked forever in its own task, with no cap on how many
      accumulate. Fix direction: wrap `handle_connection`'s read in a
      short fixed timeout (probes are always fast, local callers) and
      consider a small connection cap, mirroring `ConnectionLimits` at a
      scale appropriate for a probe endpoint.
      Fixed: `core::health::serve` ([src/core/health.rs](src/core/health.rs))
      now guards accepted connections with a `Semaphore`-backed
      `MAX_CONNECTIONS` (64, `try_acquire_owned`, mirroring
      `proxy::serve`'s `ConnectionLimits` pattern at a scale appropriate for
      a probe endpoint) — a connection over the cap is closed immediately
      instead of handed to an unsupervised `tokio::spawn`. `handle_connection`
      now races its single read against a fixed `READ_TIMEOUT` (5s, not
      exposed as config since a probe is always a short-lived local caller
      unlike the main proxy path's tunable `io_timeout`), so a connection
      that never sends a byte no longer pins its task forever. See
      `connections_beyond_the_cap_are_closed_immediately` and
      `handle_connection_times_out_when_client_sends_nothing` in
      `src/core/health.rs`.

## Low — hardening & process

- [x] **`docs/LDAP.md` documents the pre-fix, more-vulnerable
      bind-verification behavior as current.** `docs/LDAP.md:148-159`
      ("**Important caveat:** `ai-protect` does not correlate the bind
      request against its response — identity switches to the claimed DN
      as soon as the `BindRequest` is seen...") and `:202-208` ("There is
      currently no global, identity-independent cap as a backstop against
      this.") both describe exactly the bypass the "blast-radius policy
      can be bypassed by identity churn" item earlier in this file's own
      history closed: `BindState`/`resolve_pending_bind` now correlate
      request and response by message ID and only promote `Identity` on
      confirmed success (see `unverified_bind_does_not_change_identity_or_reset_budget`
      in [src/proxy.rs](src/proxy.rs)), and `ThresholdScope::Global`
      (`src/core/policy/threshold.rs`) now provides exactly the global
      backstop the doc says doesn't exist — both accurately described in
      [ARCHITECTURE.md#identity](ARCHITECTURE.md#identity). This is a
      documentation-integrity issue, not a code vulnerability, but a
      security-relevant one: `docs/LDAP.md` explicitly tells readers to
      consult its "Known limitations" section before "relying on
      `ai-protect` as a hard security boundary," and currently tells them
      there's an open bypass with no mitigation when both have shipped.
      Left uncorrected, it either erodes trust in a control that's
      actually in place, or risks a future change reintroducing the
      bypass because the doc never recorded that it needed to stay fixed.
      Fix direction: update `docs/LDAP.md`'s "Identity" and "Known
      limitations" sections to match `ARCHITECTURE.md#identity`'s current
      description (bind-response correlation, `Global`-scope backstop; the
      remaining known gap is *how many* distinct identities a caller can
      churn through, not whether one claim gets verified).
      Fixed: as part of documenting SASL/Kerberos identity coverage (see
      the Medium-severity SASL item above), `docs/LDAP.md`'s "Identity" and
      "Known limitations" sections were rewritten to describe current
      behavior — bind-request/response correlation by message ID with
      promotion only on confirmed success, and `scope = "global"` as the
      documented backstop against identity churn via distinct real DNs —
      instead of the pre-fix, no-correlation/no-backstop behavior they
      previously described.
- [x] **The `Global`-scope backstop policy is off by default and only
      ever shown commented out.** `policies/ldap.example.toml`'s only
      `scope = "global"` entry is commented out under "Recommended: a
      second threshold entry..."; `docs/INSTALLATION.md`'s "Production
      deployment checklist" (which already has checked items for turning
      on TLS and deciding `state_db` persistence deliberately) has no
      equivalent item for this. A deployment that follows the documented
      "copy the example, adjust the numbers" flow
      ([INSTALLATION.md#configuring](docs/INSTALLATION.md)) ships with only
      a `PerIdentity` threshold, inheriting the full "identity churn
      defeats a per-identity-only budget" exposure this project has
      already spent real effort closing the *mechanics* for — the
      mechanism exists and is tested, but nothing in the go-live path
      prompts an operator to actually turn it on. Same class of gap as
      "Encryption and persistent state are opt-in, not enforced" (already
      addressed the same way for TLS/`state_db`). Fix direction: add a
      third checked item to `docs/INSTALLATION.md`'s "Production
      deployment checklist" for enabling a `scope = "global"` backstop
      entry sized well above expected legitimate aggregate traffic.
      Fixed: `docs/INSTALLATION.md`'s "Production deployment checklist"
      gained a fourth item, "A `scope = "global"` threshold entry is
      enabled as a backstop against identity churn," alongside the
      existing TLS and `state_db` items — it explains that
      `policies/ldap.example.toml` ships the entry commented out, why a
      `PerIdentity`-only budget is exposed to identity churn (linking
      `ARCHITECTURE.md#identity` and `docs/LDAP.md`'s Identity section for
      the Kerberos-heavy case), and directs the operator to uncomment the
      second `[[policy]]` entry and size `max_per_window` above expected
      legitimate aggregate traffic. No code or example-config change: the
      gap was a go-live prompt missing from the documented checklist, not
      a default in the shipped example that itself needed changing.
