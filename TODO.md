# Enterprise deployment TODO

A gap list from a full security review (2026-09-06) of the current state
(see [ARCHITECTURE.md](ARCHITECTURE.md)). This pass re-confirmed the
previous rounds of hardening are still in place and working as documented
— frame-size/DN-length caps, connection limits/timeouts, mTLS, StartTLS
(both hops, with no buffered-plaintext bleed-through across the upgrade),
`MAX_PENDING_BINDS` eviction, bind-response correlation for `Identity`
(never promoted on an unverified claim), the `Global` threshold-scope
backstop, `max_tracked_identities` eviction, graceful shutdown, hot-reload,
metrics, health checks, structured JSON audit logging (properly escaped,
not forgeable via embedded control characters), fail-closed error handling
throughout `decode`/`evaluate_all`/`build_rejection` (no fail-open path
forwards a frame after an internal error), and a clean `cargo audit` —
none of that is re-litigated below. This pass instead went looking for
what those fixes might have missed. Grouped by severity; within a group,
roughly in the order you'd want to tackle them.

## Critical — policy bypass

- [x] **A lock/unlock attribute named by its numeric OID (or with an
      attribute-option suffix) instead of its descriptive name completely
      bypasses `AccountLock`/`AccountUnlock` detection.** `LOCK_ATTRIBUTES`
      ([src/connector/ldap.rs:26-31](src/connector/ldap.rs)) lists four
      lowercase descriptive names
      (`pwdaccountlockedtime`/`useraccountcontrol`/`nsaccountlock`/
      `shadowexpire`), and `touches_lock_attribute`
      ([src/connector/ldap.rs:222-228](src/connector/ldap.rs)) matches a
      `ModifyRequest` `Change`'s attribute against that list via exact
      string comparison after lowercasing:
      `LOCK_ATTRIBUTES.contains(&change.modification.r#type.0.to_lowercase().as_str())`.
      Per RFC 4512, an `AttributeDescription` on the wire may legally be
      given as either its descriptive name *or* its numeric OID — a
      directory resolves both identically to the same attribute. Every
      attribute in `LOCK_ATTRIBUTES` has a well-known OID (e.g.
      `userAccountControl` → `1.2.840.113556.1.4.8` in Active Directory,
      this project's flagship target). A `ModifyRequest` whose
      `Change.modification.type` is sent as `"1.2.840.113556.1.4.8"`
      instead of `"userAccountControl"` flips `ACCOUNTDISABLE` on the real
      directory exactly as effectively as the descriptive-name form, but
      never matches `LOCK_ATTRIBUTES`, so `decode` returns `Ok(None)` and
      the request is forwarded byte-for-byte — unthrottled by
      `ThresholdPolicy` and completely absent from `audit::log_decision`
      and the Prometheus counters. The same exact-match gap also lets an
      attribute-option suffix (`userAccountControl;x-foo`, tolerated by
      some server implementations for an otherwise-unrecognized option)
      slip through. This is a complete, silent, zero-trace bypass of the
      proxy's central detection mechanism for bulk account lock/unlock —
      the exact "4 is fine, 4,000 is not" scenario this project exists to
      catch — reachable by any client that can issue a `Modify`, with no
      elevated privilege required beyond whatever the directory itself
      demands for the underlying attribute write.
      Fix direction: resolve both forms to a canonical identifier before
      the `LOCK_ATTRIBUTES` comparison — either maintain each attribute's
      known numeric OID alongside its name in the table and match either,
      or strip a leading `;`-delimited attribute-option suffix and treat a
      numeric-OID-shaped type string as an alias lookup. Consider a test
      fixture that sends the OID form of each `LOCK_ATTRIBUTES` entry and
      asserts `decode` still produces the matching `Action`.
      Fixed: `LOCK_ATTRIBUTES` ([src/connector/ldap.rs](src/connector/ldap.rs))
      is now a table of `(descriptive name, numeric OID)` pairs — each
      schema's well-known OID (e.g. `userAccountControl` →
      `1.2.840.113556.1.4.8`) alongside its name — and a new
      `is_lock_attribute` helper strips any leading `;`-delimited
      attribute-option suffix, lowercases, and matches against either form
      before `touches_lock_attribute` consults it, so an OID-spelled or
      option-suffixed `Change.modification.type` no longer bypasses
      detection. See `decodes_lock_attribute_oid_form_as_account_lock_action`
      and
      `decodes_lock_attribute_with_attribute_option_suffix_as_account_lock_action`
      in `src/connector/ldap.rs`.

## High — window-limit bypass under `state_db`

- [ ] **A `state_db`-backed `ThresholdPolicy`'s background sync can
      silently erase in-flight admissions from local history, letting
      sustained traffic exceed `max_per_window`.** `evaluate`
      ([src/core/policy/threshold.rs:457-467](src/core/policy/threshold.rs))
      admits a request by pushing timestamps into both `history` (the live
      in-memory sliding window) and `state.pending` (queued for the next
      background flush) under two separate, sequential lock sections.
      `sync_once` ([src/core/policy/threshold.rs:303-335](src/core/policy/threshold.rs)),
      which runs on every `flush_interval` tick (default 2s) whenever
      `state_db` is configured — durability alone, no multi-instance HA
      deployment required — does, in order: (1) drain `state.pending` into
      `new_events` and release the lock; (2) `.await` `state.store.sync(...)`,
      a real, unbounded-in-practice blocking SQLite call or Valkey network
      round trip performed with **no lock held**; (3) re-lock `history` and
      unconditionally *replace* (not merge) each identity's entry with
      whatever `HistoryStore::sync` returns — documented at
      [src/core/policy/store/mod.rs:85-98](src/core/policy/store/mod.rs)
      as "the authoritative, whole-store snapshot," by design so an
      instance's own events aren't double-counted against fresh copies of
      themselves arriving from the round trip. Any `evaluate` call that
      lands between step 1 and step 3 pushes into `history` (correctly
      counted for its own request) and queues into `pending` for the *next*
      cycle — but that timestamp isn't part of the snapshot fetched in
      step 2, since the snapshot only reflects events already drained at
      step 1. When step 3's replace lands, it overwrites that identity's
      whole history with the stale, smaller snapshot, discarding every
      timestamp added during the round trip. The discarded timestamps
      aren't lost forever (they're still in `pending` and get written on
      the *next* cycle), but from the moment of each merge until that next
      cycle, `history` locally undercounts the identity's true recent
      volume — and `evaluate`'s admission check reads only `history`, so
      requests landing in that undercounted window are admitted even
      though the true recent count would have blocked them. This recurs
      every `flush_interval`, for as long as the attacker keeps flooding:
      each cycle's round-trip duration is a fresh window in which some
      admitted volume gets erased and the freed-up "room" gets re-spent,
      systematically leaking throughput above `max_per_window` in direct
      proportion to (request rate) × (store round-trip latency) per cycle
      — worse for `ValkeyStore` (network RTT) than `SqliteStore` (local
      disk via `spawn_blocking`), and worse the longer the attack is
      sustained, since every cycle reopens the same window. This applies
      to both `PerIdentity` and `Global` scope alike, since `history_key`
      just selects which bucket gets replaced.
      Fix direction: don't wholesale-replace an identity's local entry
      from the fetched snapshot — union/merge the returned timestamps with
      whatever's already in `history` (dedup on exact value, since a
      timestamp round-tripped through the store is byte-identical to the
      one already in memory), so a concurrent admission between drain and
      merge is never lost; or drain `pending` *after* the store round trip
      completes rather than before, so nothing admitted during the round
      trip is missing from the next drain. Add a test that calls
      `evaluate` (pushing to `pending`) concurrently with a slow/delayed
      fake `HistoryStore::sync` and asserts the concurrently-admitted
      timestamp survives the subsequent merge.

## Medium — identity-budget dilution

- [ ] **A bind DN is used verbatim as `Identity`, with no case or
      attribute-form normalization, letting one real principal multiply
      its own `PerIdentity` threshold budget for free.** `bind_request`
      ([src/connector/ldap.rs:316-326](src/connector/ldap.rs)) returns
      `cap_dn(bind.name.0.clone())` — `cap_dn`
      ([src/connector/ldap.rs:63-75](src/connector/ldap.rs)) only bounds
      length/hashes oversized DNs, performing no case-folding or
      canonicalization — and `Identity::from_bind_dn`
      ([src/core/identity.rs:26-28](src/core/identity.rs)) wraps it as
      `format!("dn:{dn}")` verbatim. LDAP attribute type names are
      case-insensitive and may also be given by numeric OID (e.g. `cn=` vs
      `CN=` vs `2.5.4.3=`), and RDN values typically use `caseIgnoreMatch`
      — so `"cn=alice,dc=example,dc=com"`, `"CN=alice,DC=example,DC=com"`,
      and `"cn=ALICE,dc=EXAMPLE,dc=COM"` all authenticate as the exact same
      directory entry, each producing a genuine, correlated
      `BindResponse::Success` (not the already-fixed unverified-claim
      bypass — every one of these is a real, verified bind). Because the
      DN string is used verbatim, each spelling variant promotes to a
      *distinct* `Identity` and gets its own fresh, empty `ThresholdPolicy`
      `PerIdentity` history bucket. One attacker with one valid credential
      can multiply their own effective per-identity rate limit by
      reconnecting and re-binding with a different DN spelling each time —
      no privilege escalation needed, just case or attribute-form
      variance on a DN they're already entitled to use. A `scope =
      "global"` backstop entry (see `docs/INSTALLATION.md`'s deployment
      checklist) still catches the aggregate volume regardless of which
      spelling each request is attributed to, so this doesn't defeat
      policy entirely where that's enabled — but the per-identity control
      itself, and the audit trail's ability to attribute a burst to one
      consistently-named principal, are both undermined for any deployment
      relying on `PerIdentity` scope alone.
      Fix direction: normalize the DN in `bind_request` before returning
      it — at minimum, lowercase attribute type names (the part before
      each unescaped `=`) so `cn=`/`CN=`/`Cn=` collapse together; ideally
      parse-and-re-serialize to a canonical RFC 4514 form (also resolving
      an attribute type's numeric-OID form to its descriptive name or vice
      versa) so equivalent spellings always collapse to one `Identity`.
