# Enterprise deployment TODO

A gap list from a full security review (2026-09-06) of the current state
(see [ARCHITECTURE.md](ARCHITECTURE.md)). This pass re-confirmed the
previous rounds of hardening are still in place and working as documented
— frame-size/DN-length caps, connection limits/timeouts, mTLS, StartTLS
(both hops, with no buffered-plaintext bleed-through across the upgrade),
`MAX_PENDING_BINDS` eviction, bind-response correlation for `Identity`
(never promoted on an unverified claim), the `Global` threshold-scope
backstop, the numeric-OID/attribute-option-aware `LOCK_ATTRIBUTES` match,
bind-DN case-folding, the `sync_once` merge that no longer erases
in-flight admissions during a `state_db` round trip, graceful shutdown,
hot-reload, metrics, health checks, structured JSON audit logging
(properly escaped, not forgeable via embedded control characters),
fail-closed error handling throughout `decode`/`evaluate_all`/
`build_rejection` (no fail-open path forwards a frame after an internal
error), and a clean `cargo audit` (255 dependencies, zero advisories) —
none of that is re-litigated below. This pass instead went looking for
what those fixes might have missed, with particular attention to the
`state_db`/`max_tracked_identities` machinery those earlier fixes touched
and to the account-lock detection logic's actual semantics. Grouped by
severity; within a group, roughly in the order you'd want to tackle them.

## High — `max_tracked_identities` doesn't bound `state_db` storage

- [x] **`max_tracked_identities` caps the in-memory identity history map
      but never touches `state_db`, so a `state_db`-backed deployment's
      SQLite table or Valkey key count — and the per-cycle cost of
      scanning them — grows without the bound the code's own
      documentation promises.** `evict_stalest_until`
      ([src/core/policy/threshold.rs:406-422](src/core/policy/threshold.rs)),
      called from `evaluate`
      ([src/core/policy/threshold.rs:472-483](src/core/policy/threshold.rs))
      whenever a never-before-seen identity is admitted and the map is at
      capacity, and again from `sync_once`
      ([src/core/policy/threshold.rs:328-330](src/core/policy/threshold.rs))
      after folding in a `state_db` snapshot, only ever removes entries
      from the in-memory `history: Mutex<HashMap<Identity,
      VecDeque<Instant>>>`. It never calls into `state.store` (the
      `Arc<dyn HistoryStore>`) to delete the evicted identity's persisted
      rows — there is no such method to call. `HistoryStore`'s only
      mutating operation, `sync`
      ([src/core/policy/store/mod.rs:85-98](src/core/policy/store/mod.rs)),
      prunes strictly "anything at or older than `cutoff_epoch_millis`" —
      age-based only, with no concept of an identity-count cap. Both
      backends confirm this: `SqliteStore::blocking_sync`'s only `DELETE`
      is `WHERE timestamp_millis < ?1`
      ([src/core/policy/store/sqlite.rs:70-73](src/core/policy/store/sqlite.rs))
      against one global table with no per-identity row cap, and the
      `SELECT` that rebuilds `rows_by_identity` has no `LIMIT` and groups
      every surviving row regardless of how many distinct identities that
      is
      ([src/core/policy/store/sqlite.rs:76-77](src/core/policy/store/sqlite.rs));
      `ValkeyStore::sync` discovers every key with `SCAN
      {key_prefix}:history:*`
      ([src/core/policy/store/valkey.rs:181-199](src/core/policy/store/valkey.rs))
      and does a `ZREMRANGEBYSCORE`/`ZRANGE`/`ZCARD` round trip per key
      found
      ([src/core/policy/store/valkey.rs:201-232](src/core/policy/store/valkey.rs))
      — again with no cap on how many distinct keys that loop iterates.

      This directly contradicts an explicit, repeated promise in the
      codebase's own documentation. `ThresholdConfig::max_tracked_identities`'s
      doc comment states the default "bound[s] worst-case memory (and, if
      `state_db` is set, storage) to a fixed amount regardless of how many
      distinct identities an attacker churns through"
      ([src/core/policy/threshold.rs:140-144](src/core/policy/threshold.rs));
      [ARCHITECTURE.md](ARCHITECTURE.md#policy-blast-radius-thresholding)
      (lines 381-383) repeats it near-verbatim — "bounding memory (and
      `state_db` storage, if configured) to a fixed size"; and the
      template every deployer copies,
      [policies/ldap.example.toml:21-27](policies/ldap.example.toml),
      tells the operator setting this value that it's "bounding
      memory/state_db growth." None of that holds. Verified directly: with
      `max_tracked_identities = 2` and a SQLite `state_db`, admitting 10
      distinct identities (one action each, well under `max_per_window`)
      leaves the in-memory map correctly capped at 2 entries, but after
      one `sync_once` the SQLite file holds all 10 identities' rows — the
      in-memory cap has no effect on the store at all.

      Any deployment that enables `state_db` for durability or HA —
      arguably the higher-stakes production deployments, since that's an
      opt-in hardening step per
      [ARCHITECTURE.md](ARCHITECTURE.md#known-gaps-by-design-at-this-stage)
      — gets none of `max_tracked_identities`'s advertised protection
      against identity-churn resource exhaustion on the persisted side. An
      attacker able to present many distinct identities within one
      `window` (an owned IPv6 prefix trivially yields far more distinct
      unauthenticated `ip:`-scoped identities than the default cap; a
      multi-credential compromise yields as many `dn:`-scoped ones as DNs
      it can successfully bind as) can grow the SQLite file or the Valkey
      keyspace by one row/key per distinct identity indefinitely — bounded
      only by the `window` duration, not by any operator-configured cap —
      filling disk (SQLite) or Valkey memory, and, since every `sync_once`
      cycle (`flush_interval`, default 2s) re-fetches and re-groups every
      surviving row/key regardless of count, making each cycle
      progressively slower as the unbounded set grows, which risks the
      background sync (one round trip per key for `ValkeyStore`) falling
      permanently behind under sustained churn. An evicted identity can
      also resurrect itself: `sync_once` merges whatever the snapshot
      returns into `history` *before* re-applying `evict_stalest_until`,
      so an identity evicted from memory moments earlier is pulled
      straight back in on the very next cycle for as long as its rows are
      still sitting in the (uncapped) store.
      Fix direction: give `HistoryStore` a way to bound its own identity
      cardinality — either an explicit `delete(identity)`/`evict`
      operation `evict_stalest_until` calls for the specific identity it
      removes (threading the store handle through, which `evaluate`
      doesn't have today — only `sync_once` does), or have `sync` itself
      enforce a maximum row/key count by least-recent-activity (e.g. a
      window-function-based `DELETE` in SQL, or a maintained "last active"
      sorted set in Valkey pruned by rank rather than only by score) so it
      never returns more identities than the caller's cap regardless of
      which instance wrote them. Update the doc comment and the example
      policy file only once the guarantee actually holds, and add a test
      that churns more identities than `max_tracked_identities` through a
      `state_db`-backed policy and asserts the store's own identity count
      stays at or under the cap after a sync.
      Fixed: `HistoryStore::sync` (and `SqliteStore::sync_now`) now take a
      `max_identities` parameter, and `ThresholdPolicy` passes
      `config.max_tracked_identities` through on every call (`new`'s
      startup load and `sync_once`'s periodic flush alike). Each backend
      enforces the cap itself, ranking "least recently active" the same
      way `evict_stalest_until` already does in memory — the smallest
      per-identity *maximum* timestamp, not insertion order — so both
      agree on which identity goes first: `SqliteStore` deletes every row
      for identities ranked past the cap in one window-function `DELETE`
      (`ROW_NUMBER() OVER (ORDER BY MAX(timestamp_millis) DESC)`) inside
      the same transaction as the existing age-based prune;
      `ValkeyStore::sync` ranks the per-identity sorted sets it already
      fetched by their highest score and `DEL`s the stalest ones' keys
      past the cap. Verified directly: `state_db_caps_tracked_identity_count_after_sync`
      (`src/core/policy/threshold.rs`) churns 10 identities through a
      `max_tracked_identities = 3` SQLite-backed policy and asserts the
      file itself never holds more than 3; `sync_now_caps_distinct_identities_by_evicting_the_stalest`
      (`src/core/policy/store/sqlite.rs`) and
      `sync_caps_distinct_identities_by_evicting_the_stalest`
      (`src/core/policy/store/valkey.rs`, requires a real server, run with
      `--ignored`) cover each backend directly.

## High — eviction-scan denial of service

- [x] **Once the tracked-identity map is at capacity, every single new
      identity `evaluate()` admits or blocks pays for a full linear scan
      of the entire map while holding the one lock every connection's
      policy decisions share — an attacker who reaches that capacity can
      turn ordinary traffic into a process-wide throughput bottleneck.**
      `evict_stalest_until`
      ([src/core/policy/threshold.rs:406-422](src/core/policy/threshold.rs))
      finds the identity to remove via `history.iter().min_by_key(|(_,
      timestamps)| timestamps.back().copied())` — an O(n) walk of the
      whole `HashMap` for n = current tracked-identity count (up to
      `max_tracked_identities`, defaulting to 100,000). `evaluate`
      ([src/core/policy/threshold.rs:461-523](src/core/policy/threshold.rs))
      calls it, with `target_len = max_tracked_identities.saturating_sub(1)`,
      every time it sees a key not already in `history`
      ([src/core/policy/threshold.rs:472-483](src/core/policy/threshold.rs))
      — while holding `self.history.lock()`, the single `parking_lot::Mutex`
      shared by every `evaluate()` call this `ThresholdPolicy` instance
      ever makes, across every connection the proxy is handling (policies
      are `Arc<dyn Policy>`, shared process-wide). Once the map is at
      steady-state capacity, this isn't an occasional cost: *every*
      subsequent never-before-seen identity — including one that's about
      to be blocked, since even a blocked action creates a history entry
      per the function's own comment at line 476 — triggers exactly one
      such scan.

      Measured directly on the release profile this project ships
      (`lto=true`, `codegen-units=1`): with the map pre-filled to the
      default cap of 100,000 identities, each additional new-identity
      `evaluate()` call took ~233µs, a ceiling of ~4,300 such
      admissions/sec for the whole policy instance regardless of available
      CPU, because the work is serialized behind one lock rather than
      parallelized across cores. Reaching capacity in the first place
      needs only ordinary sequential connections, not concurrency: each
      can complete (bind or send one actionable request, get a response,
      disconnect) well inside the default 60s `io_timeout`, so 100,000
      *sequential* identities is a matter of minutes at a modest
      connection rate, not 100,000 simultaneous ones (`max_connections`
      defaults to only 1024). Reaching it does require genuine identity
      diversity, not just connection volume: an `ip:`-scoped identity
      needs a distinct source address per identity (trivial to obtain in
      volume from an owned IPv6 allocation — a single /64 or /48, routine
      from most cloud/VPS providers, yields vastly more addresses than the
      default cap — or from a botnet; one fixed source address only ever
      occupies one `ip:`-scoped identity), while a `dn:`-scoped identity
      needs a distinct, successfully-verified bind per identity. Once at
      capacity, an attacker sustaining new distinct identities keeps the
      shared lock busy with O(n) work on their behalf, adding latency
      (and, past the ~4,300/sec ceiling, an outright queue) to *every*
      connection's policy evaluation on the same instance — including
      legitimate traffic that never touches a new identity itself, since
      it still has to wait for the same mutex. This is a resource-
      exhaustion vector against the proxy's own availability — notable
      since blast-radius policing exists to protect the *directory's*
      availability — reachable by a caller with no valid credential at
      all, present whether or not `state_db` is configured.
      Fix direction: replace the O(n) "find the least-recently-active
      identity" scan with a structure that supports it in better than
      linear time — e.g. a secondary ordered index (a `BTreeMap<Instant,
      Identity>` keyed by last-activity, updated alongside `history`,
      giving O(log n) eviction) or an intrusive LRU (`linked-hash-map`-
      style) ordering. Alternatively, reconsider whether eviction needs
      the *exact* least-recently-active identity at all — an approximated
      victim (sampling a handful of random entries and evicting the
      stalest of those, the approach Redis's own `maxmemory` eviction
      uses) would bound the cost per admission to a small constant
      regardless of `max_tracked_identities`, at the cost of not always
      evicting the true global minimum. Add a benchmark or test asserting
      eviction cost doesn't scale with `max_tracked_identities` before
      considering this closed.
      Fixed: `ThresholdPolicy`'s history is now a small `History` type
      ([src/core/policy/threshold.rs](src/core/policy/threshold.rs)) that
      pairs the existing `HashMap<Identity, VecDeque<Instant>>` with a
      secondary `BTreeSet<(Option<Instant>, Identity)>` index
      (`by_activity`) ordered exactly the way eviction always ranked
      identities — an identity's most recent timestamp (`None` for one with
      none left, sorting first, unchanged from before). Every mutation that
      can change an identity's last-activity — admitting a request
      (`record_admitted`), creating a brand-new entry (`ensure`), or folding
      in a whole `state_db` snapshot (`set`, used by `rows_into_history`/
      `merge_history_from_rows`) — keeps both structures in sync, so
      `evict_stalest_until` now just pops `by_activity`'s first entry
      (`BTreeSet::iter().next()`, O(log n) amortized) instead of scanning
      every tracked identity to find the minimum. `evaluate` still holds one
      lock for the whole read-prune-check-write sequence — this fixes the
      cost of eviction itself, not the lock's scope — but that cost no
      longer grows with `max_tracked_identities`, so it no longer turns
      identity churn at the cap into a process-wide bottleneck. Verified
      directly: `eviction_cost_does_not_scale_with_map_size`
      (`src/core/policy/threshold.rs`) fills a policy to capacity at 1,000
      and at 20,000 identities and times admissions that each force one
      eviction, asserting the median cost at 20,000 stays within 5x of the
      cost at 1,000 — a linear scan would cost roughly 20x more, an O(log n)
      index barely moves; every existing `ThresholdPolicy`/`History` test
      (identity-cap eviction, `state_db` sync/merge/restart, per-identity
      and `Global` scope) still passes unchanged.

## Medium — `AccountLock`/`AccountUnlock` misclassification for Active Directory

- [ ] **`decode()` classifies a lock-attribute `Modify` as `AccountLock`
      or `AccountUnlock` purely from its `ChangeOperation` (`Add`/
      `Replace` vs. `Delete`), never from the value actually being
      written — for Active Directory, this project's flagship target, a
      real-world account re-enable is a `Replace` (`userAccountControl`
      is mandatory and can't be `Delete`d), so `AccountUnlock` is
      effectively unreachable in practice and every AD lock *and* unlock
      alike is logged, metriced, and (should a deployment ever split
      their limits) policed as `AccountLock`.** `decode`'s
      `ModifyRequest` arm
      ([src/connector/ldap.rs:264-292](src/connector/ldap.rs)) computes
      `operation` from the `touches_lock_attribute` closure, which checks
      only whether `change.operation` is `Add`/`Replace` (→
      `AccountLock`) or `Delete` (→ `AccountUnlock`) and whether the
      attribute name matches `LOCK_ATTRIBUTES` — `change.modification`'s
      actual value (the `SetOf<OctetString>` being written) is never
      read. For Active Directory's `userAccountControl` — a mandatory,
      single-valued bitmask attribute — both locking (setting the
      `ACCOUNTDISABLE` bit, `0x2`) *and* unlocking (clearing it) an
      account are done identically on the wire: a `Replace` with a new
      integer value. A directory won't accept a `Delete` of a mandatory
      attribute, so real AD tooling never unlocks that way. Verified
      directly: a `Replace` of `userAccountControl` to `512`
      (`NORMAL_ACCOUNT`, i.e. enabled, no disable bit set — exactly what a
      real AD re-enable sends) still decodes to `OperationKind::AccountLock`,
      identically to a `Replace` to a value with the bit set. The
      `Delete` branch that would classify it as `AccountUnlock` is, for
      AD, effectively dead code — it only fires for a directory family
      that supports removing the attribute outright to unlock (OpenLDAP's
      `pwdAccountLockedTime`, 389 DS's `nsAccountLock`), and even for
      389 DS, replacing `nsAccountLock` with `false` — a common
      alternative to deleting it — hits the same misclassification.

      `ThresholdPolicy` doesn't currently split its budget by
      `OperationKind` (every actionable `Action` counts against the same
      per-identity/global counter regardless of kind), so this doesn't
      bypass enforcement today — a mass unlock is still counted and still
      blockable. The impact is on the audit trail and the extension point
      the codebase's own documentation treats as important:
      `OperationKind::AccountUnlock`'s doc comment
      ([src/core/action.rs:4-13](src/core/action.rs)) argues mass account
      reactivation "is arguably just as security-relevant" as mass
      locking specifically *because* it "gets its own `OperationKind`
      rather than being silently ignored or folded into `AccountLock`,
      since 'N unlocks' and 'N locks' may warrant different limits" — and
      [docs/LDAP.md](docs/LDAP.md#account-lock-attributes-recognized)
      tells operators the same thing. For the primary target directory,
      that distinction silently never materializes: every AD unlock is
      indistinguishable from a lock in `audit::log_decision`'s output, in
      the `ai_protect_policy_decisions_total{operation="..."}` metric, and
      to any future policy that tries to give unlocks a different (e.g.
      stricter) limit than locks — exactly the scenario the
      `OperationKind` split was introduced for. An incident responder
      reviewing logs after a burst of account re-enables (e.g. an
      attacker restoring accounts a prior incident-response action
      disabled, to keep credential-stuffing accounts usable) would see it
      reported as a lock spree, not an unlock spree.
      Fix direction: for a `Replace`, compare the change against the
      attribute's known "locked" representation where that's cheap and
      schema-defined — e.g. for `userAccountControl`, parse the integer
      and check the `ACCOUNTDISABLE` bit rather than assuming every
      `Replace` locks; for boolean-like attributes (`nsAccountLock`),
      compare the value against `"true"`/`"false"` case-insensitively.
      Where a schema's lock representation isn't a simple bit/boolean (or
      parsing fails), fall back to the current Add/Replace-is-a-lock
      assumption rather than guessing. Add test coverage sending a
      `Replace` that clears the disable bit for each schema in
      `LOCK_ATTRIBUTES` and asserting `AccountUnlock`, alongside the
      existing OID/option-suffix coverage.
