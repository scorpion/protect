# Enterprise deployment TODO

A gap list from a full security review (2026-09-08) of the current state
(commit `d562d35`, see [ARCHITECTURE.md](ARCHITECTURE.md)). This pass read
every module under `src/` end to end — connection handling and StartTLS
upgrade (`src/proxy.rs`), BER framing/decoding and bind-response
correlation (`src/connector/ldap.rs`), the policy engine, its threshold
logic, and both `state_db` backends (`src/core/policy/**`), the upstream
load-balancing pool (`src/core/upstream_pool.rs`), identity derivation
(`src/core/identity.rs`), TLS/mTLS setup (`src/core/tls.rs`), audit
logging, metrics, health, config parsing, and the top-level `run`/
`run_with_config`/`ProxyBuilder` entry points — plus the fuzz targets,
`docker/*/Dockerfile`, `compose.yaml`, `setup.sh`, `test.sh`, `soak.sh`,
and example configs. `cargo test` (165 passed, 4 ignored — those need a
live Valkey server) ran clean at the reviewed commit.

The prior review round (see git history) is not re-litigated here: frame-
size/DN-length caps, `MAX_PENDING_BINDS` eviction, the O(log n)
`max_tracked_identities` eviction index, bind-response correlation before
`Identity` is ever promoted, bind-DN case-folding, the `state_db`
merge-race fix, the numeric-OID/attribute-option-aware `LOCK_ATTRIBUTES`
match, `ModifyDNRequest` policing, the per-operation-kind budget filter,
Valkey credential handling (`redact_valkey_url`, separate
`username`/`password` fields), and `setup.sh`'s `-y <passwordfile>`/
`chmod 600 config.toml policies/ldap.toml` fixes all held up under this
pass. No `unsafe` code exists anywhere in the crate, and — outside test
code — the only `.unwrap()`/`.expect()` calls left are two OS
signal-handler installs in `src/lib.rs` (fail only if the platform doesn't
support the signal, not attacker-reachable) and one in
`LdapConnector::connect_upstream` guarded by an invariant `UpstreamPool`
enforces at construction (never an empty target list). SQL access in
`SqliteStore` is fully parameterized (`rusqlite::params!`); nothing here
is command- or SQL-injectable via an attacker-controlled bind DN.

The architectural tradeoffs already tracked in
[ARCHITECTURE.md "Known gaps"](ARCHITECTURE.md#known-gaps-by-design-at-this-stage)
still apply and aren't repeated here. Grouped by severity; within a group,
roughly in the order you'd want to tackle them.

## Medium — Valkey `state_db` sync can silently undercount a shared window across HA instances

- [ ] **`ValkeyStore::sync`'s per-event member string is only unique within
      one process's own lifetime, not across the multiple instances the
      Valkey backend exists to support** —
      [src/core/policy/store/valkey.rs:210-218](src/core/policy/store/valkey.rs):
      ```rust
      for (identity, timestamp_millis) in new_events {
          let member = format!(
              "{timestamp_millis}-{}",
              self.member_seq.fetch_add(1, Ordering::Relaxed)
          );
          pipe.zadd(self.history_key(identity), member, *timestamp_millis)
              .ignore();
      }
      ```
      `member_seq` ([src/core/policy/store/valkey.rs:76](src/core/policy/store/valkey.rs))
      is an `AtomicU64` that starts at `0` every time a `ValkeyStore` is
      constructed — i.e. on every process start, once per instance. Its
      own doc comment explains what it's *for*: disambiguating several
      events for the same identity landing in the same sorted set at an
      identical score within one `sync` call (a single request with
      `blast_radius` > 1), since a Redis/Valkey sorted set dedupes by
      *member*, not score. It does not — and given how it's seeded, cannot
      — disambiguate across two different `ai-protect` instances pointed
      at the same backend and `key_prefix`, which is exactly the
      multi-instance HA deployment this store exists for (see
      ARCHITECTURE.md "Valkey-backed policy state"). Two instances each
      admitting an action for the *same* identity within the *same*
      millisecond will, whenever their independent per-process counters
      happen to be at the same value (highly likely repeatedly over time
      in a symmetric-traffic HA pair, and closer to guaranteed for both
      instances' very first Valkey-backed admission right after a
      simultaneous rollout/restart), produce the identical member string.
      `ZADD` on an already-present member with an unchanged score is a
      silent no-op: the second instance's event never becomes a distinct
      element in the sorted set, so a `ZCARD`/`ZRANGE` read-back
      undercounts that identity's true admitted total. The failure mode is
      silent — `pipe.zadd(...).ignore()` discards the per-command reply,
      and no error surfaces anywhere.

      The practical consequence: the whole point of pointing multiple
      instances at one Valkey backend is a shared budget an attacker can't
      evade by hitting a different instance behind a load balancer (see
      "Global scope" and the HA deployment note in ARCHITECTURE.md) — this
      gap means a caller landing on two different instances at the right
      moment gets one of those two admissions "for free," undercounting
      exactly the quantity (`max_per_window`) the shared backend exists to
      enforce correctly. `SqliteStore` doesn't share this problem: its
      `INSERT` has no uniqueness constraint at all, so every admitted event
      becomes its own row regardless of which instance or millisecond wrote
      it ([src/core/policy/store/sqlite.rs:65-70](src/core/policy/store/sqlite.rs)).

      Fix: derive `member` from something unique per *instance*, not per
      *process lifetime* — e.g. a random UUID generated once in
      `ValkeyStore::open` (stored alongside `member_seq`) prefixed onto the
      counter, or replace the counter entirely with
      `uuid::Uuid::new_v4()` per event. Either removes the cross-instance
      collision window without changing the sorted-set schema (`score`
      stays the timestamp; only `member`'s uniqueness guarantee changes).

## Low — a `state_db` SQLite file is created with the process umask's default permissions, not restricted like `config.toml`/`policies/ldap.toml`

- [ ] **`SqliteStore::open` never tightens the permissions of the database
      file it creates** —
      [src/core/policy/store/sqlite.rs:23-38](src/core/policy/store/sqlite.rs):
      `Connection::open(path)` creates the file (if it doesn't already
      exist) with whatever the process's umask leaves it at — commonly
      `0644` (world-readable) under a typical `022` umask, the same
      default `setup.sh` was fixed to stop leaving `config.toml`/
      `policies/ldap.toml` at
      ([setup.sh:588-592](setup.sh)). That fix only reaches a SQLite
      `state_db` file `setup.sh` finds *already existing* at the path it's
      about to write into config
      ([setup.sh:599-601](setup.sh)) — the common case is the opposite
      order: `setup.sh` writes `state_db = "db.sqlite"` into
      `policies/ldap.toml` for a path that doesn't exist yet, and the file
      is actually created later, by the running `ai-protect` process
      itself, via this code path, with no chmod anywhere in it.

      The file isn't a credential store, but it does hold every tracked
      identity's raw history: bind DNs (or peer IPs) and the timestamps of
      their recent admitted lock/unlock/delete/create/rename/
      password-reset actions — exactly the kind of operational/audit
      metadata (who is acting on the directory, how recently, how often)
      an operator would not want group/world-readable on a shared host.
      Neither ARCHITECTURE.md's "SQLite-backed policy state" section nor
      any file under `docs/` mentions restricting this file's permissions,
      so nothing currently tells an operator to do it by hand either.

      Fix: after `Connection::open` succeeds, `chmod` the file to `0600`
      on Unix (`std::os::unix::fs::PermissionsExt`), mirroring what
      `setup.sh` now does for `config.toml`/`policies/ldap.toml` — cheap,
      and closes the gap regardless of which order file creation and
      `setup.sh` happen to run in.

## Low — `test.sh`/`soak.sh` still pass the upstream bind password via argv, the exact pattern just fixed in `setup.sh`

- [ ] **Every `ldapsearch`/`ldapmodify`/`ldapwhoami`/`ldappasswd`/
      `ldapdelete`/`ldapadd` invocation in `test.sh` and `soak.sh` passes
      `$LLDAP_LDAP_USER_PASS` via `-w` on the command line** — e.g.
      [test.sh:46](test.sh), [test.sh:146](test.sh), [test.sh:186](test.sh),
      [test.sh:261](test.sh), [test.sh:267](test.sh), [test.sh:269](test.sh),
      [test.sh:277](test.sh), [test.sh:279](test.sh), and the equivalent
      calls in [soak.sh:63](soak.sh), [soak.sh:239](soak.sh),
      [soak.sh:359](soak.sh), [soak.sh:369](soak.sh),
      [soak.sh:494](soak.sh). This is the identical exposure the last
      review round fixed in `setup.sh`'s `try_rootdse()` (commit
      `d562d35`, "Fix: setup.sh"): a command-line argument sits in
      `ps -ef`/`/proc/<pid>/cmdline` (and, on some systems,
      process-accounting/audit logs) for the life of the `ldap*` process,
      visible to any other local account on the same machine — the fix at
      the time was scoped to `setup.sh`'s two call sites specifically and
      never extended to these two scripts, which use the same credential
      the same way.

      Lower severity than the original finding: `LLDAP_LDAP_USER_PASS` is
      explicitly a local/CI test-fixture credential for the bundled lldap
      container (`.env.example`'s own comment: "Secrets for the local test
      lldap directory"), not a production directory credential, and both
      scripts are developer/CI tooling rather than something a deployed
      instance runs. Still worth closing for the same reason the original
      fix was: a shared dev box or self-hosted CI runner with other local
      users is exactly the threat model `-w` on argv is unsafe under, and
      leaving two of the three password-bearing scripts unfixed after
      explicitly fixing the third is an easy inconsistency to miss in
      review.

      Fix: same as the `setup.sh` fix — swap every `-w "$LLDAP_LDAP_USER_PASS"`
      for `-y <(printf '%s' "$LLDAP_LDAP_USER_PASS")` (bash process
      substitution, no argv exposure, no plaintext temp file).

These are all narrow, tooling/HA-deployment-specific issues — none affects
`ai-protect`'s own core request-handling path (`src/proxy.rs`,
`src/connector/ldap.rs`, single-instance `ThresholdPolicy`/`SqliteStore`
usage), which remains as hardened as the prior review found it.

# Correctness/logic review (2026-09-08, same day, commit `d562d35`)

A second pass over the same commit, this time hunting for correctness and
logic bugs rather than exploitability — race conditions, incorrect state
transitions, arithmetic edge cases, and error-handling gaps that produce
wrong behavior even absent an adversary. Two of the three findings below
were verified against actual compiled behavior, not just read from the
source (see each item). `cargo test` still passes clean (165/165, 4
ignored) at this commit — none of these are caught by the existing suite.

## High — unchecked `i64` subtraction in `Anchor::to_instant` panics (debug) or silently corrupts data (release) on an extreme `state_db` timestamp

- [ ] **`epoch_millis - self.epoch_millis` in `Anchor::to_instant` has no
      overflow protection**, unlike its sibling `to_epoch_millis`, which
      only ever operates on locally-generated `Instant`s —
      [src/core/policy/store/mod.rs:63-72](src/core/policy/store/mod.rs):
      ```rust
      pub fn to_instant(&self, epoch_millis: i64) -> Option<std::time::Instant> {
          let delta_millis = epoch_millis - self.epoch_millis;
          ...
      ```
      `epoch_millis` here is *externally supplied* — it's whatever
      `HistoryStore::sync` read back from `state_db`
      (`rows_into_history`/`merge_history_from_rows` in
      [src/core/policy/threshold.rs](src/core/policy/threshold.rs) both
      call this directly on every row). For `ValkeyStore`, that value
      started life as an `f64` sorted-set *score* — Valkey/Redis stores
      `ZADD` scores as IEEE-754 doubles regardless of what integer type the
      client sent — and Rust's `f64 as i64` cast is *saturating*, not
      checked: a score of `-inf` (or any very large-magnitude negative
      float) reads back as exactly `i64::MIN`.

      Verified independently of the source reading (compiled and ran the
      exact expression, not just inspected it): with `self.epoch_millis`
      at a realistic "now" (~1.7×10¹²) and `epoch_millis = i64::MIN`,
      `epoch_millis - self.epoch_millis` **panics with "attempt to subtract
      with overflow" under `debug-assertions` (`cargo test`, `cargo run`
      without `--release` — literally the commands CLAUDE.md tells a
      developer to use)**, and **silently wraps to a meaningless value
      under this crate's actual `[profile.release]`** (no
      `overflow-checks` override in `Cargo.toml`, so it's off in release
      like any default Rust binary).

      Concretely reachable with nothing more than `redis-cli` against an
      unauthenticated (or credential-guessed) Valkey `state_db` — already
      flagged in ARCHITECTURE.md as requiring `requirepass`/ACLs, but that
      note focuses on forging/erasing rate-limit rows, not on this crash/
      corruption path:
      ```
      ZADD ai_protect:threshold:history:dn=someone,dc=example,dc=com -inf poison
      ```
      The next `sync_once` tick (default every 2s) on *every* instance
      sharing that backend reads this row back. In a debug build the
      background sync task panics — tokio silently drops a panicking
      spawned task rather than crashing the process, so this manifests as
      that `ThresholdPolicy`'s Valkey sync going dead permanently and
      quietly (no more cross-instance sharing, no more persistence,
      no log line explaining why). In a release build there's no panic,
      but `checked_add`/`checked_sub` a few lines down operate on garbage
      input, so the resulting `Option<Instant>` (and therefore whether
      that poisoned row counts toward — or silently vanishes from — the
      affected identity's window) is undefined by design intent, not by
      any deliberate fallback.

      Fix: use `checked_sub`/`saturating_sub` for `delta_millis` itself
      (it's just an `i64`, not yet the `Instant` arithmetic that's already
      checked further down), treating an out-of-range result the same way
      an out-of-range `checked_add`/`checked_sub` on the `Instant` already
      is — `None`, i.e. "too old/invalid, drop it." Consider also clamping
      or rejecting scores outside a sane epoch-millis range when reading
      them back in `ValkeyStore::sync`, so a single garbage row can't reach
      this function at all.

## Medium — no flush-on-shutdown or flush-on-reload for `ThresholdPolicy`'s pending `state_db` writes

- [ ] **`sync_once` — the only thing that ever writes admitted actions to
      `state_db` — is exclusively driven by the periodic background
      timer** ([src/core/policy/threshold.rs:451-466](src/core/policy/threshold.rs)):
      ```rust
      pub fn spawn_background_sync(self: Arc<Self>) {
          ...
          tokio::spawn(async move {
              let mut interval = tokio::time::interval(flush_interval);
              loop {
                  interval.tick().await;
                  let Some(policy) = weak.upgrade() else { break };
                  policy.sync_once().await;
              }
          });
      }
      ```
      Confirmed by grep across the whole crate: `sync_once` has exactly
      one non-test caller, this loop. Neither `run_with_config`'s shutdown
      path (`proxy::serve`'s connection-drain logic, the
      `shutdown_tx.send(true)` task) nor `reload_policies_on_signal`'s
      `SIGHUP` handling ever calls it. Two distinct real-world sequences
      lose data as a result:

      1. **Graceful shutdown** (`SIGTERM`/`SIGINT`, the exact mechanism
         ARCHITECTURE.md's "Graceful shutdown" section describes as
         existing so a rolling restart "doesn't hard-cut" anything):
         connections finish draining, the process exits, and whatever was
         admitted since the *last* `flush_interval` tick (default every
         2s, so up to ~2s of the most recent traffic) was only ever in the
         dying `ThresholdPolicy`'s in-memory `pending` buffer — it's never
         written to `state_db` and is gone. This directly undercuts the
         one guarantee `state_db` exists to provide ("history survives a
         restart," ARCHITECTURE.md "SQLite-backed policy state") for
         precisely its most recent — and often most operationally
         relevant — slice: a deploy triggered *because* of a burst of
         blocked activity restarts with that burst's tail no longer
         reflected in persisted history.
      2. **Policy hot-reload** (`SIGHUP`): the *old* `ThresholdPolicy`
         instance stays alive only as long as some pre-reload connection
         still references it; once the last one closes, its background
         task's next `weak.upgrade()` fails and the loop exits — with no
         guaranteed final `sync_once()` in between. Any actions admitted
         under the old policy after its last successful flush and before
         that last connection closes are lost the same way.

      Neither failure mode is logged or surfaced anywhere — from the
      operator's perspective, history "just" silently doesn't cover the
      last couple of seconds before a restart/reload, indistinguishable
      from an ordinary window boundary.

      Fix: give `ThresholdPolicy` an explicit `flush()`/`shutdown()` that
      calls `sync_once()` once, synchronously, and wire it into (a)
      `run_with_config`'s shutdown sequence — after connections finish
      draining but before the process exits, for every policy that has a
      `state_db` — and (b) `reload_policies_on_signal`, on the *old*
      policy list, right before (or instead of relying on) dropping it in
      favor of the newly-loaded one.

## Medium — a single transient `accept()` error takes down the entire process, not just the one connection attempt

- [ ] **`proxy::serve`'s accept loop propagates *any* error from
      `listener.accept()` straight out of the function**, ending that
      listener — and, transitively, every other `[[proxy]]` entry in the
      same process — instead of logging and continuing —
      [src/proxy.rs:147-152](src/proxy.rs):
      ```rust
      let accept_result = tokio::select! {
          () = wait_for_shutdown(&mut shutdown) => break,
          result = listener.accept() => result,
      };
      let (client_stream, peer_addr) = accept_result.map_err(ProxyError::Accept)?;
      ```
      `TcpListener::accept()` is not guaranteed to only fail in ways that
      mean "this listener is now broken" — `EMFILE`/`ENFILE` (per-process
      or system-wide file-descriptor exhaustion) and `ENOBUFS`/`ENOMEM`
      are recoverable, transient conditions that a well-behaved accept
      loop logs and continues past (the listening socket itself is still
      perfectly valid). They're also *more* likely to happen precisely
      under the high-concurrent-connection load
      `proxy::ConnectionLimits`/`max_connections` exists to handle
      gracefully, not less. As written, the very first such hiccup
      returns `Err(ProxyError::Accept(..))` from `serve`, which:
      - in `run_with_config`, reaches `tasks.join_next()`'s
        `Ok(Err(err)) => return Err(err)` arm, which drops the whole
        `JoinSet` on the way out — aborting every *other* `[[proxy]]`
        entry's accept loop and in-flight connections too (per that
        function's own doc comment: "one entry's fatal error brings down
        the whole process"). A transient fd-pressure blip on *one*
        listener takes out every directory this process fronts, not just
        the one that hit it.
      - in a `ProxyBuilder`-embedded deployment, `serve()` simply returns
        `Err`, silently ending the accept loop with no automatic recovery
        unless the embedder itself notices and restarts it.

      This is different in kind from
      ARCHITECTURE.md's already-documented "one entry's fatal error aborts
      every other entry" gap (listed under "Known gaps," in the context of
      a *genuinely* fatal error like a bind failure) — this is a routine,
      recoverable I/O condition being treated with the same blast radius
      as an unrecoverable one.

      Fix: distinguish transient accept errors (`EMFILE`, `ENFILE`,
      `ECONNABORTED`, `ENOBUFS`, `ENOMEM` — the same set Tokio's own docs
      and most production accept-loop examples call out) from the
      genuinely fatal ones. Log and `continue` on the former — optionally
      with a short backoff so a sustained fd-exhaustion condition doesn't
      spin the loop — and only propagate/return on the latter.

None of these three require an adversary to trigger in the ordinary case
(the accept-loop one is pure resource-pressure; the missing-flush one
fires on every single graceful restart); the `Anchor::to_instant` one is
the exception, requiring at least network reach to an unauthenticated/
guessed-credential Valkey `state_db` — already a documented prerequisite
for other issues in this file, not a new exposure by itself.
