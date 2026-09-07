# Enterprise deployment TODO

A gap list from a full security review (2026-09-07) of the current state
(commit `e6596c8`, see [ARCHITECTURE.md](ARCHITECTURE.md)). This pass read
every module under `src/` end to end — connection handling and StartTLS
upgrade (`src/proxy.rs`), BER framing/decoding and bind-response
correlation (`src/connector/ldap.rs`), the policy engine and its
`state_db` backends (`src/core/policy/**`), identity derivation
(`src/core/identity.rs`), TLS/mTLS setup (`src/core/tls.rs`), audit
logging, metrics, health, and config parsing — plus the fuzz targets,
Dockerfiles, `compose.yaml`, CI workflow, and example configs, rather than
diffing recent commits, since `TODO.md` itself had just been cleared out.
`cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
warnings`, `cargo test` (143 passed), and `cargo audit` (255 crates, no
advisories) all ran clean at the reviewed commit. The prior rounds of
hardening this codebase's history shows — frame-size/DN-length caps
(keyed, not `DefaultHasher`, hashing), connection limits/timeouts, mTLS on
both hops, StartTLS with no buffered-plaintext bleed-through (the upgrade
peek runs against the raw `TcpStream`, never a `BufReader`), bind-response
correlation before `Identity` is ever promoted, `MAX_PENDING_BINDS`
eviction, the O(log n) `max_tracked_identities` eviction index, bind-DN
case-folding, the `state_db` merge-race fix, and the numeric-OID/
attribute-option-aware `LOCK_ATTRIBUTES` match — all held up under this
pass and aren't re-litigated below. No `unsafe` code exists anywhere in
the crate, and no `.unwrap()`/`.expect()` sits on any path reachable from
network input (`src/proxy.rs`, `src/connector/ldap.rs`,
`src/core/policy/threshold.rs`, `src/core/policy/store/{sqlite,valkey}.rs`
are all clean of both). Both store backends pass identity strings as
typed, length-prefixed parameters (`rusqlite::params!`, `redis`'s typed
command builders) rather than interpolating them into a query/command
string, so neither is SQL-/command-injectable via an attacker-influenced
bind DN. This pass instead went looking for what those fixes might have
missed. Grouped by severity; within a group, roughly in the order you'd
want to tackle them.

## High — forgeable shared rate-limit state and credential logging in the Valkey `state_db` backend

- [x] **A Valkey-backed `state_db` has no documented authentication story,
      the one way to supply a credential leaks it to the audit log in
      plaintext on any connection hiccup, and anyone who can reach the
      instance — via that leak or because it was left unauthenticated —
      can forge the very rate-limit history `ThresholdPolicy` exists to
      enforce.** Three compounding issues:

      1. **No authentication guidance.** `ValkeyStateDbConfig`
         ([src/core/policy/threshold.rs:28-52](src/core/policy/threshold.rs))
         has `url`, `key_prefix`, `ca_file`, and `client_cert` — nothing
         for a Redis/Valkey password or ACL username. ARCHITECTURE.md's
         "Valkey-backed policy state" section and
         `policies/ldap.example.toml`'s `state_db` block both document
         `rediss://` and mutual TLS in detail but never mention
         `requirepass`/ACLs, and the local `docker/valkey` image
         (`compose.yaml`'s `valkey-server --save 60 1 --appendonly yes`)
         starts with no password at all. An operator following only this
         project's own documentation for "HA across hosts with no shared
         disk" — the deployment shape this backend exists for — has no
         signal that the resulting network-reachable service needs access
         control, only that it can be encrypted.
      2. **The only available credential mechanism leaks on failure.**
         Since there's no dedicated password field, a credential can only
         be supplied embedded in `url` itself (standard `redis://` /
         `rediss://` URL userinfo, e.g. `rediss://:secret@valkey:6379`, is
         the only way `redis::Client::open`/`build_with_tls`
         ([src/core/policy/store/valkey.rs:84-130](src/core/policy/store/valkey.rs))
         accept one). `ThresholdPolicy::new`'s Valkey branch
         ([src/core/policy/threshold.rs:356-376](src/core/policy/threshold.rs))
         logs that exact string verbatim the moment `ValkeyStore::open`
         fails for *any* reason (a typo, an unreachable host, a bad
         `ca_file`/`client_cert` path, the "must be set together"
         validation error):
         ```rust
         Err(err) => {
             tracing::warn!(
                 error = %err,
                 url = %valkey.url,
                 "failed to open threshold policy state db; continuing without persistence"
             );
             None
         }
         ```
         (lines 368-371). This fires on every process start with a broken
         config *and* on every `SIGHUP` policy reload while the
         misconfiguration persists (`reload_policies_on_signal` in
         `src/lib.rs` rebuilds a fresh `ThresholdPolicy` — and re-runs this
         exact branch — from scratch each time). The line lands both on
         stdout and in `logs/ldap.log`, the structured JSON trail
         `AGENTS.md`/ARCHITECTURE.md describe as meant to be tailed by a
         log shipper or SIEM and retained — a materially wider and
         longer-lived audience than `config.toml`/`policies/*.toml`
         themselves, which at least sit behind filesystem permissions.
         Contrast the SQLite branch two arms up in the same `match`, which
         logs `path = %path.display()` — a filesystem path, not a secret,
         so this asymmetry is specific to the Valkey path.
      3. **Compromise of that store defeats the policy engine directly.**
         Neither backend's rows carry any per-identity write authorization
         or any indication of which policy/instance wrote them (already a
         documented constraint against two `[[policy]]` entries sharing
         one file/prefix). `ValkeyStore::sync`
         ([src/core/policy/store/valkey.rs:156-270](src/core/policy/store/valkey.rs))
         addresses every identity's sorted set by the literal, predictable
         key `{key_prefix}:history:{identity}` (e.g.
         `ai_protect:threshold:history:dn:cn=alice,dc=example,dc=com` —
         the bind DN appears in the *key name*, readable via `SCAN` without
         even reading a value, which is itself a modest recon leak of
         which principals are active). Anyone who can reach the instance —
         through the leaked credential above, or because it was never
         authenticated in the first place — can `ZADD` fabricated,
         current-scored entries into an arbitrary identity's key. Because
         `merge_history_from_rows`
         ([src/core/policy/threshold.rs:478-514](src/core/policy/threshold.rs))
         unconditionally unions whatever the store returns into every
         instance's local, live-decision-making `history` within one
         `flush_interval`, this is a **targeted, forgeable denial of
         service**: inject enough fake timestamps under a real,
         innocent principal's identity and `ThresholdPolicy` starts
         blocking their genuine traffic, with the audit log showing an
         entirely plausible "N matching actions in the last 60s would
         exceed window limit" against that principal's real DN —
         indistinguishable from a real over-use block to whoever
         investigates it. Symmetrically, `DEL`-ing (or
         `ZREMRANGEBYSCORE`-clearing) one's own key resets that identity's
         budget on any instance that hasn't independently cached its
         recent activity locally — most exploitable in exactly the
         multi-instance HA topology this backend exists to serve (a
         request that happens to land on an instance which hasn't seen the
         attacker recently trusts the store's now-empty view of them).
         This undermines the `Global`-scope backstop
         ([src/core/policy/threshold.rs:80-84](src/core/policy/threshold.rs))
         exactly as much as `PerIdentity`, since it's stored under the
         same mechanism (`GLOBAL_HISTORY_KEY`).

      Fix direction: add explicit `username`/`password` fields to
      `ValkeyStateDbConfig` (or at minimum stop logging `valkey.url`
      verbatim — log a redacted form with userinfo stripped, or just the
      host:port, on failure) so a credential embedded for authentication
      purposes can't round-trip into `logs/ldap.log`; document that a
      Valkey/Redis instance used as `state_db` needs `requirepass`/ACLs
      the same way ARCHITECTURE.md already insists on for TLS, and update
      `docker/valkey`'s example service accordingly; consider namespacing
      or signing rows so a `HistoryStore` write can be attributed to (and
      rejected from) something other than the policy that owns that
      prefix. Suggested tests: a `tracing` subscriber capturing output
      from a failed `ValkeyStore::open` (malformed `rediss://` URL
      containing a recognizable credential substring) asserts that
      substring never appears in the captured log, mirroring
      `src/core/audit.rs`'s existing `logs_an_oversized_identity_and_target_truncated`
      pattern; and a test that `ZADD`s a fabricated recent timestamp
      directly into a running `ValkeyStore`'s key for an identity that
      has never made a request and asserts the next `sync_once` causes
      `ThresholdPolicy` to block that identity's first genuine action.
      Fixed: `ValkeyStateDbConfig` gained `username`/`password` fields
      ([src/core/policy/threshold.rs](src/core/policy/threshold.rs)),
      applied to the parsed connection via
      `redis::RedisConnectionInfo::set_username`/`set_password`
      ([src/core/policy/store/valkey.rs](src/core/policy/store/valkey.rs)'s
      new `ValkeyAuthConfig`, threaded through `ValkeyStore::open`) rather
      than requiring the credential embedded in `url`'s userinfo, closing
      issue 1 (no documented mechanism) together with the ARCHITECTURE.md/
      `policies/ldap.example.toml`/`compose.yaml` doc updates below. Issue 2
      (the credential-logging leak) is fixed independently of whether
      `username`/`password` or the older embedded-userinfo form is used: a
      new `redact_valkey_url` strips `user:pass@` from the URL before the
      `ValkeyStore::open` failure path logs it, so a typo, unreachable host,
      or bad `ca_file`/`client_cert` path can no longer round-trip a
      credential into `logs/ldap.log` on every process start or `SIGHUP`
      reload. Verified with `threshold_policy_new_does_not_log_a_valkey_url_credential_on_failed_open`
      (captures real `tracing` output via a `MakeWriter`, mirroring
      `src/core/audit.rs`'s pattern, and asserts an embedded credential
      substring never appears after a real `open` failure) and
      `redact_valkey_url_strips_userinfo_but_keeps_the_rest` (direct cases:
      user+pass, password-only, no-credential, and unparseable input).
      ARCHITECTURE.md's "Valkey-backed policy state" section now states
      plainly that TLS on this hop doesn't substitute for authentication and
      documents `requirepass`/ACLs; `policies/ldap.example.toml`'s
      `state_db` block shows `username`/`password`; `compose.yaml`'s local
      `ha` profile `valkey` service now sets `--requirepass` so it's never
      an unauthenticated, network-reachable example by default. Issue 3
      (forged/erased history once the store is reachable) is only
      *mitigated* by requiring authentication now, not eliminated — rows
      still carry no per-write attribution, so a compromised or shared
      credential can still forge another identity's history under the same
      key prefix. Namespacing or signing rows so a write can be attributed
      to (and rejected from) something other than the owning policy, per
      the original fix direction's "consider," remains unimplemented; treat
      it as a follow-up if a deployment's `state_db` credential isn't
      trusted at the same level as the proxy process itself.

## Medium — `ThresholdPolicy` pools every policed operation kind into one shared budget

- [x] **There is no way to configure a stricter blast-radius limit for
      irreversible operations (Delete/Create/Rename) than for reversible
      ones (AccountLock/AccountUnlock/PasswordReset) — every `[[policy]]`
      entry applies uniformly to all six.** `ThresholdConfig`
      ([src/core/policy/threshold.rs:97-147](src/core/policy/threshold.rs))
      has no field naming which `OperationKind`(s) an entry applies to,
      and `evaluate_all`
      ([src/core/policy.rs:26-37](src/core/policy.rs)) runs every
      configured policy against every decoded `Action` unconditionally.
      `ThresholdPolicy::evaluate`'s bucket key
      (`history_key`, [src/core/policy/threshold.rs:537-548](src/core/policy/threshold.rs))
      is derived solely from `ctx.identity` (or the `Global` sentinel) —
      `action.operation` is read only for audit/metrics labeling
      (`src/core/audit.rs`, `src/core/metrics.rs`'s `operation_label`),
      never consulted by the admission check itself
      ([src/core/policy/threshold.rs:550-602](src/core/policy/threshold.rs)).
      This contradicts what the type design implies: `OperationKind`'s
      `AccountUnlock` variant doc comment
      ([src/core/action.rs:4-13](src/core/action.rs)) states it exists as
      its own kind rather than folding into `AccountLock` "since 'N
      unlocks' and 'N locks' may warrant different limits" — but no
      config surface can express *any* per-operation-kind limit today, for
      any pair of the six kinds, not just lock/unlock. Concretely: the
      documented example policy
      (`policies/ldap.example.toml`: `max_per_request = 10`,
      `max_per_window = 50`) is sized to tolerate a legitimate burst of
      routine account-lock activity (an HR sync, an offboarding batch).
      That same 50-per-60s budget applies identically to `DelRequest`s —
      an over-eager or compromised automated caller (exactly this
      project's threat model) can delete up to 50 directory entries
      outright inside one window before `ThresholdPolicy` blocks anything
      further, using a ceiling an operator tuned while thinking about
      reversible lock toggles, not permanent data loss. An operator who
      wants "50 lock/unlock operations is fine, but even 5 deletes in a
      window should be blocked" has no way to express that with the
      current policy schema; a second `[[policy]]` entry doesn't help,
      since it too would apply to all six kinds.
      Fix direction: add an optional operation filter to `ThresholdConfig`
      (e.g. `operations: Option<Vec<OperationKind>>`, `None` defaulting to
      "all," matching how `scope` already defaults to `PerIdentity`) and
      have `evaluate` return `Decision::Allow` immediately — bypassing
      this policy entirely, not just skipping the block — for an action
      whose `operation` isn't in the configured set, so a policy scoped to
      `[Delete, Create, Rename]` doesn't consume its own window budget on
      unrelated lock/unlock traffic. Document the recommended pattern
      (one lenient entry for lock/unlock/password-reset, a second, much
      stricter entry filtered to delete/create/rename) alongside the
      existing `PerIdentity`+`Global` two-entry pattern in
      `policies/ldap.example.toml`. Suggested test: a policy configured
      with `operations = ["delete"]` and `max_per_window = 2` blocks a
      third `Delete` in-window while an interleaved, unrelated 10th
      `AccountLock` in the same window from the same identity is still
      allowed.
      Fixed: `ThresholdConfig` gained an optional `operations:
      Option<Vec<OperationKind>>` field
      ([src/core/policy/threshold.rs](src/core/policy/threshold.rs)),
      `None` (the default) preserving today's all-six behavior for every
      existing config. `OperationKind` itself
      ([src/core/action.rs](src/core/action.rs)) now derives `Deserialize`
      (`#[serde(rename_all = "snake_case")]`, so TOML spells the six kinds
      `account_lock`, `account_unlock`, `delete`, `create`,
      `password_reset`, `rename`) plus `Copy`/`Hash`, needed to hold it in
      a `Vec` and compare cheaply. `ThresholdPolicy::evaluate` checks this
      filter first, before `max_per_request` or any history/lock access:
      an action whose `operation` isn't in the configured set returns
      `Decision::Allow` immediately, exactly the "bypass entirely" behavior
      the fix direction called for, so unrelated traffic never consumes
      this entry's window budget. `policies/ldap.example.toml` now shows
      the recommended two-entry pattern — a lenient entry filtered to
      `account_lock`/`account_unlock`/`password_reset`, and a second, much
      stricter entry filtered to `delete`/`create`/`rename` — alongside the
      existing `PerIdentity`+`Global` pattern; ARCHITECTURE.md's "Policy:
      blast-radius thresholding" section documents `operations` the same
      way it documents `scope`. Verified with the suggested test,
      `operations_filter_bypasses_the_policy_entirely_for_unmatched_kinds`
      (a policy filtered to `[Delete]` with `max_per_window = 2` blocks a
      third `Delete` while ten interleaved, unrelated `AccountLock`s from
      the same identity in the same window are all allowed and don't touch
      the budget), plus a TOML round-trip test
      (`parses_operations_filter_from_toml_and_defaults_to_none`). All
      existing `ThresholdConfig` struct-literal call sites across
      `src/core/policy/threshold.rs`, `src/proxy.rs`, and `src/builder.rs`
      were updated with the new field; every prior test (143 baseline +
      the Valkey-auth fix's 3 + this fix's 2 = 148) still passes.

## Low — health-probe request line can be misread if split across reads

- [x] **`core::health::handle_connection` treats whatever bytes one
      `TcpStream::read` call returns as the complete HTTP request line, so
      a probe request arriving in more than one read can be parsed as an
      empty or truncated path and answered `404` instead of the real
      liveness/readiness status.**
      [src/core/health.rs:119-134](src/core/health.rs) does a single
      `stream.read(&mut buf)` (raced against `READ_TIMEOUT`, not looped),
      then immediately treats `buf[..n]` as the whole request:
      ```rust
      let n = match tokio::time::timeout(read_timeout, stream.read(&mut buf)).await {
          Ok(result) => result?,
          Err(_) => { ... }
      };
      let request = String::from_utf8_lossy(&buf[..n]);
      let path = request.lines().next().and_then(|line| line.split_whitespace().nth(1)).unwrap_or("");
      ```
      If a client's request line and headers arrive as more than one TCP
      segment/`write()` (uncommon for a bare `GET /healthz HTTP/1.1\r\n...`
      from typical probe clients, but not guaranteed — some minimal HTTP
      client implementations write the request line and headers
      separately), the first `read()` can return only a partial line
      (e.g. just `"GET "`), `nth(1)` finds no path, `unwrap_or("")` yields
      `""`, and the match falls through to `NOT_FOUND_RESPONSE`
      ([src/core/health.rs:136-141](src/core/health.rs)) rather than the
      correct `200`/`503`. This fails closed (a false "not found," never a
      false `200`) and isn't attacker-exploitable — nothing sensitive is
      returned or bypassed — but a spurious `404` from `/healthz` or
      `/readyz` under real orchestrator polling could read as the process
      being unhealthy, triggering an unwanted restart or removal from a
      load balancer's rotation, undermining the availability guarantees
      graceful shutdown/health-check support exists to provide. The main
      LDAP path avoids this class of bug entirely by using `read_frame`'s
      `read_exact` loop over a length-delimited frame
      ([src/connector/ldap.rs:576-622](src/connector/ldap.rs)); this
      hand-rolled HTTP path has no equivalent framing.
      Fix direction: loop reads (bounded by the existing 512-byte buffer
      and the existing `read_timeout` deadline) until a full line
      (`\r\n`) is seen or the buffer fills, rather than parsing whatever
      the first `read()` happened to return — or read via
      `tokio::io::BufReader`/`AsyncBufReadExt::read_line`, the same
      buffering approach `src/proxy.rs` already uses for its own framing.
      Suggested test: split a canned
      `"GET /healthz HTTP/1.1\r\nhost: test\r\n\r\n"` request across two
      separate `write_all` calls with a short delay between them and
      assert the response is still `200`, not `404`.
      Fixed: `handle_connection`
      ([src/core/health.rs](src/core/health.rs)) now loops
      `stream.read` calls into the same fixed 512-byte buffer, appending
      each chunk, until either the accumulated bytes contain `\r\n` (the
      request line is complete), the peer closes the connection (`read`
      returns `0`), or the buffer fills — rather than treating whatever one
      `read()` call happened to return as the whole request. The loop, not
      each individual `read`, is what races `read_timeout`
      (`tokio::time::timeout` now wraps the whole `async` loop), so a
      connection that sends a partial line and then stalls still times out
      on the original deadline instead of hanging past it, and a
      connection that completes its line after a delay is no longer
      mis-parsed as pathless. Verified with
      `healthz_is_ok_even_when_the_request_line_arrives_split_across_reads`
      (the suggested test, using the worst-case split point — `"GET "` in
      one `write_all`, the rest after a delay in a second — chosen because
      splitting there leaves no second whitespace-separated token for the
      old code to find, guaranteeing the old single-read parse would
      return `""` and thus `404`; confirmed by temporarily reverting the
      implementation and observing this exact test fail before re-applying
      the fix). `handle_connection_times_out_when_client_sends_nothing`
      (a client that never sends a byte) continues to pass unchanged.
