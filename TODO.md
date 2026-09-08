# Enterprise deployment TODO

A gap list from a full security review (2026-09-08) of the current state
(commit `6d30f37`, see [ARCHITECTURE.md](ARCHITECTURE.md)). This pass read
every module under `src/` end to end — connection handling and StartTLS
upgrade (`src/proxy.rs`), BER framing/decoding and bind-response
correlation (`src/connector/ldap.rs`), the policy engine, its threshold
logic, and both `state_db` backends (`src/core/policy/**`), the upstream
load-balancing pool (`src/core/upstream_pool.rs`), identity derivation
(`src/core/identity.rs`), TLS/mTLS setup (`src/core/tls.rs`), audit
logging, metrics, health, config parsing, and the top-level `run`/
`run_with_config`/`ProxyBuilder` entry points — plus the fuzz targets,
Dockerfiles, `compose.yaml`, `setup.sh`, and example configs.
`cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
warnings`, `cargo test` (165 passed, 4 ignored — those need a live Valkey
server), and `cargo audit` (255 crates, no advisories) all ran clean at the
reviewed commit.

The prior rounds of hardening this codebase's history shows all held up
under this pass and aren't re-litigated below: frame-size/DN-length caps
(keyed, not `DefaultHasher`, hashing), `MAX_PENDING_BINDS` eviction, the
O(log n) `max_tracked_identities` eviction index (and its extension to both
`state_db` backends), bind-response correlation before `Identity` is ever
promoted (including the unauthenticated/SASL-bind carve-outs), bind-DN
case-folding, the `state_db` merge-race fix, the numeric-OID/attribute-
option-aware `LOCK_ATTRIBUTES` match, `ModifyDNRequest` policing, the
per-operation-kind budget filter, Valkey credential handling
(`redact_valkey_url`, the separate `username`/`password` fields instead of
URL userinfo), and StartTLS negotiation on both hops running against a raw
`TcpStream` rather than a `BufReader` (no buffered-plaintext bleed-through
across the upgrade boundary — the classic STARTTLS command-injection
pattern doesn't apply here). No `unsafe` code exists anywhere in the crate,
and no `.unwrap()`/`.expect()` sits on any path reachable from network
input. Both `state_db` backends pass identity strings as typed,
length-prefixed parameters (`rusqlite::params!`, `redis`'s typed command
builders) rather than interpolating them into a query/command string, so
neither is SQL-/command-injectable via an attacker-influenced bind DN.

The architectural tradeoffs already tracked in
[ARCHITECTURE.md "Known gaps"](ARCHITECTURE.md#known-gaps-by-design-at-this-stage)
(opt-in `state_db`, address/bind-DN-derived `Identity`, one connector type
per `[[proxy]]` entry, shared `io_timeout` budget across failover attempts,
one TLS identity per upstream pool, no per-entry supervision, and
`logs/ldap.log` never rotating on its own) still apply and aren't repeated
here. This pass instead went looking for what those didn't cover —
`setup.sh` in particular, which hadn't been in scope for a security review
before now. Grouped by severity; within a group, roughly in the order
you'd want to tackle them.

## Medium — `setup.sh` handles two secrets in ways that leak outside the files it deliberately avoids writing them to

- [ ] **The discovery bind password is passed to `ldapsearch` via `-w` on
      the command line**, in both `try_rootdse()` call sites
      ([setup.sh:232](setup.sh),
      [setup.sh:264](setup.sh),
      [setup.sh:277](setup.sh)):
      ```sh
      BIND_ARGS=(-D "$BIND_DN" -w "$BIND_PW")
      ...
      ldapsearch -x -H "$LDAP_URL" ... ${BIND_ARGS[@]+"${BIND_ARGS[@]}"} ...
      ```
      This applies both to a password the operator types interactively
      (`ask_secret BIND_PW`) and, since the "Detection improvements" commit
      (`6d30f37`), to `LLDAP_LDAP_USER_PASS` pulled automatically from a
      local `.env` for the bundled lldap test upstream. A command-line
      argument is visible to any other local account for the life of the
      process via `ps -ef`/`/proc/<pid>/cmdline` (and on some systems,
      process-accounting/audit logs) — a materially different exposure
      than the file-write risk the script's own header comment calls out
      ("any bind DN/password you give it ... is used in-memory only —
      never written to config.toml"). The credential never touches disk,
      but it's briefly world-visible in the process table instead.
      `ldapsearch` supports `-y <passwordfile>` for exactly this reason;
      swapping `-w "$BIND_PW"` for `-y <(printf '%s' "$BIND_PW")` (bash
      process substitution — no plaintext temp file, no argv exposure)
      closes this without changing the script's interactive flow.
- [ ] **`config.toml` and `policies/ldap.toml` are written with whatever
      permissions the shell's umask leaves them** — plain `>` redirection
      into a `mktemp -d` workdir file, then `mv` into place
      ([setup.sh:477-530](setup.sh),
      [setup.sh:532-584](setup.sh)), with no `chmod` anywhere in the
      script. Under a typical `022` umask that's world-readable (`0644`).
      `policies/ldap.toml` can contain a plaintext Valkey/Redis
      `state_db` password (`STATE_DB_PASS`, entered via `ask_secret` at
      [setup.sh:457](setup.sh) and written at
      [setup.sh:556](setup.sh)) — the exact credential
      `ValkeyAuthConfig`/`redact_valkey_url` exist to keep out of logs is
      then sitting in a group/world-readable file on disk. Add
      `chmod 600 config.toml policies/ldap.toml` right after the two
      `mv`s at [setup.sh:583-584](setup.sh); worth doing for a SQLite
      `state_db` file too, since it holds per-identity bind-DN history
      even though it carries no credential.

These are both narrow, `setup.sh`-only issues — the compiled proxy itself
never places a credential in argv or writes one to a file it doesn't
already document as sensitive (`config.toml`/`policies/*.toml` are already
gitignored and flagged as secrets in `.gitignore`; this is about the
permissions on the copy `setup.sh` writes, not the fact that it's
gitignored). Neither affects `ai-protect`'s own request-handling path.
