# Enterprise deployment TODO

A gap list from a full security review (2026-09-07) of the current state
(commit `c1ca346`, see [ARCHITECTURE.md](ARCHITECTURE.md)). This pass read
every module under `src/` end to end — connection handling and StartTLS
upgrade (`src/proxy.rs`), BER framing/decoding and bind-response
correlation (`src/connector/ldap.rs`), the policy engine and its
`state_db` backends (`src/core/policy/**`), identity derivation
(`src/core/identity.rs`), TLS/mTLS setup (`src/core/tls.rs`), audit
logging, metrics, health, and config parsing — rather than diffing recent
commits, since `TODO.md` itself had just been cleared out. The prior
rounds of hardening this codebase's history shows (frame-size/DN-length
caps, connection limits/timeouts, mTLS, StartTLS with no buffered-
plaintext bleed-through, `MAX_PENDING_BINDS` eviction, the O(log n)
eviction index, bind-DN case-folding, the `state_db` merge race fix, the
numeric-OID/attribute-option-aware `LOCK_ATTRIBUTES` match) all held up
under this pass and aren't re-litigated below. Both gaps this review found
(the empty-password bind identity-promotion gap, and the unkeyed
oversized-DN hash) have since been fixed.
