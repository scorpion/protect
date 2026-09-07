# What ai-protect does to LDAP traffic

This describes exactly which LDAP requests `ai-protect` looks at, how it
decides to allow or block them, what a blocked client sees, and how to
read the resulting logs. For how to install and configure `ai-protect`
in the first place, see [INSTALLATION.md](INSTALLATION.md).

## The short version

`ai-protect` decodes just enough of each request to tell whether it's one
of five kinds of account-affecting change. If it isn't, the request is
forwarded untouched — `ai-protect` doesn't parse it at all, so there's no
speed or compatibility cost for the searches, binds, compares, and
ordinary attribute edits that make up the bulk of directory traffic. If
it is one of the five, it's checked against your configured policy before
being allowed through.

## Requests that are inspected

| Request | Treated as actionable when... |
|---|---|
| **Modify** | it adds or replaces one of a fixed set of account-lock attributes (see [Account-lock attributes](#account-lock-attributes-recognized) below) |
| **Delete** | always — removing an entry outright |
| **Add** | always — creating an entry outright |
| **Modify DN** (rename/move, RFC 4511 §4.9) | always — renaming or moving an entry outright |
| **Extended: Password Modify** (RFC 3062) | always — a password reset via the standard extended operation |

Everything else — binds, searches, compares, ordinary attribute edits
that aren't a lock, every other extended operation including StartTLS —
passes through exactly as sent. `ai-protect` never queries the directory
itself to make a decision (no lookups, no schema awareness beyond the
attribute list below), so it adds no extra round trips to allowed
traffic.

### Account-lock attributes recognized

A Modify is only actionable if it **adds or replaces** (not deletes) one
of these attribute names, matched case-insensitively, covering the three
directory families `ai-protect` targets:

| Attribute | Directory |
|---|---|
| `pwdAccountLockedTime` | OpenLDAP (`ppolicy` overlay) |
| `userAccountControl` | Active Directory |
| `nsAccountLock` | 389 Directory Server |
| `shadowExpire` | RFC 2307 `shadowAccount` (some OpenLDAP setups) |

Deleting one of these attributes (clearing it back to the schema default,
typically *unlocking* the account) is not treated as a lock action — it
isn't the high-blast-radius direction. A Modify touching any other
attribute — job title, group membership, phone number, anything not in
this list — passes through untouched regardless of how many attributes
or values it changes.

### Why Delete, Add, and Modify DN are always actionable

Unlike a Modify, there's no attribute to narrow on: removing, creating,
or renaming/moving an entry is already as disruptive as a lock — moving
an account into a quarantine OU is a standard Active Directory
account-disable workflow — and there's no cheap way to tell "this is an
account" from "this is an OU or a printer object" without querying the
directory — which `ai-protect` deliberately never does. Every Delete,
Add, and Modify DN counts.

### Why Password Modify is included

A bulk password reset locks users out of their accounts just as
effectively as a bulk account lock does, so it's policed the same way.
`ai-protect` only decodes far enough to learn *whose* password is
changing (for identifying the target in logs and policy) — it never
inspects or logs the old or new password values themselves.

## What counts against your limits

Each actionable request currently counts as **1** unit of "blast radius"
regardless of what it targets — a Modify, Delete, Add, Modify DN, or
Password Modify each affect exactly one entry per request in LDAP, so
there's no per-request multiplier today. (The underlying `Action` type
does carry a
blast-radius number for future protocols/operations where one request
could affect many entries at once; for LDAP it's always 1.)

## The threshold policy

The only policy type today, configured per `[[policy]]` entry in
`policies/ldap.toml`, enforces two independent caps:

```toml
[[policy]]
type = "threshold"
max_per_request = 10   # 1: single request is always under this for LDAP
max_per_window = 50    # cumulative actions per identity within window_secs
window_secs = 60
```

1. **Per-request cap** — blocked immediately if a single request's own
   blast radius exceeds `max_per_request`. For LDAP, where every
   actionable request has a blast radius of 1, this only matters if you
   set it below 1 (effectively "block this operation type entirely").
2. **Per-identity sliding window** — each identity accumulates a history
   of its allowed actions. If admitting a new one would push that
   identity's total over `max_per_window` within the trailing
   `window_secs`, it's blocked instead. **Only allowed actions count** —
   requests that get blocked don't add to the identity's history, so a
   blocked burst doesn't itself trigger further blocks.

Multiple `[[policy]]` entries run in the order declared, and the chain
stops at the first block — so if you ever add more policy types, put
cheaper or stricter checks first.

### Picking numbers

Set `max_per_window`/`window_secs` above your normal peak legitimate
burst (an HR sync, an offboarding batch) with headroom, then watch the
audit log for a while under real traffic before tightening further. A
policy that's too tight blocks legitimate bulk operations just as
effectively as it blocks a runaway one — the log will show you which
you're getting.

## What a blocked client sees

`ai-protect` builds a proper LDAP response so the client's own error
handling behaves normally — it isn't a dropped connection or a timeout.
The response matches the request type it's answering (a `ModifyResponse`
for a blocked Modify, a `DelResponse` for a blocked Delete, and so on)
and carries:

- **Result code**: `unwillingToPerform` (53)
- **Diagnostic message**: a short, specific reason, e.g.

  ```
  blast radius 1 exceeds per-request limit 0
  47 matching actions in the last 60s would exceed window limit 50
  ```

The blocked request never reaches the real directory — from the
directory's point of view, nothing happened.

## Identity: how "who is doing this" is determined

Policy limits and audit log entries are tracked per **identity**, which
starts as the client's source IP address (the connection's, not any
claimed value) and is upgraded the moment `ai-protect` sees a **simple
bind** (DN + password, not anonymous, not SASL) naming a non-empty DN —
from then on, that connection's actions are tracked under the bound DN
instead of its IP.

This matters because multiple unrelated clients behind the same NAT or
egress otherwise share one IP-based budget; binding under distinct DNs
gives each its own.

**Important caveat:** `ai-protect` does not correlate the bind request
against its response — identity switches to the claimed DN as soon as
the `BindRequest` is seen, before the directory has had any chance to
accept or reject it. In the common case this is low-risk, since an
unauthenticated session that fails its bind upstream still gets its
writes rejected by the real directory. It does mean, however, that a
caller who can issue arbitrary bind requests can currently defeat the
per-identity window by binding under a fresh, made-up DN before each
batch of destructive requests, as long as each individual batch stays
under the configured caps — see [Known limitations](#known-limitations)
below. Anonymous binds and SASL binds leave the current identity
unchanged.

## StartTLS

If a client sends the RFC 4511 StartTLS extended request, `ai-protect`
answers it directly and performs the TLS handshake in place on the same
connection, then continues processing frames — including policy
decisions — exactly as it would for a connection that started TLS
implicitly. Whether `ai-protect` offers this to clients, or negotiates it
itself against the upstream, is a configuration choice — see
[Enabling TLS](INSTALLATION.md#enabling-tls).

## Reading the audit log

Every policy decision — allow or block — produces one structured log
line, at `info` level for an allow and `warn` for a block. With
`RUST_LOG` set, these appear both on stdout (human-readable) and in
`logs/ldap.log` (flattened JSON, one event per line — the form meant for
a log shipper or SIEM).

Each event carries:

- **identity** — the source IP or bound DN responsible (see
  [Identity](#identity-how-who-is-doing-this-is-determined) above)
- **backend** — always `ldap` today
- **operation** — one of `AccountLock`, `Delete`, `Create`, `Rename`,
  `PasswordReset`
- **target** — the DN the request names
- **blast_radius** — always `1` for LDAP today
- **reason** — present on a block, absent on an allow; the same text sent
  to the client (see [What a blocked client sees](#what-a-blocked-client-sees))

Because every decision is logged regardless of outcome, this is the
complete forensic trail of every account-lock, delete, create, and
password-reset request `ai-protect` has ever seen — there's no separate
audit store to reconcile against.

## Known limitations

`ai-protect` is early-stage. Before relying on it as a hard security
boundary rather than a safety net against accidents and unsophisticated
automation, be aware of the most significant current gap:

- **Identity-churn bypass**: as described in
  [Identity](#identity-how-who-is-doing-this-is-determined) above, a
  caller able to send its own bind requests can evade the per-identity
  window by claiming a fresh DN before each batch, since binds aren't
  verified against their response before policy starts tracking under
  the new identity. There is currently no global, identity-independent
  cap as a backstop against this.

This and other gaps — including some around unbounded identity
cardinality and TLS support for the Valkey-backed HA state store — are
tracked with full technical detail in [TODO.md](../TODO.md) in the
repository root, grouped by severity. Read it before a production
deployment that depends on `ai-protect` to hold against a motivated
adversary rather than a well-meaning script that got out of hand.
