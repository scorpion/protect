# What ai-protect does to LDAP traffic

This describes exactly which LDAP requests `ai-protect` looks at, how it
decides to allow or block them, what a blocked client sees, and how to
read the resulting logs. For how to install and configure `ai-protect`
in the first place, see [INSTALLATION.md](INSTALLATION.md).

## The short version

`ai-protect` decodes just enough of each request to tell whether it's one
of six kinds of account-affecting change. If it isn't, the request is
forwarded untouched — `ai-protect` doesn't parse it at all, so there's no
speed or compatibility cost for the searches, binds, compares, and
ordinary attribute edits that make up the bulk of directory traffic. If
it is one of the six, it's checked against your configured policy before
being allowed through.

## Requests that are inspected

| Request | Treated as actionable when... |
|---|---|
| **Modify (lock)** | it adds or replaces one of a fixed set of account-lock attributes (see [Account-lock attributes](#account-lock-attributes-recognized) below) |
| **Modify (unlock)** | it deletes one of that same set of attributes |
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

A Modify is only actionable if it touches one of these attribute names,
matched case-insensitively, covering the three directory families
`ai-protect` targets:

| Attribute | Directory |
|---|---|
| `pwdAccountLockedTime` | OpenLDAP (`ppolicy` overlay) |
| `userAccountControl` | Active Directory |
| `nsAccountLock` | 389 Directory Server |
| `shadowExpire` | RFC 2307 `shadowAccount` (some OpenLDAP setups) |

**Adding or replacing** one of these attributes is reported as
`AccountLock`; **deleting** one (clearing it back to the schema default,
typically *unlocking* the account) is reported separately as
`AccountUnlock` — the mirror image, since mass-reactivating
previously-locked accounts (e.g. to keep a credential-stuffing run alive)
is arguably just as security-relevant as mass-locking them, and "N
unlocks" may warrant a different limit than "N locks" in policy. A Modify
touching any other attribute — job title, group membership, phone number,
anything not in this list — passes through untouched regardless of how
many attributes or values it changes.

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

`ai-protect` correlates the bind request against its response by LDAP
message ID before upgrading identity: a claimed DN is staged but not
trusted the moment the `BindRequest` is seen, and only promotes the
connection's identity once the matching `BindResponse` reports success. A
bind that fails, or is never answered, leaves identity unchanged — a
caller can't buy a fresh, empty per-identity budget by claiming a
made-up DN that never actually authenticates. A `scope = "global"`
policy entry (see [The threshold policy](#the-threshold-policy)) is the
recommended backstop against a caller that *can* authenticate under many
distinct real DNs and churns through them to reset its per-identity
budget — see [Known limitations](#known-limitations) below.

Anonymous binds (empty DN) and SASL binds leave the current identity
unchanged — a SASL `name` field isn't password-verified the way a simple
bind's DN is, so it can't be trusted as identity. This matters most for
Active Directory, one of the three directories `ai-protect` targets:
AD deployments overwhelmingly authenticate LDAP traffic — interactive and
service-account alike — via SASL/GSSAPI (Kerberos), not simple DN+password
binds. In such an environment, expect most connections to stay tracked
under their source IP for their whole lifetime, meaning distinct
Kerberos-authenticated principals sharing an egress (a jump box, a
container host, a NAT gateway) are pooled into one IP-scoped budget and
one audit identity, not attributed individually. Simple-bind identity
upgrade still applies fully to directories or traffic that use it (e.g.
OpenLDAP/389 DS deployments using simple binds, or any AD traffic that
does).

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
- **operation** — one of `AccountLock`, `AccountUnlock`, `Delete`,
  `Create`, `Rename`, `PasswordReset`
- **target** — the DN the request names
- **blast_radius** — always `1` for LDAP today
- **reason** — present on a block, absent on an allow; the same text sent
  to the client (see [What a blocked client sees](#what-a-blocked-client-sees))

Because every decision is logged regardless of outcome, this is the
complete forensic trail of every account-lock, account-unlock, delete,
create, and password-reset request `ai-protect` has ever seen — there's
no separate audit store to reconcile against.

## Known limitations

`ai-protect` is early-stage. Before relying on it as a hard security
boundary rather than a safety net against accidents and unsophisticated
automation, be aware of the most significant current gaps:

- **Identity-churn volume**: as described in
  [Identity](#identity-how-who-is-doing-this-is-determined) above, binds
  are verified against their response before identity is upgraded, so a
  made-up DN that never authenticates can't reset a budget. A caller that
  *can* authenticate under many distinct real DNs, however, can still
  churn through them to get each one its own fresh per-identity budget —
  a `scope = "global"` policy entry is the backstop for that, but it isn't
  on by default in the example policy file.
- **SASL/Kerberos traffic isn't attributed by principal**: identity stays
  IP-based for anonymous and SASL-bound connections (a SASL `name` field
  isn't verified the way a simple bind's DN is). Since Active Directory
  traffic is predominantly SASL/GSSAPI (Kerberos) in most enterprise
  deployments, expect this to cover the majority of real AD traffic in
  practice — distinct principals behind a shared egress share one
  IP-scoped budget and one audit identity. Sizing a `Global`-scope backstop
  appropriately matters more, not less, in a Kerberos-heavy deployment.

This and other gaps — including some around unbounded identity
cardinality and TLS support for the Valkey-backed HA state store — are
tracked with full technical detail in [TODO.md](../TODO.md) in the
repository root, grouped by severity. Read it before a production
deployment that depends on `ai-protect` to hold against a motivated
adversary rather than a well-meaning script that got out of hand.
