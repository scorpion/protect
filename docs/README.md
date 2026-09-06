# ai-protect documentation

`ai-protect` is a small proxy you put in front of your directory server
(Active Directory, OpenLDAP, 389 Directory Server today) to stop a single
runaway caller — an AI agent with over-broad permissions, a misconfigured
script, a compromised credential — from locking, deleting, or resetting
the passwords of a large number of accounts in one go.

It does this without getting in the way of everything else your directory
does: `ai-protect` only looks closely at the handful of request types that
can hurt at scale, and forwards every other request byte-for-byte, exactly
as if it wasn't there.

This section of the documentation is written for the person **running**
`ai-protect` — deploying it, configuring its policy, and reading its
output — not for someone modifying its source. If you're looking for
that, see [AGENTS.md](../AGENTS.md) and [ARCHITECTURE.md](../ARCHITECTURE.md)
in the repository root instead.

## Start here

- **[Installing and running ai-protect](INSTALLATION.md)** — get a proxy
  up and pointed at your directory, configure TLS, and wire up logging,
  metrics, and health checks.
- **[What ai-protect does to LDAP traffic](LDAP.md)** — exactly which
  requests are inspected, what gets blocked and why, what a blocked client
  sees, and how to tune the policy that decides.

## Why this exists

Directory services have no built-in concept of "that's a lot of accounts
at once." A single authenticated caller — human or automated — can lock
every account in an OU, delete a whole subtree, or reset thousands of
passwords, and the directory will simply do it, one request at a time,
as fast as it's asked. That's rarely what anyone actually wants: it's the
signature of a bug, a bad script, or an AI agent that misunderstood its
own instructions and is now iterating over every account it can see.

`ai-protect` sits on the wire between your clients and the real directory
and adds the one thing missing: a cap on how much account-affecting change
one identity can push through before it gets frozen out. Everything under
the cap goes through untouched, at full speed, with no added round trip to
anything but the proxy itself. Everything over it is rejected with a
normal LDAP error — the directory never even sees the request — and the
attempt is logged.

```
your client(s)  ---->  ai-protect  ---->  your real directory
                            |
                            +-- most requests: forwarded as-is
                            +-- lock / delete / create / password-reset:
                                  checked against your policy first
```

## What it protects against

- An AI agent or automation tool given (or that has escalated to) broad
  write access, that starts iterating destructively over accounts due to a
  bug, bad prompt, or runaway loop.
- A compromised or leaked credential being used to do maximum damage in
  the shortest possible time before anyone notices.
- A misconfigured bulk script — an HR sync, an offboarding job, a
  migration tool — pointed at the wrong OU or run with the wrong filter.

## What it doesn't do

`ai-protect` is not a directory, not a firewall, and not an intrusion
detection system. It doesn't authenticate clients on your behalf, doesn't
inspect or block reads (searches, whoami, comparisons), and doesn't
understand your schema beyond a small, fixed list of attributes that
indicate an account lock. If a caller stays under the configured limits,
`ai-protect` allows the same action a directory administrator would have
allowed directly.

It also has known limitations at its current stage of development — most
notably, that an attacker who can issue their own bind requests can evade
a per-identity limit by switching identities between batches. See
[Known limitations](LDAP.md#known-limitations) in the LDAP reference, and
[TODO.md](../TODO.md) in the repository root for the full, current gap
list, before relying on it as your only line of defense.

## Getting help

Every decision `ai-protect` makes — allow or block — is logged with the
identity, operation, target, and (for a block) the reason. If a request is
being unexpectedly blocked or allowed, that log is the first place to
look; see [Reading the audit log](LDAP.md#reading-the-audit-log).
