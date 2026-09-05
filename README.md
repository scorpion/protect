# ai-protect

A transparent proxy for directory services (LDAP today) that blocks
bulk, high-blast-radius account operations — like an automated agent or
runaway script locking thousands of accounts — before they reach the real
directory.

It sits inline between clients and the upstream directory server. Requests
it doesn't need to act on are forwarded byte-for-byte, untouched. Requests
that modify account-lock attributes are checked against configurable
blast-radius policies and either forwarded or rejected with a proper LDAP
error, with every decision logged.

> **Status:** early / pre-alpha. Single hardcoded config, no TLS, no
> persistent state, no test suite yet. See [ARCHITECTURE.md](ARCHITECTURE.md)
> for the full design and known gaps.

## How it works

```
client  ---->  ai-protect  ---->  upstream LDAP directory
                   |
                   +-- decode request
                   +-- not a lock operation?  forward as-is
                   +-- lock operation -> evaluate policy
                         +-- within limits -> forward
                         +-- over limit    -> reject, log, never reaches directory
```

Every modify request is inspected for attributes that represent an
account lock across common directory schemas (Active Directory,
OpenLDAP, 389 DS). Matching requests are checked against policy —
currently a threshold policy that blocks:

- any single request whose blast radius exceeds a per-request cap, and
- any identity whose cumulative blast radius within a sliding time window
  exceeds a window cap

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full request lifecycle and
component design.

## Requirements

- Rust (2024 edition toolchain)
- An LDAP-speaking directory to proxy to (for local testing, any LDAP
  server reachable at the configured upstream address)

## Building

```sh
cargo build
```

## Running

```sh
cargo run
```

By default (see `Config::dev_default()` in
[src/config.rs](src/config.rs)) this:

- listens on `127.0.0.1:3890`
- proxies to an upstream LDAP server on `127.0.0.1:389`
- blocks any single request with blast radius over `10`
- blocks any identity exceeding `50` cumulative blast radius in a `60s`
  window

Point an LDAP client at `127.0.0.1:3890` instead of the real directory to
exercise it.

Logging is off by default; enable it with `RUST_LOG`:

```sh
RUST_LOG=info cargo run
```

Config is currently compiled-in only — there's no config file support yet.
To change listen/upstream addresses or thresholds, edit
`Config::dev_default()`.

## Development

```sh
cargo check    # type/borrow check
cargo fmt      # format
cargo clippy   # lint
cargo test     # no tests yet
```

## Documentation

- [AGENTS.md](AGENTS.md) — module map and conventions for anyone (human or
  agent) working on this codebase
- [ARCHITECTURE.md](ARCHITECTURE.md) — system design, request lifecycle,
  extension points, and known gaps
