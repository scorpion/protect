# ai-protect

A transparent proxy for directory services (LDAP today) that blocks
bulk, high-blast-radius account operations — like an automated agent or
runaway script locking thousands of accounts — before they reach the real
directory.

It sits inline between clients and the upstream directory server. Requests
it doesn't need to act on are forwarded byte-for-byte, untouched. Requests
that modify account-lock attributes are checked against configurable
blast-radius policies and either forwarded or rejected with a proper LDAP
error, with every decision logged. Each hop (client-facing and upstream)
can independently run plaintext LDAP or LDAPS.

> **Status:** early. TOML-based config and policy files, TLS on both hops
> (including optional mutual TLS and RFC 4511 StartTLS), bounded concurrent
> connections with per-I/O timeouts, a unit + end-to-end test suite, and CI
> all exist; there's still no persistent/shared policy state. See
> [ARCHITECTURE.md](ARCHITECTURE.md) for the full design and
> [TODO.md](TODO.md) for the gap list to a production-ready deployment.

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
OpenLDAP, 389 DS). Matching requests are checked against the configured
policy chain — currently a threshold policy that blocks:

- any single request whose blast radius exceeds a per-request cap, and
- any identity whose cumulative blast radius within a sliding time window
  exceeds a window cap

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full request lifecycle and
component design.

## Requirements

- Rust (2024 edition toolchain)
- An LDAP-speaking directory to proxy to (for local testing, `docker
  compose` brings up a disposable [lldap](https://github.com/lldap/lldap)
  instance — see [Local testing](#local-testing) below)

## Building

```sh
cargo build
```

## Configuration

`ai-protect` needs a process config file and a policy file, neither of
which is tracked in git (real deployment values may be sensitive). Copy
the tracked templates to get started:

```sh
cp config.example.toml config.toml
cp policies/ldap.example.toml policies/ldap.toml
```

- `config.toml` (schema in [config.example.toml](config.example.toml)) —
  `[proxy]` listen/upstream addresses, and optional `[proxy.listen_tls]` /
  `[proxy.upstream_tls]` tables to enable LDAPS on either hop.
- `policies/ldap.toml` (schema in
  [policies/ldap.example.toml](policies/ldap.example.toml)) — an ordered
  list of `[[policy]]` tables. The only type today is `"threshold"`
  (`max_per_request`, `max_per_window`, `window_secs`).

Both files are gitignored (see [.gitignore](.gitignore)); `ai-protect`
fails fast with a message pointing at the matching example file if either
is missing.

## Running

```sh
cargo run                        # loads ./config.toml
cargo run -- other-config.toml   # load config from a different path
```

With the example config, this listens on `127.0.0.1:3890` and proxies to
an upstream LDAP server on `127.0.0.1:389`, blocking any single request
with blast radius over `10` and any identity exceeding `50` cumulative
blast radius in a `60s` window. Point an LDAP client at `127.0.0.1:3890`
instead of the real directory to exercise it.

Logging is off by default; enable it with `RUST_LOG`:

```sh
RUST_LOG=info cargo run
```

## Local testing

[compose.yaml](compose.yaml) runs a disposable
[lldap](https://github.com/lldap/lldap) directory as a stand-in upstream:

```sh
cp .env.example .env   # fill in real secrets, see comments in the file
docker compose up -d lldap
```

[test.sh](test.sh) is a full end-to-end test: it brings up that container,
builds and runs the real `ai-protect` binary in front of it, and drives
both through the proxy and directly upstream with the system
`ldapsearch`/`ldapmodify`/`ldapwhoami`/`ldappasswd` tools to confirm
pass-through, per-request blocking, and sliding-window blocking all work
over the wire, with every decision landing in the audit log. Requires
`docker` (compose), `cargo`, and the OpenLDAP client tools.

```sh
./test.sh
```

## Development

```sh
cargo check    # type/borrow check
cargo fmt      # format
cargo clippy   # lint
cargo test     # unit + in-process integration tests
./test.sh      # real end-to-end test against a live LDAP server
```

CI ([.github/workflows/ci.yaml](.github/workflows/ci.yaml)) runs `cargo
build`/`cargo test` on stable, beta, and nightly for every push and PR.

## Documentation

- [AGENTS.md](AGENTS.md) — module map and conventions for anyone (human or
  agent) working on this codebase
- [ARCHITECTURE.md](ARCHITECTURE.md) — system design, request lifecycle,
  extension points, and known gaps
- [TODO.md](TODO.md) — gap list between the current state and a
  production-ready deployment
