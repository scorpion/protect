# Builds and runs the ai-protect binary itself (as opposed to
# docker/lldap and docker/valkey, which stand up test/HA-support
# dependencies) — see "No deployment packaging" in TODO.md.
#
# Deliberately doesn't bake config.toml/policies/*.toml/certs/ into the
# image: those are gitignored (secrets, environment-specific addresses —
# see .gitignore) and ai-protect already fails fast with a clear message if
# either file is missing, so mount them at runtime instead, e.g.:
#
#   docker build -f docker/rust/Dockerfile -t ai-protect .
#   docker run --rm \
#     -p 3890:3890 \
#     -v "$PWD/config.toml:/app/config.toml:ro" \
#     -v "$PWD/policies:/app/policies:ro" \
#     ai-protect

# Compiles the release binary (LTO + single codegen unit, per Cargo.toml's
# [profile.release]) against a pinned Debian base so the runtime stage
# below can match its glibc version exactly.
FROM rust:1-slim-bookworm AS builder
WORKDIR /build

# Cached separately from the real source so editing src/ doesn't invalidate
# (and re-download/re-build) the dependency graph on every build.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo "fn main() {}" > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src target/release/deps/ai_protect-*

COPY src ./src
RUN cargo build --release --locked

# Minimal runtime image: just the binary, its dynamic dependencies, and a
# CA trust store — rustls-native-certs (see src/core/tls.rs) reads
# /etc/ssl/certs for the OS trust store used to validate the upstream
# directory's certificate over LDAPS/StartTLS when no explicit ca_file is
# configured.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 ai-protect

COPY --from=builder /build/target/release/ai-protect /usr/local/bin/ai-protect

# Owned by the unprivileged user above: main.rs resolves config.toml and
# ./logs relative to the working directory, and creates the latter on
# startup, so it needs to be writable by whoever the process runs as.
WORKDIR /app
RUN chown ai-protect:ai-protect /app
USER ai-protect

ENTRYPOINT ["ai-protect"]
CMD ["config.toml"]
