//! `ai-protect` is an inline TCP proxy for directory-service protocols (LDAP
//! today) that inspects traffic in-flight, normalizes operations it cares
//! about into a backend-agnostic `Action`, and runs a policy engine over
//! that action before forwarding or rejecting it. See `AGENTS.md` /
//! `ARCHITECTURE.md` for the full picture.
//!
//! ## Using ai-protect as a library
//!
//! Three entry points cover different amounts of "load this from a file":
//!
//! - [`run`] — fully file-driven: reads a [`config::Config`] (one or more
//!   `[[proxy]]` entries, each with its own listener/upstream/policy file)
//!   from disk, the same thing the `ai-protect` binary does.
//! - [`run_with_config`] — takes a [`config::Config`] you already have in
//!   memory (its fields are all `pub`, so it's constructible without TOML),
//!   but still loads each entry's policies from the file it references.
//!   Every `[[proxy]]` entry runs concurrently; if one exits (normally only
//!   on error), the rest are stopped and the error is returned.
//! - [`builder::ProxyBuilder`] — fully programmatic: construct a
//!   [`core::connector::Connector`] (e.g.
//!   [`connector::ldap::LdapConnector`], or your own backend) and a list of
//!   [`core::policy::Policy`]s (e.g. [`core::policy::threshold::ThresholdPolicy`])
//!   yourself, with no file I/O at all.

pub mod builder;
pub mod config;
pub mod connector;
pub mod core;
pub mod error;
pub mod proxy;

use std::path::Path;
use std::sync::Arc;

pub use error::{Error, Result};

/// Loads configuration from `config_path`, wires up the connector and
/// policies each `[[proxy]]` entry describes, and runs every entry's accept
/// loop concurrently (which only returns on the first entry to error, since
/// each accept loop otherwise runs forever).
pub async fn run(config_path: impl AsRef<Path>) -> Result<()> {
    let config = config::Config::load(config_path)?;
    run_with_config(&config).await
}

/// Builds one `ProxyBuilder` from a single `[[proxy]]` entry of an in-memory
/// `Config` (policies are still loaded from the file `proxy.policy.file`
/// points at).
fn build_proxy(proxy: &config::ProxyConfig) -> Result<builder::ProxyBuilder> {
    let upstream_tls = proxy
        .upstream_tls
        .as_ref()
        .map(|tls| {
            let client_cert = tls
                .client_cert
                .as_ref()
                .map(|c| (c.cert_file.as_path(), c.key_file.as_path()));
            core::tls::UpstreamTls::new(&tls.server_name, tls.ca_file.as_deref(), client_cert)
        })
        .transpose()?;
    let upstream_starttls = proxy.upstream_tls.as_ref().is_some_and(|tls| tls.starttls);
    let connector: Arc<dyn core::connector::Connector> = Arc::new(
        connector::ldap::LdapConnector::new(proxy.upstream_addr, upstream_tls)
            .with_starttls(upstream_starttls),
    );

    let listen_tls = proxy
        .listen_tls
        .as_ref()
        .map(|tls| {
            core::tls::ListenTls::from_files(
                &tls.cert_file,
                &tls.key_file,
                tls.client_ca_file.as_deref(),
            )
        })
        .transpose()?;
    let listen_starttls = proxy
        .listen_starttls
        .as_ref()
        .map(|tls| {
            core::tls::ListenTls::from_files(
                &tls.cert_file,
                &tls.key_file,
                tls.client_ca_file.as_deref(),
            )
        })
        .transpose()?;

    let policies = core::policy::config::load(&proxy.policy.file)?;

    let limits = proxy::ConnectionLimits {
        max_connections: proxy.max_connections,
        io_timeout: std::time::Duration::from_secs(proxy.io_timeout_secs),
    };

    let mut builder = builder::ProxyBuilder::new(proxy.listen_addr)
        .connector(connector)
        .policies(policies)
        .limits(limits);
    if let Some(listen_tls) = listen_tls {
        builder = builder.listen_tls(listen_tls);
    }
    if let Some(listen_starttls) = listen_starttls {
        builder = builder.listen_starttls(listen_starttls);
    }
    Ok(builder)
}

/// Wires up every `[[proxy]]` entry described by an in-memory `Config` (each
/// with its own connector, TLS settings, and policy file) and runs all of
/// their accept loops concurrently as sibling tasks in a `JoinSet`. Returns
/// as soon as any one of them exits — normally that only happens on error,
/// so this mirrors a single proxy's "runs forever until something goes
/// wrong" behavior. Dropping the `JoinSet` on the way out aborts every
/// still-running sibling, so one entry's fatal error brings down the whole
/// process rather than leaving the others silently orphaned.
pub async fn run_with_config(config: &config::Config) -> Result<()> {
    let mut builders = Vec::with_capacity(config.proxy.len());
    for proxy in &config.proxy {
        builders.push(build_proxy(proxy)?);
    }

    let mut tasks = tokio::task::JoinSet::new();
    for builder in builders {
        tasks.spawn(builder.serve());
    }

    match tasks.join_next().await {
        Some(Ok(result)) => result,
        Some(Err(join_err)) => std::panic::resume_unwind(join_err.into_panic()),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use rasn_ldap::{LdapResult, ModifyResponse, ProtocolOp, ResultCode};
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::connector::ldap::read_frame;
    use crate::connector::ldap::test_support::{encode_message, modify_request_frame};

    /// Reserves a free `127.0.0.1` port by binding and immediately dropping a
    /// listener on it, for embedding in a `Config` built ahead of time (this
    /// module only exercises the config-driven path, which binds its own
    /// listener internally).
    async fn reserve_free_addr() -> SocketAddr {
        TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
    }

    /// Wires up two independent `[[proxy]]` entries — separate listeners,
    /// separate upstreams, sharing one (empty, allow-everything) policy file
    /// — and proves both are actually served concurrently by a single
    /// `run_with_config` call, not just the first one.
    #[tokio::test]
    async fn run_with_config_serves_every_proxy_entry_concurrently() {
        let policy_file = tempfile::NamedTempFile::new().unwrap();

        let request_frame = |message_id: u32| {
            modify_request_frame(
                message_id,
                "cn=alice,dc=example,dc=com",
                "userAccountControl",
                b"514",
            )
        };
        let response_frame = |message_id: u32| {
            encode_message(
                message_id,
                ProtocolOp::ModifyResponse(ModifyResponse(LdapResult::new(
                    ResultCode::Success,
                    "".into(),
                    "".into(),
                ))),
            )
        };

        let upstream_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_a_addr = upstream_a.local_addr().unwrap();
        let upstream_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_b_addr = upstream_b.local_addr().unwrap();

        for (upstream, message_id) in [(upstream_a, 1u32), (upstream_b, 2u32)] {
            tokio::spawn(async move {
                let (mut stream, _) = upstream.accept().await.unwrap();
                let received = read_frame(&mut stream).await.unwrap().unwrap();
                assert_eq!(received, request_frame(message_id));
                stream.write_all(&response_frame(message_id)).await.unwrap();
            });
        }

        let proxy_a_addr = reserve_free_addr().await;
        let proxy_b_addr = reserve_free_addr().await;

        let toml = format!(
            r#"
            [[proxy]]
            listen_addr = "{proxy_a_addr}"
            upstream_addr = "{upstream_a_addr}"

            [proxy.policy]
            file = "{policy_path}"

            [[proxy]]
            listen_addr = "{proxy_b_addr}"
            upstream_addr = "{upstream_b_addr}"

            [proxy.policy]
            file = "{policy_path}"
            "#,
            policy_path = policy_file.path().display(),
        );
        let config: config::Config = toml::from_str(&toml).unwrap();

        tokio::spawn(async move { run_with_config(&config).await });

        // Give both accept loops a moment to bind before clients connect.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        for (proxy_addr, message_id) in [(proxy_a_addr, 1u32), (proxy_b_addr, 2u32)] {
            let mut client = TcpStream::connect(proxy_addr).await.unwrap();
            client.write_all(&request_frame(message_id)).await.unwrap();
            let received = read_frame(&mut client).await.unwrap().unwrap();
            assert_eq!(received, response_frame(message_id));
        }
    }
}
