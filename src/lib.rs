//! `ai-protect` is an inline TCP proxy for directory-service protocols (LDAP
//! today) that inspects traffic in-flight, normalizes operations it cares
//! about into a backend-agnostic `Action`, and runs a policy engine over
//! that action before forwarding or rejecting it. See `AGENTS.md` /
//! `ARCHITECTURE.md` for the full picture.

pub mod config;
pub mod connector;
pub mod core;
pub mod proxy;

use anyhow::{Context, Result};

/// Loads configuration from `config_path`, wires up the connector and
/// policies it describes, and runs the proxy's accept loop (which only
/// returns on error, since it otherwise runs forever).
pub async fn run(config_path: &str) -> Result<()> {
    let config = config::Config::load(config_path)?;

    let upstream_tls = config
        .proxy
        .upstream_tls
        .as_ref()
        .map(|tls| core::tls::UpstreamTls::new(&tls.server_name, tls.ca_file.as_deref()))
        .transpose()
        .context("configuring upstream TLS")?;
    let connector = connector::ldap::LdapConnector::new(config.proxy.upstream_addr, upstream_tls);

    let listen_tls = config
        .proxy
        .listen_tls
        .as_ref()
        .map(|tls| core::tls::ListenTls::from_files(&tls.cert_file, &tls.key_file))
        .transpose()
        .context("configuring listener TLS")?;

    let policies = core::policy::config::load(&config.policy.file)
        .with_context(|| format!("loading policies referenced by {config_path}"))?;

    proxy::run(config.proxy.listen_addr, listen_tls, connector, policies).await
}
