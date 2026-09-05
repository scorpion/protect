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
//! - [`run`] — fully file-driven: reads a [`config::Config`] and its
//!   referenced policy file from disk, the same thing the `ai-protect`
//!   binary does.
//! - [`run_with_config`] — takes a [`config::Config`] you already have in
//!   memory (its fields are all `pub`, so it's constructible without TOML),
//!   but still loads policies from the file it references.
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
/// policies it describes, and runs the proxy's accept loop (which only
/// returns on error, since it otherwise runs forever).
pub async fn run(config_path: impl AsRef<Path>) -> Result<()> {
    let config = config::Config::load(config_path)?;
    run_with_config(&config).await
}

/// Wires up the connector and policies described by an in-memory `Config`
/// (policies are still loaded from the file `config.policy.file` points
/// at) and runs the proxy's accept loop.
pub async fn run_with_config(config: &config::Config) -> Result<()> {
    let upstream_tls = config
        .proxy
        .upstream_tls
        .as_ref()
        .map(|tls| core::tls::UpstreamTls::new(&tls.server_name, tls.ca_file.as_deref()))
        .transpose()?;
    let connector: Arc<dyn core::connector::Connector> = Arc::new(
        connector::ldap::LdapConnector::new(config.proxy.upstream_addr, upstream_tls),
    );

    let listen_tls = config
        .proxy
        .listen_tls
        .as_ref()
        .map(|tls| core::tls::ListenTls::from_files(&tls.cert_file, &tls.key_file))
        .transpose()?;

    let policies = core::policy::config::load(&config.policy.file)?;

    let mut builder = builder::ProxyBuilder::new(config.proxy.listen_addr)
        .connector(connector)
        .policies(policies);
    if let Some(listen_tls) = listen_tls {
        builder = builder.listen_tls(listen_tls);
    }
    builder.serve().await
}
