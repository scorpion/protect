mod audit;
mod config;
mod connector;
mod identity;
mod net;
mod policy;
mod proxy;
#[cfg(test)]
mod test_support;
mod tls;

use anyhow::{Context, Result};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());
    let config = config::Config::load(&config_path)?;

    let upstream_tls = config
        .proxy
        .upstream_tls
        .as_ref()
        .map(|tls| tls::UpstreamTls::new(&tls.server_name, tls.ca_file.as_deref()))
        .transpose()
        .context("configuring upstream TLS")?;
    let connector = connector::ldap::LdapConnector::new(config.proxy.upstream_addr, upstream_tls);

    let listen_tls = config
        .proxy
        .listen_tls
        .as_ref()
        .map(|tls| tls::ListenTls::from_files(&tls.cert_file, &tls.key_file))
        .transpose()
        .context("configuring listener TLS")?;

    let policies = policy::config::load(&config.policy.file)
        .with_context(|| format!("loading policies referenced by {config_path}"))?;

    proxy::run(config.proxy.listen_addr, listen_tls, connector, policies).await
}
