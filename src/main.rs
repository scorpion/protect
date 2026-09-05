mod audit;
mod config;
mod connector;
mod identity;
mod policy;
mod proxy;
#[cfg(test)]
mod test_support;

use anyhow::{Context, Result};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());
    let config = config::Config::load(&config_path)?;

    let connector = connector::ldap::LdapConnector::new(config.proxy.upstream_addr);
    let policies = policy::config::load(&config.policy.file)
        .with_context(|| format!("loading policies referenced by {config_path}"))?;

    proxy::run(config.proxy.listen_addr, connector, policies).await
}
