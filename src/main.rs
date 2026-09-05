mod audit;
mod config;
mod connector;
mod identity;
mod policy;
mod proxy;
#[cfg(test)]
mod test_support;

use std::sync::Arc;

use anyhow::Result;
use policy::threshold::ThresholdPolicy;
use policy::Policy;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config = config::Config::dev_default();
    let connector = connector::ldap::LdapConnector::new(config.upstream_addr);
    let threshold_policy: Arc<dyn Policy> = Arc::new(ThresholdPolicy::new(config.threshold));
    let policies = vec![threshold_policy];

    proxy::run(config.listen_addr, connector, policies).await
}
