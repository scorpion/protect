use std::net::SocketAddr;
use std::time::Duration;

use crate::policy::threshold::ThresholdConfig;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub upstream_addr: SocketAddr,
    pub threshold: ThresholdConfig,
}

impl Config {
    /// Hardcoded starting point until config-file loading (TOML/YAML) lands.
    pub fn dev_default() -> Self {
        Self {
            listen_addr: "127.0.0.1:3890".parse().unwrap(),
            upstream_addr: "127.0.0.1:389".parse().unwrap(),
            threshold: ThresholdConfig {
                max_per_request: 10,
                max_per_window: 50,
                window: Duration::from_secs(60),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_default_binds_locally_with_a_sane_threshold() {
        let config = Config::dev_default();

        assert_eq!(config.listen_addr.ip().to_string(), "127.0.0.1");
        assert_eq!(config.listen_addr.port(), 3890);
        assert_eq!(config.upstream_addr.port(), 389);
        assert!(config.threshold.max_per_request <= config.threshold.max_per_window);
        assert!(config.threshold.window.as_secs() > 0);
    }
}
