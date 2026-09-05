use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

/// Process configuration, loaded from a TOML file (see `config.example.toml`
/// for the schema and `[Config::load]` for how the path is resolved).
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub policy: PolicySource,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    pub upstream_addr: SocketAddr,
}

/// Points at the TOML file describing the policies to run against decoded
/// actions (see `src/policy/config.rs`). Kept separate from `Config` itself
/// so policy definitions — which may encode deployment-specific thresholds
/// or naming — can be gitignored and iterated on independently of process
/// config.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicySource {
    pub file: PathBuf,
}

impl Config {
    /// Reads and parses a TOML config file from `path`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path).with_context(|| {
            format!(
                "reading config file {} (copy config.example.toml to get started)",
                path.display()
            )
        })?;
        toml::from_str(&raw).with_context(|| format!("parsing config file {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let config: Config = toml::from_str(
            r#"
            [proxy]
            listen_addr = "127.0.0.1:3890"
            upstream_addr = "127.0.0.1:389"

            [policy]
            file = "policies/ldap.toml"
            "#,
        )
        .unwrap();

        assert_eq!(config.proxy.listen_addr.to_string(), "127.0.0.1:3890");
        assert_eq!(config.proxy.upstream_addr.port(), 389);
        assert_eq!(config.policy.file, PathBuf::from("policies/ldap.toml"));
    }

    #[test]
    fn load_reports_missing_file_clearly() {
        let err = Config::load("/nonexistent/path/config.toml").unwrap_err();

        assert!(err.to_string().contains("reading config file"));
    }
}
