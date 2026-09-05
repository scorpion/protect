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
    /// Present to connect to `upstream_addr` via LDAPS (implicit TLS)
    /// instead of plaintext LDAP.
    #[serde(default)]
    pub upstream_tls: Option<UpstreamTlsConfig>,
    /// Present to have ai-protect itself terminate LDAPS on `listen_addr`
    /// for incoming client connections.
    #[serde(default)]
    pub listen_tls: Option<ListenTlsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamTlsConfig {
    /// DNS name used for SNI and certificate validation against the
    /// upstream. Needed because `upstream_addr` is an IP:port and directory
    /// certificates are typically issued for a hostname, not an IP.
    pub server_name: String,
    /// PEM-encoded CA certificate(s) to trust instead of the OS trust store.
    /// Needed when the upstream's LDAPS certificate is signed by an
    /// internal/enterprise CA.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenTlsConfig {
    /// PEM-encoded certificate (chain) presented to clients.
    pub cert_file: PathBuf,
    /// PEM-encoded private key matching `cert_file`.
    pub key_file: PathBuf,
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
        assert!(config.proxy.upstream_tls.is_none());
        assert!(config.proxy.listen_tls.is_none());
    }

    #[test]
    fn parses_config_with_tls_on_both_hops() {
        let config: Config = toml::from_str(
            r#"
            [proxy]
            listen_addr = "127.0.0.1:6360"
            upstream_addr = "127.0.0.1:636"

            [proxy.upstream_tls]
            server_name = "dc01.corp.example.com"
            ca_file = "certs/internal-ca.pem"

            [proxy.listen_tls]
            cert_file = "certs/server.pem"
            key_file = "certs/server.key"

            [policy]
            file = "policies/ldap.toml"
            "#,
        )
        .unwrap();

        let upstream_tls = config.proxy.upstream_tls.unwrap();
        assert_eq!(upstream_tls.server_name, "dc01.corp.example.com");
        assert_eq!(
            upstream_tls.ca_file,
            Some(PathBuf::from("certs/internal-ca.pem"))
        );
        let listen_tls = config.proxy.listen_tls.unwrap();
        assert_eq!(listen_tls.cert_file, PathBuf::from("certs/server.pem"));
        assert_eq!(listen_tls.key_file, PathBuf::from("certs/server.key"));
    }

    #[test]
    fn load_reports_missing_file_clearly() {
        let err = Config::load("/nonexistent/path/config.toml").unwrap_err();

        assert!(err.to_string().contains("reading config file"));
    }
}
