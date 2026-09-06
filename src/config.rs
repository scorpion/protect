use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::proxy::ConnectionLimits;

/// Failure modes for loading `Config` from a TOML file.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading config file {path} (copy config.example.toml to get started)")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing config file {path}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

type Result<T> = std::result::Result<T, ConfigError>;

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
    /// Present to accept plaintext connections on `listen_addr` but let a
    /// client upgrade to TLS mid-session via RFC 4511 StartTLS instead of
    /// dialing implicit LDAPS from the first byte. Ignored if `listen_tls`
    /// is also set.
    #[serde(default)]
    pub listen_starttls: Option<ListenTlsConfig>,
    /// Maximum number of client connections handled concurrently; beyond
    /// this, new connections are closed immediately instead of queued.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Seconds allowed for any single read or write on either hop of a
    /// connection (TLS handshakes included) before it's dropped as stalled
    /// — also acts as an idle-connection timeout.
    #[serde(default = "default_io_timeout_secs")]
    pub io_timeout_secs: u64,
}

fn default_max_connections() -> usize {
    ConnectionLimits::default().max_connections
}

fn default_io_timeout_secs() -> u64 {
    ConnectionLimits::default().io_timeout.as_secs()
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
    /// Client certificate ai-protect presents to the upstream. Needed when
    /// the directory requires mutual TLS on this hop rather than trusting
    /// whoever dials in.
    #[serde(default)]
    pub client_cert: Option<ClientCertConfig>,
    /// When true, `connect_upstream` dials the upstream in plaintext and
    /// negotiates RFC 4511 StartTLS before performing the TLS handshake
    /// described by this table, instead of dialing straight into implicit
    /// TLS (LDAPS) — for directories standardized on the plaintext LDAP
    /// port plus StartTLS rather than a dedicated LDAPS port.
    #[serde(default)]
    pub starttls: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenTlsConfig {
    /// PEM-encoded certificate (chain) presented to clients.
    pub cert_file: PathBuf,
    /// PEM-encoded private key matching `cert_file`.
    pub key_file: PathBuf,
    /// PEM-encoded CA certificate(s) used to verify client certificates on
    /// this listener. When present, ai-protect requires and verifies a
    /// client certificate from every connecting client (mutual TLS) instead
    /// of trusting whoever can reach the socket — authenticating *which*
    /// agent is connecting rather than just its source IP.
    #[serde(default)]
    pub client_ca_file: Option<PathBuf>,
}

/// A certificate/key pair used to present a client certificate during a TLS
/// handshake (upstream mutual TLS today; shared shape in case the listener
/// side ever needs to present one too).
#[derive(Debug, Clone, Deserialize)]
pub struct ClientCertConfig {
    pub cert_file: PathBuf,
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
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&raw).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
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
        assert_eq!(
            config.proxy.max_connections,
            ConnectionLimits::default().max_connections
        );
        assert_eq!(
            config.proxy.io_timeout_secs,
            ConnectionLimits::default().io_timeout.as_secs()
        );
    }

    #[test]
    fn parses_connection_limit_overrides() {
        let config: Config = toml::from_str(
            r#"
            [proxy]
            listen_addr = "127.0.0.1:3890"
            upstream_addr = "127.0.0.1:389"
            max_connections = 10
            io_timeout_secs = 5

            [policy]
            file = "policies/ldap.toml"
            "#,
        )
        .unwrap();

        assert_eq!(config.proxy.max_connections, 10);
        assert_eq!(config.proxy.io_timeout_secs, 5);
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
        assert!(upstream_tls.client_cert.is_none());
        assert!(listen_tls.client_ca_file.is_none());
        assert!(!upstream_tls.starttls);
        assert!(config.proxy.listen_starttls.is_none());
    }

    #[test]
    fn parses_config_with_starttls() {
        let config: Config = toml::from_str(
            r#"
            [proxy]
            listen_addr = "127.0.0.1:3890"
            upstream_addr = "127.0.0.1:389"

            [proxy.upstream_tls]
            server_name = "dc01.corp.example.com"
            starttls = true

            [proxy.listen_starttls]
            cert_file = "certs/server.pem"
            key_file = "certs/server.key"

            [policy]
            file = "policies/ldap.toml"
            "#,
        )
        .unwrap();

        assert!(config.proxy.upstream_tls.unwrap().starttls);
        let listen_starttls = config.proxy.listen_starttls.unwrap();
        assert_eq!(listen_starttls.cert_file, PathBuf::from("certs/server.pem"));
        assert_eq!(listen_starttls.key_file, PathBuf::from("certs/server.key"));
    }

    #[test]
    fn parses_config_with_mutual_tls() {
        let config: Config = toml::from_str(
            r#"
            [proxy]
            listen_addr = "127.0.0.1:6360"
            upstream_addr = "127.0.0.1:636"

            [proxy.upstream_tls]
            server_name = "dc01.corp.example.com"
            ca_file = "certs/internal-ca.pem"

            [proxy.upstream_tls.client_cert]
            cert_file = "certs/ai-protect-client.pem"
            key_file = "certs/ai-protect-client.key"

            [proxy.listen_tls]
            cert_file = "certs/server.pem"
            key_file = "certs/server.key"
            client_ca_file = "certs/agent-ca.pem"

            [policy]
            file = "policies/ldap.toml"
            "#,
        )
        .unwrap();

        let upstream_tls = config.proxy.upstream_tls.unwrap();
        let client_cert = upstream_tls.client_cert.unwrap();
        assert_eq!(
            client_cert.cert_file,
            PathBuf::from("certs/ai-protect-client.pem")
        );
        assert_eq!(
            client_cert.key_file,
            PathBuf::from("certs/ai-protect-client.key")
        );

        let listen_tls = config.proxy.listen_tls.unwrap();
        assert_eq!(
            listen_tls.client_ca_file,
            Some(PathBuf::from("certs/agent-ca.pem"))
        );
    }

    #[test]
    fn load_reports_missing_file_clearly() {
        let err = Config::load("/nonexistent/path/config.toml").unwrap_err();

        assert!(err.to_string().contains("reading config file"));
        assert!(matches!(err, ConfigError::Read { .. }));
    }
}
