use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};

/// rustls 0.23 requires a process-wide default crypto provider before any
/// `ClientConfig`/`ServerConfig` can be built. Installing twice (e.g. across
/// tests in the same process) is harmless, so callers just ignore the result.
fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// TLS settings for connecting to the upstream directory over LDAPS.
#[derive(Clone)]
pub struct UpstreamTls {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

impl UpstreamTls {
    /// `server_name` is used for SNI and to validate the upstream's
    /// certificate against its DNS name — needed because the upstream is
    /// otherwise addressed by IP, and directory certificates are typically
    /// issued for a hostname rather than an IP.
    ///
    /// When `ca_file` is given, it replaces the OS trust store as the sole
    /// root of trust — the usual case for directories whose LDAPS
    /// certificate is signed by an internal/enterprise CA that may not be
    /// present on the host running ai-protect.
    pub fn new(server_name: &str, ca_file: Option<&Path>) -> Result<Self> {
        ensure_crypto_provider();

        let mut roots = RootCertStore::empty();
        match ca_file {
            Some(path) => {
                for cert in load_certs(path)? {
                    roots
                        .add(cert)
                        .context("adding custom CA certificate to upstream trust store")?;
                }
            }
            None => {
                for cert in rustls_native_certs::load_native_certs().certs {
                    roots
                        .add(cert)
                        .context("adding native root certificate to upstream trust store")?;
                }
            }
        }

        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = ServerName::try_from(server_name.to_string())
            .with_context(|| format!("invalid upstream TLS server name {server_name:?}"))?;

        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            server_name,
        })
    }

    pub(crate) async fn connect(&self, tcp: TcpStream) -> Result<client::TlsStream<TcpStream>> {
        self.connector
            .connect(self.server_name.clone(), tcp)
            .await
            .context("establishing LDAPS session with upstream")
    }
}

/// TLS settings for terminating LDAPS on ai-protect's client-facing listener.
#[derive(Clone)]
pub struct ListenTls {
    acceptor: TlsAcceptor,
}

impl ListenTls {
    pub fn from_files(cert_file: &Path, key_file: &Path) -> Result<Self> {
        ensure_crypto_provider();

        let certs = load_certs(cert_file)?;
        let key = load_key(key_file)?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("building TLS server config from cert/key")?;

        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
        })
    }

    pub(crate) async fn accept(&self, tcp: TcpStream) -> Result<server::TlsStream<TcpStream>> {
        self.acceptor
            .accept(tcp)
            .await
            .context("completing LDAPS handshake with client")
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)
        .with_context(|| format!("opening TLS certificate file {}", path.display()))?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing TLS certificate file {}", path.display()))
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file =
        File::open(path).with_context(|| format!("opening TLS key file {}", path.display()))?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .with_context(|| format!("parsing TLS key file {}", path.display()))?
        .ok_or_else(|| anyhow!("no private key found in {}", path.display()))
}
