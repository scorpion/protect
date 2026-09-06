use std::fs::File;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};

/// Failure modes for building or using TLS configuration on either hop
/// (client-facing listener or upstream connection).
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("opening TLS certificate file {path}")]
    OpenCert {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("parsing TLS certificate file {path}")]
    ParseCert {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("opening TLS key file {path}")]
    OpenKey {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("parsing TLS key file {path}")]
    ParseKey {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("no private key found in {path}")]
    NoPrivateKey { path: PathBuf },
    #[error("adding custom CA certificate to upstream trust store")]
    AddCustomCa {
        #[source]
        source: rustls::Error,
    },
    #[error("adding native root certificate to upstream trust store")]
    AddNativeCa {
        #[source]
        source: rustls::Error,
    },
    #[error("setting client certificate for upstream mutual TLS")]
    ClientAuthCert {
        #[source]
        source: rustls::Error,
    },
    #[error("adding client CA certificate to listener's client-auth trust store")]
    AddClientCa {
        #[source]
        source: rustls::Error,
    },
    #[error("building client certificate verifier from client CA")]
    ClientCertVerifier {
        #[source]
        source: rustls::server::VerifierBuilderError,
    },
    #[error("invalid upstream TLS server name {name:?}")]
    InvalidServerName {
        name: String,
        #[source]
        source: rustls::pki_types::InvalidDnsNameError,
    },
    #[error("building TLS server config from cert/key")]
    ServerConfig {
        #[source]
        source: rustls::Error,
    },
    #[error("establishing LDAPS session with upstream")]
    Connect {
        #[source]
        source: io::Error,
    },
    #[error("completing LDAPS handshake with client")]
    Accept {
        #[source]
        source: io::Error,
    },
}

type Result<T> = std::result::Result<T, TlsError>;

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
    ///
    /// When `client_cert` (cert file, key file) is given, it's presented to
    /// the upstream as a client certificate — for directories that require
    /// mutual TLS on this hop rather than trusting whoever dials in.
    pub fn new(
        server_name: &str,
        ca_file: Option<&Path>,
        client_cert: Option<(&Path, &Path)>,
    ) -> Result<Self> {
        ensure_crypto_provider();

        let mut roots = RootCertStore::empty();
        match ca_file {
            Some(path) => {
                for cert in load_certs(path)? {
                    roots
                        .add(cert)
                        .map_err(|source| TlsError::AddCustomCa { source })?;
                }
            }
            None => {
                for cert in rustls_native_certs::load_native_certs().certs {
                    roots
                        .add(cert)
                        .map_err(|source| TlsError::AddNativeCa { source })?;
                }
            }
        }

        let builder = ClientConfig::builder().with_root_certificates(roots);
        let config = match client_cert {
            Some((cert_file, key_file)) => {
                let certs = load_certs(cert_file)?;
                let key = load_key(key_file)?;
                builder
                    .with_client_auth_cert(certs, key)
                    .map_err(|source| TlsError::ClientAuthCert { source })?
            }
            None => builder.with_no_client_auth(),
        };
        let server_name = ServerName::try_from(server_name.to_string()).map_err(|source| {
            TlsError::InvalidServerName {
                name: server_name.to_string(),
                source,
            }
        })?;

        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            server_name,
        })
    }

    pub(crate) async fn connect(&self, tcp: TcpStream) -> Result<client::TlsStream<TcpStream>> {
        self.connector
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|source| TlsError::Connect { source })
    }
}

/// TLS settings for terminating LDAPS on ai-protect's client-facing listener.
#[derive(Clone)]
pub struct ListenTls {
    acceptor: TlsAcceptor,
}

impl ListenTls {
    /// When `client_ca_file` is given, connecting clients must present a
    /// certificate signed by it — mutual TLS, so the proxy authenticates
    /// *which* agent is connecting instead of just trusting whoever can
    /// reach the socket. When absent, any client can complete the handshake
    /// without presenting a certificate, matching prior behavior.
    pub fn from_files(
        cert_file: &Path,
        key_file: &Path,
        client_ca_file: Option<&Path>,
    ) -> Result<Self> {
        ensure_crypto_provider();

        let certs = load_certs(cert_file)?;
        let key = load_key(key_file)?;

        let client_verifier = match client_ca_file {
            Some(path) => {
                let mut roots = RootCertStore::empty();
                for cert in load_certs(path)? {
                    roots
                        .add(cert)
                        .map_err(|source| TlsError::AddClientCa { source })?;
                }
                WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .map_err(|source| TlsError::ClientCertVerifier { source })?
            }
            None => WebPkiClientVerifier::no_client_auth(),
        };

        let config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, key)
            .map_err(|source| TlsError::ServerConfig { source })?;

        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
        })
    }

    pub(crate) async fn accept(&self, tcp: TcpStream) -> Result<server::TlsStream<TcpStream>> {
        self.acceptor
            .accept(tcp)
            .await
            .map_err(|source| TlsError::Accept { source })
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).map_err(|source| TlsError::OpenCert {
        path: path.to_path_buf(),
        source,
    })?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|source| TlsError::ParseCert {
            path: path.to_path_buf(),
            source,
        })
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).map_err(|source| TlsError::OpenKey {
        path: path.to_path_buf(),
        source,
    })?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .map_err(|source| TlsError::ParseKey {
            path: path.to_path_buf(),
            source,
        })?
        .ok_or_else(|| TlsError::NoPrivateKey {
            path: path.to_path_buf(),
        })
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::io::Write;

    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use tempfile::NamedTempFile;

    /// A self-signed cert/key pair (as temp PEM files) valid for `name`, plus
    /// `name` itself for convenience. Being self-signed, the cert doubles as its
    /// own trusted CA for tests that need to configure a custom trust root.
    pub struct TestTls {
        pub server_name: &'static str,
        pub cert_file: NamedTempFile,
        pub key_file: NamedTempFile,
    }

    pub fn self_signed_tls(server_name: &'static str) -> TestTls {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed([server_name.to_string()])
                .expect("generate self-signed test certificate");

        TestTls {
            server_name,
            cert_file: pem_temp_file(&cert.pem()),
            key_file: pem_temp_file(&signing_key.serialize_pem()),
        }
    }

    fn pem_temp_file(pem: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("create temp PEM file");
        file.write_all(pem.as_bytes()).expect("write temp PEM file");
        file
    }
}
