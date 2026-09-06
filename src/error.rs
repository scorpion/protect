//! The crate's public aggregate error, returned by the top-level entry
//! points (`run`, `run_with_config`, `ProxyBuilder::serve`). Each variant
//! wraps a module-local error type that lives next to the code that
//! produces it — this type just gives callers one thing to match on.

/// Failure modes for the library's public setup/config surface: loading a
/// `Config` or policy file, building TLS configuration, or binding the
/// listener. Runtime, per-connection errors are intentionally not part of
/// this type — they're caught and logged per-connection rather than
/// returned to any caller (see `proxy::serve`).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Policy(#[from] crate::core::policy::config::PolicyConfigError),
    #[error(transparent)]
    Tls(#[from] crate::core::tls::TlsError),
    #[error(transparent)]
    Proxy(#[from] crate::proxy::ProxyError),
    #[error(transparent)]
    Metrics(#[from] metrics_exporter_prometheus::BuildError),
    #[error(transparent)]
    Health(#[from] crate::core::health::HealthError),
    #[error("proxy builder requires a connector before serving")]
    MissingConnector,
}

pub type Result<T> = std::result::Result<T, Error>;
