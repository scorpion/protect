//! Programmatic construction of a proxy, for embedding `ai-protect` in a
//! host application without going through a TOML config file. See
//! `ai_protect::run`/`run_with_config` for the file-driven entry points.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::watch;

use crate::core::connector::Connector;
use crate::core::policy::Policy;
use crate::core::tls::ListenTls;
use crate::error::{Error, Result};
use crate::proxy::{self, ConnectionLimits};

/// Builds a proxy from in-memory pieces — a connector and policies you
/// construct yourself — and runs it. This is the entry point for embedding
/// `ai-protect` as a library rather than driving it from a config file.
pub struct ProxyBuilder {
    listen_addr: SocketAddr,
    listen_tls: Option<ListenTls>,
    listen_starttls: Option<ListenTls>,
    connector: Option<Arc<dyn Connector>>,
    policies: Vec<Arc<dyn Policy>>,
    // Set by `policies_reloadable` to override `policies` above with a
    // caller-driven, live-updatable source — see that method.
    policies_rx: Option<watch::Receiver<Vec<Arc<dyn Policy>>>>,
    limits: ConnectionLimits,
    shutdown: watch::Receiver<bool>,
    // Keeps the default shutdown channel's `Sender` alive for as long as this
    // builder exists, so `shutdown` never fires on its own — see
    // `ProxyBuilder::shutdown` for how a caller replaces both halves with
    // their own.
    _default_shutdown_tx: Option<watch::Sender<bool>>,
}

impl ProxyBuilder {
    /// Starts a builder for a proxy that will listen on `listen_addr`. Runs
    /// forever (until error) unless `shutdown` is called to wire up a signal
    /// this builder should drain and stop on.
    pub fn new(listen_addr: SocketAddr) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            listen_addr,
            listen_tls: None,
            listen_starttls: None,
            connector: None,
            policies: Vec::new(),
            policies_rx: None,
            limits: ConnectionLimits::default(),
            shutdown: shutdown_rx,
            _default_shutdown_tx: Some(shutdown_tx),
        }
    }

    /// Wires up a shutdown signal: once `shutdown` carries `true`, `serve`
    /// stops accepting new connections, waits up to `limits`'s
    /// `shutdown_timeout` for in-flight ones to finish on their own, then
    /// aborts whatever's left. The caller keeps the paired `Sender` (e.g.
    /// `tokio::sync::watch::channel(false)`) to trigger it — typically from
    /// a `SIGTERM`/`SIGINT` handler.
    pub fn shutdown(mut self, shutdown: watch::Receiver<bool>) -> Self {
        self.shutdown = shutdown;
        self._default_shutdown_tx = None;
        self
    }

    /// Terminate TLS on `listen_addr` for incoming client connections.
    /// Omit this to listen in plaintext.
    pub fn listen_tls(mut self, listen_tls: ListenTls) -> Self {
        self.listen_tls = Some(listen_tls);
        self
    }

    /// Accept plaintext connections on `listen_addr`, but let a client
    /// upgrade to TLS mid-session via RFC 4511 StartTLS, using
    /// `listen_starttls` for the handshake once one requests it. Ignored if
    /// `listen_tls` is also set — implicit TLS wins and StartTLS is moot
    /// once the connection is already encrypted from the first byte.
    pub fn listen_starttls(mut self, listen_starttls: ListenTls) -> Self {
        self.listen_starttls = Some(listen_starttls);
        self
    }

    /// Sets the connector used to reach the upstream backend and interpret
    /// its protocol. Required before calling `serve`.
    pub fn connector(mut self, connector: Arc<dyn Connector>) -> Self {
        self.connector = Some(connector);
        self
    }

    /// Appends one policy to the ordered list evaluated for every decoded
    /// action (see `core::policy::evaluate_all` for ordering semantics).
    pub fn policy(mut self, policy: Arc<dyn Policy>) -> Self {
        self.policies.push(policy);
        self
    }

    /// Appends every policy in `policies`, preserving order.
    pub fn policies(mut self, policies: Vec<Arc<dyn Policy>>) -> Self {
        self.policies.extend(policies);
        self
    }

    /// Wires up a live-updatable policy source, overriding whatever was
    /// added via `policy`/`policies`: `serve` re-reads it
    /// (`watch::Receiver::borrow`) for every newly-accepted connection, so
    /// pushing a new `Vec` through the paired `Sender` (typically from a
    /// config-reload signal such as `SIGHUP`) changes policy without a
    /// restart. A connection already in flight keeps running under whichever
    /// list was current when it was accepted — see "Config hot-reload" in
    /// ARCHITECTURE.md.
    pub fn policies_reloadable(mut self, policies: watch::Receiver<Vec<Arc<dyn Policy>>>) -> Self {
        self.policies_rx = Some(policies);
        self
    }

    /// Overrides the default concurrent-connection cap and I/O timeout
    /// (1024 connections / 60s — see `ConnectionLimits::default`).
    pub fn limits(mut self, limits: ConnectionLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Binds `listen_addr` and runs the accept loop. Only returns on error
    /// (the accept loop otherwise runs forever).
    pub async fn serve(self) -> Result<()> {
        let connector = self.connector.ok_or(Error::MissingConnector)?;
        let policies = self
            .policies_rx
            .unwrap_or_else(|| watch::channel(self.policies).1);
        proxy::run(
            self.listen_addr,
            self.listen_tls,
            self.listen_starttls,
            connector,
            policies,
            self.limits,
            self.shutdown,
        )
        .await
        .map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rasn_ldap::{LdapResult, ModifyResponse, ProtocolOp, ResultCode};
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::connector::ldap::LdapConnector;
    use crate::connector::ldap::read_frame;
    use crate::connector::ldap::test_support::{encode_message, modify_request_frame};
    use crate::core::policy::threshold::{ThresholdConfig, ThresholdPolicy};

    /// Reserves a free `127.0.0.1` port by binding and immediately dropping
    /// a listener on it. `ProxyBuilder::serve` binds its own listener
    /// internally (unlike `proxy::serve`, which tests can hand a pre-bound
    /// one directly), so this is the only way to learn an address to embed
    /// in `ProxyBuilder::new` ahead of time.
    async fn reserve_free_addr() -> SocketAddr {
        TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
    }

    #[tokio::test]
    async fn embeds_a_proxy_with_no_config_file() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let request_frame = modify_request_frame(
            1,
            "cn=alice,dc=example,dc=com",
            "userAccountControl",
            b"514",
        );
        let response_frame = encode_message(
            1,
            ProtocolOp::ModifyResponse(ModifyResponse(LdapResult::new(
                ResultCode::Success,
                "".into(),
                "".into(),
            ))),
        );

        let expected_request = request_frame.clone();
        let canned_response = response_frame.clone();
        tokio::spawn(async move {
            let (mut upstream_stream, _) = upstream_listener.accept().await.unwrap();
            let received = read_frame(&mut upstream_stream).await.unwrap().unwrap();
            assert_eq!(received, expected_request);
            upstream_stream.write_all(&canned_response).await.unwrap();
        });

        let proxy_addr = reserve_free_addr().await;
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        let policy = Arc::new(ThresholdPolicy::new(ThresholdConfig {
            max_per_request: 10,
            max_per_window: 10,
            window: Duration::from_secs(60),
            state_db: None,
            flush_interval: Duration::from_secs(2),
        }));

        tokio::spawn(
            ProxyBuilder::new(proxy_addr)
                .connector(connector)
                .policy(policy)
                .serve(),
        );

        // Give the accept loop a moment to bind before the client connects.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        client_stream.write_all(&request_frame).await.unwrap();

        let received_response = read_frame(&mut client_stream).await.unwrap().unwrap();
        assert_eq!(received_response, response_frame);
    }

    #[tokio::test]
    async fn serve_without_a_connector_fails_fast() {
        let proxy_addr = reserve_free_addr().await;

        let err = ProxyBuilder::new(proxy_addr).serve().await.unwrap_err();

        assert!(matches!(err, Error::MissingConnector));
    }

    #[tokio::test]
    async fn shutdown_receiver_stops_serve_once_signaled() {
        // Bound but never connected to — `serve` should return on its own
        // once told to shut down, with no connection needing to drain.
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let proxy_addr = reserve_free_addr().await;
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let serve_task = tokio::spawn(
            ProxyBuilder::new(proxy_addr)
                .connector(connector)
                .shutdown(shutdown_rx)
                .serve(),
        );

        // Give the accept loop a moment to actually start before shutting it
        // down, so this proves a running `serve` stops rather than one that
        // never got that far.
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown_tx.send(true).unwrap();

        tokio::time::timeout(Duration::from_secs(2), serve_task)
            .await
            .expect("serve should return promptly once shutdown is signaled")
            .unwrap()
            .unwrap();
    }
}
