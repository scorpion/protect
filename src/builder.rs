//! Programmatic construction of a proxy, for embedding `ai-protect` in a
//! host application without going through a TOML config file. See
//! `ai_protect::run`/`run_with_config` for the file-driven entry points.

use std::net::SocketAddr;
use std::sync::Arc;

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
    limits: ConnectionLimits,
}

impl ProxyBuilder {
    /// Starts a builder for a proxy that will listen on `listen_addr`.
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            listen_tls: None,
            listen_starttls: None,
            connector: None,
            policies: Vec::new(),
            limits: ConnectionLimits::default(),
        }
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
        proxy::run(
            self.listen_addr,
            self.listen_tls,
            self.listen_starttls,
            connector,
            self.policies,
            self.limits,
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
}
