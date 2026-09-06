use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};

use crate::core::connector::Connector;
use crate::core::identity::Identity;
use crate::core::net::MaybeTlsStream;
use crate::core::policy::{Decision, Policy, PolicyContext, evaluate_all};
use crate::core::tls::ListenTls;

/// The client-facing connection, either plaintext or LDAPS depending on
/// whether the listener is configured to terminate TLS.
type ClientStream = MaybeTlsStream<tokio_rustls::server::TlsStream<TcpStream>>;

/// Failure modes for standing up or running the accept loop itself — as
/// opposed to a single connection's errors, which are caught and logged
/// per-connection rather than propagated here.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("binding listener on {addr}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("accepting connection")]
    Accept(#[source] std::io::Error),
}

/// Caps and timeouts applied per connection so a slow-loris client or a hung
/// upstream can't pin an accept-loop task and its memory indefinitely.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionLimits {
    /// Maximum number of connections handled concurrently. Connections
    /// beyond this are accepted off the OS backlog and then immediately
    /// closed, rather than queued.
    pub max_connections: usize,
    /// Deadline applied to every individual read/write on both hops of a
    /// connection, including TLS handshakes. Doubles as an idle timeout —
    /// a side that goes quiet (or trickles data) for longer than this gets
    /// disconnected.
    pub io_timeout: Duration,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            io_timeout: Duration::from_secs(60),
        }
    }
}

/// Races `fut` against `io_timeout`, turning an expired deadline into an
/// error so callers can handle it the same way as any other I/O failure
/// (log and drop the connection).
async fn with_timeout<T>(io_timeout: Duration, fut: impl Future<Output = Result<T>>) -> Result<T> {
    match tokio::time::timeout(io_timeout, fut).await {
        Ok(result) => result,
        Err(_) => bail!("timed out after {io_timeout:?}"),
    }
}

pub async fn run(
    listen_addr: SocketAddr,
    listen_tls: Option<ListenTls>,
    connector: Arc<dyn Connector>,
    policies: Vec<Arc<dyn Policy>>,
    limits: ConnectionLimits,
) -> std::result::Result<(), ProxyError> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|source| ProxyError::Bind {
            addr: listen_addr,
            source,
        })?;
    tracing::info!(%listen_addr, "ai-protect listening");

    serve(listener, listen_tls, connector, policies, limits).await
}

/// Accepts connections from an already-bound listener. Split out from `run`
/// so tests can bind an ephemeral port and drive the accept loop directly.
pub async fn serve(
    listener: TcpListener,
    listen_tls: Option<ListenTls>,
    connector: Arc<dyn Connector>,
    policies: Vec<Arc<dyn Policy>>,
    limits: ConnectionLimits,
) -> std::result::Result<(), ProxyError> {
    let semaphore = Arc::new(Semaphore::new(limits.max_connections));

    loop {
        let (client_stream, peer_addr) = listener.accept().await.map_err(ProxyError::Accept)?;

        let Ok(permit) = semaphore.clone().try_acquire_owned() else {
            tracing::warn!(
                %peer_addr,
                max_connections = limits.max_connections,
                "rejecting connection: at concurrent connection limit"
            );
            continue;
        };
        let listen_tls = listen_tls.clone();
        let connector = connector.clone();
        let policies = policies.clone();
        let io_timeout = limits.io_timeout;

        tokio::spawn(async move {
            let _permit = permit;
            let result = async {
                let client_stream = match &listen_tls {
                    None => MaybeTlsStream::Plain(client_stream),
                    Some(tls) => MaybeTlsStream::Tls(
                        with_timeout(io_timeout, async { Ok(tls.accept(client_stream).await?) })
                            .await?,
                    ),
                };
                handle_connection(client_stream, peer_addr, connector, policies, io_timeout).await
            }
            .await;

            if let Err(err) = result {
                tracing::warn!(%peer_addr, error = %err, "connection ended with error");
            }
        });
    }
}

async fn handle_connection(
    client_stream: ClientStream,
    peer_addr: SocketAddr,
    connector: Arc<dyn Connector>,
    policies: Vec<Arc<dyn Policy>>,
    io_timeout: Duration,
) -> Result<()> {
    let upstream_stream = with_timeout(io_timeout, connector.connect_upstream()).await?;
    let identity = Identity::from_peer_addr(peer_addr);

    let (mut client_read, client_write) = tokio::io::split(client_stream);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream_stream);
    let client_write = Arc::new(Mutex::new(client_write));

    let upstream_to_client = {
        let client_write = client_write.clone();
        let connector = connector.clone();
        async move {
            relay_upstream_responses(&mut upstream_read, client_write, &connector, io_timeout).await
        }
    };

    let client_to_upstream = {
        let client_write = client_write.clone();
        async move {
            relay_client_requests(
                &mut client_read,
                &mut upstream_write,
                client_write,
                &connector,
                &policies,
                &identity,
                io_timeout,
            )
            .await
        }
    };

    tokio::select! {
        res = upstream_to_client => res,
        res = client_to_upstream => res,
    }
}

async fn relay_upstream_responses(
    upstream_read: &mut (impl AsyncRead + Unpin + Send),
    client_write: Arc<Mutex<WriteHalf<ClientStream>>>,
    connector: &Arc<dyn Connector>,
    io_timeout: Duration,
) -> Result<()> {
    while let Some(frame) = with_timeout(io_timeout, connector.read_frame(upstream_read)).await? {
        with_timeout(io_timeout, async {
            Ok(client_write.lock().await.write_all(&frame).await?)
        })
        .await?;
    }
    Ok(())
}

async fn relay_client_requests(
    client_read: &mut (impl AsyncRead + Unpin + Send),
    upstream_write: &mut (impl AsyncWrite + Unpin),
    client_write: Arc<Mutex<WriteHalf<ClientStream>>>,
    connector: &Arc<dyn Connector>,
    policies: &[Arc<dyn Policy>],
    identity: &Identity,
    io_timeout: Duration,
) -> Result<()> {
    while let Some(frame) = with_timeout(io_timeout, connector.read_frame(client_read)).await? {
        let Some(action) = connector.decode(&frame)? else {
            with_timeout(io_timeout, async {
                Ok(upstream_write.write_all(&frame).await?)
            })
            .await?;
            continue;
        };

        let ctx = PolicyContext {
            identity: identity.clone(),
        };
        let decision = evaluate_all(policies, &action, &ctx);
        crate::core::audit::log_decision(identity, &action, &decision);

        match decision {
            Decision::Allow => {
                with_timeout(io_timeout, async {
                    Ok(upstream_write.write_all(&frame).await?)
                })
                .await?
            }
            Decision::Block { reason } => {
                let rejection = connector.build_rejection(&frame, &reason)?;
                with_timeout(io_timeout, async {
                    Ok(client_write.lock().await.write_all(&rejection).await?)
                })
                .await?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rasn_ldap::{LdapResult, ModifyResponse, ProtocolOp, ResultCode};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    use super::*;
    use crate::connector::ldap::test_support::{
        decode_message, encode_message, modify_request_frame,
    };
    use crate::connector::ldap::{LdapConnector, read_frame};
    use crate::core::policy::threshold::{ThresholdConfig, ThresholdPolicy};
    use crate::core::tls::UpstreamTls;
    use crate::core::tls::test_support::self_signed_tls;

    fn allow_all_policies() -> Vec<Arc<dyn Policy>> {
        vec![Arc::new(ThresholdPolicy::new(ThresholdConfig {
            max_per_request: 10,
            max_per_window: 10,
            window: Duration::from_secs(60),
        }))]
    }

    fn block_all_policies() -> Vec<Arc<dyn Policy>> {
        vec![Arc::new(ThresholdPolicy::new(ThresholdConfig {
            max_per_request: 0,
            max_per_window: 10,
            window: Duration::from_secs(60),
        }))]
    }

    #[tokio::test]
    async fn allowed_request_forwards_to_upstream_and_response_relays_back() {
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

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        tokio::spawn(serve(
            proxy_listener,
            None,
            connector,
            allow_all_policies(),
            ConnectionLimits::default(),
        ));

        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        client_stream.write_all(&request_frame).await.unwrap();

        let received_response = read_frame(&mut client_stream).await.unwrap().unwrap();
        assert_eq!(received_response, response_frame);
    }

    #[tokio::test]
    async fn blocked_request_never_reaches_upstream_and_client_gets_rejection() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut upstream_stream, _) = upstream_listener.accept().await.unwrap();
            let result =
                timeout(Duration::from_millis(200), read_frame(&mut upstream_stream)).await;
            assert!(result.is_err(), "blocked request must never reach upstream");
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        tokio::spawn(serve(
            proxy_listener,
            None,
            connector,
            block_all_policies(),
            ConnectionLimits::default(),
        ));

        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        let request_frame = modify_request_frame(
            7,
            "cn=alice,dc=example,dc=com",
            "userAccountControl",
            b"514",
        );
        client_stream.write_all(&request_frame).await.unwrap();

        let rejection = read_frame(&mut client_stream).await.unwrap().unwrap();
        let message = decode_message(&rejection);
        assert_eq!(message.message_id, 7);
        match message.protocol_op {
            ProtocolOp::ModifyResponse(ModifyResponse(result)) => {
                assert_eq!(result.result_code, ResultCode::UnwillingToPerform);
            }
            other => panic!("expected ModifyResponse, got {other:?}"),
        }

        // Give the upstream task a moment to finish asserting it never received the frame.
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    #[tokio::test]
    async fn client_facing_ldaps_relays_to_plaintext_upstream() {
        let tls = self_signed_tls("localhost");

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

        let listen_tls = ListenTls::from_files(tls.cert_file.path(), tls.key_file.path()).unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        tokio::spawn(serve(
            proxy_listener,
            Some(listen_tls),
            connector,
            allow_all_policies(),
            ConnectionLimits::default(),
        ));

        let client_dialer = UpstreamTls::new(tls.server_name, Some(tls.cert_file.path())).unwrap();
        let tcp = TcpStream::connect(proxy_addr).await.unwrap();
        let mut client_stream = client_dialer.connect(tcp).await.unwrap();

        client_stream.write_all(&request_frame).await.unwrap();
        let received_response = read_frame(&mut client_stream).await.unwrap().unwrap();
        assert_eq!(received_response, response_frame);
    }

    #[tokio::test]
    async fn proxy_reaches_upstream_over_ldaps() {
        let tls = self_signed_tls("dc01.corp.example.com");

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
        let upstream_acceptor =
            ListenTls::from_files(tls.cert_file.path(), tls.key_file.path()).unwrap();
        tokio::spawn(async move {
            let (tcp, _) = upstream_listener.accept().await.unwrap();
            let mut upstream_stream = upstream_acceptor.accept(tcp).await.unwrap();
            let received = read_frame(&mut upstream_stream).await.unwrap().unwrap();
            assert_eq!(received, expected_request);
            upstream_stream.write_all(&canned_response).await.unwrap();
        });

        let upstream_tls = UpstreamTls::new(tls.server_name, Some(tls.cert_file.path())).unwrap();
        let connector: Arc<dyn Connector> =
            Arc::new(LdapConnector::new(upstream_addr, Some(upstream_tls)));

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(serve(
            proxy_listener,
            None,
            connector,
            allow_all_policies(),
            ConnectionLimits::default(),
        ));

        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        client_stream.write_all(&request_frame).await.unwrap();

        let received_response = read_frame(&mut client_stream).await.unwrap().unwrap();
        assert_eq!(received_response, response_frame);
    }

    #[tokio::test]
    async fn idle_connection_is_closed_after_io_timeout() {
        // Bound but never accepted from — enough for the TCP-level connect
        // in `connect_upstream` to succeed without any data ever flowing.
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        tokio::spawn(serve(
            proxy_listener,
            None,
            connector,
            allow_all_policies(),
            ConnectionLimits {
                max_connections: 10,
                io_timeout: Duration::from_millis(100),
            },
        ));

        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();

        // Send nothing at all. Without an idle timeout this would hang
        // forever; the proxy should drop the connection shortly after the
        // 100ms io_timeout elapses.
        let mut buf = [0u8; 1];
        let read = timeout(Duration::from_secs(2), client_stream.read(&mut buf))
            .await
            .expect("proxy should have closed the idle connection well within 2s");

        assert_eq!(
            read.unwrap(),
            0,
            "expected a clean EOF from the closed connection"
        );
    }

    #[tokio::test]
    async fn connections_beyond_max_are_rejected() {
        // Bound but never accepted from, so the one permitted connection's
        // upstream connect succeeds instantly and then just sits idle,
        // occupying its permit for the duration of the test.
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        tokio::spawn(serve(
            proxy_listener,
            None,
            connector,
            allow_all_policies(),
            ConnectionLimits {
                max_connections: 1,
                io_timeout: Duration::from_secs(10),
            },
        ));

        let _first_client = TcpStream::connect(proxy_addr).await.unwrap();
        // Give the accept loop a moment to spawn the first connection's task
        // and acquire its permit before the second connection races it.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut second_client = TcpStream::connect(proxy_addr).await.unwrap();
        let mut buf = [0u8; 1];
        let read = timeout(Duration::from_secs(2), second_client.read(&mut buf))
            .await
            .expect("connection over the limit should be closed promptly, not left hanging");

        assert_eq!(
            read.unwrap(),
            0,
            "expected the over-limit connection to be closed rather than served"
        );
    }
}
