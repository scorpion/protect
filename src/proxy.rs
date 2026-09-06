use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, WriteHalf};
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
    listen_starttls: Option<ListenTls>,
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

    serve(
        listener,
        listen_tls,
        listen_starttls,
        connector,
        policies,
        limits,
    )
    .await
}

/// Accepts connections from an already-bound listener. Split out from `run`
/// so tests can bind an ephemeral port and drive the accept loop directly.
pub async fn serve(
    listener: TcpListener,
    listen_tls: Option<ListenTls>,
    listen_starttls: Option<ListenTls>,
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
        let listen_starttls = listen_starttls.clone();
        let connector = connector.clone();
        let policies = policies.clone();
        let io_timeout = limits.io_timeout;

        tokio::spawn(async move {
            let _permit = permit;
            let result = async {
                // LDAP is request/response with lots of small frames; without
                // this, Nagle's algorithm plus delayed ACKs can add tens of
                // milliseconds of latency to every round trip.
                client_stream
                    .set_nodelay(true)
                    .context("setting TCP_NODELAY on client connection")?;
                let client_stream = match &listen_tls {
                    None => MaybeTlsStream::Plain(client_stream),
                    Some(tls) => MaybeTlsStream::Tls(
                        with_timeout(io_timeout, async { Ok(tls.accept(client_stream).await?) })
                            .await?,
                    ),
                };
                handle_connection(
                    client_stream,
                    peer_addr,
                    connector,
                    policies,
                    listen_starttls,
                    io_timeout,
                )
                .await
            }
            .await;

            if let Err(err) = result {
                tracing::warn!(%peer_addr, error = %err, "connection ended with error");
            }
        });
    }
}

/// If `client_stream` is still plaintext and `listen_starttls` is
/// configured, peeks the first frame off it: an RFC 4511 StartTLS extended
/// request is answered and the connection is upgraded to TLS in place
/// before any relaying starts; anything else is handed back as `Some(frame)`
/// so the caller treats it as an ordinary first request instead of losing
/// it. A no-op (returns `client_stream` unchanged and `None`) when
/// `listen_starttls` isn't configured or the stream is already TLS
/// (implicit TLS already covers the "which agent" question StartTLS would
/// otherwise answer here).
async fn maybe_upgrade_to_tls(
    client_stream: ClientStream,
    listen_starttls: &Option<ListenTls>,
    connector: &Arc<dyn Connector>,
    io_timeout: Duration,
) -> Result<(ClientStream, Option<Vec<u8>>)> {
    let (starttls, mut tcp) = match (listen_starttls, client_stream) {
        (Some(starttls), MaybeTlsStream::Plain(tcp)) => (starttls, tcp),
        (_, client_stream) => return Ok((client_stream, None)),
    };

    let Some(frame) = with_timeout(io_timeout, connector.read_frame(&mut tcp)).await? else {
        return Ok((MaybeTlsStream::Plain(tcp), None));
    };

    match connector.upgrade_request(&frame)? {
        Some(response) => {
            with_timeout(io_timeout, async { Ok(tcp.write_all(&response).await?) }).await?;
            let tls_stream =
                with_timeout(io_timeout, async { Ok(starttls.accept(tcp).await?) }).await?;
            Ok((MaybeTlsStream::Tls(tls_stream), None))
        }
        None => Ok((MaybeTlsStream::Plain(tcp), Some(frame))),
    }
}

async fn handle_connection(
    client_stream: ClientStream,
    peer_addr: SocketAddr,
    connector: Arc<dyn Connector>,
    policies: Vec<Arc<dyn Policy>>,
    listen_starttls: Option<ListenTls>,
    io_timeout: Duration,
) -> Result<()> {
    let (client_stream, first_client_frame) =
        maybe_upgrade_to_tls(client_stream, &listen_starttls, &connector, io_timeout).await?;

    let upstream_stream = with_timeout(io_timeout, connector.connect_upstream()).await?;
    // Starting identity, in place until (and unless) a simple LDAP bind names
    // a DN — see `ClientRelayContext`/`handle_client_frame`.
    let identity = Identity::from_peer_addr(peer_addr);

    let (client_read, client_write) = tokio::io::split(client_stream);
    let (upstream_read, mut upstream_write) = tokio::io::split(upstream_stream);
    // `read_frame` pulls a message apart in several small `read_exact` calls
    // (tag, length byte(s), content); buffering coalesces those into far
    // fewer syscalls per frame on the plaintext path.
    let mut client_read = BufReader::new(client_read);
    let mut upstream_read = BufReader::new(upstream_read);
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
        let mut identity = identity;
        let ctx = ClientRelayContext {
            connector: &connector,
            policies: &policies,
            io_timeout,
        };
        async move {
            relay_client_requests(
                &mut client_read,
                &mut upstream_write,
                client_write,
                first_client_frame,
                &mut identity,
                &ctx,
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

/// Groups the pieces `handle_client_frame` needs beyond the frame and I/O
/// handles themselves, so it and `relay_client_requests` stay under
/// clippy's argument-count lint instead of growing a parameter for every
/// policy-evaluation dependency. `identity` isn't here: unlike these fields,
/// it can change mid-connection (a bind can replace it), so it's threaded
/// through separately as `&mut Identity`.
struct ClientRelayContext<'a> {
    connector: &'a Arc<dyn Connector>,
    policies: &'a [Arc<dyn Policy>],
    io_timeout: Duration,
}

async fn relay_client_requests(
    client_read: &mut (impl AsyncRead + Unpin + Send),
    upstream_write: &mut (impl AsyncWrite + Unpin),
    client_write: Arc<Mutex<WriteHalf<ClientStream>>>,
    first_frame: Option<Vec<u8>>,
    identity: &mut Identity,
    ctx: &ClientRelayContext<'_>,
) -> Result<()> {
    if let Some(frame) = first_frame {
        handle_client_frame(frame, upstream_write, &client_write, identity, ctx).await?;
    }

    while let Some(frame) =
        with_timeout(ctx.io_timeout, ctx.connector.read_frame(client_read)).await?
    {
        handle_client_frame(frame, upstream_write, &client_write, identity, ctx).await?;
    }
    Ok(())
}

async fn handle_client_frame(
    frame: Vec<u8>,
    upstream_write: &mut (impl AsyncWrite + Unpin),
    client_write: &Arc<Mutex<WriteHalf<ClientStream>>>,
    identity: &mut Identity,
    ctx: &ClientRelayContext<'_>,
) -> Result<()> {
    // A successful simple bind ties this connection to a real,
    // password-verified principal — a strictly more specific identity than
    // the peer address it replaces, so later frames on this connection are
    // policed and audited under the bind DN instead.
    if let Some(dn) = ctx.connector.bind_identity(&frame)? {
        *identity = Identity(dn);
    }

    let Some(action) = ctx.connector.decode(&frame)? else {
        return with_timeout(ctx.io_timeout, async {
            Ok(upstream_write.write_all(&frame).await?)
        })
        .await;
    };

    let policy_ctx = PolicyContext {
        identity: identity.clone(),
    };
    let decision = evaluate_all(ctx.policies, &action, &policy_ctx);
    crate::core::audit::log_decision(identity, &action, &decision);

    match decision {
        Decision::Allow => {
            with_timeout(ctx.io_timeout, async {
                Ok(upstream_write.write_all(&frame).await?)
            })
            .await
        }
        Decision::Block { reason } => {
            let rejection = ctx.connector.build_rejection(&frame, &reason)?;
            with_timeout(ctx.io_timeout, async {
                Ok(client_write.lock().await.write_all(&rejection).await?)
            })
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rasn_ldap::{
        DelResponse, ExtendedRequest, ExtendedResponse, LdapResult, ModifyResponse, ProtocolOp,
        ResultCode,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    use super::*;
    use crate::connector::ldap::test_support::{
        bind_request_frame, decode_message, del_request_frame, encode_message,
        extended_request_frame, modify_request_frame, password_modify_request_frame,
    };
    use crate::connector::ldap::{LdapConnector, START_TLS_OID, read_frame};
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
    async fn blocked_delete_never_reaches_upstream_and_client_gets_del_response() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut upstream_stream, _) = upstream_listener.accept().await.unwrap();
            let result =
                timeout(Duration::from_millis(200), read_frame(&mut upstream_stream)).await;
            assert!(
                result.is_err(),
                "blocked bulk delete must never reach upstream"
            );
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        tokio::spawn(serve(
            proxy_listener,
            None,
            None,
            connector,
            block_all_policies(),
            ConnectionLimits::default(),
        ));

        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        let request_frame = del_request_frame(7, "cn=alice,dc=example,dc=com");
        client_stream.write_all(&request_frame).await.unwrap();

        let rejection = read_frame(&mut client_stream).await.unwrap().unwrap();
        let message = decode_message(&rejection);
        assert_eq!(message.message_id, 7);
        match message.protocol_op {
            ProtocolOp::DelResponse(DelResponse(result)) => {
                assert_eq!(result.result_code, ResultCode::UnwillingToPerform);
            }
            other => panic!("expected DelResponse, got {other:?}"),
        }

        // Give the upstream task a moment to finish asserting it never received the frame.
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    #[tokio::test]
    async fn blocked_password_modify_never_reaches_upstream_and_client_gets_extended_response() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut upstream_stream, _) = upstream_listener.accept().await.unwrap();
            let result =
                timeout(Duration::from_millis(200), read_frame(&mut upstream_stream)).await;
            assert!(
                result.is_err(),
                "blocked password reset must never reach upstream"
            );
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        tokio::spawn(serve(
            proxy_listener,
            None,
            None,
            connector,
            block_all_policies(),
            ConnectionLimits::default(),
        ));

        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        let request_frame = password_modify_request_frame(7, Some("cn=alice,dc=example,dc=com"));
        client_stream.write_all(&request_frame).await.unwrap();

        let rejection = read_frame(&mut client_stream).await.unwrap().unwrap();
        let message = decode_message(&rejection);
        assert_eq!(message.message_id, 7);
        match message.protocol_op {
            ProtocolOp::ExtendedResp(ExtendedResponse { result_code, .. }) => {
                assert_eq!(result_code, ResultCode::UnwillingToPerform);
            }
            other => panic!("expected ExtendedResp, got {other:?}"),
        }

        // Give the upstream task a moment to finish asserting it never received the frame.
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    #[tokio::test]
    async fn bind_dn_becomes_identity_so_same_peer_gets_separate_budgets() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let bind_response = |message_id: u32| {
            encode_message(
                message_id,
                ProtocolOp::BindResponse(rasn_ldap::BindResponse::new(
                    ResultCode::Success,
                    "".into(),
                    "".into(),
                    None,
                    None,
                )),
            )
        };
        let modify_response = |message_id: u32| {
            encode_message(
                message_id,
                ProtocolOp::ModifyResponse(ModifyResponse(LdapResult::new(
                    ResultCode::Success,
                    "".into(),
                    "".into(),
                ))),
            )
        };

        // Two connections, each binding then locking a different account.
        // Answers a bind with a BindResponse and a modify with a
        // ModifyResponse so the test client can tell "reached upstream and
        // succeeded" apart from "blocked locally" without caring about exact
        // bytes.
        tokio::spawn(async move {
            for _ in 0..2 {
                let (mut upstream_stream, _) = upstream_listener.accept().await.unwrap();

                let bind_frame = read_frame(&mut upstream_stream).await.unwrap().unwrap();
                let message_id = decode_message(&bind_frame).message_id;
                upstream_stream
                    .write_all(&bind_response(message_id))
                    .await
                    .unwrap();

                let modify_frame = read_frame(&mut upstream_stream).await.unwrap().unwrap();
                let message_id = decode_message(&modify_frame).message_id;
                upstream_stream
                    .write_all(&modify_response(message_id))
                    .await
                    .unwrap();
            }
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        // Budget for exactly one action per identity: if both connections
        // below (same loopback source address) shared a budget keyed by
        // peer address, the second modify would be blocked instead of
        // reaching upstream.
        let policies: Vec<Arc<dyn Policy>> =
            vec![Arc::new(ThresholdPolicy::new(ThresholdConfig {
                max_per_request: 10,
                max_per_window: 1,
                window: Duration::from_secs(60),
            }))];
        tokio::spawn(serve(
            proxy_listener,
            None,
            None,
            connector,
            policies,
            ConnectionLimits::default(),
        ));

        let assert_modify_reached_upstream =
            |frame: &[u8], who: &str| match decode_message(frame).protocol_op {
                ProtocolOp::ModifyResponse(ModifyResponse(result)) => {
                    assert_eq!(
                        result.result_code,
                        ResultCode::Success,
                        "{who}'s modify should have reached upstream, not been blocked locally"
                    );
                }
                other => panic!("expected ModifyResponse, got {other:?}"),
            };

        let mut alice_stream = TcpStream::connect(proxy_addr).await.unwrap();
        alice_stream
            .write_all(&bind_request_frame(1, "cn=alice,dc=example,dc=com"))
            .await
            .unwrap();
        read_frame(&mut alice_stream).await.unwrap().unwrap();
        alice_stream
            .write_all(&modify_request_frame(
                2,
                "cn=alice,dc=example,dc=com",
                "userAccountControl",
                b"514",
            ))
            .await
            .unwrap();
        let alice_reply = read_frame(&mut alice_stream).await.unwrap().unwrap();
        assert_modify_reached_upstream(&alice_reply, "alice");

        let mut bob_stream = TcpStream::connect(proxy_addr).await.unwrap();
        bob_stream
            .write_all(&bind_request_frame(1, "cn=bob,dc=example,dc=com"))
            .await
            .unwrap();
        read_frame(&mut bob_stream).await.unwrap().unwrap();
        bob_stream
            .write_all(&modify_request_frame(
                2,
                "cn=bob,dc=example,dc=com",
                "userAccountControl",
                b"514",
            ))
            .await
            .unwrap();
        let bob_reply = read_frame(&mut bob_stream).await.unwrap().unwrap();
        assert_modify_reached_upstream(&bob_reply, "bob");
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

        let listen_tls =
            ListenTls::from_files(tls.cert_file.path(), tls.key_file.path(), None).unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        tokio::spawn(serve(
            proxy_listener,
            Some(listen_tls),
            None,
            connector,
            allow_all_policies(),
            ConnectionLimits::default(),
        ));

        let client_dialer =
            UpstreamTls::new(tls.server_name, Some(tls.cert_file.path()), None).unwrap();
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
            ListenTls::from_files(tls.cert_file.path(), tls.key_file.path(), None).unwrap();
        tokio::spawn(async move {
            let (tcp, _) = upstream_listener.accept().await.unwrap();
            let mut upstream_stream = upstream_acceptor.accept(tcp).await.unwrap();
            let received = read_frame(&mut upstream_stream).await.unwrap().unwrap();
            assert_eq!(received, expected_request);
            upstream_stream.write_all(&canned_response).await.unwrap();
        });

        let upstream_tls =
            UpstreamTls::new(tls.server_name, Some(tls.cert_file.path()), None).unwrap();
        let connector: Arc<dyn Connector> =
            Arc::new(LdapConnector::new(upstream_addr, Some(upstream_tls)));

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(serve(
            proxy_listener,
            None,
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
    async fn client_facing_mtls_relays_when_client_presents_trusted_certificate() {
        let server_tls = self_signed_tls("localhost");
        let trusted_client = self_signed_tls("agent-1");

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

        let listen_tls = ListenTls::from_files(
            server_tls.cert_file.path(),
            server_tls.key_file.path(),
            Some(trusted_client.cert_file.path()),
        )
        .unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        tokio::spawn(serve(
            proxy_listener,
            Some(listen_tls),
            None,
            connector,
            allow_all_policies(),
            ConnectionLimits::default(),
        ));

        let client_dialer = UpstreamTls::new(
            server_tls.server_name,
            Some(server_tls.cert_file.path()),
            Some((
                trusted_client.cert_file.path(),
                trusted_client.key_file.path(),
            )),
        )
        .unwrap();
        let tcp = TcpStream::connect(proxy_addr).await.unwrap();
        let mut client_stream = client_dialer.connect(tcp).await.unwrap();

        client_stream.write_all(&request_frame).await.unwrap();
        let received_response = read_frame(&mut client_stream).await.unwrap().unwrap();
        assert_eq!(received_response, response_frame);
    }

    /// TLS 1.3's client considers its handshake done once it's sent its own
    /// `Finished`, before it's seen how the server reacted to the client
    /// certificate it (didn't) present — so a client-auth rejection doesn't
    /// necessarily surface as an error from `connect()` itself. The server
    /// aborts the connection right after, so it always shows up as either a
    /// failed handshake or the very next read failing/hitting EOF.
    async fn client_tls_was_rejected(dialer: &UpstreamTls, tcp: TcpStream) -> bool {
        let mut client_stream = match dialer.connect(tcp).await {
            Ok(stream) => stream,
            Err(_) => return true,
        };
        let mut buf = [0u8; 1];
        match timeout(Duration::from_secs(2), client_stream.read(&mut buf))
            .await
            .expect("server should reject the connection promptly, not leave it hanging")
        {
            Ok(0) => true,
            Ok(_) => false,
            Err(_) => true,
        }
    }

    #[tokio::test]
    async fn client_facing_mtls_rejects_client_without_trusted_certificate() {
        let server_tls = self_signed_tls("localhost");
        let trusted_client = self_signed_tls("agent-1");
        // A real, distinct identity — just not the one the listener trusts.
        let untrusted_client = self_signed_tls("agent-2");

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let listen_tls = ListenTls::from_files(
            server_tls.cert_file.path(),
            server_tls.key_file.path(),
            Some(trusted_client.cert_file.path()),
        )
        .unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        tokio::spawn(serve(
            proxy_listener,
            Some(listen_tls),
            None,
            connector,
            allow_all_policies(),
            ConnectionLimits::default(),
        ));

        let no_cert_dialer = UpstreamTls::new(
            server_tls.server_name,
            Some(server_tls.cert_file.path()),
            None,
        )
        .unwrap();
        let tcp = TcpStream::connect(proxy_addr).await.unwrap();
        assert!(
            client_tls_was_rejected(&no_cert_dialer, tcp).await,
            "connection must be rejected when no client certificate is presented"
        );

        let untrusted_dialer = UpstreamTls::new(
            server_tls.server_name,
            Some(server_tls.cert_file.path()),
            Some((
                untrusted_client.cert_file.path(),
                untrusted_client.key_file.path(),
            )),
        )
        .unwrap();
        let tcp = TcpStream::connect(proxy_addr).await.unwrap();
        assert!(
            client_tls_was_rejected(&untrusted_dialer, tcp).await,
            "connection must be rejected when the presented certificate isn't signed by the trusted client CA"
        );
    }

    #[tokio::test]
    async fn proxy_presents_client_certificate_to_upstream_mtls() {
        let tls = self_signed_tls("dc01.corp.example.com");
        let proxy_identity = self_signed_tls("ai-protect");

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
        // Requiring a client cert here means this test only passes if
        // `UpstreamTls` actually presents one during the handshake.
        let upstream_acceptor = ListenTls::from_files(
            tls.cert_file.path(),
            tls.key_file.path(),
            Some(proxy_identity.cert_file.path()),
        )
        .unwrap();
        tokio::spawn(async move {
            let (tcp, _) = upstream_listener.accept().await.unwrap();
            let mut upstream_stream = upstream_acceptor.accept(tcp).await.unwrap();
            let received = read_frame(&mut upstream_stream).await.unwrap().unwrap();
            assert_eq!(received, expected_request);
            upstream_stream.write_all(&canned_response).await.unwrap();
        });

        let upstream_tls = UpstreamTls::new(
            tls.server_name,
            Some(tls.cert_file.path()),
            Some((
                proxy_identity.cert_file.path(),
                proxy_identity.key_file.path(),
            )),
        )
        .unwrap();
        let connector: Arc<dyn Connector> =
            Arc::new(LdapConnector::new(upstream_addr, Some(upstream_tls)));

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(serve(
            proxy_listener,
            None,
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
    async fn client_starttls_upgrades_plaintext_connection_to_tls() {
        let server_tls = self_signed_tls("localhost");

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let request_frame = modify_request_frame(
            2,
            "cn=alice,dc=example,dc=com",
            "userAccountControl",
            b"514",
        );
        let response_frame = encode_message(
            2,
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

        let listen_starttls = ListenTls::from_files(
            server_tls.cert_file.path(),
            server_tls.key_file.path(),
            None,
        )
        .unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        tokio::spawn(serve(
            proxy_listener,
            None,
            Some(listen_starttls),
            connector,
            allow_all_policies(),
            ConnectionLimits::default(),
        ));

        let mut plain_stream = TcpStream::connect(proxy_addr).await.unwrap();
        plain_stream
            .write_all(&extended_request_frame(1, START_TLS_OID))
            .await
            .unwrap();
        let starttls_response = read_frame(&mut plain_stream).await.unwrap().unwrap();
        let message = decode_message(&starttls_response);
        assert_eq!(message.message_id, 1);
        match message.protocol_op {
            ProtocolOp::ExtendedResp(ExtendedResponse { result_code, .. }) => {
                assert_eq!(result_code, ResultCode::Success);
            }
            other => panic!("expected ExtendedResp, got {other:?}"),
        }

        // The StartTLS confirmation arrived over plaintext; the rest of the
        // session is only readable by completing a TLS handshake on the
        // same socket, proving the proxy actually upgraded it in place.
        let client_dialer = UpstreamTls::new(
            server_tls.server_name,
            Some(server_tls.cert_file.path()),
            None,
        )
        .unwrap();
        let mut client_stream = client_dialer.connect(plain_stream).await.unwrap();

        client_stream.write_all(&request_frame).await.unwrap();
        let received_response = read_frame(&mut client_stream).await.unwrap().unwrap();
        assert_eq!(received_response, response_frame);
    }

    #[tokio::test]
    async fn client_skips_starttls_and_still_works_when_it_is_configured() {
        let server_tls = self_signed_tls("localhost");

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

        // StartTLS is configured but opportunistic: a client that never
        // asks for it should be relayed exactly as if it weren't set up.
        let listen_starttls = ListenTls::from_files(
            server_tls.cert_file.path(),
            server_tls.key_file.path(),
            None,
        )
        .unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        tokio::spawn(serve(
            proxy_listener,
            None,
            Some(listen_starttls),
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
    async fn proxy_negotiates_starttls_with_upstream() {
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
            ListenTls::from_files(tls.cert_file.path(), tls.key_file.path(), None).unwrap();
        tokio::spawn(async move {
            let (mut tcp, _) = upstream_listener.accept().await.unwrap();

            let starttls_request = read_frame(&mut tcp).await.unwrap().unwrap();
            let message = decode_message(&starttls_request);
            match message.protocol_op {
                ProtocolOp::ExtendedReq(ExtendedRequest { request_name, .. }) => {
                    assert_eq!(request_name.as_ref(), START_TLS_OID.as_bytes());
                }
                other => panic!("expected ExtendedReq, got {other:?}"),
            }
            let starttls_response = encode_message(
                message.message_id,
                ProtocolOp::ExtendedResp(ExtendedResponse {
                    result_code: ResultCode::Success,
                    matched_dn: "".into(),
                    diagnostic_message: "".into(),
                    referral: None,
                    response_name: None,
                    response_value: None,
                }),
            );
            tcp.write_all(&starttls_response).await.unwrap();

            let mut upstream_stream = upstream_acceptor.accept(tcp).await.unwrap();
            let received = read_frame(&mut upstream_stream).await.unwrap().unwrap();
            assert_eq!(received, expected_request);
            upstream_stream.write_all(&canned_response).await.unwrap();
        });

        let upstream_tls =
            UpstreamTls::new(tls.server_name, Some(tls.cert_file.path()), None).unwrap();
        let connector: Arc<dyn Connector> =
            Arc::new(LdapConnector::new(upstream_addr, Some(upstream_tls)).with_starttls(true));

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(serve(
            proxy_listener,
            None,
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
