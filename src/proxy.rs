use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::connector::ldap::{LdapConnector, read_frame};
use crate::core::identity::Identity;
use crate::core::net::MaybeTlsStream;
use crate::core::policy::{Decision, Policy, PolicyContext, evaluate_all};
use crate::core::tls::ListenTls;

/// The client-facing connection, either plaintext or LDAPS depending on
/// whether the listener is configured to terminate TLS.
type ClientStream = MaybeTlsStream<tokio_rustls::server::TlsStream<TcpStream>>;

pub async fn run(
    listen_addr: SocketAddr,
    listen_tls: Option<ListenTls>,
    connector: LdapConnector,
    policies: Vec<Arc<dyn Policy>>,
) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("binding listener on {listen_addr}"))?;
    tracing::info!(%listen_addr, "ai-protect listening");

    serve(listener, listen_tls, connector, policies).await
}

/// Accepts connections from an already-bound listener. Split out from `run`
/// so tests can bind an ephemeral port and drive the accept loop directly.
pub async fn serve(
    listener: TcpListener,
    listen_tls: Option<ListenTls>,
    connector: LdapConnector,
    policies: Vec<Arc<dyn Policy>>,
) -> Result<()> {
    loop {
        let (client_stream, peer_addr) = listener.accept().await?;
        let listen_tls = listen_tls.clone();
        let connector = connector.clone();
        let policies = policies.clone();

        tokio::spawn(async move {
            let result = async {
                let client_stream = match &listen_tls {
                    None => MaybeTlsStream::Plain(client_stream),
                    Some(tls) => MaybeTlsStream::Tls(tls.accept(client_stream).await?),
                };
                handle_connection(client_stream, peer_addr, connector, policies).await
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
    connector: LdapConnector,
    policies: Vec<Arc<dyn Policy>>,
) -> Result<()> {
    let upstream_stream = connector.connect_upstream().await?;
    let identity = Identity::from_peer_addr(peer_addr);

    let (mut client_read, client_write) = tokio::io::split(client_stream);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream_stream);
    let client_write = Arc::new(Mutex::new(client_write));

    let upstream_to_client = {
        let client_write = client_write.clone();
        async move { relay_upstream_responses(&mut upstream_read, client_write).await }
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
    upstream_read: &mut (impl AsyncRead + Unpin),
    client_write: Arc<Mutex<WriteHalf<ClientStream>>>,
) -> Result<()> {
    while let Some(frame) = read_frame(upstream_read).await? {
        client_write.lock().await.write_all(&frame).await?;
    }
    Ok(())
}

async fn relay_client_requests(
    client_read: &mut (impl AsyncRead + Unpin),
    upstream_write: &mut (impl AsyncWrite + Unpin),
    client_write: Arc<Mutex<WriteHalf<ClientStream>>>,
    connector: &LdapConnector,
    policies: &[Arc<dyn Policy>],
    identity: &Identity,
) -> Result<()> {
    while let Some(frame) = read_frame(client_read).await? {
        let Some(action) = connector.decode(&frame)? else {
            upstream_write.write_all(&frame).await?;
            continue;
        };

        let ctx = PolicyContext {
            identity: identity.clone(),
        };
        let decision = evaluate_all(policies, &action, &ctx);
        crate::core::audit::log_decision(identity, &action, &decision);

        match decision {
            Decision::Allow => upstream_write.write_all(&frame).await?,
            Decision::Block { reason } => {
                let rejection = connector.build_rejection(&frame, &reason)?;
                client_write.lock().await.write_all(&rejection).await?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rasn_ldap::{LdapResult, ModifyResponse, ProtocolOp, ResultCode};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    use super::*;
    use crate::core::policy::threshold::{ThresholdConfig, ThresholdPolicy};
    use crate::core::tls::UpstreamTls;
    use crate::test_support::{
        decode_message, encode_message, modify_request_frame, self_signed_tls,
    };

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
        let connector = LdapConnector::new(upstream_addr, None);
        tokio::spawn(serve(proxy_listener, None, connector, allow_all_policies()));

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
        let connector = LdapConnector::new(upstream_addr, None);
        tokio::spawn(serve(proxy_listener, None, connector, block_all_policies()));

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
        let connector = LdapConnector::new(upstream_addr, None);
        tokio::spawn(serve(
            proxy_listener,
            Some(listen_tls),
            connector,
            allow_all_policies(),
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
        let connector = LdapConnector::new(upstream_addr, Some(upstream_tls));

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(serve(proxy_listener, None, connector, allow_all_policies()));

        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        client_stream.write_all(&request_frame).await.unwrap();

        let received_response = read_frame(&mut client_stream).await.unwrap().unwrap();
        assert_eq!(received_response, response_frame);
    }
}
