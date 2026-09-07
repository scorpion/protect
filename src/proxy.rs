use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use parking_lot::Mutex as StdMutex;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore, watch};

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
    /// How long `serve` waits for in-flight connections to finish on their
    /// own once shutdown is requested before it gives up and aborts
    /// whatever's left. See "graceful shutdown" below.
    pub shutdown_timeout: Duration,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            io_timeout: Duration::from_secs(60),
            shutdown_timeout: Duration::from_secs(30),
        }
    }
}

/// Resolves once shutdown has been requested on `shutdown`, including if it
/// was already requested before this call — `wait_for` checks the current
/// value first, so (unlike a bare `changed().await`) a late subscriber can't
/// miss a request that landed before it started watching. A closed channel
/// (every `Sender` dropped without ever sending `true`) is treated as a
/// shutdown request too, fail-safe rather than waiting on it forever.
async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    let _ = shutdown.wait_for(|&requested| requested).await;
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
    policies: watch::Receiver<Vec<Arc<dyn Policy>>>,
    limits: ConnectionLimits,
    shutdown: watch::Receiver<bool>,
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
        shutdown,
    )
    .await
}

/// Accepts connections from an already-bound listener. Split out from `run`
/// so tests can bind an ephemeral port and drive the accept loop directly.
///
/// `shutdown` turning `true` stops the accept loop from taking any *new*
/// connection, then gives every connection already in flight up to
/// `limits.shutdown_timeout` to finish on its own (a client or upstream
/// closing the socket, an `io_timeout`, or the request/response it's
/// mid-handling completing) before forcibly aborting whatever's left — a
/// rolling restart or deploy drains sessions instead of hard-cutting them.
///
/// `policies` is read fresh (`watch::Receiver::borrow`) for every accepted
/// connection, so a config reload (see `ai_protect::run_with_config`) is
/// visible to new connections without a restart; a connection already in
/// flight keeps running under whichever policy list was current when it was
/// accepted; that snapshot is captured once, same as `listen_tls`/
/// `connector` are cloned once per connection rather than re-read per frame.
pub async fn serve(
    listener: TcpListener,
    listen_tls: Option<ListenTls>,
    listen_starttls: Option<ListenTls>,
    connector: Arc<dyn Connector>,
    policies: watch::Receiver<Vec<Arc<dyn Policy>>>,
    limits: ConnectionLimits,
    mut shutdown: watch::Receiver<bool>,
) -> std::result::Result<(), ProxyError> {
    let semaphore = Arc::new(Semaphore::new(limits.max_connections));
    // Tracks every spawned connection task (rather than firing them via a
    // bare `tokio::spawn`) so shutdown can wait for them to finish, and abort
    // whatever's still running past the grace period.
    let mut connections = tokio::task::JoinSet::new();

    loop {
        let accept_result = tokio::select! {
            () = wait_for_shutdown(&mut shutdown) => break,
            result = listener.accept() => result,
        };
        let (client_stream, peer_addr) = accept_result.map_err(ProxyError::Accept)?;

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
        let policies = policies.borrow().clone();
        let io_timeout = limits.io_timeout;

        connections.spawn(async move {
            let _permit = permit;
            let _connection_guard = crate::core::metrics::ConnectionGuard::open();
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
                        with_timeout(io_timeout, async {
                            let accepted = tls.accept(client_stream).await;
                            if accepted.is_err() {
                                crate::core::metrics::record_tls_handshake_failure("listen");
                            }
                            Ok(accepted?)
                        })
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

    let in_flight = connections.len();
    if in_flight == 0 {
        return Ok(());
    }
    tracing::info!(
        in_flight,
        shutdown_timeout = ?limits.shutdown_timeout,
        "shutting down: draining in-flight connections"
    );
    let drained = tokio::time::timeout(limits.shutdown_timeout, async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_ok();
    if !drained {
        tracing::warn!(
            remaining = connections.len(),
            "shutdown grace period elapsed; aborting remaining connections"
        );
        connections.shutdown().await;
    }
    Ok(())
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
            let tls_stream = with_timeout(io_timeout, async {
                let accepted = starttls.accept(tcp).await;
                if accepted.is_err() {
                    crate::core::metrics::record_tls_handshake_failure("listen_starttls");
                }
                Ok(accepted?)
            })
            .await?;
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

    let connect_started = std::time::Instant::now();
    let upstream_stream = with_timeout(io_timeout, connector.connect_upstream()).await?;
    crate::core::metrics::record_upstream_connect(connect_started.elapsed());
    // Starting identity, in place until (and unless) a simple LDAP bind names
    // a DN *and* its BindResponse confirms success — see `BindState`.
    let bind_state = Arc::new(BindState {
        identity: StdMutex::new(Identity::from_peer_addr(peer_addr)),
        pending: StdMutex::new(HashMap::new()),
    });

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
        let bind_state = bind_state.clone();
        async move {
            relay_upstream_responses(
                &mut upstream_read,
                client_write,
                &connector,
                &bind_state,
                io_timeout,
            )
            .await
        }
    };

    let client_to_upstream = {
        let client_write = client_write.clone();
        let ctx = ClientRelayContext {
            connector: &connector,
            policies: &policies,
            io_timeout,
            bind_state: bind_state.clone(),
        };
        async move {
            relay_client_requests(
                &mut client_read,
                &mut upstream_write,
                client_write,
                first_client_frame,
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

/// Shared, connection-scoped state the two concurrently-running relay
/// directions use to promote a connection's `Identity` from a claimed bind
/// DN to a verified one only once the correlated `BindResponse` reports
/// success — closing the gap where a claimed DN was trusted for policy
/// purposes the instant the `BindRequest` frame was seen, before upstream
/// ever had a chance to reject it (see ARCHITECTURE.md#identity). The client
/// direction (`handle_client_frame`) stages a `BindRequest`'s claimed DN in
/// `pending`, keyed by LDAP message ID; the upstream direction
/// (`relay_upstream_responses`) resolves it — promoting `identity` on
/// success, discarding the claim either way — when the matching response
/// arrives. A `parking_lot::Mutex` is enough for both fields: every hold is a
/// short, synchronous map/scalar operation with no `.await` in between, and
/// unlike `std::sync::Mutex`, it doesn't poison on a panic while held, so a
/// panic here can't wedge every future decision on this connection.
struct BindState {
    identity: StdMutex<Identity>,
    pending: StdMutex<HashMap<u32, String>>,
}

/// Bound on how many not-yet-resolved bind claims `BindState.pending` can
/// accumulate on one connection. A well-behaved client's claims are drained
/// promptly by `resolve_pending_bind` as `BindResponse`s arrive, so ordinary
/// use never comes close to this; it exists only to stop a
/// pre-authenticated client (reaching `bind_request` requires no valid
/// credentials at all) from pipelining `BindRequest`s without ever reading a
/// response and growing this map without bound — unconstrained by
/// `max_connections` or `io_timeout`, since both cap *connection* count/
/// idle time, not how much one already-open connection can stage here (see
/// TODO.md).
const MAX_PENDING_BINDS: usize = 1024;

/// Stages `dn` in `pending` under `message_id`, first evicting the
/// oldest (smallest) message ID if `pending` is already at
/// `MAX_PENDING_BINDS` and `message_id` isn't already staged — bounding
/// `pending`'s size regardless of how many claims a connection leaves
/// unresolved. LDAP message IDs aren't guaranteed monotonic by RFC 4511, but
/// real clients issue them that way, and the exact choice of victim doesn't
/// matter for the memory bound this exists to guarantee: eviction only ever
/// runs on a connection that's already misbehaving by leaving
/// `MAX_PENDING_BINDS` binds unresolved, never in ordinary use. Re-staging
/// under a message ID already pending (e.g. a client re-sending under the
/// same still-unresolved ID) overwrites in place and never evicts.
fn stage_pending_bind(pending: &mut HashMap<u32, String>, message_id: u32, dn: String) {
    if pending.len() >= MAX_PENDING_BINDS
        && !pending.contains_key(&message_id)
        && let Some(&oldest) = pending.keys().min()
    {
        pending.remove(&oldest);
        tracing::warn!(
            message_id = oldest,
            max_pending_binds = MAX_PENDING_BINDS,
            "connection has too many outstanding unresolved BindRequests; evicting oldest pending bind claim"
        );
    }
    pending.insert(message_id, dn);
}

async fn relay_upstream_responses(
    upstream_read: &mut (impl AsyncRead + Unpin + Send),
    client_write: Arc<Mutex<WriteHalf<ClientStream>>>,
    connector: &Arc<dyn Connector>,
    bind_state: &BindState,
    io_timeout: Duration,
) -> Result<()> {
    while let Some(frame) = with_timeout(io_timeout, connector.read_frame(upstream_read)).await? {
        resolve_pending_bind(connector, bind_state, &frame)?;
        with_timeout(io_timeout, async {
            Ok(client_write.lock().await.write_all(&frame).await?)
        })
        .await?;
    }
    Ok(())
}

/// If `frame` is the response to a `BindRequest` staged in
/// `bind_state.pending`, resolves it: promotes `bind_state.identity` to the
/// claimed DN when the bind succeeded, and discards the pending entry either
/// way. A bind gets exactly one correlated response, so nothing staged here
/// outlives the connection even if the client never binds again.
fn resolve_pending_bind(
    connector: &Arc<dyn Connector>,
    bind_state: &BindState,
    frame: &[u8],
) -> Result<()> {
    let Some((message_id, success)) = connector.bind_response(frame)? else {
        return Ok(());
    };
    let Some(dn) = bind_state.pending.lock().remove(&message_id) else {
        return Ok(());
    };
    if success {
        *bind_state.identity.lock() = Identity::from_bind_dn(dn);
    }
    Ok(())
}

/// Groups the pieces `handle_client_frame` needs beyond the frame and I/O
/// handles themselves, so it and `relay_client_requests` stay under
/// clippy's argument-count lint instead of growing a parameter for every
/// policy-evaluation dependency.
struct ClientRelayContext<'a> {
    connector: &'a Arc<dyn Connector>,
    policies: &'a [Arc<dyn Policy>],
    io_timeout: Duration,
    bind_state: Arc<BindState>,
}

async fn relay_client_requests(
    client_read: &mut (impl AsyncRead + Unpin + Send),
    upstream_write: &mut (impl AsyncWrite + Unpin),
    client_write: Arc<Mutex<WriteHalf<ClientStream>>>,
    first_frame: Option<Vec<u8>>,
    ctx: &ClientRelayContext<'_>,
) -> Result<()> {
    if let Some(frame) = first_frame {
        handle_client_frame(frame, upstream_write, &client_write, ctx).await?;
    }

    while let Some(frame) =
        with_timeout(ctx.io_timeout, ctx.connector.read_frame(client_read)).await?
    {
        handle_client_frame(frame, upstream_write, &client_write, ctx).await?;
    }
    Ok(())
}

async fn handle_client_frame(
    frame: Vec<u8>,
    upstream_write: &mut (impl AsyncWrite + Unpin),
    client_write: &Arc<Mutex<WriteHalf<ClientStream>>>,
    ctx: &ClientRelayContext<'_>,
) -> Result<()> {
    // A simple bind only *claims* a DN — it's staged here, not trusted yet.
    // `resolve_pending_bind` promotes it to the connection's real `Identity`
    // once (and only if) the correlated `BindResponse` reports success, so a
    // claim that's never actually password-verified upstream can't buy a
    // fresh, empty blast-radius budget under a made-up name.
    if let Some((message_id, dn)) = ctx.connector.bind_request(&frame)? {
        stage_pending_bind(&mut ctx.bind_state.pending.lock(), message_id, dn);
    }

    let Some(action) = ctx.connector.decode(&frame)? else {
        return with_timeout(ctx.io_timeout, async {
            Ok(upstream_write.write_all(&frame).await?)
        })
        .await;
    };

    let identity = ctx.bind_state.identity.lock().clone();
    let policy_ctx = PolicyContext {
        identity: identity.clone(),
    };
    let decision = evaluate_all(ctx.policies, &action, &policy_ctx);
    crate::core::audit::log_decision(&identity, &action, &decision);
    crate::core::metrics::record_decision(&action, &decision);

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
        unauthenticated_bind_request_frame,
    };
    use crate::connector::ldap::{LdapConnector, START_TLS_OID, read_frame};
    use crate::core::policy::threshold::{ThresholdConfig, ThresholdPolicy, ThresholdScope};
    use crate::core::tls::UpstreamTls;
    use crate::core::tls::test_support::self_signed_tls;

    fn allow_all_policies() -> Vec<Arc<dyn Policy>> {
        vec![Arc::new(ThresholdPolicy::new(ThresholdConfig {
            max_per_request: 10,
            max_per_window: 10,
            window: Duration::from_secs(60),
            state_db: None,
            flush_interval: Duration::from_secs(2),
            max_tracked_identities: 100_000,
            scope: ThresholdScope::PerIdentity,
            operations: None,
        }))]
    }

    fn block_all_policies() -> Vec<Arc<dyn Policy>> {
        vec![Arc::new(ThresholdPolicy::new(ThresholdConfig {
            max_per_request: 0,
            max_per_window: 10,
            window: Duration::from_secs(60),
            state_db: None,
            flush_interval: Duration::from_secs(2),
            max_tracked_identities: 100_000,
            scope: ThresholdScope::PerIdentity,
            operations: None,
        }))]
    }

    /// A shutdown receiver that never fires, for tests not exercising
    /// shutdown itself. Leaks the paired `Sender` deliberately — a `serve`
    /// under test must outlive the local variables of the function that
    /// spawned it, so there's no scope to hold a `Sender` in that would keep
    /// it alive for exactly as long as needed; closing it early would
    /// otherwise read as an immediate shutdown request (see
    /// `wait_for_shutdown`).
    fn no_shutdown() -> watch::Receiver<bool> {
        let (tx, rx) = watch::channel(false);
        std::mem::forget(tx);
        rx
    }

    /// Wraps a fixed policy list as the `watch::Receiver` `serve` now
    /// expects, for tests that don't exercise hot-reload itself. Dropping
    /// the paired `Sender` is fine here (unlike `no_shutdown`'s deliberate
    /// leak): this receiver is only ever `borrow()`-ed, never awaited via
    /// `changed`/`wait_for`, so a closed channel doesn't change what it
    /// reports.
    fn policies_rx(policies: Vec<Arc<dyn Policy>>) -> watch::Receiver<Vec<Arc<dyn Policy>>> {
        watch::channel(policies).1
    }

    #[test]
    fn stage_pending_bind_evicts_oldest_message_id_once_at_capacity() {
        let mut pending = HashMap::new();
        for id in 0..MAX_PENDING_BINDS as u32 {
            stage_pending_bind(&mut pending, id, format!("cn=user{id}"));
        }
        assert_eq!(pending.len(), MAX_PENDING_BINDS);

        // A pre-authenticated client pipelining BindRequests without ever
        // reading a response must not grow `pending` past the cap.
        stage_pending_bind(
            &mut pending,
            MAX_PENDING_BINDS as u32,
            "cn=overflow".to_string(),
        );
        assert_eq!(pending.len(), MAX_PENDING_BINDS);
        assert!(
            !pending.contains_key(&0),
            "oldest (smallest) message id should have been evicted to make room"
        );
        assert!(pending.contains_key(&(MAX_PENDING_BINDS as u32)));
    }

    #[test]
    fn stage_pending_bind_restaging_an_existing_id_does_not_evict() {
        let mut pending = HashMap::new();
        for id in 0..MAX_PENDING_BINDS as u32 {
            stage_pending_bind(&mut pending, id, format!("cn=user{id}"));
        }

        // A client re-sending a BindRequest under a message id it already
        // has an unresolved claim for must overwrite in place, not evict a
        // different, unrelated claim to make room.
        stage_pending_bind(&mut pending, 5, "cn=updated".to_string());
        assert_eq!(pending.len(), MAX_PENDING_BINDS);
        assert_eq!(pending.get(&5), Some(&"cn=updated".to_string()));
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
            policies_rx(allow_all_policies()),
            ConnectionLimits::default(),
            no_shutdown(),
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
            policies_rx(block_all_policies()),
            ConnectionLimits::default(),
            no_shutdown(),
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
            policies_rx(block_all_policies()),
            ConnectionLimits::default(),
            no_shutdown(),
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
            policies_rx(block_all_policies()),
            ConnectionLimits::default(),
            no_shutdown(),
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
                state_db: None,
                flush_interval: Duration::from_secs(2),
                max_tracked_identities: 100_000,
                scope: ThresholdScope::PerIdentity,
                operations: None,
            }))];
        tokio::spawn(serve(
            proxy_listener,
            None,
            None,
            connector,
            policies_rx(policies),
            ConnectionLimits::default(),
            no_shutdown(),
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
    async fn unverified_bind_does_not_change_identity_or_reset_budget() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

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
        let bind_response = |message_id: u32, result_code: ResultCode| {
            encode_message(
                message_id,
                ProtocolOp::BindResponse(rasn_ldap::BindResponse::new(
                    result_code,
                    "".into(),
                    "".into(),
                    None,
                    None,
                )),
            )
        };

        tokio::spawn(async move {
            let (mut upstream_stream, _) = upstream_listener.accept().await.unwrap();

            let modify_frame = read_frame(&mut upstream_stream).await.unwrap().unwrap();
            let message_id = decode_message(&modify_frame).message_id;
            upstream_stream
                .write_all(&modify_response(message_id))
                .await
                .unwrap();

            let bind_frame = read_frame(&mut upstream_stream).await.unwrap().unwrap();
            let message_id = decode_message(&bind_frame).message_id;
            upstream_stream
                .write_all(&bind_response(message_id, ResultCode::InvalidCredentials))
                .await
                .unwrap();

            // The third (blocked) modify below never reaches upstream — keep
            // this connection open a little longer instead of dropping it
            // immediately, so the proxy's two concurrent relay directions
            // (raced via `tokio::select!` in `handle_connection`) don't tear
            // the whole connection down on upstream EOF before the client
            // side has a chance to read the locally-generated rejection.
            let _ = timeout(Duration::from_millis(300), read_frame(&mut upstream_stream)).await;
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        // Budget for exactly one action per identity: a second modify on the
        // same connection must be blocked locally unless the failed bind
        // below incorrectly resets the budget under a fresh, made-up identity.
        let policies: Vec<Arc<dyn Policy>> =
            vec![Arc::new(ThresholdPolicy::new(ThresholdConfig {
                max_per_request: 10,
                max_per_window: 1,
                window: Duration::from_secs(60),
                state_db: None,
                flush_interval: Duration::from_secs(2),
                max_tracked_identities: 100_000,
                scope: ThresholdScope::PerIdentity,
                operations: None,
            }))];
        tokio::spawn(serve(
            proxy_listener,
            None,
            None,
            connector,
            policies_rx(policies),
            ConnectionLimits::default(),
            no_shutdown(),
        ));

        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        client_stream
            .write_all(&modify_request_frame(
                1,
                "cn=alice,dc=example,dc=com",
                "userAccountControl",
                b"514",
            ))
            .await
            .unwrap();
        let first_reply = read_frame(&mut client_stream).await.unwrap().unwrap();
        match decode_message(&first_reply).protocol_op {
            ProtocolOp::ModifyResponse(ModifyResponse(result)) => {
                assert_eq!(result.result_code, ResultCode::Success);
            }
            other => panic!("expected ModifyResponse, got {other:?}"),
        }

        // Bind under a brand-new, made-up DN, chosen so a naive
        // "trust the request" implementation would give it a fresh, empty
        // budget — but the upstream rejects it.
        client_stream
            .write_all(&bind_request_frame(2, "cn=throwaway,dc=example,dc=com"))
            .await
            .unwrap();
        let bind_reply = read_frame(&mut client_stream).await.unwrap().unwrap();
        match decode_message(&bind_reply).protocol_op {
            ProtocolOp::BindResponse(rasn_ldap::BindResponse { result_code, .. }) => {
                assert_eq!(result_code, ResultCode::InvalidCredentials);
            }
            other => panic!("expected BindResponse, got {other:?}"),
        }

        // A second modify on the same connection: if the failed bind had
        // (incorrectly) swapped identity to the throwaway DN, this would
        // land in a brand-new, empty budget and be allowed instead of
        // blocked.
        client_stream
            .write_all(&modify_request_frame(
                3,
                "cn=alice,dc=example,dc=com",
                "userAccountControl",
                b"514",
            ))
            .await
            .unwrap();
        let second_reply = read_frame(&mut client_stream).await.unwrap().unwrap();
        match decode_message(&second_reply).protocol_op {
            ProtocolOp::ModifyResponse(ModifyResponse(result)) => {
                assert_eq!(result.result_code, ResultCode::UnwillingToPerform);
            }
            other => panic!("expected ModifyResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unauthenticated_bind_does_not_change_identity_or_reset_budget() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

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
        let bind_response = |message_id: u32, result_code: ResultCode| {
            encode_message(
                message_id,
                ProtocolOp::BindResponse(rasn_ldap::BindResponse::new(
                    result_code,
                    "".into(),
                    "".into(),
                    None,
                    None,
                )),
            )
        };

        tokio::spawn(async move {
            let (mut upstream_stream, _) = upstream_listener.accept().await.unwrap();

            let modify_frame = read_frame(&mut upstream_stream).await.unwrap().unwrap();
            let message_id = decode_message(&modify_frame).message_id;
            upstream_stream
                .write_all(&modify_response(message_id))
                .await
                .unwrap();

            // Many real directories answer an RFC 4513 §5.1.2
            // unauthenticated (empty-password) bind with plain success
            // while treating the session as anonymous underneath — the
            // wire-level result gives no indication that no credential was
            // actually checked, which is exactly why `bind_request` must
            // never stage this as a pending claim in the first place.
            let bind_frame = read_frame(&mut upstream_stream).await.unwrap().unwrap();
            let message_id = decode_message(&bind_frame).message_id;
            upstream_stream
                .write_all(&bind_response(message_id, ResultCode::Success))
                .await
                .unwrap();

            // The third (blocked) modify below never reaches upstream — keep
            // this connection open a little longer instead of dropping it
            // immediately, so the proxy's two concurrent relay directions
            // (raced via `tokio::select!` in `handle_connection`) don't tear
            // the whole connection down on upstream EOF before the client
            // side has a chance to read the locally-generated rejection.
            let _ = timeout(Duration::from_millis(300), read_frame(&mut upstream_stream)).await;
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        // Budget for exactly one action per identity: a second modify on the
        // same connection must be blocked locally unless the unauthenticated
        // bind below incorrectly promotes identity to a fresh, made-up DN.
        let policies: Vec<Arc<dyn Policy>> =
            vec![Arc::new(ThresholdPolicy::new(ThresholdConfig {
                max_per_request: 10,
                max_per_window: 1,
                window: Duration::from_secs(60),
                state_db: None,
                flush_interval: Duration::from_secs(2),
                max_tracked_identities: 100_000,
                scope: ThresholdScope::PerIdentity,
                operations: None,
            }))];
        tokio::spawn(serve(
            proxy_listener,
            None,
            None,
            connector,
            policies_rx(policies),
            ConnectionLimits::default(),
            no_shutdown(),
        ));

        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        client_stream
            .write_all(&modify_request_frame(
                1,
                "cn=alice,dc=example,dc=com",
                "userAccountControl",
                b"514",
            ))
            .await
            .unwrap();
        let first_reply = read_frame(&mut client_stream).await.unwrap().unwrap();
        match decode_message(&first_reply).protocol_op {
            ProtocolOp::ModifyResponse(ModifyResponse(result)) => {
                assert_eq!(result.result_code, ResultCode::Success);
            }
            other => panic!("expected ModifyResponse, got {other:?}"),
        }

        // An empty-password bind naming a brand-new, made-up DN, chosen so a
        // naive "trust any successful bind" implementation would give it a
        // fresh, empty budget — but the upstream's success here never
        // reflects a real credential check.
        client_stream
            .write_all(&unauthenticated_bind_request_frame(
                2,
                "cn=throwaway,dc=example,dc=com",
            ))
            .await
            .unwrap();
        let bind_reply = read_frame(&mut client_stream).await.unwrap().unwrap();
        match decode_message(&bind_reply).protocol_op {
            ProtocolOp::BindResponse(rasn_ldap::BindResponse { result_code, .. }) => {
                assert_eq!(result_code, ResultCode::Success);
            }
            other => panic!("expected BindResponse, got {other:?}"),
        }

        // A second modify on the same connection: if the unauthenticated
        // bind had (incorrectly) swapped identity to the throwaway DN, this
        // would land in a brand-new, empty budget and be allowed instead of
        // blocked.
        client_stream
            .write_all(&modify_request_frame(
                3,
                "cn=alice,dc=example,dc=com",
                "userAccountControl",
                b"514",
            ))
            .await
            .unwrap();
        let second_reply = read_frame(&mut client_stream).await.unwrap().unwrap();
        match decode_message(&second_reply).protocol_op {
            ProtocolOp::ModifyResponse(ModifyResponse(result)) => {
                assert_eq!(result.result_code, ResultCode::UnwillingToPerform);
            }
            other => panic!("expected ModifyResponse, got {other:?}"),
        }
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
            policies_rx(allow_all_policies()),
            ConnectionLimits::default(),
            no_shutdown(),
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
            policies_rx(allow_all_policies()),
            ConnectionLimits::default(),
            no_shutdown(),
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
            policies_rx(allow_all_policies()),
            ConnectionLimits::default(),
            no_shutdown(),
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
            policies_rx(allow_all_policies()),
            ConnectionLimits::default(),
            no_shutdown(),
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
            policies_rx(allow_all_policies()),
            ConnectionLimits::default(),
            no_shutdown(),
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
            policies_rx(allow_all_policies()),
            ConnectionLimits::default(),
            no_shutdown(),
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
            policies_rx(allow_all_policies()),
            ConnectionLimits::default(),
            no_shutdown(),
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
            policies_rx(allow_all_policies()),
            ConnectionLimits::default(),
            no_shutdown(),
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
            policies_rx(allow_all_policies()),
            ConnectionLimits {
                max_connections: 10,
                io_timeout: Duration::from_millis(100),
                ..ConnectionLimits::default()
            },
            no_shutdown(),
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
            policies_rx(allow_all_policies()),
            ConnectionLimits {
                max_connections: 1,
                io_timeout: Duration::from_secs(10),
                ..ConnectionLimits::default()
            },
            no_shutdown(),
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

    #[tokio::test]
    async fn policy_reload_applies_to_new_connections_only() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

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
        // Only the pre-reload connection's requests ever reach upstream (both
        // of them, over the one connection it keeps using) — a post-reload
        // request is blocked locally by the stricter policy and must never
        // reach upstream as an LDAP frame. But `connect_upstream` runs
        // unconditionally as soon as a client connects (before any per-frame
        // policy check), so the post-reload client's own TCP-level dial to
        // upstream still needs somewhere to land — accept it too and just
        // hold it open, unread.
        tokio::spawn(async move {
            let (mut upstream_stream, _) = upstream_listener.accept().await.unwrap();
            for _ in 0..2 {
                let frame = read_frame(&mut upstream_stream).await.unwrap().unwrap();
                let message_id = decode_message(&frame).message_id;
                upstream_stream
                    .write_all(&modify_response(message_id))
                    .await
                    .unwrap();
            }
            let _second_upstream_stream = upstream_listener.accept().await.unwrap();
            std::future::pending::<()>().await
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        let (policies_tx, policies_rx) = watch::channel(allow_all_policies());
        tokio::spawn(serve(
            proxy_listener,
            None,
            None,
            connector,
            policies_rx,
            ConnectionLimits::default(),
            no_shutdown(),
        ));

        let request_frame = |message_id: u32| {
            modify_request_frame(
                message_id,
                "cn=alice,dc=example,dc=com",
                "userAccountControl",
                b"514",
            )
        };
        let assert_reached_upstream = |reply: &[u8]| match decode_message(reply).protocol_op {
            ProtocolOp::ModifyResponse(ModifyResponse(result)) => {
                assert_eq!(result.result_code, ResultCode::Success);
            }
            other => panic!("expected ModifyResponse, got {other:?}"),
        };
        let assert_blocked_locally = |reply: &[u8]| match decode_message(reply).protocol_op {
            ProtocolOp::ModifyResponse(ModifyResponse(result)) => {
                assert_eq!(result.result_code, ResultCode::UnwillingToPerform);
            }
            other => panic!("expected ModifyResponse, got {other:?}"),
        };

        // A full request/response round trip proves `serve` already accepted
        // this connection and captured the (allow-everything) policy list in
        // effect at the time, before the reload below happens — otherwise a
        // connection that's merely TCP-connected but not yet `accept()`-ed by
        // the server could race the reload and pick up the new list anyway.
        let mut pre_reload_client = TcpStream::connect(proxy_addr).await.unwrap();
        pre_reload_client
            .write_all(&request_frame(1))
            .await
            .unwrap();
        assert_reached_upstream(&read_frame(&mut pre_reload_client).await.unwrap().unwrap());

        policies_tx.send(block_all_policies()).unwrap();

        // Same, already-open connection: must keep running under the policy
        // snapshot it was accepted with, not the reloaded one.
        pre_reload_client
            .write_all(&request_frame(2))
            .await
            .unwrap();
        assert_reached_upstream(&read_frame(&mut pre_reload_client).await.unwrap().unwrap());

        // A newly-accepted connection must be evaluated under the reloaded,
        // blocking policy list.
        let mut post_reload_client = TcpStream::connect(proxy_addr).await.unwrap();
        post_reload_client
            .write_all(&request_frame(3))
            .await
            .unwrap();
        assert_blocked_locally(&read_frame(&mut post_reload_client).await.unwrap().unwrap());
    }

    #[tokio::test]
    async fn graceful_shutdown_stops_accepting_and_waits_for_in_flight_connection() {
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
            // Keep this side of the connection open rather than letting it
            // drop (and EOF the proxy's upstream-facing read) as soon as the
            // response is sent — the test needs the connection to still be
            // in flight when shutdown is requested, closed only by the
            // client end below.
            std::future::pending::<()>().await;
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_task = tokio::spawn(serve(
            proxy_listener,
            None,
            None,
            connector,
            policies_rx(allow_all_policies()),
            ConnectionLimits::default(),
            shutdown_rx,
        ));

        // Complete one full request/response while the connection stays
        // open, so it's genuinely in flight (not just accepted) when
        // shutdown is requested.
        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        client_stream.write_all(&request_frame).await.unwrap();
        let received_response = read_frame(&mut client_stream).await.unwrap().unwrap();
        assert_eq!(received_response, response_frame);

        shutdown_tx.send(true).unwrap();

        // A new connection attempt after shutdown must not be served: it
        // either never completes a handshake against a socket nothing is
        // accepting from (read times out), or the listener drops out from
        // under it once `serve` returns (clean EOF or a reset) — either way,
        // no response is ever readable from it, unlike the exchange above.
        let mut late_client = TcpStream::connect(proxy_addr).await.unwrap();
        let mut buf = [0u8; 1];
        match timeout(Duration::from_millis(300), late_client.read(&mut buf)).await {
            Err(_timed_out) => {}
            Ok(Ok(0)) => {}
            Ok(Err(_reset_or_similar)) => {}
            Ok(Ok(n)) => panic!(
                "a connection accepted after shutdown was requested must not be served, got {n} byte(s)"
            ),
        }

        // The in-flight connection above is still open; closing it lets
        // `serve` finish draining and return.
        drop(client_stream);
        timeout(Duration::from_secs(2), serve_task)
            .await
            .expect("serve should return promptly once the in-flight connection closes")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn graceful_shutdown_aborts_connections_still_running_past_the_grace_period() {
        // Bound but never accepted from: the request the client sends below
        // reaches upstream and then just sits there, unanswered, so the
        // connection never finishes on its own.
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut upstream_stream, _) = upstream_listener.accept().await.unwrap();
            read_frame(&mut upstream_stream).await.unwrap().unwrap();
            // No response, deliberately: the client-facing connection has
            // nothing to relay back and never closes on its own.
            std::future::pending::<()>().await;
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connector: Arc<dyn Connector> = Arc::new(LdapConnector::new(upstream_addr, None));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_task = tokio::spawn(serve(
            proxy_listener,
            None,
            None,
            connector,
            policies_rx(allow_all_policies()),
            ConnectionLimits {
                // Long enough that this test's own timeout below would fail
                // first if shutdown were (wrongly) waiting on it instead of
                // aborting after `shutdown_timeout`.
                io_timeout: Duration::from_secs(10),
                shutdown_timeout: Duration::from_millis(100),
                ..ConnectionLimits::default()
            },
            shutdown_rx,
        ));

        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        client_stream
            .write_all(&modify_request_frame(
                1,
                "cn=alice,dc=example,dc=com",
                "userAccountControl",
                b"514",
            ))
            .await
            .unwrap();
        // Give the connection a moment to actually reach upstream before
        // shutdown is requested, so it's genuinely in flight.
        tokio::time::sleep(Duration::from_millis(50)).await;

        shutdown_tx.send(true).unwrap();

        timeout(Duration::from_secs(2), serve_task)
            .await
            .expect(
                "serve should abort the stuck connection at shutdown_timeout, \
                 not wait for io_timeout",
            )
            .unwrap()
            .unwrap();
    }
}
