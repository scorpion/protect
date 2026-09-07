//! Minimal HTTP liveness/readiness endpoint for orchestrator probes (k8s
//! `livenessProbe`/`readinessProbe`, or equivalent). Hand-rolled rather than
//! pulling in an HTTP framework dependency — the whole surface is two
//! fixed-response routes read off the request line, the same "only decode
//! what's needed" bar the rest of this codebase holds itself to.
//!
//! `/healthz` (liveness) always answers `200` — it must keep answering
//! throughout a graceful shutdown's drain window (`shutdown_timeout`, up to
//! 30s by default), or a orchestrator's liveness probe would see the port go
//! quiet mid-drain and kill the process outright, defeating the point of
//! draining at all. `/readyz` (readiness) answers `200` until graceful
//! shutdown is requested (the same `watch::channel(bool)`
//! `proxy::serve`'s accept loops watch — see `run_with_config`), then flips
//! to `503` immediately so a load balancer stops routing new connections
//! here without waiting for the drain itself to finish. Because both routes
//! must stay reachable across that window, `serve` never stops accepting on
//! its own — `run_with_config` spawns it and lets the whole process take it
//! down on exit, the same way the installed Prometheus exporter is never
//! explicitly stopped either.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};

/// Failure modes for standing up the health endpoint — just binding the
/// listener, mirroring `proxy::ProxyError::Bind`.
#[derive(Debug, thiserror::Error)]
pub enum HealthError {
    #[error("binding health listener on {addr}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

/// Deadline for reading one probe request. Not exposed as config — unlike
/// the main proxy path's `io_timeout`, a probe is always a short-lived local
/// caller (kubelet, a sidecar), so a generous fixed value is enough to catch
/// a connection that never sends a byte without adding a knob nobody needs
/// to tune.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum probe connections handled concurrently. Orders of magnitude below
/// `ConnectionLimits::default().max_connections` (1024) — this endpoint only
/// ever expects a handful of orchestrator probes at once, not real traffic —
/// so a small fixed cap stops connections that never send a byte (each
/// otherwise parked forever in its own task, per the module doc) from
/// accumulating without bound.
const MAX_CONNECTIONS: usize = 64;

const OK_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
const UNAVAILABLE_RESPONSE: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
const NOT_FOUND_RESPONSE: &[u8] =
    b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

/// Binds `listen_addr`, split out from `serve` (which never returns) so
/// `run_with_config` can propagate a bind failure — a misconfigured or
/// already-in-use address — as a startup error instead of it surfacing only
/// once something first probes the endpoint.
pub async fn bind(listen_addr: SocketAddr) -> Result<TcpListener, HealthError> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|source| HealthError::Bind {
            addr: listen_addr,
            source,
        })?;
    tracing::info!(%listen_addr, "health: serving /healthz and /readyz");
    Ok(listener)
}

/// Accepts connections from an already-bound listener and answers
/// `/healthz`/`/readyz` off of `shutdown` forever — see the module doc for
/// why this deliberately never stops accepting on its own. Concurrency is
/// capped at `MAX_CONNECTIONS`, mirroring `proxy::ConnectionLimits` at a
/// scale appropriate for a probe endpoint: a connection beyond the cap is
/// closed immediately rather than queued.
pub async fn serve(listener: TcpListener, shutdown: watch::Receiver<bool>) {
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let Ok((stream, peer_addr)) = listener.accept().await else {
            continue;
        };
        let Ok(permit) = semaphore.clone().try_acquire_owned() else {
            tracing::warn!(
                %peer_addr,
                max_connections = MAX_CONNECTIONS,
                "health: rejecting connection: at concurrent connection limit"
            );
            continue;
        };
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = handle_connection(stream, &shutdown, READ_TIMEOUT).await {
                tracing::debug!(%err, "health: connection error");
            }
        });
    }
}

/// Reads just enough of one HTTP/1.1 request to pull the path off its
/// request line, answers it, and closes the connection — probes are
/// short-lived, single-request clients, so there's no need for
/// keep-alive/pipelining support here. The whole read loop (not each
/// individual `read` call) races `read_timeout` (always `READ_TIMEOUT`
/// outside tests, parameterized so tests can use a short deadline instead of
/// waiting out the real one) so a connection that never sends a byte, or
/// never finishes its request line, doesn't pin its task forever.
async fn handle_connection(
    mut stream: TcpStream,
    shutdown: &watch::Receiver<bool>,
    read_timeout: Duration,
) -> std::io::Result<()> {
    let mut buf = [0u8; 512];
    let mut len = 0;

    // A bare `GET /healthz HTTP/1.1\r\n...` from a typical probe client
    // arrives in one TCP segment, but that's not guaranteed — some minimal
    // HTTP client implementations write the request line and headers as
    // separate `write()` calls. Looping until the request line's `\r\n`
    // shows up (or the connection closes, or `buf` fills) avoids treating
    // whatever one `read()` happened to return as the complete line, which
    // would otherwise mis-parse a request split mid-line as pathless and
    // answer a spurious 404 instead of the real liveness/readiness status.
    let read_result: Result<std::io::Result<()>, _> = tokio::time::timeout(read_timeout, async {
        loop {
            if len == buf.len() || buf[..len].windows(2).any(|w| w == b"\r\n") {
                return Ok(());
            }
            match stream.read(&mut buf[len..]).await? {
                0 => return Ok(()), // peer closed before finishing the line
                n => len += n,
            }
        }
    })
    .await;
    match read_result {
        Ok(result) => result?,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("no request received within {read_timeout:?}"),
            ));
        }
    }
    let request = String::from_utf8_lossy(&buf[..len]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("");

    let response: &[u8] = match path {
        "/healthz" => OK_RESPONSE,
        "/readyz" if !*shutdown.borrow() => OK_RESPONSE,
        "/readyz" => UNAVAILABLE_RESPONSE,
        _ => NOT_FOUND_RESPONSE,
    };

    stream.write_all(response).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn get(addr: SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nhost: test\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    async fn spawn_server(shutdown: watch::Receiver<bool>) -> SocketAddr {
        let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, shutdown));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        addr
    }

    #[tokio::test]
    async fn healthz_is_always_ok() {
        let (_tx, rx) = watch::channel(false);
        let addr = spawn_server(rx).await;

        assert!(get(addr, "/healthz").await.starts_with("HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn healthz_stays_ok_after_shutdown_is_requested() {
        let (tx, rx) = watch::channel(false);
        let addr = spawn_server(rx).await;

        tx.send(true).unwrap();

        assert!(get(addr, "/healthz").await.starts_with("HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn readyz_flips_to_unavailable_once_shutdown_is_requested() {
        let (tx, rx) = watch::channel(false);
        let addr = spawn_server(rx).await;

        assert!(get(addr, "/readyz").await.starts_with("HTTP/1.1 200"));

        tx.send(true).unwrap();

        assert!(get(addr, "/readyz").await.starts_with("HTTP/1.1 503"));
    }

    #[tokio::test]
    async fn unknown_path_is_not_found() {
        let (_tx, rx) = watch::channel(false);
        let addr = spawn_server(rx).await;

        assert!(get(addr, "/other").await.starts_with("HTTP/1.1 404"));
    }

    #[tokio::test]
    async fn healthz_is_ok_even_when_the_request_line_arrives_split_across_reads() {
        let (_tx, rx) = watch::channel(false);
        let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut client = TcpStream::connect(addr).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let server = tokio::spawn(async move {
            handle_connection(stream, &rx, READ_TIMEOUT).await.unwrap();
        });

        // Split mid-request-line: after this first write, a single `read()`
        // sees only "GET " — no second whitespace-separated token yet, so
        // parsing this alone would find no path.
        client.write_all(b"GET ").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        client
            .write_all(b"/healthz HTTP/1.1\r\nhost: test\r\n\r\n")
            .await
            .unwrap();

        server.await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn handle_connection_times_out_when_client_sends_nothing() {
        let (_tx, rx) = watch::channel(false);
        let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let _client = TcpStream::connect(addr).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();

        // A short deadline in place of the real `READ_TIMEOUT`, so the test
        // doesn't wait out the real one.
        let result = handle_connection(stream, &rx, Duration::from_millis(50)).await;
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn connections_beyond_the_cap_are_closed_immediately() {
        let (_tx, rx) = watch::channel(false);
        let addr = spawn_server(rx).await;

        // Fill every permit with connections that never send a byte, so
        // they're held open (and thus counted) for the rest of the test.
        let mut held = Vec::with_capacity(MAX_CONNECTIONS);
        for _ in 0..MAX_CONNECTIONS {
            held.push(TcpStream::connect(addr).await.unwrap());
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut rejected = TcpStream::connect(addr).await.unwrap();
        let mut response = Vec::new();
        rejected.read_to_end(&mut response).await.unwrap();
        assert!(
            response.is_empty(),
            "expected the connection over the cap to be closed with no response"
        );

        drop(held);
    }
}
