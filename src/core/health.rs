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

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

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
/// why this deliberately never stops accepting on its own.
pub async fn serve(listener: TcpListener, shutdown: watch::Receiver<bool>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, &shutdown).await {
                tracing::debug!(%err, "health: connection error");
            }
        });
    }
}

/// Reads just enough of one HTTP/1.1 request to pull the path off its
/// request line, answers it, and closes the connection — probes are
/// short-lived, single-request clients, so there's no need for
/// keep-alive/pipelining support here.
async fn handle_connection(
    mut stream: TcpStream,
    shutdown: &watch::Receiver<bool>,
) -> std::io::Result<()> {
    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).await?;
    let request = String::from_utf8_lossy(&buf[..n]);
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
}
