//! The list of upstream targets one connector load-balances across, plus the
//! selection/health/load state `LdapConnector::connect_upstream` needs to
//! pick one, fail over on a dial error, and track active connections for the
//! `LeastConnections` strategy. Kept protocol-agnostic (nothing here parses
//! LDAP) so a future non-LDAP connector could reuse it too.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rand::seq::SliceRandom;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Default cooldown (`ProxyConfig::upstream_failure_cooldown_secs`'s
/// default) a target is excluded from selection for after a failed dial/TLS
/// handshake. Shared here so `LdapConnector::new`'s single-target
/// constructor and `config.rs`'s `#[serde(default)]` stay in sync without
/// duplicating the number in two places.
pub const DEFAULT_FAILURE_COOLDOWN_SECS: u64 = 30;

/// How `UpstreamPool::candidates` orders the currently-healthy targets for a
/// connection to try first. Defaults to `RoundRobin` — the only strategy
/// that behaves reasonably with zero tuning and no assumption about request
/// cost/duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    #[default]
    RoundRobin,
    Random,
    LeastConnections,
}

struct Target {
    addr: SocketAddr,
    active_connections: AtomicUsize,
    /// `None` = healthy. `Some(t)` = excluded from the healthy tier of
    /// `candidates` until `Instant::now() >= t`.
    down_until: Mutex<Option<Instant>>,
}

/// One target to try dialing, in the order `UpstreamPool::candidates` wants
/// them attempted.
pub struct Candidate {
    pub index: usize,
    pub addr: SocketAddr,
}

/// The upstream targets one `LdapConnector` load-balances across, shared
/// (via `Arc`) across every connection it dials — round-robin position,
/// per-target failure cooldowns, and per-target active-connection counts are
/// all process-wide state, not per-connection state.
pub struct UpstreamPool {
    targets: Vec<Target>,
    strategy: LoadBalanceStrategy,
    cooldown: Duration,
    round_robin_counter: AtomicUsize,
}

impl UpstreamPool {
    /// Panics if `addrs` is empty — callers (`config.rs`'s deserializer,
    /// `LdapConnector::new`/`with_targets`) are expected to have already
    /// rejected that case, since a connector with no upstream to dial isn't
    /// a state this type can do anything useful with.
    pub fn new(addrs: Vec<SocketAddr>, strategy: LoadBalanceStrategy, cooldown: Duration) -> Self {
        assert!(!addrs.is_empty(), "UpstreamPool needs at least one target");
        let targets = addrs
            .into_iter()
            .map(|addr| Target {
                addr,
                active_connections: AtomicUsize::new(0),
                down_until: Mutex::new(None),
            })
            .collect();
        Self {
            targets,
            strategy,
            cooldown,
            round_robin_counter: AtomicUsize::new(0),
        }
    }

    fn is_healthy(&self, index: usize) -> bool {
        match *self.targets[index].down_until.lock() {
            None => true,
            Some(until) => Instant::now() >= until,
        }
    }

    /// Every target, ordered by preference: healthy ones first (per
    /// `strategy`), then currently-cooling-down ones appended in original
    /// config order — so a caller that exhausts every healthy target still
    /// gets to try every configured one, rather than failing outright just
    /// because passive health tracking (a heuristic, not a hard veto) marked
    /// all of them down at once (e.g. a brief simultaneous blip on every
    /// replica).
    pub fn candidates(&self) -> Vec<Candidate> {
        let (mut healthy, down): (Vec<usize>, Vec<usize>) =
            (0..self.targets.len()).partition(|&i| self.is_healthy(i));

        match self.strategy {
            LoadBalanceStrategy::RoundRobin => {
                if !healthy.is_empty() {
                    let offset =
                        self.round_robin_counter.fetch_add(1, Ordering::Relaxed) % healthy.len();
                    healthy.rotate_left(offset);
                }
            }
            LoadBalanceStrategy::Random => {
                healthy.shuffle(&mut rand::rng());
            }
            LoadBalanceStrategy::LeastConnections => {
                healthy
                    .sort_by_key(|&i| self.targets[i].active_connections.load(Ordering::Relaxed));
            }
        }

        healthy
            .into_iter()
            .chain(down)
            .map(|index| Candidate {
                index,
                addr: self.targets[index].addr,
            })
            .collect()
    }

    /// Records a failed dial/handshake to `index`: excludes it from the
    /// healthy tier of `candidates` until `cooldown` from now elapses.
    /// Affects every future connection's selection, not just the one that
    /// just failed.
    pub fn mark_failed(&self, index: usize) {
        let target = &self.targets[index];
        let mut down_until = target.down_until.lock();
        let was_healthy = down_until.is_none_or(|until| Instant::now() >= until);
        *down_until = Some(Instant::now() + self.cooldown);
        drop(down_until);

        crate::core::metrics::record_upstream_target_failure(target.addr);
        if was_healthy {
            tracing::warn!(
                target = %target.addr,
                cooldown = ?self.cooldown,
                "upstream target marked down after a failed connection attempt"
            );
        }
    }

    /// Records a successful dial to `index`: clears any cooldown (passive
    /// recovery — a target that just answered is healthy now, regardless of
    /// how long its cooldown had left) and bumps its active-connection
    /// count. Returns a guard that decrements the count again on drop.
    pub fn mark_connected(self: &Arc<Self>, index: usize) -> ActiveConnectionGuard {
        let target = &self.targets[index];
        let mut down_until = target.down_until.lock();
        let was_down = down_until.is_some_and(|until| Instant::now() < until);
        *down_until = None;
        drop(down_until);

        if was_down {
            tracing::info!(target = %target.addr, "upstream target back up");
        }

        let count = target.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
        crate::core::metrics::set_upstream_target_active_connections(target.addr, count);

        ActiveConnectionGuard {
            pool: Arc::clone(self),
            index,
        }
    }
}

/// RAII: decrements the owning target's active-connection count on drop,
/// regardless of how the connection holding it ends (clean EOF, I/O error,
/// `io_timeout`) — the only lifecycle hook available, since
/// `Connector::connect_upstream` has no explicit "connection closed"
/// callback.
pub struct ActiveConnectionGuard {
    pool: Arc<UpstreamPool>,
    index: usize,
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        let target = &self.pool.targets[self.index];
        let count = target.active_connections.fetch_sub(1, Ordering::Relaxed) - 1;
        crate::core::metrics::set_upstream_target_active_connections(target.addr, count);
    }
}

/// Wraps a dialed upstream stream together with the `ActiveConnectionGuard`
/// tracking it, forwarding `AsyncRead`/`AsyncWrite` to the inner stream by
/// delegation — same pattern as `core::net::MaybeTlsStream` — so `proxy.rs`
/// relays through it exactly as it would a bare stream, oblivious to the
/// accounting happening on drop.
pub struct CountedStream<S> {
    inner: S,
    _guard: ActiveConnectionGuard,
}

impl<S> CountedStream<S> {
    pub(crate) fn new(inner: S, guard: ActiveConnectionGuard) -> Self {
        Self {
            inner,
            _guard: guard,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[test]
    fn round_robin_cycles_through_every_healthy_target() {
        let pool = UpstreamPool::new(
            vec![addr(1), addr(2), addr(3)],
            LoadBalanceStrategy::RoundRobin,
            Duration::from_secs(30),
        );

        let first: Vec<u16> = pool.candidates().iter().map(|c| c.addr.port()).collect();
        let second: Vec<u16> = pool.candidates().iter().map(|c| c.addr.port()).collect();
        let third: Vec<u16> = pool.candidates().iter().map(|c| c.addr.port()).collect();

        assert_eq!(first, vec![1, 2, 3]);
        assert_eq!(second, vec![2, 3, 1]);
        assert_eq!(third, vec![3, 1, 2]);
    }

    #[test]
    fn round_robin_skips_a_target_marked_down() {
        let pool = UpstreamPool::new(
            vec![addr(1), addr(2)],
            LoadBalanceStrategy::RoundRobin,
            Duration::from_secs(30),
        );
        pool.mark_failed(0);

        let candidates = pool.candidates();

        assert_eq!(
            candidates[0].addr.port(),
            2,
            "the only healthy target should be tried first"
        );
        assert_eq!(
            candidates[1].addr.port(),
            1,
            "the down target should still appear, last"
        );
    }

    #[test]
    fn random_with_one_target_always_returns_it() {
        let pool = UpstreamPool::new(
            vec![addr(1)],
            LoadBalanceStrategy::Random,
            Duration::from_secs(30),
        );

        for _ in 0..10 {
            assert_eq!(pool.candidates()[0].addr.port(), 1);
        }
    }

    #[test]
    fn random_distribution_sanity_every_target_appears_first_eventually() {
        let pool = UpstreamPool::new(
            vec![addr(1), addr(2), addr(3)],
            LoadBalanceStrategy::Random,
            Duration::from_secs(30),
        );

        let mut seen_first = std::collections::HashSet::new();
        for _ in 0..200 {
            seen_first.insert(pool.candidates()[0].addr.port());
        }

        assert_eq!(seen_first, [1, 2, 3].into_iter().collect());
    }

    #[test]
    fn least_connections_prefers_the_target_with_fewer_active_connections() {
        let pool = Arc::new(UpstreamPool::new(
            vec![addr(1), addr(2)],
            LoadBalanceStrategy::LeastConnections,
            Duration::from_secs(30),
        ));

        let _guard_a = pool.mark_connected(0);
        let _guard_b = pool.mark_connected(0);
        // Target 0 (port 1) now has 2 active connections, target 1 (port 2) has 0.

        let candidates = pool.candidates();

        assert_eq!(
            candidates[0].addr.port(),
            2,
            "target with fewer active connections goes first"
        );
        assert_eq!(candidates[1].addr.port(), 1);
    }

    #[test]
    fn active_connection_guard_decrements_the_count_on_drop() {
        let pool = Arc::new(UpstreamPool::new(
            vec![addr(1), addr(2)],
            LoadBalanceStrategy::LeastConnections,
            Duration::from_secs(30),
        ));

        let guard = pool.mark_connected(0);
        assert_eq!(
            pool.candidates()[0].addr.port(),
            2,
            "target 1 has fewer active connections while the guard is held"
        );
        drop(guard);

        let counts: Vec<usize> = pool
            .targets
            .iter()
            .map(|t| t.active_connections.load(Ordering::Relaxed))
            .collect();
        assert_eq!(counts, vec![0, 0]);
    }

    #[test]
    fn mark_failed_excludes_a_target_until_cooldown_elapses() {
        let pool = UpstreamPool::new(
            vec![addr(1), addr(2)],
            LoadBalanceStrategy::RoundRobin,
            Duration::from_millis(50),
        );
        pool.mark_failed(0);

        assert!(!pool.is_healthy(0));

        std::thread::sleep(Duration::from_millis(80));

        assert!(pool.is_healthy(0));
    }

    #[test]
    fn mark_connected_clears_cooldown_and_restores_the_target_to_the_healthy_tier() {
        let pool = Arc::new(UpstreamPool::new(
            vec![addr(1), addr(2)],
            LoadBalanceStrategy::RoundRobin,
            Duration::from_secs(30),
        ));
        pool.mark_failed(0);
        assert!(!pool.is_healthy(0));

        let _guard = pool.mark_connected(0);

        assert!(pool.is_healthy(0));
    }

    #[test]
    fn candidates_returns_every_target_when_all_are_down() {
        let pool = UpstreamPool::new(
            vec![addr(1), addr(2)],
            LoadBalanceStrategy::RoundRobin,
            Duration::from_secs(30),
        );
        pool.mark_failed(0);
        pool.mark_failed(1);

        let candidates = pool.candidates();

        assert_eq!(candidates.len(), 2);
    }
}
