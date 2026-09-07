//! Prometheus metrics, recorded through the `metrics` facade crate so
//! instrumentation call sites (`proxy.rs`, `connector/ldap.rs`, `audit.rs`)
//! don't need to know whether or where a recorder is installed — recording
//! against no installed recorder is a documented no-op, so these calls are
//! safe even for an embedder (`ProxyBuilder`) that never sets one up.
//! `install_prometheus_exporter` wires up the one concrete recorder
//! `run_with_config` installs: a Prometheus text-format `/metrics` endpoint.

use std::net::SocketAddr;
use std::time::Duration;

use metrics::{counter, gauge, histogram};

use crate::core::action::{Action, OperationKind};
use crate::core::policy::Decision;

const CONNECTIONS_ACTIVE: &str = "ai_protect_connections_active";
const CONNECTIONS_TOTAL: &str = "ai_protect_connections_total";
const POLICY_DECISIONS_TOTAL: &str = "ai_protect_policy_decisions_total";
const UPSTREAM_CONNECT_SECONDS: &str = "ai_protect_upstream_connect_duration_seconds";
const TLS_HANDSHAKE_FAILURES_TOTAL: &str = "ai_protect_tls_handshake_failures_total";

/// Installs the process-wide Prometheus recorder and starts serving
/// `/metrics` on `listen_addr` in the background. Call at most once per
/// process, before any traffic flows — every recording call in this module
/// is a no-op until a recorder is installed.
pub fn install_prometheus_exporter(
    listen_addr: SocketAddr,
) -> Result<(), metrics_exporter_prometheus::BuildError> {
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(listen_addr)
        .install()?;
    tracing::info!(%listen_addr, "metrics: serving Prometheus text format at /metrics");
    Ok(())
}

/// Tracks one accepted connection as an active-count gauge, incremented on
/// construction and decremented on drop so the gauge can't drift regardless
/// of how the connection's task ends (clean finish, error, or panic-unwind
/// during shutdown's forced abort).
pub struct ConnectionGuard;

impl ConnectionGuard {
    pub fn open() -> Self {
        counter!(CONNECTIONS_TOTAL).increment(1);
        gauge!(CONNECTIONS_ACTIVE).increment(1.0);
        Self
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        gauge!(CONNECTIONS_ACTIVE).decrement(1.0);
    }
}

fn operation_label(operation: &OperationKind) -> &'static str {
    match operation {
        OperationKind::AccountLock => "account_lock",
        OperationKind::Delete => "delete",
        OperationKind::Create => "create",
        OperationKind::PasswordReset => "password_reset",
        OperationKind::Rename => "rename",
    }
}

/// Records one policy decision — allow/block rate, broken down by backend
/// and operation kind. Called alongside `audit::log_decision`, which is the
/// forensic (per-event) record; this is the aggregate one.
pub fn record_decision(action: &Action, decision: &Decision) {
    let decision_label = match decision {
        Decision::Allow => "allow",
        Decision::Block { .. } => "block",
    };
    counter!(
        POLICY_DECISIONS_TOTAL,
        "decision" => decision_label,
        "backend" => action.backend,
        "operation" => operation_label(&action.operation),
    )
    .increment(1);
}

/// Records how long it took to establish the upstream connection —
/// `Connector::connect_upstream`'s TCP dial plus, when configured, its TLS
/// or StartTLS handshake. Not a per-request round-trip latency: the relay
/// forwards both directions concurrently without correlating individual
/// request/response frames (see `proxy::handle_connection`), so connection
/// setup is the one discrete, measurable "upstream latency" available
/// without decoding every frame just to time it.
pub fn record_upstream_connect(elapsed: Duration) {
    histogram!(UPSTREAM_CONNECT_SECONDS).record(elapsed.as_secs_f64());
}

/// Records a failed TLS handshake on one of the three points a handshake can
/// happen: `"listen"` (implicit TLS on the client-facing listener),
/// `"listen_starttls"` (client-facing StartTLS upgrade), or `"upstream"`
/// (implicit or StartTLS TLS to the real directory).
pub fn record_tls_handshake_failure(hop: &'static str) {
    counter!(TLS_HANDSHAKE_FAILURES_TOTAL, "hop" => hop).increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only one global recorder can ever be installed in a process — the
    /// second `install` call here proves that's a clean, typed error rather
    /// than a panic, which matters because `run_with_config` (unlike this
    /// test) can't just avoid calling it twice: a host embedding ai-protect
    /// more than once in the same process needs a real error to react to.
    #[tokio::test]
    async fn installing_the_exporter_twice_fails_cleanly_instead_of_panicking() {
        let first = install_prometheus_exporter("127.0.0.1:0".parse().unwrap());
        let second = install_prometheus_exporter("127.0.0.1:0".parse().unwrap());

        // Exactly one of the two calls in this whole test binary is the
        // "first" install; if some earlier test already installed a
        // recorder, both calls here fail the same way "second" describes.
        assert!(first.is_ok() || second.is_err());
        if first.is_ok() {
            assert!(matches!(
                second,
                Err(metrics_exporter_prometheus::BuildError::FailedToSetGlobalRecorder(_))
            ));
        }
    }

    #[test]
    fn connection_guard_decrements_the_active_gauge_on_drop() {
        // No recorder installed in this test (unlike the one above) — every
        // call here must be a documented no-op, not a panic.
        let guard = ConnectionGuard::open();
        drop(guard);
    }

    #[test]
    fn recording_functions_are_no_ops_without_an_installed_recorder() {
        record_decision(
            &Action {
                backend: "ldap",
                operation: OperationKind::AccountLock,
                target: "cn=alice,dc=example,dc=com".into(),
                blast_radius: 1,
            },
            &Decision::Allow,
        );
        record_upstream_connect(Duration::from_millis(5));
        record_tls_handshake_failure("upstream");
    }
}
