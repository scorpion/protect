use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer};

use crate::core::action::Action;
use crate::core::identity::Identity;

use super::store::{Anchor, HistoryStore};
use super::{Decision, Policy, PolicyContext};

#[derive(Debug, Clone, Deserialize)]
pub struct ThresholdConfig {
    /// Blast radius of a single request that immediately trips a block,
    /// regardless of history (e.g. one request that itself claims 4,000 accounts).
    pub max_per_request: usize,
    /// Total blast radius allowed per identity within `window`.
    pub max_per_window: usize,
    #[serde(rename = "window_secs", deserialize_with = "deserialize_secs")]
    pub window: Duration,
    /// Optional SQLite file this policy's history survives a restart in and
    /// (approximately, on a `flush_interval` delay) shares with any other
    /// `ai-protect` instance pointed at the same file. `None` (the default)
    /// keeps today's pure in-memory, single-process-only behavior. Two
    /// `ThresholdPolicy`s must not share one file — pruning/history would
    /// mix between their windows.
    #[serde(default)]
    pub state_db: Option<PathBuf>,
    /// How often admitted actions are flushed to `state_db` and history is
    /// refreshed from it. Only meaningful when `state_db` is set. Defaults
    /// to 2 seconds: frequent enough that a multi-instance deployment's
    /// shared budget is enforced within a couple seconds of drift, rare
    /// enough that it's a handful of small writes a second regardless of
    /// how many requests per second the process itself is handling.
    #[serde(
        rename = "flush_interval_secs",
        default = "default_flush_interval",
        deserialize_with = "deserialize_secs"
    )]
    pub flush_interval: Duration,
}

fn default_flush_interval() -> Duration {
    Duration::from_secs(2)
}

/// TOML has no native duration type, so the config file spells the window in
/// plain seconds (`window_secs = 60`) and this maps it onto `Duration`.
fn deserialize_secs<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Duration::from_secs(u64::deserialize(deserializer)?))
}

/// The `state_db` machinery: a handle to the store plus the buffer of
/// actions admitted since the last flush. Kept as one `Option` field on
/// `ThresholdPolicy` so the no-`state_db` path (the common case, and every
/// existing test) touches none of it.
struct PersistentState {
    store: Arc<HistoryStore>,
    pending: Mutex<Vec<(Identity, Instant)>>,
}

/// Blocks an action outright once it (or the identity's recent history)
/// exceeds a configured blast-radius threshold. This is the "4 accounts is
/// fine, 4,000 is not" rule.
pub struct ThresholdPolicy {
    config: ThresholdConfig,
    history: Mutex<HashMap<Identity, VecDeque<Instant>>>,
    state: Option<PersistentState>,
}

impl ThresholdPolicy {
    /// Opening `state_db` (if configured) and loading its existing history
    /// happens here, synchronously, since it's a one-time startup cost, not
    /// the request hot path. A failure to open it is logged and degrades to
    /// pure in-memory behavior rather than stopping the proxy from starting
    /// — durability/sharing is a best-effort enhancement, not a hard
    /// dependency for this policy to function.
    pub fn new(config: ThresholdConfig) -> Self {
        let state = config.state_db.as_deref().and_then(|path| {
            HistoryStore::open(path)
                .inspect_err(|err| {
                    tracing::warn!(
                        error = %err,
                        path = %path.display(),
                        "failed to open threshold policy state db; continuing without persistence"
                    );
                })
                .ok()
                .map(|store| PersistentState {
                    store: Arc::new(store),
                    pending: Mutex::new(Vec::new()),
                })
        });

        let history = state
            .as_ref()
            .map(|state| {
                let anchor = Anchor::now();
                let cutoff = anchor.epoch_millis_before(config.window);
                match state.store.sync(&[], cutoff) {
                    Ok(rows) => rows_into_history(&anchor, rows, config.window),
                    Err(err) => {
                        tracing::warn!(error = %err, "failed to load threshold policy history from state db");
                        HashMap::new()
                    }
                }
            })
            .unwrap_or_default();

        Self {
            config,
            history: Mutex::new(history),
            state,
        }
    }

    /// Starts the background task that periodically flushes newly-admitted
    /// actions to `state_db` and refreshes history from it. A no-op unless
    /// `state_db` is configured. Requires an active tokio runtime (called
    /// from `core::policy::config::load`, itself only ever reached from
    /// `run`/`run_with_config`, both async).
    pub fn spawn_background_sync(self: Arc<Self>) {
        if self.state.is_none() {
            return;
        }
        let flush_interval = self.config.flush_interval;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(flush_interval);
            loop {
                interval.tick().await;
                self.sync_once().await;
            }
        });
    }

    /// Drains actions admitted since the last cycle, writes them to
    /// `state_db`, prunes anything the window has aged out, and folds the
    /// resulting whole-table snapshot back into local history — the step
    /// that picks up rows written by any other instance pointed at the same
    /// file. Always off the hot path: the SQLite round trip runs in
    /// `spawn_blocking`, never on the tokio worker thread evaluating live
    /// requests.
    ///
    /// A request admitted by `evaluate` locally is visible to *this*
    /// instance's own next decision immediately (it's in `history` before
    /// this ever runs); this only affects how soon *other* instances (or a
    /// restart) observe it, and how soon this instance observes theirs.
    async fn sync_once(&self) {
        let Some(state) = &self.state else { return };

        let anchor = Anchor::now();
        let new_events: Vec<(String, i64)> = {
            let mut pending = state.pending.lock().unwrap();
            std::mem::take(&mut *pending)
                .into_iter()
                .map(|(identity, instant)| (identity.0, anchor.to_epoch_millis(instant)))
                .collect()
        };
        let cutoff = anchor.epoch_millis_before(self.config.window);

        let store = state.store.clone();
        let synced = tokio::task::spawn_blocking(move || store.sync(&new_events, cutoff)).await;
        let rows = match synced {
            Ok(Ok(rows)) => rows,
            Ok(Err(err)) => {
                tracing::warn!(error = %err, "threshold policy state db sync failed");
                return;
            }
            Err(err) => {
                tracing::warn!(error = %err, "threshold policy state db sync task panicked");
                return;
            }
        };

        // Each identity's row set from the DB is authoritative as of this
        // sync (it already reflects the events just inserted above), so it
        // replaces rather than merges with local history — merging would
        // double-count this instance's own events on every cycle, since
        // they'd never leave `history` even as fresh copies of them keep
        // arriving from the round trip.
        let mut history = self.history.lock().unwrap();
        for (identity, timestamps) in rows_into_history(&anchor, rows, self.config.window) {
            history.insert(identity, timestamps);
        }
    }
}

fn rows_into_history(
    anchor: &Anchor,
    rows: HashMap<String, Vec<i64>>,
    window: Duration,
) -> HashMap<Identity, VecDeque<Instant>> {
    let now = Instant::now();
    rows.into_iter()
        .filter_map(|(identity, timestamps)| {
            let mut instants: Vec<Instant> = timestamps
                .into_iter()
                .filter_map(|epoch_millis| anchor.to_instant(epoch_millis))
                .filter(|&instant| now.duration_since(instant) <= window)
                .collect();
            instants.sort();
            if instants.is_empty() {
                None
            } else {
                Some((Identity(identity), instants.into()))
            }
        })
        .collect()
}

impl Policy for ThresholdPolicy {
    fn evaluate(&self, action: &Action, ctx: &PolicyContext) -> Decision {
        if action.blast_radius > self.config.max_per_request {
            return Decision::Block {
                reason: format!(
                    "blast radius {} exceeds per-request limit {}",
                    action.blast_radius, self.config.max_per_request
                ),
            };
        }

        let mut history = self.history.lock().unwrap();
        let entry = history.entry(ctx.identity.clone()).or_default();

        let now = Instant::now();
        while let Some(&oldest) = entry.front() {
            if now.duration_since(oldest) > self.config.window {
                entry.pop_front();
            } else {
                break;
            }
        }

        if entry.len() + action.blast_radius > self.config.max_per_window {
            return Decision::Block {
                reason: format!(
                    "{} matching actions in the last {:?} would exceed window limit {}",
                    entry.len(),
                    self.config.window,
                    self.config.max_per_window
                ),
            };
        }

        for _ in 0..action.blast_radius {
            entry.push_back(now);
        }
        drop(history);

        if let Some(state) = &self.state {
            let mut pending = state.pending.lock().unwrap();
            for _ in 0..action.blast_radius {
                pending.push((ctx.identity.clone(), now));
            }
        }

        Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::action::OperationKind;

    #[test]
    fn parses_window_secs_from_toml() {
        let config: ThresholdConfig = toml::from_str(
            r#"
            max_per_request = 10
            max_per_window = 50
            window_secs = 60
            "#,
        )
        .unwrap();

        assert_eq!(config.max_per_request, 10);
        assert_eq!(config.max_per_window, 50);
        assert_eq!(config.window, Duration::from_secs(60));
    }

    fn action(blast_radius: usize) -> Action {
        Action {
            backend: "ldap",
            operation: OperationKind::AccountLock,
            target: "cn=alice,dc=example,dc=com".into(),
            blast_radius,
        }
    }

    fn ctx_for(identity: &Identity) -> PolicyContext {
        PolicyContext {
            identity: identity.clone(),
        }
    }

    #[test]
    fn allows_action_within_thresholds() {
        let policy = ThresholdPolicy::new(ThresholdConfig {
            max_per_request: 10,
            max_per_window: 10,
            window: Duration::from_secs(60),
            state_db: None,
            flush_interval: Duration::from_secs(2),
        });
        let identity = Identity("agent-1".into());

        let decision = policy.evaluate(&action(4), &ctx_for(&identity));

        assert!(matches!(decision, Decision::Allow));
    }

    #[test]
    fn blocks_when_single_request_blast_radius_exceeds_limit() {
        let policy = ThresholdPolicy::new(ThresholdConfig {
            max_per_request: 10,
            max_per_window: 10_000,
            window: Duration::from_secs(60),
            state_db: None,
            flush_interval: Duration::from_secs(2),
        });
        let identity = Identity("agent-1".into());

        let decision = policy.evaluate(&action(4000), &ctx_for(&identity));

        assert!(matches!(decision, Decision::Block { .. }));
    }

    #[test]
    fn blocks_when_cumulative_window_total_exceeds_limit() {
        let policy = ThresholdPolicy::new(ThresholdConfig {
            max_per_request: 10,
            max_per_window: 6,
            window: Duration::from_secs(60),
            state_db: None,
            flush_interval: Duration::from_secs(2),
        });
        let identity = Identity("agent-1".into());

        for _ in 0..6 {
            let decision = policy.evaluate(&action(1), &ctx_for(&identity));
            assert!(matches!(decision, Decision::Allow));
        }

        let decision = policy.evaluate(&action(1), &ctx_for(&identity));

        assert!(matches!(decision, Decision::Block { .. }));
    }

    #[test]
    fn tracks_history_independently_per_identity() {
        let policy = ThresholdPolicy::new(ThresholdConfig {
            max_per_request: 10,
            max_per_window: 1,
            window: Duration::from_secs(60),
            state_db: None,
            flush_interval: Duration::from_secs(2),
        });
        let alice = Identity("alice".into());
        let bob = Identity("bob".into());

        assert!(matches!(
            policy.evaluate(&action(1), &ctx_for(&alice)),
            Decision::Allow
        ));
        assert!(matches!(
            policy.evaluate(&action(1), &ctx_for(&bob)),
            Decision::Allow
        ));
        assert!(matches!(
            policy.evaluate(&action(1), &ctx_for(&alice)),
            Decision::Block { .. }
        ));
    }

    #[test]
    fn window_expiry_allows_further_actions() {
        let policy = ThresholdPolicy::new(ThresholdConfig {
            max_per_request: 10,
            max_per_window: 1,
            window: Duration::from_millis(20),
            state_db: None,
            flush_interval: Duration::from_secs(2),
        });
        let identity = Identity("agent-1".into());

        assert!(matches!(
            policy.evaluate(&action(1), &ctx_for(&identity)),
            Decision::Allow
        ));
        assert!(matches!(
            policy.evaluate(&action(1), &ctx_for(&identity)),
            Decision::Block { .. }
        ));

        std::thread::sleep(Duration::from_millis(40));

        assert!(matches!(
            policy.evaluate(&action(1), &ctx_for(&identity)),
            Decision::Allow
        ));
    }

    fn state_db_config(window: Duration, path: &std::path::Path) -> ThresholdConfig {
        ThresholdConfig {
            max_per_request: 10,
            max_per_window: 1,
            window,
            state_db: Some(path.to_path_buf()),
            flush_interval: Duration::from_secs(2),
        }
    }

    #[tokio::test]
    async fn state_db_flush_makes_history_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("history.sqlite3");
        let identity = Identity("agent-1".into());

        let policy = ThresholdPolicy::new(state_db_config(Duration::from_secs(60), &db_path));
        assert!(matches!(
            policy.evaluate(&action(1), &ctx_for(&identity)),
            Decision::Allow
        ));
        // Force the flush that would otherwise wait for the next
        // `flush_interval` tick, then simulate a restart.
        policy.sync_once().await;

        let restarted = ThresholdPolicy::new(state_db_config(Duration::from_secs(60), &db_path));

        assert!(matches!(
            restarted.evaluate(&action(1), &ctx_for(&identity)),
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn state_db_sync_shares_history_across_instances() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("history.sqlite3");
        let identity = Identity("agent-1".into());

        let instance_a = ThresholdPolicy::new(state_db_config(Duration::from_secs(60), &db_path));
        let instance_b = ThresholdPolicy::new(state_db_config(Duration::from_secs(60), &db_path));

        assert!(matches!(
            instance_a.evaluate(&action(1), &ctx_for(&identity)),
            Decision::Allow
        ));
        instance_a.sync_once().await;
        // instance_b never saw the action itself, but the budget
        // instance_a consumed becomes visible through the shared file once
        // it pulls a fresh snapshot.
        instance_b.sync_once().await;

        assert!(matches!(
            instance_b.evaluate(&action(1), &ctx_for(&identity)),
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn state_db_prunes_entries_older_than_window_on_sync() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("history.sqlite3");
        let identity = Identity("agent-1".into());

        let policy = ThresholdPolicy::new(state_db_config(Duration::from_millis(20), &db_path));
        assert!(matches!(
            policy.evaluate(&action(1), &ctx_for(&identity)),
            Decision::Allow
        ));

        std::thread::sleep(Duration::from_millis(40));
        policy.sync_once().await;

        let restarted = ThresholdPolicy::new(state_db_config(Duration::from_millis(20), &db_path));

        assert!(matches!(
            restarted.evaluate(&action(1), &ctx_for(&identity)),
            Decision::Allow
        ));
    }
}
