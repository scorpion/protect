use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer};

use crate::core::action::Action;
use crate::core::identity::Identity;

use super::store::{Anchor, HistoryStore, SqliteStore, ValkeyStore, ValkeyTlsConfig};
use super::{Decision, Policy, PolicyContext};

/// Where `ThresholdPolicy` persists/shares its sliding-window history.
/// Deserializes from either a bare string — a SQLite file path, today's
/// original config shape, unchanged — or a table naming a Valkey/Redis
/// backend (`state_db = { url = "redis://valkey:6379", key_prefix = "..." }`).
/// See [`super::store`] for how the two backends differ.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum StateDbConfig {
    Sqlite(PathBuf),
    Valkey(ValkeyStateDbConfig),
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValkeyStateDbConfig {
    /// Use a `rediss://` (rather than `redis://`) URL to encrypt this hop —
    /// see `ca_file`/`client_cert` below for options beyond trusting the OS
    /// certificate store. A `rediss://` URL with neither set still works,
    /// exactly like connecting to LDAPS with no `upstream_tls.ca_file`
    /// configured.
    pub url: String,
    /// Namespaces this policy's keys so multiple `ThresholdPolicy`s (or an
    /// unrelated application) can share one Valkey instance without their
    /// histories colliding. Two `ThresholdPolicy`s must not share one
    /// prefix — pruning/history would mix between their windows, exactly
    /// as with two policies pointed at the same SQLite file.
    #[serde(default = "default_valkey_key_prefix")]
    pub key_prefix: String,
    /// PEM-encoded CA certificate(s) to trust instead of the OS trust store.
    /// Needed when the Valkey/Redis server's certificate is signed by an
    /// internal/enterprise CA. Ignored for a plain `redis://` URL.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// Client certificate ai-protect presents to Valkey/Redis. Needed when
    /// the server requires mutual TLS on this hop. Ignored for a plain
    /// `redis://` URL.
    #[serde(default)]
    pub client_cert: Option<ValkeyClientCertConfig>,
}

/// A certificate/key pair `ValkeyStateDbConfig` presents for mutual TLS —
/// the same shape as `config::ClientCertConfig` for the upstream LDAPS hop,
/// but a separate type since policy config (this file) and process config
/// (`src/config.rs`) are deliberately independent modules (see CLAUDE.md).
#[derive(Debug, Clone, Deserialize)]
pub struct ValkeyClientCertConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

fn default_valkey_key_prefix() -> String {
    "ai_protect:threshold".to_string()
}

/// Whether a `ThresholdPolicy` instance tracks its sliding-window budget
/// separately per `Identity` (the default — "4 accounts is fine for this
/// caller, 4,000 is not") or as one shared, identity-independent ceiling
/// across every caller regardless of how identity is derived. `Global` is
/// meant to run as a second, stricter-in-aggregate `[[policy]]` entry
/// alongside a `PerIdentity` one: identity churn (a fresh, unverified bind
/// DN claimed before each batch) resets a `PerIdentity` budget, but can't
/// reset a `Global` one, since it isn't keyed by identity at all — closing
/// the "compromised credential enumerates fresh identities" bypass a
/// per-identity-only budget is otherwise exposed to.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdScope {
    #[default]
    PerIdentity,
    Global,
}

/// The `history`/`state_db` key every action is bucketed under when a
/// `ThresholdPolicy` is configured with `ThresholdScope::Global`, instead of
/// `ctx.identity`. Reuses the same `Identity`-keyed map and persistence path
/// as per-identity scope (rather than a parallel set of fields) purely to
/// avoid duplicating that machinery; NUL-delimited so an ordinary bind DN or
/// peer IP address can't spell it by accident. A caller that deliberately
/// crafts an identity string equal to this sentinel only pools its own
/// budget into the shared global one — a variant of the identity-namespace-
/// collision gap already tracked in TODO.md, not a new one.
const GLOBAL_HISTORY_KEY: &str = "\0ai-protect:global\0";

#[derive(Debug, Clone, Deserialize)]
pub struct ThresholdConfig {
    /// Blast radius of a single request that immediately trips a block,
    /// regardless of history (e.g. one request that itself claims 4,000 accounts).
    pub max_per_request: usize,
    /// Total blast radius allowed per identity within `window` — or, when
    /// `scope` is `Global`, total blast radius allowed across every identity
    /// combined within `window`.
    pub max_per_window: usize,
    /// See [`ThresholdScope`]. Defaults to `PerIdentity`, preserving today's
    /// behavior for any config that doesn't set it.
    #[serde(default)]
    pub scope: ThresholdScope,
    #[serde(rename = "window_secs", deserialize_with = "deserialize_secs")]
    pub window: Duration,
    /// Optional backing store this policy's history survives a restart in
    /// and (approximately, on a `flush_interval` delay) shares with any
    /// other `ai-protect` instance pointed at the same store. `None` (the
    /// default) keeps today's pure in-memory, single-process-only behavior.
    #[serde(default)]
    pub state_db: Option<StateDbConfig>,
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
    /// Hard upper bound on the number of distinct identities tracked at
    /// once in this policy's sliding-window history. The existing
    /// age-based pruning in `evaluate` only removes a given identity's own
    /// stale timestamps, and only when that same identity is evaluated
    /// again — an identity seen exactly once (an unauthenticated caller
    /// churning through fresh bind DNs, one per throwaway action) has
    /// nothing left in its `VecDeque` after the window passes but still
    /// occupies a `HashMap` entry forever. Once this cap is reached,
    /// admitting a brand-new identity evicts the tracked identity with the
    /// least recently recorded activity to make room, logged at `warn` —
    /// see `evict_stalest_until`. Defaults to 100,000: comfortably above
    /// any real deployment's distinct concurrent callers, while bounding
    /// worst-case memory (and, if `state_db` is set, storage) to a fixed
    /// amount regardless of how many distinct identities an attacker churns
    /// through.
    #[serde(default = "default_max_tracked_identities")]
    pub max_tracked_identities: usize,
}

fn default_flush_interval() -> Duration {
    Duration::from_secs(2)
}

fn default_max_tracked_identities() -> usize {
    100_000
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
    store: Arc<dyn HistoryStore>,
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
    /// Opening `state_db` (if configured) happens here, synchronously,
    /// since it's a one-time startup cost, not the request hot path. A
    /// failure to open it is logged and degrades to pure in-memory behavior
    /// rather than stopping the proxy from starting — durability/sharing is
    /// a best-effort enhancement, not a hard dependency for this policy to
    /// function.
    ///
    /// Only `SqliteStore` can warm `history` from existing state
    /// synchronously here (its `sync_now` is plain blocking I/O, safe to
    /// call from a non-async constructor); a `ValkeyStore` needs an async
    /// connection, so a Valkey-backed policy starts with empty history and
    /// catches up within one `flush_interval` via the same background task
    /// that later performs cross-instance sync (see
    /// `ValkeyStore::open`).
    pub fn new(config: ThresholdConfig) -> Self {
        let mut history = HashMap::new();

        let state = match &config.state_db {
            Some(StateDbConfig::Sqlite(path)) => match SqliteStore::open(path) {
                Ok(store) => {
                    let anchor = Anchor::now();
                    let cutoff = anchor.epoch_millis_before(config.window);
                    match store.sync_now(&[], cutoff) {
                        Ok(rows) => {
                            history = rows_into_history(&anchor, rows, config.window);
                            evict_stalest_until(&mut history, config.max_tracked_identities);
                        }
                        Err(err) => tracing::warn!(
                            error = %err,
                            "failed to load threshold policy history from state db"
                        ),
                    }
                    Some(PersistentState {
                        store: Arc::new(store),
                        pending: Mutex::new(Vec::new()),
                    })
                }
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        path = %path.display(),
                        "failed to open threshold policy state db; continuing without persistence"
                    );
                    None
                }
            },
            Some(StateDbConfig::Valkey(valkey)) => {
                let tls = ValkeyTlsConfig {
                    ca_file: valkey.ca_file.clone(),
                    client_cert_file: valkey.client_cert.as_ref().map(|c| c.cert_file.clone()),
                    client_key_file: valkey.client_cert.as_ref().map(|c| c.key_file.clone()),
                };
                match ValkeyStore::open(&valkey.url, valkey.key_prefix.clone(), tls) {
                    Ok(store) => Some(PersistentState {
                        store: Arc::new(store),
                        pending: Mutex::new(Vec::new()),
                    }),
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            url = %valkey.url,
                            "failed to open threshold policy state db; continuing without persistence"
                        );
                        None
                    }
                }
            }
            None => None,
        };

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
    ///
    /// Holds only a `Weak` reference, so a policy superseded by a config
    /// reload (`ai_protect::run_with_config`'s `SIGHUP` handling) doesn't
    /// pin its own background task alive forever once every connection that
    /// was using it has closed — the task exits the tick after `upgrade`
    /// first fails instead of syncing on behalf of nothing.
    pub fn spawn_background_sync(self: Arc<Self>) {
        if self.state.is_none() {
            return;
        }
        let flush_interval = self.config.flush_interval;
        let weak = Arc::downgrade(&self);
        drop(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(flush_interval);
            loop {
                interval.tick().await;
                let Some(policy) = weak.upgrade() else { break };
                policy.sync_once().await;
            }
        });
    }

    /// Drains actions admitted since the last cycle, writes them to
    /// `state_db`, prunes anything the window has aged out, and folds the
    /// resulting whole-store snapshot back into local history — the step
    /// that picks up rows written by any other instance pointed at the same
    /// backend. Always off the hot path: each `HistoryStore` impl keeps its
    /// own I/O (a blocking SQLite call via `spawn_blocking`, an async
    /// Valkey round trip) off the tokio worker thread evaluating live
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

        let rows = match state.store.sync(&new_events, cutoff).await {
            Ok(rows) => rows,
            Err(err) => {
                tracing::warn!(error = %err, "threshold policy state db sync failed");
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
        evict_stalest_until(&mut history, self.config.max_tracked_identities);
    }
}

/// Evicts the identity with the least recently recorded activity — the
/// smallest last-seen timestamp across its own history, not insertion order
/// — until `history` has at most `target_len` entries, logging each
/// eviction at `warn`. An identity with no timestamps left (already aged
/// out by its own per-request pruning in `evaluate`, but not yet removed
/// from the map) sorts before every identity with at least one, since
/// `back()` on an empty `VecDeque` is `None` and `None < Some(_)` — exactly
/// the identity that should go first.
///
/// Called two ways: `evaluate` passes `cap - 1` *before* inserting a
/// brand-new identity, so the map never exceeds `cap` even momentarily;
/// `ThresholdPolicy::new`/`sync_once` pass `cap` *after* folding in a whole
/// `state_db` snapshot, since those insert in bulk and only need the map
/// back at or under the cap afterward. See
/// `ThresholdConfig::max_tracked_identities`.
fn evict_stalest_until(history: &mut HashMap<Identity, VecDeque<Instant>>, target_len: usize) {
    while history.len() > target_len {
        let Some(stalest) = history
            .iter()
            .min_by_key(|(_, timestamps)| timestamps.back().copied())
            .map(|(identity, _)| identity.clone())
        else {
            break;
        };
        history.remove(&stalest);
        tracing::warn!(
            identity = %stalest.0,
            target_len,
            "threshold policy history at max_tracked_identities capacity; evicted least-recently-active identity to make room"
        );
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

impl ThresholdPolicy {
    /// The `history`/`state_db` key this action is bucketed under: the
    /// caller's own `Identity` for `PerIdentity` scope, or the fixed
    /// `GLOBAL_HISTORY_KEY` sentinel for `Global` scope, so every caller
    /// shares one bucket regardless of identity.
    fn history_key(&self, ctx: &PolicyContext) -> Identity {
        match self.config.scope {
            ThresholdScope::PerIdentity => ctx.identity.clone(),
            ThresholdScope::Global => Identity(GLOBAL_HISTORY_KEY.to_string()),
        }
    }
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

        let key = self.history_key(ctx);
        let mut history = self.history.lock().unwrap();
        if !history.contains_key(&key) {
            // Make room before admitting a never-before-seen identity —
            // including one that's about to be blocked below, since even a
            // blocked action still creates an (empty) history entry and an
            // attacker gets no cheaper a way to grow the map by staying
            // under max_per_request/max_per_window than by exceeding it.
            evict_stalest_until(
                &mut history,
                self.config.max_tracked_identities.saturating_sub(1),
            );
        }
        let entry = history.entry(key.clone()).or_default();

        let now = Instant::now();
        while let Some(&oldest) = entry.front() {
            if now.duration_since(oldest) > self.config.window {
                entry.pop_front();
            } else {
                break;
            }
        }

        if entry.len() + action.blast_radius > self.config.max_per_window {
            let scope_label = match self.config.scope {
                ThresholdScope::PerIdentity => "matching actions",
                ThresholdScope::Global => "matching actions across all identities",
            };
            return Decision::Block {
                reason: format!(
                    "{} {scope_label} in the last {:?} would exceed window limit {}",
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
                pending.push((key.clone(), now));
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

    #[test]
    fn parses_state_db_as_sqlite_path_from_bare_string() {
        let config: ThresholdConfig = toml::from_str(
            r#"
            max_per_request = 10
            max_per_window = 50
            window_secs = 60
            state_db = "db.sqlite"
            "#,
        )
        .unwrap();

        match config.state_db {
            Some(StateDbConfig::Sqlite(path)) => assert_eq!(path, PathBuf::from("db.sqlite")),
            other => panic!("expected a Sqlite state_db, got {other:?}"),
        }
    }

    #[test]
    fn parses_state_db_as_valkey_table_with_default_key_prefix() {
        let config: ThresholdConfig = toml::from_str(
            r#"
            max_per_request = 10
            max_per_window = 50
            window_secs = 60
            [state_db]
            url = "redis://valkey:6379"
            "#,
        )
        .unwrap();

        match config.state_db {
            Some(StateDbConfig::Valkey(valkey)) => {
                assert_eq!(valkey.url, "redis://valkey:6379");
                assert_eq!(valkey.key_prefix, "ai_protect:threshold");
                assert!(valkey.ca_file.is_none());
                assert!(valkey.client_cert.is_none());
            }
            other => panic!("expected a Valkey state_db, got {other:?}"),
        }
    }

    #[test]
    fn parses_state_db_valkey_tls_config() {
        let config: ThresholdConfig = toml::from_str(
            r#"
            max_per_request = 10
            max_per_window = 50
            window_secs = 60
            [state_db]
            url = "rediss://valkey:6379"
            ca_file = "certs/valkey-ca.pem"
            [state_db.client_cert]
            cert_file = "certs/ai-protect-client.pem"
            key_file = "certs/ai-protect-client.key"
            "#,
        )
        .unwrap();

        match config.state_db {
            Some(StateDbConfig::Valkey(valkey)) => {
                assert_eq!(valkey.url, "rediss://valkey:6379");
                assert_eq!(valkey.ca_file, Some(PathBuf::from("certs/valkey-ca.pem")));
                let client_cert = valkey.client_cert.unwrap();
                assert_eq!(
                    client_cert.cert_file,
                    PathBuf::from("certs/ai-protect-client.pem")
                );
                assert_eq!(
                    client_cert.key_file,
                    PathBuf::from("certs/ai-protect-client.key")
                );
            }
            other => panic!("expected a Valkey state_db, got {other:?}"),
        }
    }

    #[test]
    fn parses_state_db_valkey_key_prefix_override() {
        let config: ThresholdConfig = toml::from_str(
            r#"
            max_per_request = 10
            max_per_window = 50
            window_secs = 60
            [state_db]
            url = "redis://valkey:6379"
            key_prefix = "custom"
            "#,
        )
        .unwrap();

        match config.state_db {
            Some(StateDbConfig::Valkey(valkey)) => assert_eq!(valkey.key_prefix, "custom"),
            other => panic!("expected a Valkey state_db, got {other:?}"),
        }
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
            max_tracked_identities: 100_000,
            scope: ThresholdScope::PerIdentity,
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
            max_tracked_identities: 100_000,
            scope: ThresholdScope::PerIdentity,
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
            max_tracked_identities: 100_000,
            scope: ThresholdScope::PerIdentity,
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
            max_tracked_identities: 100_000,
            scope: ThresholdScope::PerIdentity,
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
    fn caps_tracked_identity_count_by_evicting_the_stalest_one() {
        // A cap of 2: admitting a third, never-before-seen identity must
        // evict one of the first two rather than growing the map to 3 —
        // this is what actually bounds an unauthenticated caller churning
        // through fresh bind DNs, one per throwaway action (see TODO.md).
        let policy = ThresholdPolicy::new(ThresholdConfig {
            max_per_request: 10,
            max_per_window: 10,
            window: Duration::from_secs(60),
            state_db: None,
            flush_interval: Duration::from_secs(2),
            max_tracked_identities: 2,
            scope: ThresholdScope::PerIdentity,
        });
        let alice = Identity("alice".into());
        let bob = Identity("bob".into());
        let carol = Identity("carol".into());

        assert!(matches!(
            policy.evaluate(&action(1), &ctx_for(&alice)),
            Decision::Allow
        ));
        assert!(matches!(
            policy.evaluate(&action(1), &ctx_for(&bob)),
            Decision::Allow
        ));
        assert_eq!(policy.history.lock().unwrap().len(), 2);

        // alice is the stalest (least recently active) of the two tracked
        // identities, so admitting carol should evict her, not bob.
        assert!(matches!(
            policy.evaluate(&action(1), &ctx_for(&carol)),
            Decision::Allow
        ));

        let history = policy.history.lock().unwrap();
        assert_eq!(history.len(), 2);
        assert!(!history.contains_key(&alice), "alice should be evicted");
        assert!(history.contains_key(&bob));
        assert!(history.contains_key(&carol));
    }

    #[test]
    fn global_scope_shares_one_budget_across_every_identity() {
        // The whole point of a `Global` instance: unlike `PerIdentity`,
        // switching identities can't buy a fresh budget, since every
        // identity is bucketed under the same key.
        let policy = ThresholdPolicy::new(ThresholdConfig {
            max_per_request: 10,
            max_per_window: 1,
            window: Duration::from_secs(60),
            state_db: None,
            flush_interval: Duration::from_secs(2),
            max_tracked_identities: 100_000,
            scope: ThresholdScope::Global,
        });
        let alice = Identity("alice".into());
        let bob = Identity("bob".into());

        assert!(matches!(
            policy.evaluate(&action(1), &ctx_for(&alice)),
            Decision::Allow
        ));
        assert!(matches!(
            policy.evaluate(&action(1), &ctx_for(&bob)),
            Decision::Block { .. }
        ));
    }

    #[test]
    fn parses_scope_from_toml_and_defaults_to_per_identity() {
        let default_config: ThresholdConfig = toml::from_str(
            r#"
            max_per_request = 10
            max_per_window = 50
            window_secs = 60
            "#,
        )
        .unwrap();
        assert_eq!(default_config.scope, ThresholdScope::PerIdentity);

        let global_config: ThresholdConfig = toml::from_str(
            r#"
            max_per_request = 10
            max_per_window = 50
            window_secs = 60
            scope = "global"
            "#,
        )
        .unwrap();
        assert_eq!(global_config.scope, ThresholdScope::Global);
    }

    #[test]
    fn falls_back_to_in_memory_when_valkey_url_is_invalid() {
        // `ValkeyStore::open` only parses the URL — it never connects — so
        // this is a pure unit test: a malformed URL is the one failure mode
        // that surfaces synchronously, and it must degrade to in-memory
        // behavior rather than panicking `ThresholdPolicy::new`.
        let policy = ThresholdPolicy::new(ThresholdConfig {
            max_per_request: 10,
            max_per_window: 10,
            window: Duration::from_secs(60),
            state_db: Some(StateDbConfig::Valkey(ValkeyStateDbConfig {
                url: "not-a-valid-url".into(),
                key_prefix: "ai_protect_test".into(),
                ca_file: None,
                client_cert: None,
            })),
            flush_interval: Duration::from_secs(2),
            max_tracked_identities: 100_000,
            scope: ThresholdScope::PerIdentity,
        });
        let identity = Identity("agent-1".into());

        let decision = policy.evaluate(&action(4), &ctx_for(&identity));

        assert!(matches!(decision, Decision::Allow));
    }

    #[test]
    fn window_expiry_allows_further_actions() {
        let policy = ThresholdPolicy::new(ThresholdConfig {
            max_per_request: 10,
            max_per_window: 1,
            window: Duration::from_millis(20),
            state_db: None,
            flush_interval: Duration::from_secs(2),
            max_tracked_identities: 100_000,
            scope: ThresholdScope::PerIdentity,
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
            state_db: Some(StateDbConfig::Sqlite(path.to_path_buf())),
            flush_interval: Duration::from_secs(2),
            max_tracked_identities: 100_000,
            scope: ThresholdScope::PerIdentity,
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

    // Exercises the same cross-instance sharing as
    // `state_db_sync_shares_history_across_instances` above, but through a
    // Valkey-backed `state_db` end to end (config parsing, `ThresholdPolicy`,
    // and `ValkeyStore` together). Skipped unless a real server is
    // available — see `store::valkey::tests` for how to run one locally.
    #[tokio::test]
    #[ignore]
    async fn state_db_valkey_sync_shares_history_across_instances() {
        let Some(url) = std::env::var("VALKEY_TEST_URL").ok() else {
            eprintln!("skipping: VALKEY_TEST_URL not set");
            return;
        };
        let key_prefix = format!(
            "ai_protect_test:{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let config = |window: Duration| ThresholdConfig {
            max_per_request: 10,
            max_per_window: 1,
            window,
            state_db: Some(StateDbConfig::Valkey(ValkeyStateDbConfig {
                url: url.clone(),
                key_prefix: key_prefix.clone(),
                ca_file: None,
                client_cert: None,
            })),
            flush_interval: Duration::from_secs(2),
            max_tracked_identities: 100_000,
            scope: ThresholdScope::PerIdentity,
        };
        let identity = Identity("agent-1".into());

        let instance_a = ThresholdPolicy::new(config(Duration::from_secs(60)));
        let instance_b = ThresholdPolicy::new(config(Duration::from_secs(60)));

        assert!(matches!(
            instance_a.evaluate(&action(1), &ctx_for(&identity)),
            Decision::Allow
        ));
        instance_a.sync_once().await;
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
