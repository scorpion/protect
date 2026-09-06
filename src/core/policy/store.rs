//! SQLite-backed durability/sharing layer for [`ThresholdPolicy`](super::threshold::ThresholdPolicy)'s
//! sliding-window history. Deliberately kept off the request hot path:
//! `ThresholdPolicy::evaluate` only ever touches its in-memory
//! `Mutex<HashMap<..>>`, never this store directly. A background task
//! (`ThresholdPolicy::spawn_background_sync`) is the only caller, on an
//! interval, always via `spawn_blocking` so a slow disk never stalls the
//! tokio runtime a live connection is relying on.
//!
//! Schema is intentionally global (no policy identifier column): each
//! `ThresholdPolicy` that enables `state_db` must point at its own file, or
//! two policies' windows will prune/observe each other's rows. Point
//! distinct `[[policy]]` entries at distinct files.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;

/// A wall-clock-anchored snapshot of `Instant::now()` at the moment it was
/// taken, letting `Instant` (monotonic, process-local) round-trip through
/// SQLite as epoch milliseconds (wall-clock, portable across a restart)
/// and back. Not meant to be reused long after `now()` is called — the
/// pair drifts apart from true wall-clock time exactly as much as the
/// monotonic clock does, which is negligible over the lifetime of one sync
/// cycle.
pub struct Anchor {
    instant: std::time::Instant,
    epoch_millis: i64,
}

impl Anchor {
    pub fn now() -> Self {
        let instant = std::time::Instant::now();
        let epoch_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        Self {
            instant,
            epoch_millis,
        }
    }

    pub fn to_epoch_millis(&self, instant: std::time::Instant) -> i64 {
        if instant >= self.instant {
            self.epoch_millis + (instant - self.instant).as_millis() as i64
        } else {
            self.epoch_millis - (self.instant - instant).as_millis() as i64
        }
    }

    /// `None` if the timestamp is so far in the past that offsetting
    /// `self.instant` by it would underflow `Instant`'s valid range — safe
    /// to treat as "older than any window we'd care about" and drop.
    pub fn to_instant(&self, epoch_millis: i64) -> Option<std::time::Instant> {
        let delta_millis = epoch_millis - self.epoch_millis;
        if delta_millis >= 0 {
            self.instant
                .checked_add(std::time::Duration::from_millis(delta_millis as u64))
        } else {
            self.instant
                .checked_sub(std::time::Duration::from_millis((-delta_millis) as u64))
        }
    }

    pub fn epoch_millis_before(&self, window: std::time::Duration) -> i64 {
        self.epoch_millis - window.as_millis() as i64
    }
}

pub struct HistoryStore {
    conn: Mutex<Connection>,
}

impl HistoryStore {
    /// Opens (creating if needed) the SQLite file at `path` and ensures its
    /// schema exists. WAL journaling is used so this instance's periodic
    /// writes don't block a concurrent reader from another `ai-protect`
    /// process pointed at the same file.
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS threshold_history (
                identity TEXT NOT NULL,
                timestamp_millis INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_threshold_history_identity
                ON threshold_history (identity);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Inserts `new_events` (this instance's newly-admitted actions since
    /// the last sync), prunes anything at or older than `cutoff_epoch_millis`
    /// (any instance's rows — pruning by age alone is always safe), then
    /// returns every remaining row grouped by identity: the authoritative,
    /// whole-table snapshot the caller folds into its in-memory history,
    /// which is how this instance picks up rows written by any other
    /// instance pointed at the same file.
    pub fn sync(
        &self,
        new_events: &[(String, i64)],
        cutoff_epoch_millis: i64,
    ) -> rusqlite::Result<HashMap<String, Vec<i64>>> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        {
            let mut insert = tx.prepare(
                "INSERT INTO threshold_history (identity, timestamp_millis) VALUES (?1, ?2)",
            )?;
            for (identity, timestamp_millis) in new_events {
                insert.execute(rusqlite::params![identity, timestamp_millis])?;
            }
        }
        tx.execute(
            "DELETE FROM threshold_history WHERE timestamp_millis < ?1",
            [cutoff_epoch_millis],
        )?;
        let mut rows_by_identity: HashMap<String, Vec<i64>> = HashMap::new();
        {
            let mut select = tx.prepare(
                "SELECT identity, timestamp_millis FROM threshold_history ORDER BY timestamp_millis ASC",
            )?;
            let mut rows = select.query([])?;
            while let Some(row) = rows.next()? {
                let identity: String = row.get(0)?;
                let timestamp_millis: i64 = row.get(1)?;
                rows_by_identity
                    .entry(identity)
                    .or_default()
                    .push(timestamp_millis);
            }
        }
        tx.commit()?;
        Ok(rows_by_identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_instant_through_epoch_millis() {
        let anchor = Anchor::now();
        let instant = std::time::Instant::now();

        let epoch_millis = anchor.to_epoch_millis(instant);
        let recovered = anchor.to_instant(epoch_millis).unwrap();

        // Sub-millisecond precision is lost in the round trip; within 1ms
        // is the contract.
        let diff = if recovered >= instant {
            recovered - instant
        } else {
            instant - recovered
        };
        assert!(diff < std::time::Duration::from_millis(1));
    }

    #[test]
    fn sync_persists_events_and_prunes_stale_rows() {
        let dir = tempfile::tempdir().unwrap();
        let store = HistoryStore::open(&dir.path().join("history.sqlite3")).unwrap();

        let rows = store
            .sync(
                &[("alice".to_string(), 1_000), ("bob".to_string(), 1_500)],
                0,
            )
            .unwrap();
        assert_eq!(rows.get("alice").unwrap(), &vec![1_000]);
        assert_eq!(rows.get("bob").unwrap(), &vec![1_500]);

        // A cutoff past "alice"'s only row prunes it but keeps "bob"'s.
        let rows = store.sync(&[], 1_200).unwrap();
        assert!(!rows.contains_key("alice"));
        assert_eq!(rows.get("bob").unwrap(), &vec![1_500]);
    }

    #[test]
    fn sync_accumulates_events_for_the_same_identity() {
        let dir = tempfile::tempdir().unwrap();
        let store = HistoryStore::open(&dir.path().join("history.sqlite3")).unwrap();

        store.sync(&[("alice".to_string(), 1_000)], 0).unwrap();
        let rows = store.sync(&[("alice".to_string(), 2_000)], 0).unwrap();

        assert_eq!(rows.get("alice").unwrap(), &vec![1_000, 2_000]);
    }

    #[test]
    fn reopening_the_same_file_recovers_prior_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.sqlite3");

        {
            let store = HistoryStore::open(&path).unwrap();
            store.sync(&[("alice".to_string(), 1_000)], 0).unwrap();
        }

        let store = HistoryStore::open(&path).unwrap();
        let rows = store.sync(&[], 0).unwrap();

        assert_eq!(rows.get("alice").unwrap(), &vec![1_000]);
    }
}
