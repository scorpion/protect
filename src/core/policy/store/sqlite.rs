//! SQLite-backed [`HistoryStore`](super::HistoryStore): durability and
//! approximate cross-instance sharing over a shared file/volume. See the
//! `store` module doc for how this fits into `ThresholdPolicy`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use super::HistoryStore;

pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStore {
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
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// The blocking query logic, exposed directly (not just through
    /// `HistoryStore::sync`) so `ThresholdPolicy::new` can load existing
    /// history synchronously at startup — a one-time cost with no executor
    /// requirement, unlike the periodic background sync, which always runs
    /// this via `spawn_blocking` so a slow disk never stalls a live
    /// connection's tokio worker.
    pub(crate) fn sync_now(
        &self,
        new_events: &[(String, i64)],
        cutoff_epoch_millis: i64,
    ) -> rusqlite::Result<HashMap<String, Vec<i64>>> {
        blocking_sync(&self.conn, new_events, cutoff_epoch_millis)
    }
}

fn blocking_sync(
    conn: &Mutex<Connection>,
    new_events: &[(String, i64)],
    cutoff_epoch_millis: i64,
) -> rusqlite::Result<HashMap<String, Vec<i64>>> {
    let mut conn = conn.lock().unwrap();
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

#[async_trait::async_trait]
impl HistoryStore for SqliteStore {
    async fn sync(
        &self,
        new_events: &[(String, i64)],
        cutoff_epoch_millis: i64,
    ) -> anyhow::Result<HashMap<String, Vec<i64>>> {
        let conn = self.conn.clone();
        let new_events = new_events.to_vec();
        tokio::task::spawn_blocking(move || blocking_sync(&conn, &new_events, cutoff_epoch_millis))
            .await
            .map_err(anyhow::Error::from)?
            .map_err(anyhow::Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_persists_events_and_prunes_stale_rows() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::open(&dir.path().join("history.sqlite3")).unwrap();

        let rows = store
            .sync_now(
                &[("alice".to_string(), 1_000), ("bob".to_string(), 1_500)],
                0,
            )
            .unwrap();
        assert_eq!(rows.get("alice").unwrap(), &vec![1_000]);
        assert_eq!(rows.get("bob").unwrap(), &vec![1_500]);

        // A cutoff past "alice"'s only row prunes it but keeps "bob"'s.
        let rows = store.sync_now(&[], 1_200).unwrap();
        assert!(!rows.contains_key("alice"));
        assert_eq!(rows.get("bob").unwrap(), &vec![1_500]);
    }

    #[test]
    fn sync_accumulates_events_for_the_same_identity() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::open(&dir.path().join("history.sqlite3")).unwrap();

        store.sync_now(&[("alice".to_string(), 1_000)], 0).unwrap();
        let rows = store.sync_now(&[("alice".to_string(), 2_000)], 0).unwrap();

        assert_eq!(rows.get("alice").unwrap(), &vec![1_000, 2_000]);
    }

    #[test]
    fn reopening_the_same_file_recovers_prior_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.sqlite3");

        {
            let store = SqliteStore::open(&path).unwrap();
            store.sync_now(&[("alice".to_string(), 1_000)], 0).unwrap();
        }

        let store = SqliteStore::open(&path).unwrap();
        let rows = store.sync_now(&[], 0).unwrap();

        assert_eq!(rows.get("alice").unwrap(), &vec![1_000]);
    }

    #[tokio::test]
    async fn trait_sync_matches_sync_now() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::open(&dir.path().join("history.sqlite3")).unwrap();

        let rows = HistoryStore::sync(&store, &[("alice".to_string(), 1_000)], 0)
            .await
            .unwrap();

        assert_eq!(rows.get("alice").unwrap(), &vec![1_000]);
    }
}
