//! Valkey/Redis-protocol-compatible [`HistoryStore`](super::HistoryStore):
//! shared state for a multi-instance HA deployment where instances have no
//! shared disk for `SqliteStore`'s file-based sharing (see the `ha` profile
//! in `compose.yaml` for a local one). Valkey (<https://valkey.io>) speaks
//! the same RESP protocol as Redis, so any RESP2/3 server works here.
//!
//! Each identity's events live in a sorted set keyed by
//! `{key_prefix}:history:{identity}`, scored by epoch milliseconds — pruning
//! by age (`ZREMRANGEBYSCORE`) and reading the survivors back in order
//! (`ZRANGE ... WITHSCORES`) are both native, per-identity operations,
//! unlike `SqliteStore`'s single global table that every sync scans in full.
//! Identities are enumerated with `SCAN` rather than a maintained index, so
//! this store never needs to reconcile a separate registry with the sorted
//! sets it actually holds.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use tokio::sync::Mutex;

use crate::core::tls::ensure_crypto_provider;

use super::HistoryStore;

/// Optional TLS settings for a `rediss://` `ValkeyStateDbConfig`. All-`None`
/// (the default) still works for a `rediss://` URL — `redis::Client::open`
/// validates the server's certificate against the OS trust store in that
/// case, the same as `SqliteStore`'s deployment needs no extra config for
/// the common case. These fields exist for the two cases that do: an
/// internal CA (`ca_file`) or a Valkey/Redis server requiring mutual TLS
/// (`client_cert_file`/`client_key_file`, both required together).
#[derive(Debug, Clone, Default)]
pub struct ValkeyTlsConfig {
    pub ca_file: Option<PathBuf>,
    pub client_cert_file: Option<PathBuf>,
    pub client_key_file: Option<PathBuf>,
}

impl ValkeyTlsConfig {
    fn is_default(&self) -> bool {
        self.ca_file.is_none() && self.client_cert_file.is_none() && self.client_key_file.is_none()
    }
}

pub struct ValkeyStore {
    client: redis::Client,
    key_prefix: String,
    conn: Mutex<Option<ConnectionManager>>,
    /// Disambiguates events landing in the same sorted set with an
    /// identical score: a sorted set dedupes by *member*, not score, so a
    /// single request with `blast_radius` > 1 (several events for the same
    /// identity at the same `Instant`) would otherwise collapse into one
    /// entry instead of counting `blast_radius` times.
    member_seq: AtomicU64,
}

impl ValkeyStore {
    /// Parses `url` (e.g. `redis://valkey:6379/0` or, for an encrypted
    /// connection, `rediss://valkey:6379/0`) but doesn't connect —
    /// connecting is async, and this is called from `ThresholdPolicy::new`,
    /// a synchronous constructor with no executor requirement. The first
    /// `sync` call connects lazily (see `connection`).
    ///
    /// Unlike `SqliteStore`, that means a freshly opened `ValkeyStore`
    /// cannot warm `ThresholdPolicy`'s in-memory history synchronously at
    /// startup: `ThresholdPolicy::new` leaves history empty for a
    /// `state_db` pointed at Valkey, and it catches up within one
    /// `flush_interval` via the same background task that later performs
    /// cross-instance sync.
    ///
    /// `tls` is ignored for a plain `redis://` URL. For `rediss://`, an
    /// all-default `tls` builds a client the same way `redis::Client::open`
    /// always has (system trust store, no client certificate); a non-default
    /// `tls` instead builds one via `redis::Client::build_with_tls` with the
    /// given CA and/or client certificate — see [`ValkeyTlsConfig`]. Either
    /// way, this installs the process-wide `rustls` crypto provider
    /// `rediss://` needs (see `ensure_crypto_provider`), since this may be
    /// the only TLS-using code path in a process whose LDAP hops are both
    /// plaintext.
    pub fn open(url: &str, key_prefix: String, tls: ValkeyTlsConfig) -> anyhow::Result<Self> {
        ensure_crypto_provider();

        let client = if tls.is_default() {
            redis::Client::open(url).context("parsing Valkey/Redis state_db URL")?
        } else {
            let root_cert = tls
                .ca_file
                .map(|path| {
                    std::fs::read(&path)
                        .with_context(|| format!("reading Valkey TLS ca_file {}", path.display()))
                })
                .transpose()?;
            let client_tls = match (tls.client_cert_file, tls.client_key_file) {
                (Some(cert_path), Some(key_path)) => Some(redis::ClientTlsConfig {
                    client_cert: std::fs::read(&cert_path).with_context(|| {
                        format!(
                            "reading Valkey TLS client_cert file {}",
                            cert_path.display()
                        )
                    })?,
                    client_key: std::fs::read(&key_path).with_context(|| {
                        format!("reading Valkey TLS client_key file {}", key_path.display())
                    })?,
                }),
                (None, None) => None,
                _ => anyhow::bail!(
                    "Valkey state_db TLS config: client_cert_file and client_key_file must be set together"
                ),
            };
            redis::Client::build_with_tls(
                url,
                redis::TlsCertificates {
                    client_tls,
                    root_cert,
                },
            )
            .context("building TLS-enabled Valkey/Redis client")?
        };

        Ok(Self {
            client,
            key_prefix,
            conn: Mutex::new(None),
            member_seq: AtomicU64::new(0),
        })
    }

    fn key_prefix(&self) -> String {
        format!("{}:history:", self.key_prefix)
    }

    fn history_key(&self, identity: &str) -> String {
        format!("{}{identity}", self.key_prefix())
    }

    /// `ConnectionManager` multiplexes over a single connection and
    /// reconnects automatically on failure, so it's cheap to clone and
    /// worth caching rather than reopening per call — the piece that makes
    /// this store tolerate a Valkey restart without `ThresholdPolicy`
    /// needing to know.
    async fn connection(&self) -> redis::RedisResult<ConnectionManager> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_ref() {
            return Ok(conn.clone());
        }
        let conn = ConnectionManager::new(self.client.clone()).await?;
        *guard = Some(conn.clone());
        Ok(conn)
    }
}

#[async_trait::async_trait]
impl HistoryStore for ValkeyStore {
    async fn sync(
        &self,
        new_events: &[(String, i64)],
        cutoff_epoch_millis: i64,
    ) -> anyhow::Result<HashMap<String, Vec<i64>>> {
        let mut conn = self.connection().await?;

        if !new_events.is_empty() {
            let mut pipe = redis::pipe();
            for (identity, timestamp_millis) in new_events {
                let member = format!(
                    "{timestamp_millis}-{}",
                    self.member_seq.fetch_add(1, Ordering::Relaxed)
                );
                pipe.zadd(self.history_key(identity), member, *timestamp_millis)
                    .ignore();
            }
            pipe.query_async::<()>(&mut conn).await?;
        }

        // Every instance pointed at this backend may have written keys this
        // one never did, so identities are discovered by pattern rather
        // than tracked locally.
        let key_prefix = self.key_prefix();
        let pattern = format!("{key_prefix}*");
        let mut keys = Vec::new();
        let mut cursor: u64 = 0;
        loop {
            let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(200)
                .query_async(&mut conn)
                .await?;
            keys.extend(batch);
            if next_cursor == 0 {
                break;
            }
            cursor = next_cursor;
        }

        let mut rows_by_identity = HashMap::with_capacity(keys.len());
        for key in keys {
            let (remaining, count): (Vec<(String, f64)>, usize) = redis::pipe()
                .zrembyscore(&key, "-inf", format!("({cutoff_epoch_millis}"))
                .ignore()
                .zrange_withscores(&key, 0, -1)
                .zcard(&key)
                .query_async(&mut conn)
                .await?;

            if count == 0 {
                // The window aged out every event for this identity —
                // delete the now-empty key so it drops out of future SCANs
                // instead of accumulating forever. Best-effort: a failure
                // here just means one more harmless empty key next cycle.
                if let Err(err) = conn.del::<_, usize>(&key).await {
                    tracing::debug!(error = %err, key = %key, "failed to delete emptied threshold history key");
                }
                continue;
            }

            let Some(identity) = key.strip_prefix(&key_prefix) else {
                continue;
            };
            rows_by_identity.insert(
                identity.to_string(),
                remaining
                    .into_iter()
                    .map(|(_, score)| score as i64)
                    .collect(),
            );
        }

        Ok(rows_by_identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_rejects_an_invalid_url_without_connecting() {
        assert!(
            ValkeyStore::open("not-a-url", "ai_protect".into(), ValkeyTlsConfig::default())
                .is_err()
        );
    }

    #[test]
    fn history_key_is_namespaced_by_prefix_and_identity() {
        let store = ValkeyStore::open(
            "redis://127.0.0.1:6379",
            "ai_protect".into(),
            ValkeyTlsConfig::default(),
        )
        .unwrap();

        assert_eq!(store.history_key("alice"), "ai_protect:history:alice");
    }

    #[test]
    fn open_rejects_a_client_cert_without_a_matching_key() {
        let tls = ValkeyTlsConfig {
            ca_file: None,
            client_cert_file: Some("cert.pem".into()),
            client_key_file: None,
        };

        let result = ValkeyStore::open("rediss://127.0.0.1:6379", "ai_protect".into(), tls);
        let Err(err) = result else {
            panic!("expected an error");
        };

        assert!(err.to_string().contains("must be set together"));
    }

    // The tests below exercise `sync` against a real Valkey/Redis server and
    // are skipped by default since neither CI nor a fresh checkout has one
    // running. Bring one up locally with:
    //   docker compose --profile ha up -d valkey
    // then run:
    //   VALKEY_TEST_URL=redis://127.0.0.1:6379 cargo test valkey_store -- --ignored
    fn test_url() -> Option<String> {
        std::env::var("VALKEY_TEST_URL").ok()
    }

    #[tokio::test]
    #[ignore]
    async fn sync_persists_events_and_prunes_stale_rows() {
        let Some(url) = test_url() else {
            eprintln!("skipping: VALKEY_TEST_URL not set");
            return;
        };
        let key_prefix = format!("ai_protect_test:{}", unique_test_suffix());
        let store = ValkeyStore::open(&url, key_prefix, ValkeyTlsConfig::default()).unwrap();

        let rows = store
            .sync(
                &[("alice".to_string(), 1_000), ("bob".to_string(), 1_500)],
                0,
            )
            .await
            .unwrap();
        assert_eq!(rows.get("alice").unwrap(), &vec![1_000]);
        assert_eq!(rows.get("bob").unwrap(), &vec![1_500]);

        // A cutoff past "alice"'s only row prunes it (and deletes the now-
        // empty key) but keeps "bob"'s.
        let rows = store.sync(&[], 1_200).await.unwrap();
        assert!(!rows.contains_key("alice"));
        assert_eq!(rows.get("bob").unwrap(), &vec![1_500]);
    }

    #[tokio::test]
    #[ignore]
    async fn sync_shares_history_across_instances() {
        let Some(url) = test_url() else {
            eprintln!("skipping: VALKEY_TEST_URL not set");
            return;
        };
        let key_prefix = format!("ai_protect_test:{}", unique_test_suffix());
        let instance_a =
            ValkeyStore::open(&url, key_prefix.clone(), ValkeyTlsConfig::default()).unwrap();
        let instance_b = ValkeyStore::open(&url, key_prefix, ValkeyTlsConfig::default()).unwrap();

        instance_a
            .sync(&[("alice".to_string(), 1_000)], 0)
            .await
            .unwrap();
        let rows = instance_b.sync(&[], 0).await.unwrap();

        assert_eq!(rows.get("alice").unwrap(), &vec![1_000]);
    }

    /// Nanoseconds alone aren't a reliable uniqueness source under some
    /// clock resolutions (concurrently run tests have collided on it), so a
    /// per-process counter is folded in to guarantee two calls never
    /// produce the same key prefix, however close together they run.
    fn unique_test_suffix() -> String {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{nanos}-{seq}")
    }
}
