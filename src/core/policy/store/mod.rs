//! Backing stores for [`ThresholdPolicy`](super::threshold::ThresholdPolicy)'s
//! sliding-window history: durability across a restart and, for a
//! multi-instance HA deployment, approximate sharing of a budget that would
//! otherwise live only in each process's own in-memory map. Deliberately
//! kept off the request hot path: `ThresholdPolicy::evaluate` only ever
//! touches its in-memory `Mutex<HashMap<..>>`, never a [`HistoryStore`]
//! directly. A background task (`ThresholdPolicy::spawn_background_sync`) is
//! the only caller, on an interval.
//!
//! Two backends implement [`HistoryStore`]: [`sqlite::SqliteStore`] (a local
//! file, shared only across instances that can reach the same disk/volume)
//! and [`valkey::ValkeyStore`] (a network service, for HA across hosts with
//! no shared disk — see the `ha` profile in `compose.yaml` for a local one).
//! Schema/keying is intentionally global in both — neither backend has a
//! policy identifier column/prefix reservation — so each `ThresholdPolicy`
//! that enables `state_db` must point at its own file or key prefix, or two
//! policies' windows will prune/observe each other's rows.

pub mod sqlite;
pub mod valkey;

use std::collections::HashMap;

pub use sqlite::SqliteStore;
pub use valkey::ValkeyStore;

/// A wall-clock-anchored snapshot of `Instant::now()` at the moment it was
/// taken, letting `Instant` (monotonic, process-local) round-trip through a
/// store as epoch milliseconds (wall-clock, portable across a restart or
/// between processes) and back. Not meant to be reused long after `now()` is
/// called — the pair drifts apart from true wall-clock time exactly as much
/// as the monotonic clock does, which is negligible over the lifetime of one
/// sync cycle.
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

/// Durability/sharing backend for `ThresholdPolicy` history. Implementations
/// own how "blocking-ness" (a local disk write, a network round trip) is
/// kept off the tokio worker thread evaluating live requests — the trait
/// itself is async so `ThresholdPolicy::sync_once` doesn't need to know
/// which kind of I/O a given backend requires.
#[async_trait::async_trait]
pub trait HistoryStore: Send + Sync {
    /// Inserts `new_events` (this instance's newly-admitted actions since
    /// the last sync), prunes anything at or older than
    /// `cutoff_epoch_millis` (any instance's rows — pruning by age alone is
    /// always safe), then returns every remaining row grouped by identity:
    /// the authoritative, whole-store snapshot the caller folds into its
    /// in-memory history, which is how this instance picks up rows written
    /// by any other instance pointed at the same backend.
    async fn sync(
        &self,
        new_events: &[(String, i64)],
        cutoff_epoch_millis: i64,
    ) -> anyhow::Result<HashMap<String, Vec<i64>>>;
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
}
