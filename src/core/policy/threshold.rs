use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer};

use crate::core::action::Action;
use crate::core::identity::Identity;

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
}

/// TOML has no native duration type, so the config file spells the window in
/// plain seconds (`window_secs = 60`) and this maps it onto `Duration`.
fn deserialize_secs<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Duration::from_secs(u64::deserialize(deserializer)?))
}

/// Blocks an action outright once it (or the identity's recent history)
/// exceeds a configured blast-radius threshold. This is the "4 accounts is
/// fine, 4,000 is not" rule.
pub struct ThresholdPolicy {
    config: ThresholdConfig,
    history: Mutex<HashMap<Identity, VecDeque<Instant>>>,
}

impl ThresholdPolicy {
    pub fn new(config: ThresholdConfig) -> Self {
        Self {
            config,
            history: Mutex::new(HashMap::new()),
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
        });
        let alice = Identity("alice".into());
        let bob = Identity("bob".into());

        assert!(matches!(policy.evaluate(&action(1), &ctx_for(&alice)), Decision::Allow));
        assert!(matches!(policy.evaluate(&action(1), &ctx_for(&bob)), Decision::Allow));
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
        });
        let identity = Identity("agent-1".into());

        assert!(matches!(policy.evaluate(&action(1), &ctx_for(&identity)), Decision::Allow));
        assert!(matches!(
            policy.evaluate(&action(1), &ctx_for(&identity)),
            Decision::Block { .. }
        ));

        std::thread::sleep(Duration::from_millis(40));

        assert!(matches!(policy.evaluate(&action(1), &ctx_for(&identity)), Decision::Allow));
    }
}
