use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;

use super::Policy;
use super::threshold::{ThresholdConfig, ThresholdPolicy};

/// Failure modes for loading the ordered `[[policy]]` list from a TOML file.
#[derive(Debug, thiserror::Error)]
pub enum PolicyConfigError {
    #[error("reading policy file {path} (copy policies/ldap.example.toml to get started)")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing policy file {path}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

type Result<T> = std::result::Result<T, PolicyConfigError>;

/// One `[[policy]]` table. Tagged by `type` so a policy file can declare an
/// ordered list of heterogeneous policies; adding a new `Policy` impl means
/// adding a variant here, not changing the file format.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PolicyEntry {
    Threshold(ThresholdConfig),
}

impl PolicyEntry {
    fn build(self) -> Arc<dyn Policy> {
        match self {
            PolicyEntry::Threshold(config) => {
                let policy = Arc::new(ThresholdPolicy::new(config));
                // A no-op unless this entry set `state_db`. Needs an active
                // tokio runtime, which holds here: `load`/`parse` are only
                // ever reached from `run`/`run_with_config`, both async.
                policy.clone().spawn_background_sync();
                policy
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct PolicyFile {
    #[serde(rename = "policy", default)]
    policies: Vec<PolicyEntry>,
}

/// Reads and parses an ordered list of policies from a TOML file (see
/// `policies/ldap.example.toml` for the schema).
pub fn load(path: &Path) -> Result<Vec<Arc<dyn Policy>>> {
    let raw = std::fs::read_to_string(path).map_err(|source| PolicyConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    parse(&raw).map_err(|source| PolicyConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

/// Order is preserved from the file: `evaluate_all` stops at the first
/// block, and stateful policies (like threshold history) only advance their
/// state on `Allow`, so where a policy sits in the list matters.
fn parse(raw: &str) -> std::result::Result<Vec<Arc<dyn Policy>>, toml::de::Error> {
    let file: PolicyFile = toml::from_str(raw)?;
    Ok(file.policies.into_iter().map(PolicyEntry::build).collect())
}

#[cfg(test)]
mod tests {
    use crate::core::action::{Action, OperationKind};
    use crate::core::identity::Identity;
    use crate::core::policy::{Decision, PolicyContext, evaluate_all};

    use super::*;

    fn action(blast_radius: usize) -> Action {
        Action {
            backend: "ldap",
            operation: OperationKind::AccountLock,
            target: "cn=alice,dc=example,dc=com".into(),
            blast_radius,
        }
    }

    fn ctx() -> PolicyContext {
        PolicyContext {
            identity: Identity("agent-1".into()),
        }
    }

    #[test]
    fn parses_empty_policy_file_as_no_policies() {
        let policies = parse("").unwrap();

        assert!(policies.is_empty());
    }

    #[test]
    fn parses_threshold_entry_into_working_policy() {
        let policies = parse(
            r#"
            [[policy]]
            type = "threshold"
            max_per_request = 3
            max_per_window = 100
            window_secs = 60
            "#,
        )
        .unwrap();

        assert_eq!(policies.len(), 1);
        let decision = evaluate_all(&policies, &action(4), &ctx());
        assert!(matches!(decision, Decision::Block { .. }));
    }

    #[test]
    fn preserves_declared_order_across_multiple_entries() {
        let policies = parse(
            r#"
            [[policy]]
            type = "threshold"
            max_per_request = 1
            max_per_window = 1
            window_secs = 60

            [[policy]]
            type = "threshold"
            max_per_request = 100
            max_per_window = 100
            window_secs = 60
            "#,
        )
        .unwrap();

        assert_eq!(policies.len(), 2);
        let decision = evaluate_all(&policies, &action(2), &ctx());
        match decision {
            Decision::Block { reason } => assert!(reason.contains("per-request limit 1")),
            Decision::Allow => panic!("expected the first, stricter policy to block"),
        }
    }

    #[test]
    fn rejects_unknown_policy_type() {
        let err = parse(
            r#"
            [[policy]]
            type = "not_a_real_policy"
            "#,
        )
        .err()
        .expect("expected an error for an unrecognized policy type");

        assert!(
            err.to_string().contains("not_a_real_policy")
                || err.to_string().contains("unknown variant")
        );
    }
}
