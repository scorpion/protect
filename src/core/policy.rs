pub mod config;
pub mod store;
pub mod threshold;

use std::sync::Arc;

use crate::core::action::Action;
use crate::core::identity::Identity;

#[derive(Debug, Clone)]
pub enum Decision {
    Allow,
    Block { reason: String },
}

pub struct PolicyContext {
    pub identity: Identity,
}

pub trait Policy: Send + Sync {
    fn evaluate(&self, action: &Action, ctx: &PolicyContext) -> Decision;
}

/// Runs every policy in order and stops at the first block, so the caller
/// gets one authoritative decision regardless of how many rules are configured.
pub fn evaluate_all(
    policies: &[Arc<dyn Policy>],
    action: &Action,
    ctx: &PolicyContext,
) -> Decision {
    for policy in policies {
        if let Decision::Block { reason } = policy.evaluate(action, ctx) {
            return Decision::Block { reason };
        }
    }
    Decision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::action::OperationKind;

    struct AlwaysAllow;
    impl Policy for AlwaysAllow {
        fn evaluate(&self, _action: &Action, _ctx: &PolicyContext) -> Decision {
            Decision::Allow
        }
    }

    struct AlwaysBlock(&'static str);
    impl Policy for AlwaysBlock {
        fn evaluate(&self, _action: &Action, _ctx: &PolicyContext) -> Decision {
            Decision::Block {
                reason: self.0.to_string(),
            }
        }
    }

    fn action() -> Action {
        Action {
            backend: "ldap",
            operation: OperationKind::AccountLock,
            target: "cn=alice,dc=example,dc=com".into(),
            blast_radius: 1,
        }
    }

    fn ctx() -> PolicyContext {
        PolicyContext {
            identity: Identity("agent-1".into()),
        }
    }

    #[test]
    fn allows_when_every_policy_allows() {
        let policies: Vec<Arc<dyn Policy>> = vec![Arc::new(AlwaysAllow), Arc::new(AlwaysAllow)];

        let decision = evaluate_all(&policies, &action(), &ctx());

        assert!(matches!(decision, Decision::Allow));
    }

    #[test]
    fn blocks_and_stops_at_first_blocking_policy() {
        let policies: Vec<Arc<dyn Policy>> = vec![
            Arc::new(AlwaysAllow),
            Arc::new(AlwaysBlock("first block")),
            Arc::new(AlwaysBlock("second block")),
        ];

        let decision = evaluate_all(&policies, &action(), &ctx());

        match decision {
            Decision::Block { reason } => assert_eq!(reason, "first block"),
            Decision::Allow => panic!("expected a block decision"),
        }
    }

    #[test]
    fn allows_when_no_policies_configured() {
        let policies: Vec<Arc<dyn Policy>> = vec![];

        let decision = evaluate_all(&policies, &action(), &ctx());

        assert!(matches!(decision, Decision::Allow));
    }
}
