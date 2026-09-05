pub mod ldap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationKind {
    AccountLock,
}

/// A normalized, backend-agnostic representation of an operation a client is
/// attempting, produced by a connector so the policy engine never has to
/// understand any particular wire protocol.
#[derive(Debug, Clone)]
pub struct Action {
    pub backend: &'static str,
    pub operation: OperationKind,
    pub target: String,
    pub blast_radius: usize,
}
