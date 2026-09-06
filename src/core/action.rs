#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationKind {
    AccountLock,
    /// A directory entry being removed entirely (LDAP `DelRequest`) —
    /// at least as high-blast-radius as locking one, and not distinguished
    /// by target object type (see `LdapConnector::decode`).
    Delete,
    /// A directory entry being created (LDAP `AddRequest`).
    Create,
    /// A password being reset via an extended operation rather than
    /// `Modify` (LDAP's RFC 3062 Password Modify) — a bulk reset locks
    /// affected users out of their accounts just as a bulk `AccountLock`
    /// would (see `LdapConnector::decode`).
    PasswordReset,
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
