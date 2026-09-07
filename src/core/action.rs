#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationKind {
    AccountLock,
    /// A lock attribute being cleared back to its schema default (LDAP
    /// `ModifyRequest` with `ChangeOperation::Delete` against a
    /// `LOCK_ATTRIBUTES` entry) — the mirror image of `AccountLock`: mass
    /// *reactivating* previously-locked/disabled accounts is arguably just
    /// as security-relevant as mass-locking them (e.g. stripping lockout
    /// state to keep a credential-stuffing run alive), so it gets its own
    /// `OperationKind` rather than being silently ignored or folded into
    /// `AccountLock`, since "N unlocks" and "N locks" may warrant different
    /// limits (see `LdapConnector::decode`).
    AccountUnlock,
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
    /// An entry being renamed or moved (LDAP `ModifyDNRequest`, RFC 4511
    /// §4.9) — reported unconditionally, like `Delete`/`Create`, since a
    /// move into a quarantine OU can disable an account as effectively as
    /// `AccountLock`, and there's no cheap way to tell that apart from an
    /// ordinary rename without querying the directory (see
    /// `LdapConnector::decode`).
    Rename,
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
