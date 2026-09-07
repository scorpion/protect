use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Identity(pub String);

impl Identity {
    /// Uses only the client's IP, not its ephemeral source port, so a
    /// reconnect keeps the same identity instead of resetting its
    /// rate-limit history — and so `ThresholdPolicy`'s history map stays
    /// bounded by distinct client hosts rather than growing by one entry
    /// per connection ever made.
    ///
    /// Prefixed with `ip:` so this can never collide with a bind-DN-derived
    /// identity ([`Identity::from_bind_dn`]) even when a DN is crafted to
    /// read identically to some peer's IP-address string — see
    /// ARCHITECTURE.md#identity.
    pub fn from_peer_addr(addr: SocketAddr) -> Self {
        Self(format!("ip:{}", addr.ip()))
    }

    /// Builds an identity from a DN confirmed by a successful `BindResponse`
    /// (see `proxy::resolve_pending_bind`). Prefixed with `dn:` — the
    /// counterpart to the `ip:` prefix on [`Identity::from_peer_addr`] —
    /// so the two derivation sources can never collide in
    /// `ThresholdPolicy`'s identity-keyed history map.
    pub fn from_bind_dn(dn: String) -> Self {
        Self(format!("dn:{dn}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_peer_ip_as_identity_string() {
        let addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();

        let identity = Identity::from_peer_addr(addr);

        assert_eq!(identity.0, "ip:127.0.0.1");
    }

    #[test]
    fn formats_bind_dn_as_identity_string() {
        let identity = Identity::from_bind_dn("cn=alice,dc=example,dc=com".to_string());

        assert_eq!(identity.0, "dn:cn=alice,dc=example,dc=com");
    }

    #[test]
    fn peer_ip_and_bind_dn_never_collide_even_with_matching_text() {
        // A DN crafted to read identically to a peer's IP-address string
        // must not land in the same `ThresholdPolicy` history bucket as
        // that peer — see ARCHITECTURE.md#identity.
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let ip_identity = Identity::from_peer_addr(addr);
        let dn_identity = Identity::from_bind_dn("127.0.0.1".to_string());

        assert_ne!(ip_identity, dn_identity);
    }

    #[test]
    fn same_ip_different_ports_share_identity() {
        let a = Identity::from_peer_addr("127.0.0.1:1".parse().unwrap());
        let b = Identity::from_peer_addr("127.0.0.1:2".parse().unwrap());

        assert_eq!(a, b);
    }

    #[test]
    fn distinct_ips_produce_distinct_identities() {
        let a = Identity::from_peer_addr("127.0.0.1:1".parse().unwrap());
        let b = Identity::from_peer_addr("127.0.0.2:1".parse().unwrap());

        assert_ne!(a, b);
    }
}
