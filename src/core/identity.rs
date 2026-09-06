use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identity(pub String);

impl Identity {
    /// Uses only the client's IP, not its ephemeral source port, so a
    /// reconnect keeps the same identity instead of resetting its
    /// rate-limit history — and so `ThresholdPolicy`'s history map stays
    /// bounded by distinct client hosts rather than growing by one entry
    /// per connection ever made.
    pub fn from_peer_addr(addr: SocketAddr) -> Self {
        Self(addr.ip().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_peer_ip_as_identity_string() {
        let addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();

        let identity = Identity::from_peer_addr(addr);

        assert_eq!(identity.0, "127.0.0.1");
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
