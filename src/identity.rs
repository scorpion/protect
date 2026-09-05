use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identity(pub String);

impl Identity {
    pub fn from_peer_addr(addr: SocketAddr) -> Self {
        Self(addr.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_peer_address_as_identity_string() {
        let addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();

        let identity = Identity::from_peer_addr(addr);

        assert_eq!(identity.0, "127.0.0.1:54321");
    }

    #[test]
    fn distinct_peers_produce_distinct_identities() {
        let a = Identity::from_peer_addr("127.0.0.1:1".parse().unwrap());
        let b = Identity::from_peer_addr("127.0.0.1:2".parse().unwrap());

        assert_ne!(a, b);
    }
}
