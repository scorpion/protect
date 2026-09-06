use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::action::Action;

/// A duplex, boxable connection to an upstream backend — lets a `Connector`
/// impl return any transport (plain TCP, TLS, ...) behind one type, so
/// `proxy.rs` never has to know which.
pub trait DuplexStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> DuplexStream for T {}

/// Protocol-specific glue between raw bytes and the normalized `Action`
/// pipeline. Implement this to add a new backend (a different directory
/// protocol, or a non-LDAP admin surface) without touching `src/proxy.rs`
/// or anything under `src/core/policy/`.
#[async_trait]
pub trait Connector: Send + Sync {
    /// Dial the upstream backend this connector is configured for.
    async fn connect_upstream(&self) -> anyhow::Result<Box<dyn DuplexStream>>;

    /// Read exactly one protocol frame from `stream`. Returns `None` on a
    /// clean EOF before any bytes of a new frame are read.
    async fn read_frame(
        &self,
        stream: &mut (dyn AsyncRead + Send + Unpin),
    ) -> anyhow::Result<Option<Vec<u8>>>;

    /// Decode a full frame and, if it represents an operation the policy
    /// engine cares about, return a normalized `Action`. `None` means "not
    /// my concern," and the proxy forwards the frame untouched.
    fn decode(&self, frame: &[u8]) -> anyhow::Result<Option<Action>>;

    /// Build a protocol-appropriate rejection response for a blocked frame.
    fn build_rejection(&self, frame: &[u8], reason: &str) -> anyhow::Result<Vec<u8>>;

    /// If `frame` is a request to upgrade the connection carrying it to TLS
    /// mid-session (LDAP's RFC 4511 StartTLS extended operation is the only
    /// example today), returns the protocol response confirming the
    /// upgrade — sent over the current, still-plaintext transport
    /// immediately before the proxy performs the TLS handshake in place.
    /// `Ok(None)` means "not an upgrade request," and the proxy treats
    /// `frame` as an ordinary request instead. Defaults to "this protocol
    /// has no such mechanism," so connectors that don't support an
    /// in-session upgrade need no changes.
    fn upgrade_request(&self, frame: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        let _ = frame;
        Ok(None)
    }

    /// If `frame` establishes the connection's identity for policy purposes
    /// (LDAP's simple `BindRequest` is the only example today), returns that
    /// identity's string form so the proxy can replace its current
    /// `Identity` with it. This exists because two agents sharing a
    /// NAT/egress address otherwise share one blast-radius budget under
    /// address-based identity alone — a bind DN distinguishes them. `Ok(None)`
    /// means "not an identity-establishing request" (including anonymous or
    /// SASL binds, whose named DN isn't password-verified the way a simple
    /// bind's is), and the proxy leaves the connection's current identity
    /// unchanged. Defaults to "this protocol has no such mechanism," so
    /// connectors that don't support it need no changes.
    fn bind_identity(&self, frame: &[u8]) -> anyhow::Result<Option<String>> {
        let _ = frame;
        Ok(None)
    }
}
