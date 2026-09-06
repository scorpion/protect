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

    /// If `frame` is a request that claims an identity for policy purposes
    /// (LDAP's simple `BindRequest` is the only example today), returns its
    /// message ID and the claimed identity's string form so the proxy can
    /// stage it as *pending* — not yet trusted — until the correlated
    /// response is seen (see `bind_response`). This exists because two
    /// agents sharing a NAT/egress address otherwise share one blast-radius
    /// budget under address-based identity alone — a bind DN distinguishes
    /// them, but only once it's known to be real. `Ok(None)` means "not an
    /// identity-claiming request" (including anonymous or SASL binds, whose
    /// named DN isn't password-verified the way a simple bind's is), and the
    /// proxy leaves any pending claim alone. Defaults to "this protocol has
    /// no such mechanism," so connectors that don't support it need no
    /// changes.
    fn bind_request(&self, frame: &[u8]) -> anyhow::Result<Option<(u32, String)>> {
        let _ = frame;
        Ok(None)
    }

    /// If `frame` is the response correlating to a request staged via
    /// `bind_request` (matched by message ID, LDAP being request/response),
    /// returns that message ID and whether the claim succeeded, so the proxy
    /// can promote its pending identity claim to the connection's actual
    /// `Identity` — or discard it — accordingly. Trusting the identity named
    /// in a bind *request* before this fires is exactly the policy-bypass
    /// gap this hook closes: a claimed DN that's never actually
    /// password-verified upstream must not get a fresh, empty blast-radius
    /// budget. `Ok(None)` means "not a response to a staged claim," and the
    /// proxy leaves the pending state untouched. Defaults to "this protocol
    /// has no such mechanism," so connectors that don't support
    /// `bind_request` need no changes here either.
    fn bind_response(&self, frame: &[u8]) -> anyhow::Result<Option<(u32, bool)>> {
        let _ = frame;
        Ok(None)
    }
}
