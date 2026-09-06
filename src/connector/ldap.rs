use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use rasn::types::OctetString;
use rasn::{AsnType, Decode, Decoder, Encode};
use rasn_ldap::{
    AddResponse, AuthenticationChoice, ChangeOperation, DelResponse, ExtendedRequest,
    ExtendedResponse, LdapMessage, LdapResult, ModifyResponse, ProtocolOp, ResultCode,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::core::action::{Action, OperationKind};
use crate::core::connector::{Connector, DuplexStream};
use crate::core::net::MaybeTlsStream;
use crate::core::tls::UpstreamTls;

/// The upstream connection, either plaintext or LDAPS depending on how the
/// connector was configured.
pub type UpstreamStream = MaybeTlsStream<tokio_rustls::client::TlsStream<TcpStream>>;

/// Attribute names (lowercased) whose modification we treat as an account
/// lock/unlock across common directory schemas (AD, OpenLDAP, 389 DS).
const LOCK_ATTRIBUTES: &[&str] = &[
    "pwdaccountlockedtime",
    "useraccountcontrol",
    "nsaccountlock",
    "shadowexpire",
];

/// Hard cap on a single LDAP message's BER content length. Applied before
/// `read_frame` allocates a buffer for that content, so a client claiming an
/// oversized length (up to `u32::MAX` under the wire format) gets the
/// connection closed instead of a multi-gigabyte allocation. LDAP directory
/// operations — even bulky ones like a large `SearchResultEntry` — comfortably
/// fit well under this.
const MAX_FRAME_CONTENT_LEN: usize = 16 * 1024 * 1024; // 16 MiB

/// Hard cap on the length of a DN string, extracted from a decoded LDAP
/// message, before it's used as an `Identity` (bind DN) or `Action::target`
/// (modify/del/add object, password-modify user identity). Without this, a
/// DN can be as large as `MAX_FRAME_CONTENT_LEN` allows (16 MiB), so an
/// unauthenticated caller could grow `ThresholdPolicy`'s
/// `Identity`-keyed history map (and its `state_db`-backed persistence, if
/// configured) by a large, attacker-chosen amount per entry — see TODO.md.
/// A real DN is a handful of RDNs and is nowhere close to this length.
const MAX_DN_LEN: usize = 256;

/// Bounds a DN's size before it's used for policy/identity purposes.
/// Shorter DNs pass through untouched. A DN over `MAX_DN_LEN` is replaced by
/// a small, fixed-shape marker carrying its true length and a stable hash of
/// its full content (not just a truncated prefix) — so two distinct
/// oversized DNs that happen to share a prefix still don't collide into the
/// same `Identity`/history bucket, while the representation itself stays
/// bounded in size regardless of how large the original DN was. The hash
/// uses `DefaultHasher`'s fixed (unrandomized) keys deliberately, so the
/// same oversized DN maps to the same marker within one process run and
/// across a restart — required for `state_db`-backed history and the
/// sliding window itself to keep working for a caller using one
/// consistently oversized DN.
fn cap_dn(dn: String) -> String {
    if dn.len() <= MAX_DN_LEN {
        return dn;
    }
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    dn.hash(&mut hasher);
    format!(
        "(oversized DN, {} bytes, hash {:016x})",
        dn.len(),
        hasher.finish()
    )
}

/// RFC 4511 §4.14.1 — the extended-operation OID a client sends to request
/// upgrading a plaintext connection to TLS mid-session, instead of dialing
/// implicit TLS (LDAPS) from the start.
pub(crate) const START_TLS_OID: &str = "1.3.6.1.4.1.1466.20037";

/// Message ID used for the StartTLS request `connect_upstream` sends when
/// negotiating StartTLS with the upstream. Arbitrary but fixed: it's always
/// the first message on a freshly dialed connection, so there's no
/// in-flight request it could collide with.
const START_TLS_UPSTREAM_MESSAGE_ID: u32 = 1;

/// RFC 3062 — the extended-operation OID for the Password Modify operation,
/// which some directories expose as an alternative to a plain `Modify` for
/// resetting a password. A bulk password reset is disruptive the same way a
/// bulk account lock is (both leave the affected users unable to log in), so
/// this proxy polices it identically instead of letting it pass through
/// `decode` unrecognized like any other extended operation.
const PASSWORD_MODIFY_OID: &str = "1.3.6.1.4.1.4203.1.11.1";

/// RFC 3062 §2's `PasswdModifyRequestValue`, the BER payload carried in an
/// `ExtendedRequest.request_value` for the Password Modify operation:
/// `PasswdModifyRequestValue ::= SEQUENCE { userIdentity [0] OCTET STRING
/// OPTIONAL, oldPasswd [1] OCTET STRING OPTIONAL, newPasswd [2] OCTET STRING
/// OPTIONAL }`. Decoded only far enough to learn which identity's password
/// is changing; `old_passwd`/`new_passwd` are parsed (so the SEQUENCE
/// decodes correctly at all) but never inspected or logged — this proxy
/// checks blast radius, not credential contents.
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
struct PasswdModifyRequestValue {
    #[rasn(tag(0))]
    user_identity: Option<OctetString>,
    #[rasn(tag(1))]
    old_passwd: Option<OctetString>,
    #[rasn(tag(2))]
    new_passwd: Option<OctetString>,
}

#[derive(Clone)]
pub struct LdapConnector {
    upstream_addr: SocketAddr,
    upstream_tls: Option<UpstreamTls>,
    /// When true, `connect_upstream` dials the upstream in plaintext and
    /// negotiates RFC 4511 StartTLS before handing off to the TLS handshake
    /// described by `upstream_tls`, instead of dialing straight into
    /// implicit TLS (LDAPS). Has no effect if `upstream_tls` is `None`.
    upstream_starttls: bool,
}

impl LdapConnector {
    pub fn new(upstream_addr: SocketAddr, upstream_tls: Option<UpstreamTls>) -> Self {
        Self {
            upstream_addr,
            upstream_tls,
            upstream_starttls: false,
        }
    }

    /// Negotiate TLS with the upstream via RFC 4511 StartTLS (dial
    /// plaintext, exchange the StartTLS extended request/response, then
    /// perform the TLS handshake described by `upstream_tls`) instead of
    /// implicit TLS from the first byte — for directories standardized on
    /// the plaintext LDAP port plus StartTLS rather than a dedicated LDAPS
    /// port. No effect unless `upstream_tls` is also set.
    pub fn with_starttls(mut self, enabled: bool) -> Self {
        self.upstream_starttls = enabled;
        self
    }

    pub async fn connect_upstream(&self) -> Result<UpstreamStream> {
        let mut tcp = TcpStream::connect(self.upstream_addr)
            .await
            .with_context(|| format!("connecting to upstream LDAP at {}", self.upstream_addr))?;
        tcp.set_nodelay(true)
            .context("setting TCP_NODELAY on upstream connection")?;

        let Some(tls) = &self.upstream_tls else {
            return Ok(MaybeTlsStream::Plain(tcp));
        };
        if self.upstream_starttls {
            negotiate_starttls(&mut tcp).await?;
        }
        let connected = tls.connect(tcp).await;
        if connected.is_err() {
            crate::core::metrics::record_tls_handshake_failure("upstream");
        }
        Ok(MaybeTlsStream::Tls(connected?))
    }

    /// Recognizes an RFC 4511 StartTLS extended request and builds the
    /// success response confirming it, so the proxy can send it over the
    /// still-plaintext connection immediately before performing the TLS
    /// handshake in place. Returns `None` for every other frame (including
    /// extended requests for other OIDs), which the proxy forwards like any
    /// other frame.
    pub fn upgrade_request(&self, frame: &[u8]) -> Result<Option<Vec<u8>>> {
        let message: LdapMessage = rasn::ber::decode(frame).context("decoding LDAP message")?;
        let ProtocolOp::ExtendedReq(ExtendedRequest { request_name, .. }) = &message.protocol_op
        else {
            return Ok(None);
        };
        if request_name.as_ref() != START_TLS_OID.as_bytes() {
            return Ok(None);
        }

        let response = LdapMessage::new(
            message.message_id,
            ProtocolOp::ExtendedResp(ExtendedResponse {
                result_code: ResultCode::Success,
                matched_dn: "".into(),
                diagnostic_message: "".into(),
                referral: None,
                response_name: None,
                response_value: None,
            }),
        );
        Ok(Some(
            rasn::ber::encode(&response).context("encoding StartTLS response")?,
        ))
    }

    /// Decode a full LDAP message frame and, if it represents an operation the
    /// policy engine cares about, return a normalized `Action`. A `Modify` is
    /// only actionable if it touches a lock attribute (most modifies are
    /// mundane attribute edits); a `Del`/`Add` is actionable unconditionally —
    /// removing or creating an entry outright is at least as high-blast-radius
    /// as a lock, and unlike `Modify` there's no cheap way to further narrow
    /// it to "account-like" objects without querying the directory, which
    /// this proxy deliberately never does. An `ExtendedRequest` is actionable
    /// only for the RFC 3062 Password Modify OID — every other extended
    /// operation (including StartTLS) is left alone here, since
    /// `upgrade_request` already handles the one that needs a response before
    /// `decode` would ever see it. Returns `None` for everything else (binds,
    /// searches, ...), which the proxy passes straight through.
    pub fn decode(&self, frame: &[u8]) -> Result<Option<Action>> {
        let message: LdapMessage = rasn::ber::decode(frame).context("decoding LDAP message")?;

        match &message.protocol_op {
            ProtocolOp::ModifyRequest(modify) => {
                // Add/Replace can set a lock value; Delete of these attributes
                // just clears them back to the schema default, which isn't a
                // lock action.
                let touches_lock_attribute = modify.changes.iter().any(|change| {
                    matches!(
                        change.operation,
                        ChangeOperation::Add | ChangeOperation::Replace
                    ) && LOCK_ATTRIBUTES
                        .contains(&change.modification.r#type.0.to_lowercase().as_str())
                });

                if !touches_lock_attribute {
                    return Ok(None);
                }

                Ok(Some(Action {
                    backend: "ldap",
                    operation: OperationKind::AccountLock,
                    target: cap_dn(modify.object.0.clone()),
                    blast_radius: 1,
                }))
            }
            ProtocolOp::DelRequest(del) => Ok(Some(Action {
                backend: "ldap",
                operation: OperationKind::Delete,
                target: cap_dn(del.0.0.clone()),
                blast_radius: 1,
            })),
            ProtocolOp::AddRequest(add) => Ok(Some(Action {
                backend: "ldap",
                operation: OperationKind::Create,
                target: cap_dn(add.entry.0.clone()),
                blast_radius: 1,
            })),
            ProtocolOp::ExtendedReq(ExtendedRequest {
                request_name,
                request_value,
            }) => {
                if request_name.as_ref() != PASSWORD_MODIFY_OID.as_bytes() {
                    return Ok(None);
                }

                // userIdentity is itself OPTIONAL within the value (RFC 3062
                // allows a client to ask the server to reset its own,
                // currently-bound password without naming a DN), and some
                // clients omit the value entirely for the same self-service
                // case — either way there's no DN to report.
                let target = match request_value {
                    Some(value) => {
                        let parsed: PasswdModifyRequestValue = rasn::ber::decode(value)
                            .context("decoding RFC 3062 PasswdModifyRequestValue")?;
                        match parsed.user_identity {
                            Some(identity) => {
                                cap_dn(String::from_utf8_lossy(identity.as_ref()).into_owned())
                            }
                            None => "(bound identity)".to_string(),
                        }
                    }
                    None => "(bound identity)".to_string(),
                };

                Ok(Some(Action {
                    backend: "ldap",
                    operation: OperationKind::PasswordReset,
                    target,
                    blast_radius: 1,
                }))
            }
            _ => Ok(None),
        }
    }

    /// Decode a BindRequest and, if it's a simple (DN + password) bind naming
    /// a non-empty DN, return its message ID and that DN so the proxy can
    /// stage it as a pending identity claim instead of trusting it
    /// immediately — necessary because two agents behind the same NAT/egress
    /// otherwise share one blast-radius budget, and a source address alone
    /// proves nothing about which principal is acting, but a *claimed* DN
    /// proves nothing either until the directory actually verifies the
    /// password (see `bind_response`, which correlates by this same message
    /// ID). Anonymous binds (empty DN) and SASL binds (the `name` field
    /// there isn't password-verified the way it is for a simple bind — the
    /// real identity comes from the SASL mechanism) return `None`, leaving
    /// any pending claim alone, as does every non-bind frame. The DN is
    /// passed through `cap_dn` before returning, since it eventually becomes
    /// an `Identity` — see `cap_dn`'s doc comment.
    pub fn bind_request(&self, frame: &[u8]) -> Result<Option<(u32, String)>> {
        let message: LdapMessage = rasn::ber::decode(frame).context("decoding LDAP message")?;
        let ProtocolOp::BindRequest(bind) = &message.protocol_op else {
            return Ok(None);
        };
        if bind.name.0.is_empty() || !matches!(bind.authentication, AuthenticationChoice::Simple(_))
        {
            return Ok(None);
        }
        Ok(Some((message.message_id, cap_dn(bind.name.0.clone()))))
    }

    /// Decode a response frame and, if it's a `BindResponse`, return its
    /// message ID and whether the bind it answers succeeded, so the proxy
    /// can resolve the matching pending claim staged by `bind_request` —
    /// promoting the connection's `Identity` on success, discarding the
    /// claim otherwise. Every other response returns `None`, so the proxy
    /// leaves pending state untouched.
    pub fn bind_response(&self, frame: &[u8]) -> Result<Option<(u32, bool)>> {
        let message: LdapMessage = rasn::ber::decode(frame).context("decoding LDAP message")?;
        let ProtocolOp::BindResponse(bind_response) = &message.protocol_op else {
            return Ok(None);
        };
        Ok(Some((
            message.message_id,
            bind_response.result_code == ResultCode::Success,
        )))
    }

    /// Build a well-formed LDAP response rejecting the request whose raw
    /// bytes are `frame`, so the caller learns why without the request ever
    /// reaching the real directory. The response variant matches the
    /// request's own operation (`ModifyResponse` for a `Modify`, and so on)
    /// since LDAP clients validate that a response's tag matches the request
    /// it answers.
    pub fn build_rejection(&self, frame: &[u8], reason: &str) -> Result<Vec<u8>> {
        let message: LdapMessage =
            rasn::ber::decode(frame).context("decoding LDAP message for rejection")?;
        let result = LdapResult::new(ResultCode::UnwillingToPerform, "".into(), reason.into());

        let response_op = match message.protocol_op {
            ProtocolOp::ModifyRequest(_) => ProtocolOp::ModifyResponse(ModifyResponse(result)),
            ProtocolOp::DelRequest(_) => ProtocolOp::DelResponse(DelResponse(result)),
            ProtocolOp::AddRequest(_) => ProtocolOp::AddResponse(AddResponse(result)),
            ProtocolOp::ExtendedReq(_) => ProtocolOp::ExtendedResp(ExtendedResponse {
                result_code: result.result_code,
                matched_dn: result.matched_dn,
                diagnostic_message: result.diagnostic_message,
                referral: result.referral,
                response_name: None,
                response_value: None,
            }),
            other => bail!("cannot build a rejection for protocol op {other:?}"),
        };

        let response = LdapMessage::new(message.message_id, response_op);
        rasn::ber::encode(&response).context("encoding rejection response")
    }
}

// These just forward to the inherent methods above, boxing the upstream
// stream where needed. The inherent methods stay concretely typed (no `dyn`)
// so tests and other LDAP-specific code can call them without going through
// the trait object.
#[async_trait]
impl Connector for LdapConnector {
    async fn connect_upstream(&self) -> Result<Box<dyn DuplexStream>> {
        Ok(Box::new(self.connect_upstream().await?))
    }

    async fn read_frame(
        &self,
        stream: &mut (dyn AsyncRead + Send + Unpin),
    ) -> Result<Option<Vec<u8>>> {
        read_frame(stream).await
    }

    fn decode(&self, frame: &[u8]) -> Result<Option<Action>> {
        self.decode(frame)
    }

    fn build_rejection(&self, frame: &[u8], reason: &str) -> Result<Vec<u8>> {
        self.build_rejection(frame, reason)
    }

    fn upgrade_request(&self, frame: &[u8]) -> Result<Option<Vec<u8>>> {
        self.upgrade_request(frame)
    }

    fn bind_request(&self, frame: &[u8]) -> Result<Option<(u32, String)>> {
        self.bind_request(frame)
    }

    fn bind_response(&self, frame: &[u8]) -> Result<Option<(u32, bool)>> {
        self.bind_response(frame)
    }
}

/// Sends an RFC 4511 StartTLS extended request over `tcp` (still plaintext)
/// and waits for a success response, so the caller can then perform the TLS
/// handshake in place. Used when the upstream directory expects StartTLS on
/// its plaintext port instead of implicit TLS (LDAPS) on a dedicated one.
async fn negotiate_starttls(tcp: &mut TcpStream) -> Result<()> {
    let request = LdapMessage::new(
        START_TLS_UPSTREAM_MESSAGE_ID,
        ProtocolOp::ExtendedReq(ExtendedRequest {
            request_name: START_TLS_OID.as_bytes().into(),
            request_value: None,
        }),
    );
    let frame = rasn::ber::encode(&request).context("encoding StartTLS request")?;
    tcp.write_all(&frame)
        .await
        .context("sending StartTLS request to upstream")?;

    let response_frame = read_frame(tcp)
        .await?
        .context("upstream closed the connection before responding to StartTLS")?;
    let response: LdapMessage =
        rasn::ber::decode(&response_frame).context("decoding upstream's StartTLS response")?;
    let ProtocolOp::ExtendedResp(ExtendedResponse { result_code, .. }) = response.protocol_op
    else {
        bail!("upstream did not respond to StartTLS with an ExtendedResponse");
    };
    if result_code != ResultCode::Success {
        bail!("upstream rejected StartTLS: {result_code:?}");
    }
    Ok(())
}

/// Read exactly one BER-encoded LDAP message frame (tag + definite-length +
/// content) from `stream`. Returns `None` on a clean EOF before any bytes of
/// a new frame are read. LDAP requires definite-length BER encoding (RFC 4511
/// section 5.1), so long-form lengths are the only case beyond the single
/// length byte.
pub async fn read_frame<R: AsyncRead + Unpin + ?Sized>(stream: &mut R) -> Result<Option<Vec<u8>>> {
    let mut tag = [0u8; 1];
    match stream.read_exact(&mut tag).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }

    let mut first_length_byte = [0u8; 1];
    stream.read_exact(&mut first_length_byte).await?;

    let mut frame = vec![tag[0], first_length_byte[0]];

    let content_len = if first_length_byte[0] & 0x80 == 0 {
        // High bit clear: short form. The byte itself is the length (0-127).
        first_length_byte[0] as usize
    } else {
        // High bit set: long form. The low 7 bits say how many following
        // bytes hold the big-endian length. Definite-length BER (RFC 4511
        // 5.1) never needs more than 4, since LDAP frames fit in a u32.
        let num_bytes = (first_length_byte[0] & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 4 {
            bail!("unsupported LDAP message length encoding ({num_bytes} length bytes)");
        }
        // Right-align the bytes we read into a 4-byte buffer so short
        // encodings (e.g. num_bytes == 2) still parse as the correct u32.
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes[4 - num_bytes..]).await?;
        frame.extend_from_slice(&len_bytes[4 - num_bytes..]);
        u32::from_be_bytes(len_bytes) as usize
    };

    if content_len > MAX_FRAME_CONTENT_LEN {
        bail!(
            "LDAP message length {content_len} exceeds max frame size ({MAX_FRAME_CONTENT_LEN} bytes)"
        );
    }

    // Read the content directly into `frame`'s tail instead of filling a
    // separate buffer and copying it over, avoiding a second allocation and
    // memcpy of up to MAX_FRAME_CONTENT_LEN bytes per message.
    let header_len = frame.len();
    frame.resize(header_len + content_len, 0);
    stream.read_exact(&mut frame[header_len..]).await?;

    Ok(Some(frame))
}

#[cfg(test)]
pub(crate) mod test_support {
    use rasn::types::{OctetString, SetOf};
    use rasn_ldap::{
        AddRequest, AuthenticationChoice, BindRequest, ChangeOperation, DelRequest, LdapMessage,
        ModifyRequest, ModifyRequestChanges, PartialAttribute, ProtocolOp,
    };

    pub fn encode_message(message_id: u32, protocol_op: ProtocolOp) -> Vec<u8> {
        rasn::ber::encode(&LdapMessage::new(message_id, protocol_op)).expect("encode LDAP message")
    }

    pub fn decode_message(frame: &[u8]) -> LdapMessage {
        rasn::ber::decode(frame).expect("decode LDAP message")
    }

    pub fn modify_request_frame(
        message_id: u32,
        dn: &str,
        attribute: &str,
        value: &[u8],
    ) -> Vec<u8> {
        let change = ModifyRequestChanges {
            operation: ChangeOperation::Replace,
            modification: PartialAttribute::new(
                attribute.into(),
                SetOf::from_vec(vec![OctetString::from(value.to_vec())]),
            ),
        };

        encode_message(
            message_id,
            ProtocolOp::ModifyRequest(ModifyRequest {
                object: dn.into(),
                changes: vec![change],
            }),
        )
    }

    pub fn del_request_frame(message_id: u32, dn: &str) -> Vec<u8> {
        encode_message(message_id, ProtocolOp::DelRequest(DelRequest(dn.into())))
    }

    pub fn add_request_frame(message_id: u32, dn: &str) -> Vec<u8> {
        encode_message(
            message_id,
            ProtocolOp::AddRequest(AddRequest {
                entry: dn.into(),
                attributes: vec![],
            }),
        )
    }

    pub fn bind_request_frame(message_id: u32, dn: &str) -> Vec<u8> {
        encode_message(
            message_id,
            ProtocolOp::BindRequest(BindRequest::new(
                3,
                dn.into(),
                AuthenticationChoice::Simple(OctetString::from(b"password".to_vec())),
            )),
        )
    }

    pub fn sasl_bind_request_frame(message_id: u32, dn: &str) -> Vec<u8> {
        encode_message(
            message_id,
            ProtocolOp::BindRequest(BindRequest::new(
                3,
                dn.into(),
                AuthenticationChoice::Sasl(rasn_ldap::SaslCredentials::new("GSSAPI".into(), None)),
            )),
        )
    }

    pub fn extended_request_frame(message_id: u32, oid: &str) -> Vec<u8> {
        encode_message(
            message_id,
            ProtocolOp::ExtendedReq(rasn_ldap::ExtendedRequest {
                request_name: oid.as_bytes().into(),
                request_value: None,
            }),
        )
    }

    pub fn password_modify_request_frame(message_id: u32, user_identity: Option<&str>) -> Vec<u8> {
        let value = super::PasswdModifyRequestValue {
            user_identity: user_identity.map(|dn| OctetString::from(dn.as_bytes().to_vec())),
            old_passwd: None,
            new_passwd: Some(OctetString::from(b"new-password".to_vec())),
        };

        encode_message(
            message_id,
            ProtocolOp::ExtendedReq(rasn_ldap::ExtendedRequest {
                request_name: super::PASSWORD_MODIFY_OID.as_bytes().into(),
                request_value: Some(
                    rasn::ber::encode(&value)
                        .expect("encode PasswdModifyRequestValue")
                        .into(),
                ),
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{
        add_request_frame, bind_request_frame, decode_message, del_request_frame,
        extended_request_frame, modify_request_frame, password_modify_request_frame,
        sasl_bind_request_frame,
    };
    use super::*;

    fn connector() -> LdapConnector {
        LdapConnector::new("127.0.0.1:389".parse().unwrap(), None)
    }

    #[test]
    fn upgrade_request_confirms_starttls_and_preserves_message_id() {
        let frame = extended_request_frame(9, START_TLS_OID);

        let response = connector()
            .upgrade_request(&frame)
            .unwrap()
            .expect("expected a StartTLS confirmation response");
        let message = decode_message(&response);

        assert_eq!(message.message_id, 9);
        match message.protocol_op {
            ProtocolOp::ExtendedResp(ExtendedResponse { result_code, .. }) => {
                assert_eq!(result_code, ResultCode::Success);
            }
            other => panic!("expected ExtendedResp, got {other:?}"),
        }
    }

    #[test]
    fn upgrade_request_ignores_other_extended_operations() {
        let frame = extended_request_frame(1, "1.2.3.4.5.6.7.8.9");

        let response = connector().upgrade_request(&frame).unwrap();

        assert!(response.is_none());
    }

    #[test]
    fn upgrade_request_ignores_non_extended_operations() {
        let frame = bind_request_frame(1, "cn=alice,dc=example,dc=com");

        let response = connector().upgrade_request(&frame).unwrap();

        assert!(response.is_none());
    }

    #[test]
    fn decodes_lock_attribute_modify_as_account_lock_action() {
        let frame = modify_request_frame(
            1,
            "cn=alice,dc=example,dc=com",
            "userAccountControl",
            b"514",
        );

        let action = connector()
            .decode(&frame)
            .unwrap()
            .expect("expected an action");

        assert_eq!(action.backend, "ldap");
        assert_eq!(action.operation, OperationKind::AccountLock);
        assert_eq!(action.target, "cn=alice,dc=example,dc=com");
        assert_eq!(action.blast_radius, 1);
    }

    #[test]
    fn ignores_modify_of_unrelated_attribute() {
        let frame = modify_request_frame(
            1,
            "cn=alice,dc=example,dc=com",
            "description",
            b"new description",
        );

        let action = connector().decode(&frame).unwrap();

        assert!(action.is_none());
    }

    #[test]
    fn ignores_non_modify_operations() {
        let frame = bind_request_frame(1, "cn=alice,dc=example,dc=com");

        let action = connector().decode(&frame).unwrap();

        assert!(action.is_none());
    }

    #[test]
    fn lock_attribute_match_is_case_insensitive() {
        let frame = modify_request_frame(
            1,
            "cn=alice,dc=example,dc=com",
            "USERACCOUNTCONTROL",
            b"514",
        );

        let action = connector().decode(&frame).unwrap();

        assert!(action.is_some());
    }

    #[test]
    fn decodes_del_request_as_delete_action_unconditionally() {
        let frame = del_request_frame(1, "cn=alice,dc=example,dc=com");

        let action = connector()
            .decode(&frame)
            .unwrap()
            .expect("expected an action");

        assert_eq!(action.backend, "ldap");
        assert_eq!(action.operation, OperationKind::Delete);
        assert_eq!(action.target, "cn=alice,dc=example,dc=com");
        assert_eq!(action.blast_radius, 1);
    }

    #[test]
    fn decodes_add_request_as_create_action_unconditionally() {
        let frame = add_request_frame(1, "cn=alice,dc=example,dc=com");

        let action = connector()
            .decode(&frame)
            .unwrap()
            .expect("expected an action");

        assert_eq!(action.backend, "ldap");
        assert_eq!(action.operation, OperationKind::Create);
        assert_eq!(action.target, "cn=alice,dc=example,dc=com");
        assert_eq!(action.blast_radius, 1);
    }

    #[test]
    fn decodes_password_modify_with_explicit_identity_as_password_reset_action() {
        let frame = password_modify_request_frame(1, Some("cn=alice,dc=example,dc=com"));

        let action = connector()
            .decode(&frame)
            .unwrap()
            .expect("expected an action");

        assert_eq!(action.backend, "ldap");
        assert_eq!(action.operation, OperationKind::PasswordReset);
        assert_eq!(action.target, "cn=alice,dc=example,dc=com");
        assert_eq!(action.blast_radius, 1);
    }

    #[test]
    fn decodes_password_modify_without_identity_as_password_reset_action() {
        let frame = password_modify_request_frame(1, None);

        let action = connector()
            .decode(&frame)
            .unwrap()
            .expect("expected an action");

        assert_eq!(action.operation, OperationKind::PasswordReset);
        assert_eq!(action.target, "(bound identity)");
    }

    #[test]
    fn ignores_extended_request_for_other_oid() {
        let frame = extended_request_frame(1, START_TLS_OID);

        let action = connector().decode(&frame).unwrap();

        assert!(action.is_none());
    }

    #[test]
    fn bind_request_extracts_message_id_and_dn_from_simple_bind() {
        let frame = bind_request_frame(7, "cn=alice,dc=example,dc=com");

        let claim = connector().bind_request(&frame).unwrap();

        assert_eq!(claim, Some((7, "cn=alice,dc=example,dc=com".to_string())));
    }

    #[test]
    fn cap_dn_passes_short_dns_through_unchanged() {
        let dn = "cn=alice,dc=example,dc=com".to_string();

        assert_eq!(cap_dn(dn.clone()), dn);
    }

    #[test]
    fn cap_dn_bounds_the_size_of_an_oversized_dn() {
        let huge_dn = "a".repeat(MAX_DN_LEN * 4);

        let capped = cap_dn(huge_dn);

        assert!(capped.len() < MAX_DN_LEN);
    }

    #[test]
    fn cap_dn_is_stable_and_distinguishes_distinct_oversized_dns() {
        let a = "a".repeat(MAX_DN_LEN * 4);
        let b = "b".repeat(MAX_DN_LEN * 4);

        // Same input always caps to the same output (required so a
        // sliding-window budget for one oversized-DN caller stays coherent
        // across separate requests), but two distinct oversized DNs must
        // not collapse into the same capped identity.
        assert_eq!(cap_dn(a.clone()), cap_dn(a.clone()));
        assert_ne!(cap_dn(a), cap_dn(b));
    }

    #[test]
    fn bind_request_caps_an_oversized_claimed_dn() {
        let huge_dn = "cn=".to_string() + &"a".repeat(MAX_DN_LEN * 4);
        let frame = bind_request_frame(7, &huge_dn);

        let (message_id, claimed_dn) = connector().bind_request(&frame).unwrap().unwrap();

        assert_eq!(message_id, 7);
        assert!(claimed_dn.len() < MAX_DN_LEN);
    }

    #[test]
    fn bind_request_ignores_anonymous_bind() {
        let frame = bind_request_frame(1, "");

        let claim = connector().bind_request(&frame).unwrap();

        assert!(claim.is_none());
    }

    #[test]
    fn bind_request_ignores_sasl_bind() {
        let frame = sasl_bind_request_frame(1, "cn=alice,dc=example,dc=com");

        let claim = connector().bind_request(&frame).unwrap();

        assert!(claim.is_none());
    }

    #[test]
    fn bind_request_ignores_non_bind_operations() {
        let frame = modify_request_frame(
            1,
            "cn=alice,dc=example,dc=com",
            "userAccountControl",
            b"514",
        );

        let claim = connector().bind_request(&frame).unwrap();

        assert!(claim.is_none());
    }

    #[test]
    fn bind_response_reports_success_and_message_id() {
        let frame = test_support::encode_message(
            7,
            ProtocolOp::BindResponse(rasn_ldap::BindResponse::new(
                ResultCode::Success,
                "".into(),
                "".into(),
                None,
                None,
            )),
        );

        let outcome = connector().bind_response(&frame).unwrap();

        assert_eq!(outcome, Some((7, true)));
    }

    #[test]
    fn bind_response_reports_failure() {
        let frame = test_support::encode_message(
            7,
            ProtocolOp::BindResponse(rasn_ldap::BindResponse::new(
                ResultCode::InvalidCredentials,
                "".into(),
                "".into(),
                None,
                None,
            )),
        );

        let outcome = connector().bind_response(&frame).unwrap();

        assert_eq!(outcome, Some((7, false)));
    }

    #[test]
    fn bind_response_ignores_non_bind_responses() {
        let frame = modify_request_frame(
            1,
            "cn=alice,dc=example,dc=com",
            "userAccountControl",
            b"514",
        );

        let outcome = connector().bind_response(&frame).unwrap();

        assert!(outcome.is_none());
    }

    #[test]
    fn build_rejection_preserves_message_id_and_reason() {
        let frame = modify_request_frame(
            42,
            "cn=alice,dc=example,dc=com",
            "userAccountControl",
            b"514",
        );

        let rejection = connector()
            .build_rejection(&frame, "too many locks")
            .unwrap();
        let message = decode_message(&rejection);

        assert_eq!(message.message_id, 42);
        match message.protocol_op {
            ProtocolOp::ModifyResponse(ModifyResponse(result)) => {
                assert_eq!(result.result_code, ResultCode::UnwillingToPerform);
                assert_eq!(result.diagnostic_message.0, "too many locks");
            }
            other => panic!("expected ModifyResponse, got {other:?}"),
        }
    }

    #[test]
    fn build_rejection_for_del_request_returns_del_response() {
        let frame = del_request_frame(7, "cn=alice,dc=example,dc=com");

        let rejection = connector()
            .build_rejection(&frame, "too many deletes")
            .unwrap();
        let message = decode_message(&rejection);

        assert_eq!(message.message_id, 7);
        match message.protocol_op {
            ProtocolOp::DelResponse(DelResponse(result)) => {
                assert_eq!(result.result_code, ResultCode::UnwillingToPerform);
                assert_eq!(result.diagnostic_message.0, "too many deletes");
            }
            other => panic!("expected DelResponse, got {other:?}"),
        }
    }

    #[test]
    fn build_rejection_for_add_request_returns_add_response() {
        let frame = add_request_frame(7, "cn=alice,dc=example,dc=com");

        let rejection = connector()
            .build_rejection(&frame, "too many creates")
            .unwrap();
        let message = decode_message(&rejection);

        assert_eq!(message.message_id, 7);
        match message.protocol_op {
            ProtocolOp::AddResponse(AddResponse(result)) => {
                assert_eq!(result.result_code, ResultCode::UnwillingToPerform);
                assert_eq!(result.diagnostic_message.0, "too many creates");
            }
            other => panic!("expected AddResponse, got {other:?}"),
        }
    }

    #[test]
    fn build_rejection_for_password_modify_returns_extended_response() {
        let frame = password_modify_request_frame(7, Some("cn=alice,dc=example,dc=com"));

        let rejection = connector()
            .build_rejection(&frame, "too many password resets")
            .unwrap();
        let message = decode_message(&rejection);

        assert_eq!(message.message_id, 7);
        match message.protocol_op {
            ProtocolOp::ExtendedResp(ExtendedResponse {
                result_code,
                diagnostic_message,
                ..
            }) => {
                assert_eq!(result_code, ResultCode::UnwillingToPerform);
                assert_eq!(diagnostic_message.0, "too many password resets");
            }
            other => panic!("expected ExtendedResp, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn works_through_the_connector_trait_object() {
        let connector: Box<dyn Connector> = Box::new(connector());
        let frame = modify_request_frame(
            1,
            "cn=alice,dc=example,dc=com",
            "userAccountControl",
            b"514",
        );
        let mut cursor = std::io::Cursor::new(frame.clone());

        let read = connector.read_frame(&mut cursor).await.unwrap().unwrap();
        assert_eq!(read, frame);

        let action = connector
            .decode(&read)
            .unwrap()
            .expect("expected an action");
        assert_eq!(action.operation, OperationKind::AccountLock);

        let rejection = connector.build_rejection(&read, "too many locks").unwrap();
        let message = decode_message(&rejection);
        assert_eq!(message.message_id, 1);
    }

    #[tokio::test]
    async fn read_frame_reads_short_form_length() {
        let frame = modify_request_frame(
            1,
            "cn=alice,dc=example,dc=com",
            "userAccountControl",
            b"514",
        );
        let mut cursor = std::io::Cursor::new(frame.clone());

        let read = read_frame(&mut cursor).await.unwrap().unwrap();

        assert_eq!(read, frame);
    }

    #[tokio::test]
    async fn read_frame_reads_long_form_length() {
        // A large attribute value forces BER into long-form length encoding
        // (content > 127 bytes), which exercises the other branch of read_frame.
        let big_value = vec![b'x'; 300];
        let frame = modify_request_frame(
            1,
            "cn=alice,dc=example,dc=com",
            "userAccountControl",
            &big_value,
        );
        assert!(
            frame[1] & 0x80 != 0,
            "expected long-form length for this test to be meaningful"
        );
        let mut cursor = std::io::Cursor::new(frame.clone());

        let read = read_frame(&mut cursor).await.unwrap().unwrap();

        assert_eq!(read, frame);
    }

    #[tokio::test]
    async fn read_frame_returns_none_on_clean_eof() {
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());

        let read = read_frame(&mut cursor).await.unwrap();

        assert!(read.is_none());
    }

    #[tokio::test]
    async fn read_frame_rejects_length_over_max_frame_size_without_allocating() {
        // Tag byte, long-form length (4 following bytes), then a claimed
        // content length just over the cap. No content bytes are provided —
        // if `read_frame` allocated first and tried to fill the buffer it
        // would hang/error on the short read instead of rejecting up front.
        let oversized_len = (MAX_FRAME_CONTENT_LEN + 1) as u32;
        let mut header = vec![0x30u8, 0x84];
        header.extend_from_slice(&oversized_len.to_be_bytes());
        let mut cursor = std::io::Cursor::new(header);

        let err = read_frame(&mut cursor).await.unwrap_err();

        assert!(err.to_string().contains("exceeds max frame size"));
    }
}
