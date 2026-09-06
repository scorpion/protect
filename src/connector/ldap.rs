use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use rasn_ldap::{
    AuthenticationChoice, ChangeOperation, ExtendedRequest, ExtendedResponse, LdapMessage,
    LdapResult, ModifyResponse, ProtocolOp, ResultCode,
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

/// RFC 4511 §4.14.1 — the extended-operation OID a client sends to request
/// upgrading a plaintext connection to TLS mid-session, instead of dialing
/// implicit TLS (LDAPS) from the start.
pub(crate) const START_TLS_OID: &str = "1.3.6.1.4.1.1466.20037";

/// Message ID used for the StartTLS request `connect_upstream` sends when
/// negotiating StartTLS with the upstream. Arbitrary but fixed: it's always
/// the first message on a freshly dialed connection, so there's no
/// in-flight request it could collide with.
const START_TLS_UPSTREAM_MESSAGE_ID: u32 = 1;

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
        Ok(MaybeTlsStream::Tls(tls.connect(tcp).await?))
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
    /// policy engine cares about, return a normalized `Action`. Returns `None`
    /// for everything else (binds, searches, unrelated modifies, ...), which
    /// the proxy passes straight through.
    pub fn decode(&self, frame: &[u8]) -> Result<Option<Action>> {
        let message: LdapMessage = rasn::ber::decode(frame).context("decoding LDAP message")?;

        let ProtocolOp::ModifyRequest(modify) = &message.protocol_op else {
            return Ok(None);
        };

        // Add/Replace can set a lock value; Delete of these attributes just
        // clears them back to the schema default, which isn't a lock action.
        let touches_lock_attribute = modify.changes.iter().any(|change| {
            matches!(
                change.operation,
                ChangeOperation::Add | ChangeOperation::Replace
            ) && LOCK_ATTRIBUTES.contains(&change.modification.r#type.0.to_lowercase().as_str())
        });

        if !touches_lock_attribute {
            return Ok(None);
        }

        Ok(Some(Action {
            backend: "ldap",
            operation: OperationKind::AccountLock,
            target: modify.object.0.clone(),
            blast_radius: 1,
        }))
    }

    /// Decode a BindRequest and, if it's a simple (DN + password) bind naming
    /// a non-empty DN, return that DN so the proxy can start tracking policy
    /// history under it instead of the client's source address — necessary
    /// because two agents behind the same NAT/egress otherwise share one
    /// blast-radius budget, and a source address alone proves nothing about
    /// which principal is acting. Anonymous binds (empty DN) and SASL binds
    /// (the `name` field there isn't password-verified the way it is for a
    /// simple bind — the real identity comes from the SASL mechanism) return
    /// `None`, leaving the connection's current identity unchanged, as does
    /// every non-bind frame.
    pub fn bind_identity(&self, frame: &[u8]) -> Result<Option<String>> {
        let message: LdapMessage = rasn::ber::decode(frame).context("decoding LDAP message")?;
        let ProtocolOp::BindRequest(bind) = &message.protocol_op else {
            return Ok(None);
        };
        if bind.name.0.is_empty() || !matches!(bind.authentication, AuthenticationChoice::Simple(_))
        {
            return Ok(None);
        }
        Ok(Some(bind.name.0.clone()))
    }

    /// Build a well-formed LDAP ModifyResponse rejecting the request whose raw
    /// bytes are `frame`, so the caller learns why without the request ever
    /// reaching the real directory.
    pub fn build_rejection(&self, frame: &[u8], reason: &str) -> Result<Vec<u8>> {
        let message: LdapMessage =
            rasn::ber::decode(frame).context("decoding LDAP message for rejection")?;

        let response = LdapMessage::new(
            message.message_id,
            ProtocolOp::ModifyResponse(ModifyResponse(LdapResult::new(
                ResultCode::UnwillingToPerform,
                "".into(),
                reason.into(),
            ))),
        );

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

    fn bind_identity(&self, frame: &[u8]) -> Result<Option<String>> {
        self.bind_identity(frame)
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
        AuthenticationChoice, BindRequest, ChangeOperation, LdapMessage, ModifyRequest,
        ModifyRequestChanges, PartialAttribute, ProtocolOp,
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
}

#[cfg(test)]
mod tests {
    use super::test_support::{
        bind_request_frame, decode_message, extended_request_frame, modify_request_frame,
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
    fn bind_identity_extracts_dn_from_simple_bind() {
        let frame = bind_request_frame(1, "cn=alice,dc=example,dc=com");

        let identity = connector().bind_identity(&frame).unwrap();

        assert_eq!(identity.as_deref(), Some("cn=alice,dc=example,dc=com"));
    }

    #[test]
    fn bind_identity_ignores_anonymous_bind() {
        let frame = bind_request_frame(1, "");

        let identity = connector().bind_identity(&frame).unwrap();

        assert!(identity.is_none());
    }

    #[test]
    fn bind_identity_ignores_sasl_bind() {
        let frame = sasl_bind_request_frame(1, "cn=alice,dc=example,dc=com");

        let identity = connector().bind_identity(&frame).unwrap();

        assert!(identity.is_none());
    }

    #[test]
    fn bind_identity_ignores_non_bind_operations() {
        let frame = modify_request_frame(
            1,
            "cn=alice,dc=example,dc=com",
            "userAccountControl",
            b"514",
        );

        let identity = connector().bind_identity(&frame).unwrap();

        assert!(identity.is_none());
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
