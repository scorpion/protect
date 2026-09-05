use std::net::SocketAddr;

use anyhow::{bail, Context, Result};
use rasn_ldap::{ChangeOperation, LdapMessage, LdapResult, ModifyResponse, ProtocolOp, ResultCode};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;

use super::{Action, OperationKind};

/// Attribute names (lowercased) whose modification we treat as an account
/// lock/unlock across common directory schemas (AD, OpenLDAP, 389 DS).
const LOCK_ATTRIBUTES: &[&str] = &[
    "pwdaccountlockedtime",
    "useraccountcontrol",
    "nsaccountlock",
    "shadowexpire",
];

#[derive(Clone)]
pub struct LdapConnector {
    upstream_addr: SocketAddr,
}

impl LdapConnector {
    pub fn new(upstream_addr: SocketAddr) -> Self {
        Self { upstream_addr }
    }

    pub async fn connect_upstream(&self) -> Result<TcpStream> {
        TcpStream::connect(self.upstream_addr)
            .await
            .with_context(|| format!("connecting to upstream LDAP at {}", self.upstream_addr))
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

        let touches_lock_attribute = modify.changes.iter().any(|change| {
            matches!(change.operation, ChangeOperation::Add | ChangeOperation::Replace)
                && LOCK_ATTRIBUTES.contains(&change.modification.r#type.0.to_lowercase().as_str())
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

/// Read exactly one BER-encoded LDAP message frame (tag + definite-length +
/// content) from `stream`. Returns `None` on a clean EOF before any bytes of
/// a new frame are read. LDAP requires definite-length BER encoding (RFC 4511
/// section 5.1), so long-form lengths are the only case beyond the single
/// length byte.
pub async fn read_frame<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Option<Vec<u8>>> {
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
        first_length_byte[0] as usize
    } else {
        let num_bytes = (first_length_byte[0] & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 4 {
            bail!("unsupported LDAP message length encoding ({num_bytes} length bytes)");
        }
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes[4 - num_bytes..]).await?;
        frame.extend_from_slice(&len_bytes[4 - num_bytes..]);
        u32::from_be_bytes(len_bytes) as usize
    };

    let mut content = vec![0u8; content_len];
    stream.read_exact(&mut content).await?;
    frame.extend_from_slice(&content);

    Ok(Some(frame))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{bind_request_frame, decode_message, modify_request_frame};

    fn connector() -> LdapConnector {
        LdapConnector::new("127.0.0.1:389".parse().unwrap())
    }

    #[test]
    fn decodes_lock_attribute_modify_as_account_lock_action() {
        let frame = modify_request_frame(1, "cn=alice,dc=example,dc=com", "userAccountControl", b"514");

        let action = connector().decode(&frame).unwrap().expect("expected an action");

        assert_eq!(action.backend, "ldap");
        assert_eq!(action.operation, OperationKind::AccountLock);
        assert_eq!(action.target, "cn=alice,dc=example,dc=com");
        assert_eq!(action.blast_radius, 1);
    }

    #[test]
    fn ignores_modify_of_unrelated_attribute() {
        let frame = modify_request_frame(1, "cn=alice,dc=example,dc=com", "description", b"new description");

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
        let frame = modify_request_frame(1, "cn=alice,dc=example,dc=com", "USERACCOUNTCONTROL", b"514");

        let action = connector().decode(&frame).unwrap();

        assert!(action.is_some());
    }

    #[test]
    fn build_rejection_preserves_message_id_and_reason() {
        let frame = modify_request_frame(42, "cn=alice,dc=example,dc=com", "userAccountControl", b"514");

        let rejection = connector().build_rejection(&frame, "too many locks").unwrap();
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
    async fn read_frame_reads_short_form_length() {
        let frame = modify_request_frame(1, "cn=alice,dc=example,dc=com", "userAccountControl", b"514");
        let mut cursor = std::io::Cursor::new(frame.clone());

        let read = read_frame(&mut cursor).await.unwrap().unwrap();

        assert_eq!(read, frame);
    }

    #[tokio::test]
    async fn read_frame_reads_long_form_length() {
        // A large attribute value forces BER into long-form length encoding
        // (content > 127 bytes), which exercises the other branch of read_frame.
        let big_value = vec![b'x'; 300];
        let frame = modify_request_frame(1, "cn=alice,dc=example,dc=com", "userAccountControl", &big_value);
        assert!(frame[1] & 0x80 != 0, "expected long-form length for this test to be meaningful");
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
}
