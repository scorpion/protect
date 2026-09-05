#![cfg(test)]

use std::io::Write;

use rasn::types::{OctetString, SetOf};
use rasn_ldap::{
    AuthenticationChoice, BindRequest, ChangeOperation, LdapMessage, ModifyRequest,
    ModifyRequestChanges, PartialAttribute, ProtocolOp,
};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use tempfile::NamedTempFile;

pub fn encode_message(message_id: u32, protocol_op: ProtocolOp) -> Vec<u8> {
    rasn::ber::encode(&LdapMessage::new(message_id, protocol_op)).expect("encode LDAP message")
}

pub fn decode_message(frame: &[u8]) -> LdapMessage {
    rasn::ber::decode(frame).expect("decode LDAP message")
}

pub fn modify_request_frame(message_id: u32, dn: &str, attribute: &str, value: &[u8]) -> Vec<u8> {
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

/// A self-signed cert/key pair (as temp PEM files) valid for `name`, plus
/// `name` itself for convenience. Being self-signed, the cert doubles as its
/// own trusted CA for tests that need to configure a custom trust root.
pub struct TestTls {
    pub server_name: &'static str,
    pub cert_file: NamedTempFile,
    pub key_file: NamedTempFile,
}

pub fn self_signed_tls(server_name: &'static str) -> TestTls {
    let CertifiedKey { cert, signing_key } = generate_simple_self_signed([server_name.to_string()])
        .expect("generate self-signed test certificate");

    TestTls {
        server_name,
        cert_file: pem_temp_file(&cert.pem()),
        key_file: pem_temp_file(&signing_key.serialize_pem()),
    }
}

fn pem_temp_file(pem: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("create temp PEM file");
    file.write_all(pem.as_bytes()).expect("write temp PEM file");
    file
}
