#![cfg(test)]

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
