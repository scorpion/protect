//! Fuzzes the BER-decoding surface that runs on fully untrusted, already
//! length-delimited bytes (i.e. whatever `read_frame` handed back): every
//! `LdapConnector` method that calls `rasn::ber::decode` directly. `decode`
//! is the one actually wired into the policy path; `upgrade_request`,
//! `bind_request`, `bind_response`, and `build_rejection` are fuzzed here
//! too since they parse the same untrusted frame on other paths (StartTLS
//! negotiation, identity-claim tracking on both the request and response
//! side, and rejecting a blocked request) and share the same risk (a
//! malformed/adversarial frame panicking instead of returning `Err`). None
//! of these should ever panic — an error is a fine outcome, a panic isn't.

#![no_main]

use ai_protect::connector::ldap::LdapConnector;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

static CONNECTOR: LazyLock<LdapConnector> =
    LazyLock::new(|| LdapConnector::new("127.0.0.1:389".parse().unwrap(), None));

fuzz_target!(|data: &[u8]| {
    let _ = CONNECTOR.decode(data);
    let _ = CONNECTOR.upgrade_request(data);
    let _ = CONNECTOR.bind_request(data);
    let _ = CONNECTOR.bind_response(data);
    let _ = CONNECTOR.build_rejection(data, "fuzz");
});
