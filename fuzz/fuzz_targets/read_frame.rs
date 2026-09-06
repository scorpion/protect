//! Fuzzes `read_frame`'s BER tag/length framing logic directly against raw,
//! untrusted bytes off the wire — the one piece of the decode path that
//! `decode.rs` can't reach, since it only sees bytes *after* framing already
//! split them into a message. This is also where `MAX_FRAME_CONTENT_LEN`
//! enforcement lives, so it exercises the boundary between "reject the
//! claimed length up front" and "read exactly that many content bytes."

#![no_main]

use ai_protect::connector::ldap::read_frame;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use tokio::runtime::Runtime;

static RT: LazyLock<Runtime> =
    LazyLock::new(|| Runtime::new().expect("building a tokio runtime for the fuzz target"));

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = RT.block_on(read_frame(&mut cursor));
});
