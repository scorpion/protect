use std::borrow::Cow;

use crate::core::action::Action;
use crate::core::identity::Identity;
use crate::core::policy::Decision;

/// Hard cap on the length of the `identity`/`target` strings actually
/// written to a log line. Independent of (and in addition to) any capping a
/// `Connector` does before constructing an `Identity`/`Action` (e.g.
/// `connector::ldap::cap_dn`) — this module is deliberately decoupled from
/// any specific `Connector`, so it can't assume every implementation caps
/// these before they get here. Without this, an attacker-controlled DN
/// otherwise inflates every log line it appears in, turning "logs never
/// rotate" (see ARCHITECTURE.md's "Known gaps") into a disk-fill lever this
/// module can close on its own regardless of upstream capping.
const MAX_LOGGED_FIELD_LEN: usize = 512;

/// Truncates `value` to `MAX_LOGGED_FIELD_LEN` bytes for log output,
/// appending the original length so a truncated line is still
/// distinguishable from a suspiciously-exact-512-byte one. Truncates on a
/// UTF-8 char boundary rather than a raw byte offset, since `value` may
/// come from attacker-controlled input (a bind DN) that isn't guaranteed to
/// be ASCII.
fn truncate_for_log(value: &str) -> Cow<'_, str> {
    if value.len() <= MAX_LOGGED_FIELD_LEN {
        return Cow::Borrowed(value);
    }
    let mut end = MAX_LOGGED_FIELD_LEN;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    Cow::Owned(format!(
        "{}... ({} bytes total)",
        &value[..end],
        value.len()
    ))
}

pub fn log_decision(identity: &Identity, action: &Action, decision: &Decision) {
    let identity = truncate_for_log(&identity.0);
    let target = truncate_for_log(&action.target);
    match decision {
        Decision::Allow => tracing::info!(
            identity = %identity,
            backend = action.backend,
            operation = ?action.operation,
            target = %target,
            blast_radius = action.blast_radius,
            "action allowed"
        ),
        Decision::Block { reason } => tracing::warn!(
            identity = %identity,
            backend = action.backend,
            operation = ?action.operation,
            target = %target,
            blast_radius = action.blast_radius,
            reason = %reason,
            "action blocked"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::action::OperationKind;
    use std::io;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl SharedBuffer {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl io::Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for SharedBuffer {
        type Writer = SharedBuffer;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn action() -> Action {
        Action {
            backend: "ldap",
            operation: OperationKind::AccountLock,
            target: "cn=alice,dc=example,dc=com".into(),
            blast_radius: 1,
        }
    }

    #[test]
    fn logs_allow_decision() {
        let buffer = SharedBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            log_decision(&Identity("test-peer".into()), &action(), &Decision::Allow);
        });

        let output = buffer.contents();
        assert!(output.contains("action allowed"));
        assert!(output.contains("test-peer"));
    }

    #[test]
    fn logs_block_decision_with_reason() {
        let buffer = SharedBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            log_decision(
                &Identity("test-peer".into()),
                &action(),
                &Decision::Block {
                    reason: "too many locks".into(),
                },
            );
        });

        let output = buffer.contents();
        assert!(output.contains("action blocked"));
        assert!(output.contains("too many locks"));
        assert!(output.contains("test-peer"));
    }

    #[test]
    fn truncate_for_log_passes_short_values_through_unchanged() {
        assert_eq!(
            truncate_for_log("cn=alice,dc=example,dc=com"),
            "cn=alice,dc=example,dc=com"
        );
    }

    #[test]
    fn truncate_for_log_bounds_an_oversized_value() {
        let huge = "a".repeat(MAX_LOGGED_FIELD_LEN * 4);

        let truncated = truncate_for_log(&huge);

        assert!(truncated.len() < huge.len());
        assert!(truncated.contains(&format!("{} bytes total", huge.len())));
    }

    #[test]
    fn truncate_for_log_does_not_split_a_multi_byte_char() {
        // "é" is 2 bytes in UTF-8; repeating it so the cutoff at
        // MAX_LOGGED_FIELD_LEN bytes lands mid-character must not panic on
        // a non-char-boundary slice (`str` indexing panics on those).
        let huge = "é".repeat(MAX_LOGGED_FIELD_LEN * 2);

        let truncated = truncate_for_log(&huge);

        assert!(truncated.contains(&format!("{} bytes total", huge.len())));
    }

    #[test]
    fn logs_an_oversized_identity_and_target_truncated() {
        let buffer = SharedBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_ansi(false)
            .finish();
        let huge_dn = "a".repeat(MAX_LOGGED_FIELD_LEN * 4);
        let mut oversized_action = action();
        oversized_action.target = huge_dn.clone();

        tracing::subscriber::with_default(subscriber, || {
            log_decision(
                &Identity(huge_dn.clone()),
                &oversized_action,
                &Decision::Allow,
            );
        });

        let output = buffer.contents();
        assert!(!output.contains(&huge_dn));
        assert!(output.contains(&format!("{} bytes total", huge_dn.len())));
    }
}
