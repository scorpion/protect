use crate::connector::Action;
use crate::identity::Identity;
use crate::policy::Decision;

pub fn log_decision(identity: &Identity, action: &Action, decision: &Decision) {
    match decision {
        Decision::Allow => tracing::info!(
            identity = %identity.0,
            backend = action.backend,
            operation = ?action.operation,
            target = %action.target,
            blast_radius = action.blast_radius,
            "action allowed"
        ),
        Decision::Block { reason } => tracing::warn!(
            identity = %identity.0,
            backend = action.backend,
            operation = ?action.operation,
            target = %action.target,
            blast_radius = action.blast_radius,
            reason = %reason,
            "action blocked"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::OperationKind;
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
}
