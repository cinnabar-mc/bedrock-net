//! Established and local-close capabilities over one existing service/transport owner.

use super::{Engine, Error, ReceiveState};
use bytes::Bytes;
use nethernet_tokio::SessionSender;

/// One actually established signed transport and its caller-driven protected service socket.
/// No public constructor can skip the original protected setup/deadline/readiness checks.
#[must_use]
pub struct MessagingConnection {
    pub(super) engine: Box<Engine>,
}

impl MessagingConnection {
    /// Shares established send/control while this owner continues driving recv/maintenance.
    /// Existing shared senders observe later global closure at the original runtime gate.
    pub fn sender(&self) -> SessionSender {
        self.engine.sender()
    }

    /// Drives service/control without consuming game data while application capacity is full.
    pub async fn maintain(&mut self) {
        self.engine.maintain().await;
    }

    /// Receives original reliable data before one staged service/transport error or EOF.
    pub async fn recv(&mut self) -> Result<Option<Bytes>, Error> {
        self.engine.recv().await
    }

    /// Synchronously consumes local sending capability and retains the accepted reliable prefix.
    /// No async close future can lose the transferred owner before returning its continuation.
    ///
    /// ```compile_fail
    /// fn send_after_local_close(connection: bedrock_net::messaging::MessagingConnection) {
    ///     let closing = connection.begin_close();
    ///     let _sender = closing.sender();
    /// }
    /// ```
    pub fn begin_close(mut self) -> ClosingMessagingConnection {
        self.engine.retire();
        ClosingMessagingConnection {
            engine: self.engine,
        }
    }
}

/// Local admission is retired; only the same accepted FIFO/terminal can be drained.
#[must_use = "drain accepted input and its terminal or explicitly drop the retired connection"]
pub struct ClosingMessagingConnection {
    engine: Box<Engine>,
}

impl ClosingMessagingConnection {
    /// Drains original accepted reliable messages before the existing one error/EOF.
    /// Cancellation retains this same owner and all unread accepted messages.
    pub async fn recv(&mut self) -> Result<Option<Bytes>, Error> {
        self.engine.recv().await
    }

    /// Consumes only after the original reliable terminal was reported; otherwise returns this owner.
    /// This proves local reader completion, not a remote acknowledgment or actor join.
    pub fn try_finish(self) -> Result<ClosedMessaging, Self> {
        if matches!(self.engine.receive, ReceiveState::Done) {
            Ok(ClosedMessaging { _private: () })
        } else {
            Err(self)
        }
    }
}

/// Local service retirement and original reliable reader completion, with no network capability.
pub struct ClosedMessaging {
    _private: (),
}
