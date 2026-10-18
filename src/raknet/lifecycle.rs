//! Local transport capabilities over the same socket, protocol state and accepted FIFO.

use std::fmt;
use std::net::SocketAddr;

use bytes::Bytes;

use super::{Engine, RakNetError};

/// One negotiated socket and its original bounded receive FIFO.
///
/// Queue once, then drive `flush` or `recv`; cancelling either wait retains all
/// accepted messages and the front pending datagram. No background task is spawned.
#[must_use]
pub struct RakNetConnection {
    pub(super) engine: Box<Engine>,
}

impl RakNetConnection {
    /// Returns the bound local address, including after peer termination.
    pub fn local_addr(&self) -> SocketAddr {
        self.engine.local_addr()
    }

    /// Returns the selected peer endpoint.
    pub fn peer_addr(&self) -> SocketAddr {
        self.engine.peer_addr()
    }

    /// Returns the negotiated outgoing message limit, or zero after termination.
    pub fn max_message_len(&self) -> usize {
        self.engine.max_message_len()
    }

    /// Admits one complete reliable ordered message without a fixed flush delay.
    /// Retrying after admission duplicates the message; a full queue can be retried
    /// after `wait_send_capacity` services the original connection.
    pub fn queue_send(&mut self, message: Bytes) -> Result<(), RakNetError> {
        self.engine.queue_send(message)
    }

    /// Drives acknowledgments until capacity is available, retaining received messages.
    /// Cancellation admits no message and preserves this same owner and its queues.
    pub async fn wait_send_capacity(&mut self, message_bytes: usize) -> Result<(), RakNetError> {
        self.engine.wait_send_capacity(message_bytes).await
    }

    /// Sends currently available datagrams, retaining the front until its atomic send.
    /// Completion is local emission, not a peer delivery acknowledgment.
    pub async fn flush(&mut self) -> Result<(), RakNetError> {
        self.engine.flush().await
    }

    /// Drives protocol I/O and returns the accepted FIFO before one terminal error.
    pub async fn recv(&mut self) -> Result<Bytes, RakNetError> {
        self.engine.recv().await
    }

    /// Consumes local send permission and starts the original finite close budget.
    /// Even a failed transition returns the closing owner and its preceding output.
    ///
    /// ```compile_fail
    /// use bedrock_net::raknet::RakNetConnection;
    /// fn send_after_close(connection: RakNetConnection) {
    ///     if let Ok(mut closing) = connection.begin_close() {
    ///         closing.queue_send(bytes::Bytes::from_static(b"late"));
    ///     }
    /// }
    /// ```
    pub fn begin_close(mut self) -> Result<ClosingRakNetConnection, RakNetCloseError> {
        let result = self.engine.begin_close();
        let connection = ClosingRakNetConnection {
            engine: self.engine,
        };
        match result {
            Ok(()) => Ok(connection),
            Err(cause) => Err(RakNetCloseError { connection, cause }),
        }
    }
}

/// Local sending has retired; the original protocol output and accepted input remain owned.
#[must_use = "drive close and drain accepted input, or explicitly drop this connection"]
pub struct ClosingRakNetConnection {
    pub(super) engine: Box<Engine>,
}

impl ClosingRakNetConnection {
    /// Returns the retained local endpoint, including after socket release.
    pub fn local_addr(&self) -> SocketAddr {
        self.engine.local_addr()
    }

    /// Returns the retained peer endpoint.
    pub fn peer_addr(&self) -> SocketAddr {
        self.engine.peer_addr()
    }

    /// Emits original pending protocol work without admitting application messages.
    pub async fn flush(&mut self) -> Result<(), RakNetError> {
        self.engine.flush().await
    }

    /// Drives close until the socket is released; accepted input remains readable.
    /// Cancelling this borrowed wait retains the original absolute close deadline.
    pub async fn finish_close(&mut self) -> Result<(), RakNetError> {
        self.engine.finish_close().await
    }

    /// Drains accepted messages before the original terminal error, then `Closed`.
    pub async fn recv(&mut self) -> Result<Bytes, RakNetError> {
        self.engine.recv().await
    }

    /// Finishes only after socket release and observation of the accepted FIFO and terminal.
    /// Otherwise returns the same closing owner. This does not prove remote delivery.
    pub fn try_finish(self) -> Result<ClosedRakNetConnection, Self> {
        if self.engine.socket.is_some()
            || self.engine.session.is_some()
            || self.engine.pending_datagram.is_some()
            || !self.engine.incoming.is_empty()
            || self.engine.failure.is_some()
        {
            return Err(self);
        }
        Ok(ClosedRakNetConnection {
            local: self.engine.local,
            peer: self.engine.peer,
        })
    }
}

/// A failed local-close transition retains the drainable owner and original failure.
pub struct RakNetCloseError {
    connection: ClosingRakNetConnection,
    cause: RakNetError,
}

impl RakNetCloseError {
    /// Recovers the closing connection and original failure without restoring send permission.
    pub fn into_parts(self) -> (ClosingRakNetConnection, RakNetError) {
        (self.connection, self.cause)
    }
}

impl fmt::Debug for RakNetCloseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RakNetCloseError")
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for RakNetCloseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "raknet close: {}", self.cause)
    }
}

impl std::error::Error for RakNetCloseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

/// Completed local retirement and input drain, without any network capability.
pub struct ClosedRakNetConnection {
    local: SocketAddr,
    peer: SocketAddr,
}

impl ClosedRakNetConnection {
    /// Returns the retired local endpoint.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Returns the retired peer endpoint.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
}
