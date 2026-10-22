//! A single-owner Tokio driver for the pinned `RakNet` protocol engine.
//!
//! No background task is spawned. Keep [`RakNetConnection::recv`] or
//! [`RakNetConnection::maintain`] polled to service protocol control and timers.
//! Cancellation retains queued protocol outputs; dropping the connection closes
//! its socket immediately.

mod connect;
mod lifecycle;
mod observation;
mod receive;

pub use lifecycle::{
    ClosedRakNetConnection, ClosingRakNetConnection, RakNetCloseError, RakNetConnection,
};
pub use observation::RttObservation;

#[cfg(test)]
mod tests;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;

use ::raknet::prelude::{
    Closing, Established, RakClientConfig, RakClientError, RakPriority, RakReliability, RakSession,
    RakSessionConfig, RakSessionError, RakSessionInput, RakSessionOutput, RakSessionState, Sans,
};
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::time::{Instant, sleep_until};

pub use ::raknet::prelude::RakDisconnectReason as DisconnectReason;

const RECEIVE_QUEUE_MESSAGES: usize = 64;
const UDP_BUFFER_BYTES: usize = 1 << 16;

/// Connection deadlines and application receive-queue bounds.
#[derive(Clone, Debug)]
pub struct RakNetOptions {
    /// Largest permitted MTU, including IP and UDP headers.
    ///
    /// Cap this to the local interface MTU for tunnels or VPNs. Values outside
    /// the protocol engine's supported bounds fail before opening a socket.
    pub max_mtu: u16,
    /// Maximum duration of the complete transport handshake.
    pub connect_timeout: Duration,
    /// Maximum duration of graceful close before releasing the socket.
    pub close_timeout: Duration,
    /// Maximum complete message bytes in the receive FIFO.
    /// One additional original head can wait for aggregate capacity. A single
    /// message larger than this entire allowance is rejected.
    pub receive_buffer_bytes: usize,
    /// Maximum complete messages in the receive FIFO.
    pub receive_buffer_messages: usize,
    /// Maximum unacknowledged outgoing message bytes, bounded by the engine limit.
    pub send_buffer_bytes: usize,
}

impl Default for RakNetOptions {
    fn default() -> Self {
        let session = RakSessionConfig::default();
        let client = RakClientConfig::default();
        Self {
            max_mtu: client.max_mtu_size,
            connect_timeout: client.conn_attempt_timeout,
            close_timeout: session.close_timeout,
            receive_buffer_bytes: usize::try_from(session.max_queued_bytes)
                .expect("default RakNet byte bound is positive"),
            receive_buffer_messages: RECEIVE_QUEUE_MESSAGES,
            send_buffer_bytes: usize::try_from(session.max_outbound_bytes)
                .expect("default RakNet outbound bound is positive"),
        }
    }
}

/// A transport failure; these diagnostics never include message bodies.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RakNetError {
    /// Socket I/O failed.
    #[error("raknet socket: {0}")]
    Io(#[from] std::io::Error),
    /// The handshake protocol rejected or failed the connection.
    #[error("raknet handshake: {0}")]
    Handshake(#[from] RakClientError),
    /// The connected protocol engine failed.
    #[error("raknet session: {0}")]
    Session(#[from] RakSessionError),
    /// The complete handshake exceeded its deadline.
    #[error("raknet handshake timed out")]
    ConnectTimeout,
    /// A configured duration or capacity is unsupported.
    #[error("invalid raknet option: {0}")]
    InvalidOption(&'static str),
    /// One complete received message exceeds the entire receive-byte allowance.
    #[error("raknet receive queue exceeds its configured capacity")]
    ReceiveBufferExceeded,
    /// The caller must service the connection before queuing more messages.
    #[error("raknet outbound queue is full")]
    SendBufferFull,
    /// A message exceeds the negotiated transport limit.
    #[error("raknet message has {actual} bytes, maximum {maximum}")]
    MessageTooLarge {
        /// Message length.
        actual: usize,
        /// Negotiated maximum outgoing message length.
        maximum: usize,
    },
    /// Empty application messages are not accepted.
    #[error("empty raknet message")]
    EmptyMessage,
    /// The engine terminated the connection.
    #[error("raknet disconnected: {0:?}")]
    Disconnected(DisconnectReason),
    /// The socket has already been released.
    #[error("raknet connection is closed")]
    Closed,
}

/// A single core owner whose local send capability cannot be recovered after close.
enum SessionSlot {
    Established(RakSession<Established>),
    Closing(RakSession<Closing>),
}

impl SessionSlot {
    /// Observes liveness without changing the local phase.
    fn state(&self) -> RakSessionState {
        match self {
            Self::Established(session) => session.state(),
            Self::Closing(session) => session.state(),
        }
    }

    /// Reads the original negotiated complete-message limit.
    fn max_message_len(&self) -> usize {
        match self {
            Self::Established(session) => session.max_message_len(),
            Self::Closing(session) => session.max_message_len(),
        }
    }

    /// Reads the original congestion-controller round-trip estimate.
    fn rtt(&self) -> Duration {
        match self {
            Self::Established(session) => session.rtt(),
            Self::Closing(session) => session.rtt(),
        }
    }

    /// Reads the original retained outgoing byte count.
    fn outbound_bytes(&self) -> usize {
        match self {
            Self::Established(session) => session.outbound_bytes(),
            Self::Closing(session) => session.outbound_bytes(),
        }
    }

    /// Drives the same engine's explicit flush cadence.
    fn tick(&mut self, now: std::time::Instant) -> Result<(), RakSessionError> {
        #[cfg(test)]
        tests::record_maintenance_pass();
        match self {
            Self::Established(session) => session.tick(now),
            Self::Closing(session) => session.tick(now),
        }
    }

    /// Delivers transport input in either local phase; application Send is unavailable.
    fn handle(&mut self, input: RakSessionInput) -> Result<(), RakSessionError> {
        match self {
            Self::Established(session) => session.handle(input),
            Self::Closing(session) => session.handle(input),
        }
    }

    /// Uses the same core parser without committing new application frames.
    fn handle_backpressured(&mut self, input: RakSessionInput) -> Result<(), RakSessionError> {
        match self {
            Self::Established(session) => session.handle_backpressured(input),
            Self::Closing(session) => session.handle_backpressured(input),
        }
    }

    /// Takes only original wire/control output while application output is retained.
    fn poll_control(&mut self) -> Option<RakSessionOutput> {
        match self {
            Self::Established(session) => session.poll_control(),
            Self::Closing(session) => session.poll_control(),
        }
    }

    /// Observes the canonical peer, reliable-input and original-close expiry.
    fn expiry_deadline(&self, now: std::time::Instant) -> Option<std::time::Instant> {
        match self {
            Self::Established(session) => session.expiry_deadline(now),
            Self::Closing(session) => session.expiry_deadline(now),
        }
    }

    /// Drains the original core output FIFO without copying it.
    fn poll(&mut self) -> Option<RakSessionOutput> {
        match self {
            Self::Established(session) => session.poll(),
            Self::Closing(session) => session.poll(),
        }
    }
}

/// One retained protocol/socket/FIFO owner across public capability transitions.
struct Engine {
    socket: Option<UdpSocket>,
    local: SocketAddr,
    peer: SocketAddr,
    session: Option<SessionSlot>,
    options: RakNetOptions,
    incoming: VecDeque<Bytes>,
    incoming_bytes: usize,
    pending_message: Option<Box<[u8]>>,
    pending_datagram: Option<Box<[u8]>>,
    receive_buffer: Vec<u8>,
    next_tick: Instant,
    close_deadline: Option<Instant>,
    failure: Option<RakNetError>,
    rtt: RttObservation,
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.rtt.retire();
    }
}

impl Engine {
    /// Returns the bound local address, including after close for diagnostics.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Returns the peer selected for this connection.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Returns the negotiated outgoing message limit, or zero after close.
    pub fn max_message_len(&self) -> usize {
        if self.socket.is_none() {
            return 0;
        }
        self.session.as_ref().map_or(0, |session| {
            session
                .max_message_len()
                .min(self.options.send_buffer_bytes)
        })
    }

    /// Publishes only positive estimates while the original connection admits work.
    fn publish_rtt(&self) {
        let sample = self.session.as_ref().and_then(|session| {
            (self.socket.is_some()
                && self.close_deadline.is_none()
                && session.state() == RakSessionState::Connected)
                .then(|| session.rtt())
                .filter(|sample| !sample.is_zero())
        });
        self.rtt.publish(sample);
    }

    /// Admits a complete message for reliable, ordered delivery without a fixed flush delay.
    ///
    /// Admission and the first socket-send attempt are synchronous. Socket or
    /// congestion pressure retains the original bytes for `recv` or `maintain`.
    /// Once accepted, do not queue it again if a later wait is cancelled.
    /// This method does not add or remove the Bedrock batch marker.
    ///
    /// # Errors
    /// Returns an error for a closed connection, empty/oversized message, full
    /// outgoing queue, or protocol-engine failure. A full queue can be retried
    /// after [`Self::wait_send_capacity`] services incoming acknowledgements.
    pub fn queue_send(&mut self, message: Bytes) -> Result<(), RakNetError> {
        if !self.has_send_capacity(message.len())? {
            return Err(RakNetError::SendBufferFull);
        }
        let session = self.session.as_mut().ok_or(RakNetError::Closed)?;
        let SessionSlot::Established(session) = session else {
            return Err(RakNetError::Closed);
        };
        let result = session.send(
            message.as_ref().into(),
            RakReliability::ReliableOrdered,
            RakPriority::Normal,
            Instant::now().into_std(),
        );
        if let Err(error) = result {
            self.end(RakNetError::Closed);
            return Err(error.into());
        }
        let result = self.try_flush_datagrams();
        if result.is_err() {
            self.end(RakNetError::Closed);
        }
        result
    }

    /// Services protocol I/O until `message_bytes` can be admitted without overflow.
    ///
    /// Incoming messages remain in the bounded receive FIFO. Cancelling this wait
    /// loses no state and admits no application message. Queue the message once
    /// after this returns; another sender cannot race this exclusive owner.
    ///
    /// # Errors
    /// Returns invalid message size, closed connection, or fatal I/O/protocol and
    /// receive-capacity failures encountered while servicing the connection.
    pub async fn wait_send_capacity(&mut self, message_bytes: usize) -> Result<(), RakNetError> {
        loop {
            self.flush().await?;
            if self.has_send_capacity(message_bytes)? {
                return Ok(());
            }
            if let Err(error) = self.step().await {
                self.end(RakNetError::Closed);
                return Err(error);
            }
        }
    }

    /// Validates message size and checks the remaining outgoing byte budget.
    fn has_send_capacity(&self, message_bytes: usize) -> Result<bool, RakNetError> {
        self.socket.as_ref().ok_or(RakNetError::Closed)?;
        let session = self.session.as_ref().ok_or(RakNetError::Closed)?;
        if session.state() != RakSessionState::Connected {
            return Err(RakNetError::Closed);
        }
        if message_bytes == 0 {
            return Err(RakNetError::EmptyMessage);
        }
        let maximum = self.max_message_len();
        if message_bytes > maximum {
            return Err(RakNetError::MessageTooLarge {
                actual: message_bytes,
                maximum,
            });
        }
        Ok(message_bytes
            <= self
                .options
                .send_buffer_bytes
                .saturating_sub(session.outbound_bytes()))
    }

    /// Sends every datagram the engine can emit immediately, retaining state on cancellation.
    ///
    /// This is not a peer acknowledgement: reliable delivery continues as `recv`
    /// services acknowledgements, retransmission and congestion control.
    ///
    /// # Errors
    /// Returns socket, protocol or receive-queue failures. These end the connection.
    pub async fn flush(&mut self) -> Result<(), RakNetError> {
        self.expire_close();
        if self.socket.is_none() {
            return self.collect_outputs();
        }
        let result = self
            .session
            .as_mut()
            .map_or(Ok(()), |session| session.tick(Instant::now().into_std()));
        if let Err(error) = result {
            self.end(RakNetError::Closed);
            return Err(error.into());
        }
        let result = if let Some(deadline) = self.close_deadline {
            match tokio::time::timeout_at(deadline, self.flush_datagrams()).await {
                Ok(result) => result,
                Err(_) => {
                    self.end(RakNetError::Disconnected(DisconnectReason::Requested));
                    Ok(())
                }
            }
        } else {
            self.flush_datagrams().await
        };
        if result.is_err() {
            self.end(RakNetError::Closed);
        }
        result
    }

    /// Retains the front datagram until the socket confirms its atomic send.
    async fn flush_datagrams(&mut self) -> Result<(), RakNetError> {
        loop {
            if self.pending_datagram.is_none() {
                self.collect_outputs()?;
            }
            let Some(datagram) = self.pending_datagram.as_ref() else {
                return Ok(());
            };
            let sent = self
                .socket
                .as_ref()
                .ok_or(RakNetError::Closed)?
                .send(datagram)
                .await?;
            if sent != datagram.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "partial UDP datagram send",
                )
                .into());
            }
            self.pending_datagram = None;
        }
    }

    /// Emits writable output now, retaining the exact front under socket pressure.
    fn try_flush_datagrams(&mut self) -> Result<(), RakNetError> {
        loop {
            if self.pending_datagram.is_none() {
                self.collect_outputs()?;
            }
            let Some(datagram) = self.pending_datagram.as_ref() else {
                return Ok(());
            };
            let sent = match self
                .socket
                .as_ref()
                .ok_or(RakNetError::Closed)?
                .try_send(datagram)
            {
                Ok(sent) => sent,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error.into()),
            };
            if sent != datagram.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "partial UDP datagram send",
                )
                .into());
            }
            self.pending_datagram = None;
        }
    }

    /// Retires local admission before returning the same drainable protocol owner.
    fn begin_close(&mut self) -> Result<(), RakNetError> {
        self.rtt.retire();
        if self.socket.is_none() {
            return Ok(());
        }
        let Some(deadline) = Instant::now().checked_add(self.options.close_timeout) else {
            self.end(RakNetError::Closed);
            return Err(RakNetError::InvalidOption("close timeout is too large"));
        };
        self.close_deadline = Some(deadline);
        let Some(SessionSlot::Established(session)) = self.session.take() else {
            unreachable!("only established public owners begin close");
        };
        match session.close(Instant::now().into_std()) {
            Ok(session) => self.session = Some(SessionSlot::Closing(session)),
            Err(error) => {
                let (session, cause) = error.into_parts();
                self.session = Some(SessionSlot::Closing(session));
                return Err(cause.into());
            }
        }
        Ok(())
    }

    /// Drives the original close budget without changing it when this wait is cancelled.
    async fn finish_close(&mut self) -> Result<(), RakNetError> {
        while self.socket.is_some() {
            let result = async {
                self.flush().await?;
                if self.socket.is_some() {
                    self.step().await?;
                }
                Ok::<(), RakNetError>(())
            }
            .await;
            if let Err(error) = result {
                self.end(RakNetError::Closed);
                return Err(error);
            }
        }
        Ok(())
    }

    /// Advances one socket or timer event. All state survives cancellation of its wait.
    async fn step(&mut self) -> Result<(), RakNetError> {
        if self.expire_close() {
            return Ok(());
        }
        let backpressured = self.receive_blocked();
        let socket = self.socket.as_ref().ok_or(RakNetError::Closed)?;
        let mut next = self
            .close_deadline
            .map_or(self.next_tick, |deadline| deadline.min(self.next_tick));
        if let Some(deadline) = self
            .session
            .as_ref()
            .and_then(|session| session.expiry_deadline(Instant::now().into_std()))
        {
            next = next.min(Instant::from_std(deadline));
        }
        let input = tokio::select! {
            received = socket.recv(&mut self.receive_buffer) => {
                let length = received?;
                RakSessionInput::Datagram(
                    self.receive_buffer[..length].into(),
                    Instant::now().into_std(),
                )
            }
            _ = sleep_until(next) => {
                if self.expire_close() {
                    return Ok(());
                }
                RakSessionInput::Update(Instant::now().into_std())
            }
        };
        let session = self.session.as_mut().ok_or(RakNetError::Closed)?;
        let result = if backpressured {
            session.handle_backpressured(input)
        } else {
            session.handle(input)
        };
        if result.is_ok() {
            self.publish_rtt();
        }
        result.map_err(Into::into)
    }

    /// Releases I/O and retains the original bounded core output for subsequent receive calls.
    fn end(&mut self, error: RakNetError) {
        self.rtt.retire();
        self.failure.get_or_insert(error);
        self.socket = None;
        self.pending_datagram = None;
    }

    /// Applies a retained close deadline to every operation that drives protocol I/O.
    fn expire_close(&mut self) -> bool {
        if self.socket.is_some()
            && self
                .close_deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.end(RakNetError::Disconnected(DisconnectReason::Requested));
            return true;
        }
        false
    }
}
