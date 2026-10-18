//! A single-owner Tokio driver for the pinned RakNet protocol engine.
//!
//! No background task is spawned. Keep [`RakNetConnection::recv`] polled in the
//! session's network loop to service acknowledgements, retransmission and pings.
//! Cancellation retains queued protocol outputs; dropping the connection closes
//! its socket immediately.

mod connect;

#[cfg(test)]
mod tests;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;

use ::raknet::prelude::{
    RakClientConfig, RakClientError, RakPriority, RakReliability, RakSession, RakSessionConfig,
    RakSessionError, RakSessionInput, RakSessionOutput, RakSessionState, Sans,
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
    /// Maximum complete message bytes retained while driving other operations.
    pub receive_buffer_bytes: usize,
    /// Maximum complete messages retained while driving other operations.
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
    /// A complete received message cannot fit the receive queue.
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

/// Owns one socket, protocol session and FIFO of complete received messages.
///
/// Queue messages synchronously, then poll `flush` or `recv` to drive I/O. This
/// allows a session loop to select `recv` against its outgoing command channel
/// without detaching tasks or losing protocol state when a future is cancelled.
pub struct RakNetConnection {
    socket: Option<UdpSocket>,
    local: SocketAddr,
    peer: SocketAddr,
    session: Option<Box<RakSession>>,
    options: RakNetOptions,
    incoming: VecDeque<Bytes>,
    incoming_bytes: usize,
    pending_datagram: Option<Box<[u8]>>,
    receive_buffer: Vec<u8>,
    next_tick: Instant,
    close_deadline: Option<Instant>,
    failure: Option<RakNetError>,
}

impl RakNetConnection {
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
        self.session.as_ref().map_or(0, |session| {
            session
                .max_message_len()
                .min(self.options.send_buffer_bytes)
        })
    }

    /// Admits a complete message for reliable, ordered delivery without a fixed flush delay.
    ///
    /// Admission is synchronous. Once accepted, do not queue it again if a later
    /// `flush` or `recv` is cancelled: its state is retained in this connection.
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
        let result = session.handle(RakSessionInput::Send(
            message.as_ref().into(),
            RakReliability::ReliableOrdered,
            RakPriority::Normal,
            Instant::now().into_std(),
        ));
        if let Err(error) = result {
            self.end(RakNetError::Closed);
            return Err(error.into());
        }
        Ok(())
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
        let session = self.session.as_ref().ok_or(RakNetError::Closed)?;
        if session.get_state() != RakSessionState::Connected {
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
        if self.expire_close() {
            return Ok(());
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

    /// Returns the next complete message, servicing I/O and timers while waiting.
    ///
    /// Cancelling this wait loses no message or pending datagram. Messages already
    /// received precede the terminal error, even if the peer closes immediately.
    ///
    /// # Errors
    /// Returns the terminal failure after draining received messages; later calls
    /// return [`RakNetError::Closed`].
    pub async fn recv(&mut self) -> Result<Bytes, RakNetError> {
        loop {
            if let Err(error) = self.flush().await {
                self.failure = Some(error);
            }
            if let Some(message) = self.incoming.pop_front() {
                self.incoming_bytes -= message.len();
                return Ok(message);
            }
            if self.session.is_none() {
                return Err(self.failure.take().unwrap_or(RakNetError::Closed));
            }
            if let Err(error) = self.step().await {
                self.end(error);
            }
        }
    }

    /// Drains reliable outgoing state until closed or the configured close deadline.
    ///
    /// On completion the socket is released. Previously received messages remain
    /// readable through `recv`. Dropping this future retains closing state; dropping
    /// the connection itself releases the socket immediately.
    ///
    /// # Errors
    /// Returns an I/O, capacity or protocol failure encountered during close.
    pub async fn close(&mut self) -> Result<(), RakNetError> {
        let Some(session) = self.session.as_mut() else {
            return Ok(());
        };
        if self.close_deadline.is_none() {
            let deadline = Instant::now()
                .checked_add(self.options.close_timeout)
                .ok_or(RakNetError::InvalidOption("close timeout is too large"))?;
            let result = session.handle(RakSessionInput::Disconnect(Instant::now().into_std()));
            if let Err(error) = result {
                self.end(RakNetError::Closed);
                return Err(error.into());
            }
            self.close_deadline = Some(deadline);
        }
        while self.session.is_some() {
            let result = async {
                self.flush().await?;
                if self.session.is_some() {
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
        let socket = self.socket.as_ref().ok_or(RakNetError::Closed)?;
        let next = self
            .close_deadline
            .map_or(self.next_tick, |deadline| deadline.min(self.next_tick));
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
        let result = self
            .session
            .as_mut()
            .ok_or(RakNetError::Closed)?
            .handle(input);
        result.map_err(Into::into)
    }

    /// Processes engine outputs in order, stopping before the next asynchronous socket send.
    fn collect_outputs(&mut self) -> Result<(), RakNetError> {
        while let Some(output) = self.session.as_mut().and_then(|session| session.poll()) {
            match output {
                RakSessionOutput::Packet(message) => {
                    self.retain_message(message)?;
                }
                RakSessionOutput::Datagram(datagram, _) => {
                    self.pending_datagram = Some(datagram);
                    return Ok(());
                }
                RakSessionOutput::Wait(duration) => {
                    self.next_tick = Instant::now()
                        .checked_add(duration)
                        .ok_or(RakNetError::InvalidOption("engine timer is too large"))?;
                }
                RakSessionOutput::Disconnected(_, reason) => {
                    self.session = None;
                    self.end(RakNetError::Disconnected(reason));
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Retains the completed output prefix, then releases protocol and socket resources.
    fn end(&mut self, error: RakNetError) {
        self.failure.get_or_insert(error);
        if let Some(mut session) = self.session.take() {
            while let Some(output) = session.poll() {
                match output {
                    RakSessionOutput::Packet(message) => {
                        if let Err(error) = self.retain_message(message) {
                            self.failure = Some(error);
                            break;
                        }
                    }
                    RakSessionOutput::Disconnected(..) => break,
                    RakSessionOutput::Datagram(..) | RakSessionOutput::Wait(..) => {}
                }
            }
        }
        self.socket = None;
        self.pending_datagram = None;
    }

    /// Admits one message; rejection discards the engine's remainder to preserve a FIFO prefix.
    fn retain_message(&mut self, message: Box<[u8]>) -> Result<(), RakNetError> {
        if self.incoming.len() >= self.options.receive_buffer_messages
            || message.len()
                > self
                    .options
                    .receive_buffer_bytes
                    .saturating_sub(self.incoming_bytes)
        {
            self.session = None;
            return Err(RakNetError::ReceiveBufferExceeded);
        }
        self.incoming_bytes += message.len();
        self.incoming.push_back(Bytes::from(message));
        Ok(())
    }

    /// Applies a retained close deadline to every operation that drives protocol I/O.
    fn expire_close(&mut self) -> bool {
        if self.session.is_some()
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
