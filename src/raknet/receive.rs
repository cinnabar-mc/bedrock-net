//! Bounded application admission while the same socket services protocol control.

use std::future::pending;

use bytes::Bytes;
use tokio::time::Instant;

use super::{Engine, RakNetError, RakSessionOutput};

impl Engine {
    /// Returns the accepted FIFO before its original terminal, retaining every borrowed wait.
    pub(super) async fn recv(&mut self) -> Result<Bytes, RakNetError> {
        loop {
            if self.incoming.is_empty() {
                if let Err(error) = self.flush().await {
                    self.failure = Some(error);
                }
            } else {
                self.expire_close();
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

    /// Services the original driver without taking an application body from its FIFO.
    pub(super) async fn maintain(&mut self) {
        loop {
            if let Err(error) = self.flush().await {
                self.failure = Some(error);
            }
            if self.socket.is_none() {
                // Ordinary receive observes the retained prefix and first failure.
                pending::<()>().await;
            }
            if let Err(error) = self.step().await {
                self.end(error);
            }
        }
    }

    /// Keeps one unadmitted head ahead of the remaining original core output.
    fn promote_pending(&mut self) {
        if self
            .pending_message
            .as_ref()
            .is_some_and(|message| self.message_fits(message.len()))
        {
            let message = self
                .pending_message
                .take()
                .expect("checked pending message");
            self.incoming_bytes += message.len();
            self.incoming.push_back(Bytes::from(message));
        }
    }

    /// Checks aggregate capacity without changing admission or the queue's oldest head.
    fn message_fits(&self, length: usize) -> bool {
        self.incoming.len() < self.options.receive_buffer_messages
            && length
                <= self
                    .options
                    .receive_buffer_bytes
                    .saturating_sub(self.incoming_bytes)
    }

    /// Refuses new application input whenever the original FIFO/head cannot advance.
    pub(super) fn receive_blocked(&self) -> bool {
        self.pending_message.is_some()
            || self.incoming.len() >= self.options.receive_buffer_messages
            || self.incoming_bytes >= self.options.receive_buffer_bytes
    }

    /// Collects bounded application output and services control without another payload FIFO.
    pub(super) fn collect_outputs(&mut self) -> Result<(), RakNetError> {
        self.promote_pending();
        loop {
            let blocked = self.receive_blocked();
            let output = self.session.as_mut().and_then(|session| {
                if blocked {
                    session.poll_control()
                } else {
                    session.poll()
                }
            });
            let Some(output) = output else {
                if self.socket.is_none() && !blocked {
                    self.session = None;
                }
                return Ok(());
            };
            match output {
                RakSessionOutput::Packet(message) => self.retain_message(message)?,
                RakSessionOutput::Datagram(..) | RakSessionOutput::Wait(..)
                    if self.socket.is_none() => {}
                RakSessionOutput::Datagram(datagram, _) => {
                    self.pending_datagram = Some(datagram);
                    return Ok(());
                }
                RakSessionOutput::Wait(duration) => {
                    let now = Instant::now();
                    let next = now
                        .checked_add(duration)
                        .ok_or(RakNetError::InvalidOption("engine timer is too large"))?;
                    self.next_tick = self
                        .session
                        .as_ref()
                        .and_then(|session| session.expiry_deadline(now.into_std()))
                        .map_or(next, |deadline| next.min(Instant::from_std(deadline)));
                }
                RakSessionOutput::Disconnected(_, reason) => {
                    self.end(RakNetError::Disconnected(reason));
                }
            }
        }
    }

    /// Rejects an individually invalid body; aggregate pressure retains the exact head.
    fn retain_message(&mut self, message: Box<[u8]>) -> Result<(), RakNetError> {
        if message.len() > self.options.receive_buffer_bytes {
            self.session = None;
            return Err(RakNetError::ReceiveBufferExceeded);
        }
        if self.message_fits(message.len()) {
            self.incoming_bytes += message.len();
            self.incoming.push_back(Bytes::from(message));
        } else {
            self.pending_message = Some(message);
        }
        Ok(())
    }
}
