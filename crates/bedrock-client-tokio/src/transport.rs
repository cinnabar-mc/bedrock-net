// SPDX-License-Identifier: MIT

//! Concrete established transport lifecycles; dialing and admission stay with the caller.

mod accepted;
mod admission;
pub(crate) use admission::SendPermit;
#[cfg(feature = "test-support")]
pub mod inbox;
#[cfg(not(feature = "test-support"))]
mod inbox;
mod messaging;
use super::RoundTripTime;
use accepted::AcceptedTransport;
use bedrock_net::BatchHeader;
use bytes::Bytes;
use futures::future::BoxFuture;
use inbox::Inbox;
use messaging::MessagingTransport;
use std::future::Future;
use std::{io, time::Instant};
use zeroize::Zeroizing;

/// One actual established association and its retained input/output owners.
/// Construction does not authenticate a player or grant service membership.
pub struct Transport {
    state: State,
    nonce: Zeroizing<String>,
}

enum State {
    Messaging(Box<MessagingTransport>),
    Accepted(Box<AcceptedTransport>),
    Lan(Box<AcceptedTransport>),
    Http(Box<AcceptedTransport>),
}

impl Transport {
    /// Installs connection limits without replacing a transport or already accepted input.
    pub(super) fn configure_limits(&mut self, limits: bedrock_net::BatchLimits) {
        match &mut self.state {
            State::Messaging(connection) => connection.configure_limits(limits),
            State::Accepted(connection) | State::Lan(connection) | State::Http(connection) => {
                connection.configure_limits(limits)
            }
        }
    }

    /// Retains a protected messaging connection and its caller-validated challenge.
    pub fn from_messaging(
        connection: bedrock_net::messaging::MessagingConnection,
        nonce: String,
    ) -> Self {
        Self {
            state: State::Messaging(Box::new(MessagingTransport::new(connection))),
            nonce: Zeroizing::new(nonce),
        }
    }
    /// Takes only the caller's actual Ready server association.
    pub fn from_accepted(connection: nethernet_tokio::AcceptedSession) -> Self {
        Self {
            state: State::Accepted(Box::new(AcceptedTransport::new(connection))),
            nonce: Zeroizing::new(String::new()),
        }
    }
    /// Retains a caller's already Ready client through the same accepted I/O owner.
    /// The challenge is metadata only and grants no membership or Login authority.
    pub fn from_ready_client(connection: nethernet_tokio::NetherClient, nonce: String) -> Self {
        Self {
            state: State::Accepted(Box::new(AcceptedTransport::new(connection.into_accepted()))),
            nonce: Zeroizing::new(nonce),
        }
    }
    /// Retains a real Ready client and the challenge obtained by its original discovery owner.
    pub fn from_lan(connection: nethernet_tokio::NetherClient, nonce: String) -> Self {
        Self {
            state: State::Lan(Box::new(AcceptedTransport::new(connection.into_accepted()))),
            nonce: Zeroizing::new(nonce),
        }
    }
    /// Retains a real Ready HTTP-signaled client, including its original receive queues.
    pub fn from_http(connection: nethernet_tokio::NetherClient) -> Self {
        Self {
            state: State::Http(Box::new(AcceptedTransport::new(connection.into_accepted()))),
            nonce: Zeroizing::new(String::new()),
        }
    }
    /// Observes the selected association's original full round-trip estimate.
    pub fn observe_rtt(&self) -> Option<RoundTripTime> {
        match &self.state {
            State::Messaging(connection) => connection.observe_rtt(),
            State::Accepted(connection) | State::Lan(connection) | State::Http(connection) => {
                connection.observe_rtt()
            }
        }
    }
    /// Borrows the challenge retained from the original selected route, if present.
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    /// Selects the original association's Bedrock batch envelope.
    pub fn header(&self) -> BatchHeader {
        BatchHeader::NetherNet
    }
    /// Whether this transport needs Bedrock's application cipher above its socket.
    pub fn batch_encryption(&self) -> bool {
        false
    }
    /// Applies the original absolute admission deadline without restarting accepted work.
    pub async fn send_until(
        &mut self,
        message: Bytes,
        deadline: Option<Instant>,
    ) -> io::Result<()> {
        match &mut self.state {
            State::Messaging(connection) => connection.send_until(message, deadline).await,
            State::Accepted(connection) => connection.send_until(message, deadline).await,
            State::Lan(connection) => {
                if let Some(deadline) = deadline {
                    ensure_current(deadline, Instant::now())?;
                }
                let result = connection.send_until(message, deadline).await;
                if let Some(deadline) = deadline {
                    ensure_current(deadline, Instant::now())?;
                }
                result
            }
            State::Http(connection) => {
                let result = connection.send_until(message, deadline).await;
                if let Some(deadline) = deadline {
                    ensure_current(deadline, Instant::now())?;
                }
                result
            }
        }
    }
    /// Receives original accepted input before its retained first terminal cause.
    pub async fn recv(&mut self) -> io::Result<Bytes> {
        match &mut self.state {
            State::Messaging(connection) => connection.recv().await,
            State::Accepted(connection) | State::Lan(connection) | State::Http(connection) => {
                connection.recv().await
            }
        }
    }
    /// Services original timers/control without consuming an accepted application prefix.
    pub async fn maintain(&mut self) {
        match &mut self.state {
            State::Messaging(connection) => connection.maintain().await,
            State::Accepted(_) | State::Lan(_) | State::Http(_) => std::future::pending().await,
        }
    }
    /// Consumes local admission while retaining queues across a canceled teardown wait.
    pub async fn close(&mut self) -> io::Result<()> {
        match &mut self.state {
            State::Messaging(connection) => {
                connection.close();
                Ok(())
            }
            State::Accepted(connection) | State::Lan(connection) | State::Http(connection) => {
                connection.close();
                Ok(())
            }
        }
    }

    /// Retires and drains the original transport for callers that no longer need game input.
    /// Keep this wait under the caller's original deadline; cancellation retains the same owner.
    pub async fn finish_close(&mut self) -> io::Result<()> {
        match &mut self.state {
            State::Messaging(connection) => connection.finish_close().await,
            State::Accepted(connection) | State::Lan(connection) | State::Http(connection) => {
                connection.finish_close().await
            }
        }
    }
    /// Synchronously retires only a server association, preserving its same receive prefix.
    pub fn retire_accepted(&mut self) {
        if let State::Accepted(connection) = &mut self.state {
            connection.close();
        }
    }
    /// Checks actual established accepted admission before encoding any retained effect.
    pub(super) fn check_prepared_send(&self) -> io::Result<()> {
        match &self.state {
            State::Accepted(connection) | State::Http(connection) | State::Lan(connection) => {
                connection.sender().map(drop)
            }
            _ => Err(prepared_unsupported()),
        }
    }
    /// Reserves the same bounded transport capacity without owning a payload or cipher effect.
    pub(super) fn reserve_send(
        &self,
        _bytes: usize,
        deadline: Instant,
    ) -> io::Result<BoxFuture<'static, io::Result<SendPermit>>> {
        match &self.state {
            State::Accepted(connection) | State::Http(connection) | State::Lan(connection) => {
                let sender = connection.sender()?;
                Ok(Box::pin(async move {
                    sender
                        .reserve_send(Some(deadline))
                        .await
                        .map(SendPermit)
                        .map_err(io::Error::other)
                }))
            }
            _ => Err(prepared_unsupported()),
        }
    }
    pub(super) async fn progress_accepted<T: Send>(
        &mut self,
        progress: impl Future<Output = T> + Send,
    ) -> io::Result<T> {
        match &mut self.state {
            State::Accepted(connection) | State::Http(connection) | State::Lan(connection) => {
                connection.progress(progress).await
            }
            _ => Err(prepared_unsupported()),
        }
    }
    pub(super) async fn settle_accepted<T: Send>(
        &mut self,
        progress: impl Future<Output = T> + Send,
    ) -> io::Result<T> {
        match &mut self.state {
            State::Accepted(connection) | State::Http(connection) | State::Lan(connection) => {
                connection.settle(progress).await
            }
            _ => Err(prepared_unsupported()),
        }
    }
}

/// The finite caller-supplied output admission deadline elapsed.
#[derive(Debug, thiserror::Error)]
#[error("native multiplayer credential expired before Login")]
pub struct ExpiredAdmission;

fn expired() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, ExpiredAdmission)
}
fn ensure_current(deadline: Instant, now: Instant) -> io::Result<()> {
    if now < deadline {
        Ok(())
    } else {
        Err(expired())
    }
}
fn closing() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "native transport is closing")
}
fn prepared_unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "prepared send requires an accepted transport",
    )
}
