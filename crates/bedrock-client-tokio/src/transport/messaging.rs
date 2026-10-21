// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The signed service signaling edge of the existing native connection owner.

use super::Inbox;
use super::expired;
use bedrock_net::messaging::{ClosingMessagingConnection, MessagingConnection};
use bytes::Bytes;
use nethernet_tokio::NetherError;
use std::{io, time::Instant};

pub(super) struct MessagingTransport {
    connection: Option<Connection>,
    inbox: Inbox,
}

enum Connection {
    Established(MessagingConnection),
    Closing(ClosingMessagingConnection),
}

impl MessagingTransport {
    /// Applies caller-owned wire/count limits while retaining the same accepted prefix.
    pub(super) fn configure_limits(&mut self, limits: bedrock_net::BatchLimits) {
        self.inbox.configure_limits(limits);
    }

    /// Observes the same established transport without retaining its send capability.
    pub(super) fn observe_rtt(&self) -> Option<super::RoundTripTime> {
        match self.connection.as_ref()? {
            Connection::Established(connection) => Some(super::RoundTripTime::nethernet(
                connection.sender().observe_rtt(),
            )),
            _ => None,
        }
    }

    /// Retains only the caller's original established protected messaging connection.
    pub(super) fn new(connection: MessagingConnection) -> Self {
        Self {
            connection: Some(Connection::Established(connection)),
            inbox: Inbox::default(),
        }
    }

    /// Drives service and incoming data while waiting for actual SCTP output admission.
    pub(super) async fn send_until(
        &mut self,
        message: Bytes,
        deadline: Option<Instant>,
    ) -> io::Result<()> {
        let Connection::Established(connection) = self
            .connection
            .as_mut()
            .expect("synchronous transport transition")
        else {
            return Err(super::closing());
        };
        let sender = connection.sender();
        let sending = async {
            let result = match deadline {
                Some(deadline) => sender.send_before(message, deadline).await,
                None => sender.send(message).await,
            };
            match result {
                Err(NetherError::Timeout) if deadline.is_some() => Err(expired()),
                result => result.map_err(io::Error::other),
            }
        };
        tokio::pin!(sending);
        loop {
            if self.inbox.is_full() {
                tokio::select! {
                    biased;
                    result = &mut sending => return result,
                    _ = connection.maintain() => {},
                }
            } else {
                tokio::select! {
                    biased;
                    result = &mut sending => return result,
                    message = connection.recv() => {
                        let message = message.map_err(io::Error::other)?
                            .ok_or_else(Inbox::closed_during_write)?;
                        self.inbox.retain(message)?;
                    }
                }
            }
        }
    }

    /// Preserves messages accepted while a write was pending, ahead of the next transport read.
    pub(super) async fn recv(&mut self) -> io::Result<Bytes> {
        if let Some(message) = self.inbox.pop() {
            return Ok(message);
        }
        let result = match self
            .connection
            .as_mut()
            .expect("synchronous transport transition")
        {
            Connection::Established(connection) => connection.recv().await,
            Connection::Closing(connection) => connection.recv().await,
        };
        result
            .map_err(io::Error::other)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "NetherNet peer closed"))
    }

    /// Drives only service/control/signaling; terminal reporting waits behind accepted input.
    pub(super) async fn maintain(&mut self) {
        match self
            .connection
            .as_mut()
            .expect("synchronous transport transition")
        {
            Connection::Established(connection) => connection.maintain().await,
            Connection::Closing(_) => std::future::pending().await,
        }
    }

    /// Consumes local sending synchronously while retaining the exact service/receiver drain owner.
    pub(super) fn close(&mut self) {
        let current = self
            .connection
            .take()
            .expect("synchronous transport transition");
        self.connection = Some(match current {
            Connection::Established(connection) => Connection::Closing(connection.begin_close()),
            closing @ Connection::Closing(_) => closing,
        });
    }

    /// Drains the original retired reliable prefix and terminal without another service owner.
    pub(super) async fn finish_close(&mut self) -> io::Result<()> {
        self.close();
        while self.inbox.pop().is_some() {}
        let Connection::Closing(connection) =
            self.connection.as_mut().expect("retained retirement")
        else {
            unreachable!("close consumed established admission")
        };
        while connection.recv().await.map_err(io::Error::other)?.is_some() {}
        Ok(())
    }
}
