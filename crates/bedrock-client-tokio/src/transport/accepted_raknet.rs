// SPDX-License-Identifier: MIT

//! An accepted `RakNet` session retains its original receive and consuming close owners.

use super::Inbox;
use bytes::Bytes;
use raknet_tokio::prelude::{Closing, Established, RakSession, RakSessionError, SessionSender};
use std::{future::Future, io, sync::Arc, time::Instant};

pub(super) struct AcceptedRakNetTransport {
    state: Option<State>,
    inbox: Inbox,
    input_failure: Option<Arc<io::Error>>,
    input_terminal_seen: bool,
    close_failure: Option<Arc<io::Error>>,
}

enum State {
    Established(RakSession<Established>),
    Closing(RakSession<Closing>),
    Closed,
}

impl AcceptedRakNetTransport {
    /// Retains the actual server handoff without opening another socket or session.
    pub(super) fn new(session: RakSession<Established>) -> Self {
        Self {
            state: Some(State::Established(session)),
            inbox: Inbox::default(),
            input_failure: None,
            input_terminal_seen: false,
            close_failure: None,
        }
    }

    pub(super) fn configure_limits(&mut self, limits: bedrock_net::BatchLimits) {
        self.inbox.configure_limits(limits);
    }

    /// Borrows only the established session's original bounded send admission.
    pub(super) fn sender(&self) -> io::Result<SessionSender> {
        match self.state.as_ref().expect("synchronous phase transition") {
            State::Established(session) => Ok(session.sender()),
            State::Closing(_) | State::Closed => Err(super::closing()),
        }
    }

    /// Retains input beside a borrowed capacity or committed-receipt wait.
    pub(super) async fn progress<T: Send>(
        &mut self,
        progress: impl Future<Output = T> + Send,
    ) -> io::Result<T> {
        if let Some(error) = &self.input_failure {
            return Err(repeat(error));
        }
        let incoming = futures::stream::unfold(
            self.state.as_mut().expect("retained session"),
            |state| async move { Some((read(state).await, state)) },
        );
        match self
            .inbox
            .send(async { Ok(progress.await) }, incoming)
            .await
        {
            Ok(result) => Ok(result),
            Err(error) => {
                let error = Arc::new(error);
                let result = repeat(&error);
                self.input_failure = Some(error);
                Err(result)
            }
        }
    }

    /// Failed input cannot prevent settlement of the original committed command.
    pub(super) async fn settle<T: Send>(
        &mut self,
        progress: impl Future<Output = T> + Send,
    ) -> io::Result<T> {
        if self.input_failure.is_some() {
            Ok(progress.await)
        } else {
            self.progress(progress).await
        }
    }

    pub(super) async fn send_until(
        &mut self,
        data: Bytes,
        deadline: Option<Instant>,
    ) -> io::Result<()> {
        check_deadline(deadline)?;
        let sender = self.sender()?;
        let send = async move {
            let permit = sender
                .reserve_send(data.len())
                .await
                .map_err(io::Error::other)?;
            check_deadline(deadline)?;
            super::SendPermit::RakNet(permit).commit(data)?.await
        };
        let result = match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline.into(), self.progress(send))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "RakNet send expired"))??,
            None => self.progress(send).await?,
        };
        check_deadline(deadline)?;
        result
    }

    pub(super) async fn recv(&mut self) -> io::Result<Bytes> {
        if let Some(message) = self.inbox.pop() {
            return Ok(message);
        }
        if let Some(error) = &self.input_failure {
            if !self.input_terminal_seen {
                self.input_terminal_seen = true;
                return Err(repeat(error));
            }
            return Err(super::closing());
        }
        read(self.state.as_mut().expect("retained session")).await
    }

    /// Consumes established send capability before any cancellable drain.
    pub(super) fn close(&mut self) {
        self.state = Some(
            match self.state.take().expect("synchronous phase transition") {
                State::Established(session) => match session.close() {
                    Ok(session) => State::Closing(session),
                    Err(error) => {
                        let (session, cause) = error.into_parts();
                        self.close_failure = Some(Arc::new(io::Error::other(cause)));
                        State::Closing(session)
                    }
                },
                state => state,
            },
        );
    }

    /// Drains the same receive prefix and requires its original terminal owner.
    pub(super) async fn finish_close(&mut self) -> io::Result<()> {
        self.close();
        while self.inbox.pop().is_some() {}
        if let State::Closing(session) = self.state.as_mut().expect("retained retirement") {
            loop {
                match session.recv::<Box<[u8]>>().await {
                    Ok(_) => {}
                    Err(RakSessionError::Closed) => break,
                    Err(error) => return Err(io::Error::other(error)),
                }
            }
        }
        if let State::Closing(session) = self.state.take().expect("retained retirement") {
            match session.finish() {
                Ok(_) => self.state = Some(State::Closed),
                Err(session) => {
                    self.state = Some(State::Closing(session));
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "RakNet terminal owner is still pending",
                    ));
                }
            }
        } else {
            self.state = Some(State::Closed);
        }
        self.close_failure
            .as_ref()
            .map_or(Ok(()), |error| Err(repeat(error)))
    }
}

/// Reads the same original receiver in either locally sendable or closing phase.
async fn read(state: &mut State) -> io::Result<Bytes> {
    let bytes = match state {
        State::Established(session) => session.recv::<Box<[u8]>>().await,
        State::Closing(session) => session.recv::<Box<[u8]>>().await,
        State::Closed => return Err(super::closing()),
    };
    bytes.map(Bytes::from).map_err(io::Error::other)
}

fn repeat(error: &Arc<io::Error>) -> io::Error {
    io::Error::new(error.kind(), Arc::clone(error))
}

/// Uses the adapter clock before admission and after any late ready completion.
fn check_deadline(deadline: Option<Instant>) -> io::Result<()> {
    if deadline.is_some_and(|deadline| tokio::time::Instant::now().into_std() >= deadline) {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "RakNet send expired",
        ))
    } else {
        Ok(())
    }
}
