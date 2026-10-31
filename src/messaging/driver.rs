//! Correlation between two existing bounded signaling owners.

use super::incoming::Batch;
use super::socket::{Outgoing, SocketStep, socket_step};
use super::{Error, Recipient, caller::Caller};
use bedrock_services::signaling::{Event, RequestId, websocket::MessagingSocket};
use futures::future::{BoxFuture, pending, select_all};
use nethernet_tokio::{
    CallerServerSignalingDriver, CallerSignalingDriver, CallerSignalingError, SignalDelivery,
    SignalRequest,
};
use std::{
    collections::HashMap,
    future::{Future, poll_fn},
    task::Poll,
    time::{Duration, Instant},
};
use uuid::Uuid;

mod race;
mod refresh;
use refresh::Refresh;
pub use refresh::TurnRefresh;

pub(super) struct Driver {
    socket: MessagingSocket,
    caller: Caller,
    peer: Option<Recipient>,
    pending: HashMap<RequestId, SignalRequest>,
    terminal: Option<Error>,
    refresh: Option<Refresh>,
    incoming: Batch,
    admission_timeout: Duration,
    outgoing: Option<Outgoing>,
    attempt_deadline: Option<Instant>,
    cancellation: Option<BoxFuture<'static, ()>>,
}

impl Driver {
    /// Moves both bounded owners into a single caller-polled service driver.
    pub(super) fn new(
        socket: MessagingSocket,
        caller: CallerSignalingDriver,
        peer: Recipient,
        admission_timeout: Duration,
        attempt_deadline: Instant,
    ) -> Self {
        Self::with_caller(
            socket,
            Caller::Client(caller),
            Some(peer),
            admission_timeout,
            Some(attempt_deadline),
            None,
        )
    }

    /// Uses the same bounded service engine for unsolicited accepting routes.
    pub(super) fn server(
        socket: MessagingSocket,
        caller: CallerServerSignalingDriver,
        admission_timeout: Duration,
        cancellation: impl Future<Output = ()> + Send + 'static,
    ) -> Self {
        Self::with_caller(
            socket,
            Caller::Server(caller),
            None,
            admission_timeout,
            None,
            Some(Box::pin(cancellation)),
        )
    }

    /// Captures a concrete route direction without changing queue, request or timer ownership.
    fn with_caller(
        socket: MessagingSocket,
        caller: Caller,
        peer: Option<Recipient>,
        admission_timeout: Duration,
        attempt_deadline: Option<Instant>,
        cancellation: Option<BoxFuture<'static, ()>>,
    ) -> Self {
        Self {
            socket,
            caller,
            peer,
            pending: HashMap::new(),
            terminal: None,
            refresh: None,
            incoming: Batch::default(),
            admission_timeout,
            outgoing: None,
            attempt_deadline,
            cancellation,
        }
    }

    /// Retires the exact socket and its correlated waits without a detached cleanup task.
    /// Only refresh correlation survives, so its original terminal error remains observable.
    pub(super) fn close(&mut self) {
        self.terminal.get_or_insert(Error::Closed);
        self.caller.close();
        self.socket.abort();
        self.pending.clear();
        self.incoming.clear();
        self.outgoing = None;
        self.cancellation = None;
        if let Some(refresh) = &mut self.refresh {
            refresh.result = None;
        }
    }

    /// Seals original routes while retaining the same socket's bounded close handshake.
    pub(super) fn begin_close(&mut self) {
        self.terminal.get_or_insert(Error::Closed);
        self.caller.close();
        self.socket.close();
        self.pending.clear();
        self.incoming.clear();
        self.outgoing = None;
        self.cancellation = None;
        self.refresh = None;
    }

    /// Drains the original socket and its completions; cancellation retains its close cutoff.
    pub(super) async fn finish_close(&mut self) -> Result<(), Error> {
        let result = loop {
            match self.socket.drive().await {
                Ok(_) => {}
                Err(bedrock_services::signaling::websocket::SocketError::Closed) => break Ok(()),
                Err(error) => break Err(Error::Messaging(error)),
            }
        };
        match &self.terminal {
            Some(error) if !matches!(error, Error::Closed) => Err(error.clone()),
            _ => result,
        }
    }

    /// Ends only the setup deadline; already retained envelope deadlines never restart.
    pub(super) fn established(&mut self) {
        self.attempt_deadline = None;
    }

    /// Returns the first service failure without replacing it with local cleanup closure.
    pub(super) fn failure(&self) -> Option<Error> {
        self.terminal.clone()
    }

    /// Polls service I/O beside a transport operation without spawning another task.
    pub(super) async fn run<F: Future>(&mut self, operation: F) -> Result<F::Output, Error> {
        if let Some(error) = self.terminal.clone() {
            return Err(error);
        }
        tokio::pin!(operation);
        let mut output = None;
        poll_fn(|cx| {
            for _ in 0..bedrock_services::signaling::MAX_BATCH_MESSAGES {
                let service = {
                    let advance = self.advance();
                    tokio::pin!(advance);
                    advance.as_mut().poll(cx)
                };
                if output.is_none()
                    && let Poll::Ready(value) = operation.as_mut().poll(cx)
                {
                    output = Some(value);
                }
                match service {
                    Poll::Ready(Err(error)) => {
                        self.terminal = Some(error.clone());
                        self.close();
                        return Poll::Ready(output.take().ok_or(error));
                    }
                    Poll::Ready(Ok(())) => {}
                    Poll::Pending => {
                        return output
                            .take()
                            .map_or(Poll::Pending, |value| Poll::Ready(Ok(value)));
                    }
                }
            }
            // Drain ready service transitions before returning data, with a finite per-poll budget.
            match output.take() {
                Some(value) => Poll::Ready(Ok(value)),
                None => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        })
        .await
    }

    /// Cancels abandoned operations before driving bytes; a written send is never retried.
    async fn advance(&mut self) -> Result<(), Error> {
        let cancelled: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, request)| request.is_cancelled())
            .map(|(id, _)| *id)
            .collect();
        for id in cancelled {
            self.socket.cancel(id);
            self.pending.remove(&id);
        }
        if self
            .outgoing
            .as_ref()
            .is_some_and(|outgoing| outgoing.request.is_cancelled())
        {
            self.outgoing = None;
        }
        enum Step {
            Outgoing(Option<SignalRequest>),
            Service(race::Progress),
            AdmissionTimeout,
            Cancelled,
            Stopped,
        }
        let step = {
            let front = self.incoming.front_mut();
            let outgoing_deadline = self
                .outgoing
                .as_ref()
                .map(|outgoing| outgoing.request.deadline());
            let has_outgoing = self.outgoing.is_some();
            let (receipt, waiting, deadline) = match front {
                Some(front) => {
                    let receipt = if front.waiting.is_none() {
                        Some((&front.signal, front.receipt, front.deadline))
                    } else {
                        None
                    };
                    (
                        receipt,
                        Some(&mut front.waiting),
                        Some(
                            outgoing_deadline
                                .map_or(front.deadline, |deadline| deadline.min(front.deadline)),
                        ),
                    )
                }
                None => (None, None, outgoing_deadline),
            };
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(Error::TimedOut);
            }
            let progress = async {
                tokio::select! {
                    biased;
                    request = async {
                        if has_outgoing { pending().await } else { self.caller.recv().await }
                    } => Step::Outgoing(request),

                    progress = race::step(
                        socket_step(&mut self.socket, receipt, self.outgoing.as_mut()),
                        async {
                            match waiting {
                                Some(Some(wait)) => wait.await,
                                _ => pending().await,
                            }
                        }
                    ) => Step::Service(progress),
                    _ = async {
                        if self.pending.is_empty() { pending::<()>().await; }
                        let waits: Vec<_> = self.pending.values_mut()
                            .map(|request| Box::pin(request.cancelled())).collect();
                        select_all(waits).await;
                    } => Step::Cancelled,
                    _ = async {
                        match deadline { Some(deadline) => tokio::time::sleep_until(deadline.into()).await, None => pending().await }
                    } => Step::AdmissionTimeout,
                }
            };
            tokio::pin!(progress);
            tokio::select! { biased;
                _ = async {
                    match &mut self.cancellation {
                        Some(cancellation) => cancellation.await,
                        None => pending().await,
                    }
                } => Step::Stopped,
                step = &mut progress => step,
            }
        };
        match step {
            Step::Stopped => Err(Error::Closed),
            Step::Cancelled => Ok(()),
            Step::Outgoing(None) => Err(Error::Closed),
            Step::Outgoing(Some(request)) => {
                if request.is_cancelled() {
                    return Ok(());
                }
                let peer = match &self.peer {
                    Some(peer) => peer.clone(),
                    None => {
                        let peer = Uuid::parse_str(&request.signal().network_id)
                            .map_err(|_| Error::Signaling)?;
                        if peer.is_nil() {
                            return Err(Error::Signaling);
                        }
                        Recipient::Messaging(peer)
                    }
                };
                self.outgoing = Some(Outgoing::new(request, peer));
                let progress = socket_step(&mut self.socket, None, self.outgoing.as_mut()).await;
                self.socket_progress(progress)
            }
            Step::Service(progress) => {
                match progress.admitted {
                    Some(Ok(())) => self.incoming.admitted(),
                    Some(Err(CallerSignalingError::RouteMismatch))
                        if matches!(&self.caller, Caller::Server(_)) =>
                    {
                        self.incoming.discard();
                    }
                    Some(Err(CallerSignalingError::TimedOut)) => return Err(Error::TimedOut),
                    Some(Err(CallerSignalingError::Closed)) => return Err(Error::Closed),
                    Some(Err(_)) => return Err(Error::Signaling),
                    None => {}
                }
                progress
                    .socket
                    .map_or(Ok(()), |event| self.socket_progress(event))
            }
            Step::AdmissionTimeout => Err(Error::TimedOut),
        }
    }

    /// Caps either dialect's retained incoming handoff at the same original attempt cutoff.
    fn incoming_deadline(&self) -> Result<Instant, Error> {
        let deadline = Instant::now()
            .checked_add(self.admission_timeout)
            .ok_or(Error::Configuration)?;
        Ok(self
            .attempt_deadline
            .map_or(deadline, |attempt| attempt.min(deadline)))
    }

    /// Applies socket progress after recording any handoff completed in the same poll.
    fn socket_progress(&mut self, event: Result<SocketStep, Error>) -> Result<(), Error> {
        match event? {
            SocketStep::Acknowledged(event) => {
                self.incoming.acknowledged();
                event.map_or(Ok(()), |event| {
                    self.socket_progress(Ok(SocketStep::Event(event)))
                })
            }
            SocketStep::Outgoing(id, event) => {
                if let Some(outgoing) = self.outgoing.take() {
                    self.pending.insert(id, outgoing.request);
                }
                event.map_or(Ok(()), |event| {
                    self.socket_progress(Ok(SocketStep::Event(event)))
                })
            }
            SocketStep::OutgoingCancelled => {
                self.outgoing = None;
                Ok(())
            }
            SocketStep::Event(Err(error)) => Err(Error::Messaging(error)),
            SocketStep::Event(Ok(Event::Completed { request, result })) => {
                if let Some(refresh) = self.refresh.as_mut()
                    && refresh.request == request
                    && refresh.result.is_none()
                {
                    refresh.result = Some(
                        result
                            .map_err(refresh::failure)
                            .and_then(|()| self.socket.take_credentials().ok_or(Error::Ice)),
                    );
                    return Ok(());
                }
                if let Some(wait) = self.pending.remove(&request) {
                    complete(wait, result);
                }
                Ok(())
            }
            SocketStep::Event(Ok(Event::Signal(signal))) => {
                let deadline = self.incoming_deadline()?;
                self.caller.receive(&mut self.incoming, signal, deadline)
            }
            SocketStep::Event(Ok(_)) => Ok(()),
        }
    }
}

/// Maps completion only after the SDK's configured service/peer evidence has completed.
fn complete(wait: SignalRequest, result: Result<(), bedrock_services::signaling::Failure>) {
    let evidence = if wait.requires_peer_receipt() {
        SignalDelivery::PeerReceived
    } else {
        SignalDelivery::ServiceAccepted
    };
    wait.finish(
        result
            .map(|()| evidence)
            .map_err(|_| CallerSignalingError::Rejected),
    );
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod fairness_tests;
#[cfg(test)]
mod tests;
