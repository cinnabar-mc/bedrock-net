//! Correlation between two existing bounded signaling owners.

use super::Error;
use bedrock_services::signaling::{Event, RequestId, websocket::MessagingSocket};
use futures::future::{pending, select_all};
use nethernet_tokio::{CallerSignalingDriver, CallerSignalingError, SignalDelivery, SignalRequest};
use std::{
    collections::HashMap,
    future::{Future, poll_fn},
    task::Poll,
    time::Instant,
};
use uuid::Uuid;

pub(super) struct Driver {
    socket: MessagingSocket,
    caller: CallerSignalingDriver,
    peer: Uuid,
    pending: HashMap<RequestId, SignalRequest>,
    terminal: Option<Error>,
}

impl Driver {
    /// Moves both bounded owners into a single caller-polled service driver.
    pub(super) fn new(socket: MessagingSocket, caller: CallerSignalingDriver, peer: Uuid) -> Self {
        Self {
            socket,
            caller,
            peer,
            pending: HashMap::new(),
            terminal: None,
        }
    }

    /// Retires the exact socket and its correlated waits without a detached cleanup task.
    pub(super) fn close(&mut self) {
        self.terminal.get_or_insert(Error::Closed);
        self.caller.close();
        self.socket.abort();
        self.pending.clear();
    }

    /// Polls service I/O beside a transport operation without spawning another task.
    pub(super) async fn run<F: Future>(&mut self, operation: F) -> Result<F::Output, Error> {
        if let Some(error) = self.terminal {
            return Err(error);
        }
        tokio::pin!(operation);
        let mut steps = 0;
        loop {
            enum Step<T> {
                Output(T),
                Progress,
                Error(Error),
            }
            let step = {
                let advance = self.advance();
                tokio::pin!(advance);
                poll_fn(|cx| {
                    // Poll both owners even if application data stays continuously ready.
                    let service = advance.as_mut().poll(cx);
                    let application = operation.as_mut().poll(cx);
                    match service {
                        Poll::Ready(Err(error)) => Poll::Ready(Step::Error(error)),
                        Poll::Ready(Ok(())) => match application {
                            Poll::Ready(value) => Poll::Ready(Step::Output(value)),
                            Poll::Pending => Poll::Ready(Step::Progress),
                        },
                        Poll::Pending => application.map(Step::Output),
                    }
                })
                .await
            };
            match step {
                Step::Output(value) => return Ok(value),
                Step::Error(error) => {
                    self.terminal = Some(error);
                    self.close();
                    return Err(error);
                }
                Step::Progress => {
                    steps += 1;
                    if steps == bedrock_services::signaling::MAX_BATCH_MESSAGES {
                        tokio::task::yield_now().await;
                        steps = 0;
                    }
                }
            }
        }
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
        enum Step {
            Outgoing(Option<SignalRequest>),
            Incoming(Result<Event, bedrock_services::signaling::websocket::SocketError>),
            Cancelled,
        }
        let step = tokio::select! {
            request = self.caller.recv() => Step::Outgoing(request),
            event = self.socket.drive() => Step::Incoming(event),
            _ = async {
                if self.pending.is_empty() { pending::<()>().await; }
                let waits: Vec<_> = self.pending.values_mut()
                    .map(|request| Box::pin(request.cancelled())).collect();
                select_all(waits).await;
            } => Step::Cancelled,
        };
        match step {
            Step::Cancelled => Ok(()),
            Step::Outgoing(None) => Err(Error::Closed),
            Step::Outgoing(Some(request)) => {
                if request.is_cancelled() {
                    return Ok(());
                }
                // CallerSignaling's permit remains held in this map until completion.
                let wire = zeroize::Zeroizing::new(request.signal().to_string());
                let result = self.socket.send_signal(
                    self.peer,
                    Uuid::new_v4(),
                    &wire,
                    request.requires_peer_receipt(),
                    request.deadline(),
                );
                match result {
                    Ok(id) => {
                        self.pending.insert(id, request);
                        Ok(())
                    }
                    Err(_) => {
                        request.finish(Err(CallerSignalingError::Rejected));
                        Err(Error::Admission)
                    }
                }
            }
            Step::Incoming(Err(error)) => Err(Error::Messaging(error)),
            Step::Incoming(Ok(Event::Completed { request, result })) => {
                if let Some(wait) = self.pending.remove(&request) {
                    complete(wait, result);
                }
                Ok(())
            }
            Step::Incoming(Ok(Event::Signal(signal))) => {
                if admit(&self.caller, &signal)? {
                    // The JSON-RPC owner's receipt is sent only after the transport queue accepted it.
                    let deadline = Instant::now()
                        .checked_add(std::time::Duration::from_secs(5))
                        .ok_or(Error::Configuration)?;
                    self.socket
                        .acknowledge(&signal, Uuid::new_v4(), deadline)
                        .map_err(|_| Error::Admission)?;
                }
                Ok(())
            }
            Step::Incoming(Ok(_)) => Ok(()),
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

/// Uses the authenticated envelope sender; advertised NetherNet IDs never select a peer.
fn admit(
    caller: &CallerSignalingDriver,
    signal: &bedrock_services::signaling::ReceivedSignal,
) -> Result<bool, Error> {
    match caller.try_deliver(&signal.sender().to_string(), signal.signal()) {
        Ok(()) => Ok(true),
        Err(CallerSignalingError::RouteMismatch | CallerSignalingError::InvalidSignal) => Ok(false),
        Err(_) => Err(Error::Signaling),
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests;
