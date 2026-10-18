//! Transactional SDK admission while its existing socket owner drives wire/control progress.

use super::Error;
use bedrock_services::signaling::{
    self, Event, ReceivedSignal, RequestId, websocket::MessagingSocket,
};
use nethernet_tokio::SignalRequest;
use std::{
    future::{Future, poll_fn},
    task::Poll,
    time::Instant,
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub(super) struct Outgoing {
    pub(super) request: SignalRequest,
    message: Uuid,
    wire: Zeroizing<String>,
}

impl Outgoing {
    /// Captures one existing bounded request without replacing its deadline or retrying written bytes.
    pub(super) fn new(request: SignalRequest) -> Self {
        let wire = Zeroizing::new(request.signal().to_string());
        Self {
            request,
            wire,
            message: Uuid::new_v4(),
        }
    }
}

pub(super) enum SocketStep {
    Event(Result<Event, signaling::websocket::SocketError>),
    Acknowledged,
    Outgoing(RequestId),
    OutgoingCancelled,
}

/// Retries only locally unadmitted sends/receipts while driving socket I/O and control frames.
/// Rebuilding the SDK drive wait preserves its owned partial write and incoming buffers.
pub(super) async fn socket_step(
    socket: &mut MessagingSocket,
    peer: Uuid,
    receipt: Option<(&ReceivedSignal, Uuid, Instant)>,
    mut outgoing: Option<&mut Outgoing>,
) -> Result<SocketStep, Error> {
    poll_fn(|cx| {
        if let Some(outgoing) = outgoing.as_deref_mut() {
            let cancelled = outgoing.request.cancelled();
            tokio::pin!(cancelled);
            if cancelled.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok(SocketStep::OutgoingCancelled));
            }
        }
        match admit(socket, peer, receipt, outgoing.as_deref_mut()) {
            Ok(Some(step)) => return Poll::Ready(Ok(step)),
            Err(error) => return Poll::Ready(Err(error)),
            Ok(None) => {}
        }
        let event = {
            let driving = socket.drive();
            tokio::pin!(driving);
            driving.as_mut().poll(cx)
        };
        if let Poll::Ready(event) = event {
            return Poll::Ready(Ok(SocketStep::Event(event)));
        }
        // A sink flush can free admission without producing any application event.
        match admit(socket, peer, receipt, outgoing.as_deref_mut()) {
            Ok(Some(step)) => Poll::Ready(Ok(step)),
            Err(error) => Poll::Ready(Err(error)),
            Ok(None) => Poll::Pending,
        }
    })
    .await
}

/// Keeps original IDs/deadlines across local capacity retries; written requests leave this owner once.
fn admit(
    socket: &mut MessagingSocket,
    peer: Uuid,
    receipt: Option<(&ReceivedSignal, Uuid, Instant)>,
    outgoing: Option<&mut Outgoing>,
) -> Result<Option<SocketStep>, Error> {
    if let Some((signal, message, deadline)) = receipt {
        if Instant::now() >= deadline {
            return Err(Error::TimedOut);
        }
        match socket.acknowledge(signal, message, deadline) {
            Ok(_) => return Ok(Some(SocketStep::Acknowledged)),
            Err(signaling::Error::Limit) => {}
            Err(_) => return Err(Error::Admission),
        }
    }
    if let Some(outgoing) = outgoing {
        if outgoing.request.is_cancelled() {
            return Ok(Some(SocketStep::OutgoingCancelled));
        }
        match socket.send_signal(
            peer,
            outgoing.message,
            &outgoing.wire,
            outgoing.request.requires_peer_receipt(),
            outgoing.request.deadline(),
        ) {
            Ok(id) => return Ok(Some(SocketStep::Outgoing(id))),
            Err(signaling::Error::Limit) => {}
            Err(_) => return Err(Error::Admission),
        }
    }
    Ok(None)
}
