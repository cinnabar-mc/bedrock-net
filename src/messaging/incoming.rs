//! One bounded service batch retained across transport admission and receipt capacity waits.

use super::Error;
use bedrock_services::signaling::{self, ReceivedSignal};
use futures::future::BoxFuture;
use nethernet_tokio::{CallerServerSignalingDriver, CallerSignalingDriver, CallerSignalingError};
use std::future::Future;
use std::{collections::VecDeque, time::Instant};
use uuid::Uuid;

/// Largest retained envelope count, derived from the SDK's nested callback batch bounds.
pub(super) const MAX_SIGNALS: usize = signaling::MAX_BATCH_MESSAGES * signaling::MAX_BATCH_MESSAGES;

pub(super) struct Incoming {
    pub(super) signal: ReceivedSignal,
    pub(super) receipt: Uuid,
    pub(super) deadline: Instant,
    pub(super) waiting: Option<BoxFuture<'static, Result<(), CallerSignalingError>>>,
    bytes: usize,
}

#[derive(Default)]
pub(super) struct Batch {
    queue: VecDeque<Incoming>,
    bytes: usize,
}

impl Batch {
    /// Validates through the existing route owner before retaining a bounded service envelope.
    pub(super) fn push(
        &mut self,
        caller: &CallerSignalingDriver,
        signal: ReceivedSignal,
        deadline: Instant,
    ) -> Result<(), Error> {
        let delivery =
            caller.prepare_delivery_before(&signal.sender().to_string(), signal.signal(), deadline);
        self.retain(signal, deadline, delivery)
    }

    /// Uses the same envelope budget with the accepting bridge's actual route reservation.
    pub(super) fn push_server(
        &mut self,
        caller: &CallerServerSignalingDriver,
        signal: ReceivedSignal,
        deadline: Instant,
    ) -> Result<(), Error> {
        let delivery =
            caller.prepare_delivery_before(&signal.sender().to_string(), signal.signal(), deadline);
        if matches!(delivery.as_ref(), Err(CallerSignalingError::Capacity)) {
            // An offer outside the accepting route limit cannot retire unrelated peers.
            return Ok(());
        }
        match self.retain(signal, deadline, delivery) {
            Err(Error::TimedOut) => Ok(()),
            result => result,
        }
    }

    /// Retains one prepared admission in the original bounded allocation, regardless of route direction.
    fn retain(
        &mut self,
        signal: ReceivedSignal,
        deadline: Instant,
        delivery: Result<
            impl Future<Output = Result<(), CallerSignalingError>> + Send + 'static,
            CallerSignalingError,
        >,
    ) -> Result<(), Error> {
        let delivery = match delivery {
            Ok(delivery) => delivery,
            Err(CallerSignalingError::RouteMismatch | CallerSignalingError::InvalidSignal) => {
                return Ok(());
            }
            Err(CallerSignalingError::TimedOut) => return Err(Error::TimedOut),
            Err(_) => return Err(Error::Signaling),
        };
        let bytes = signal
            .signal()
            .len()
            .checked_add(signal.network_id().len())
            .ok_or(Error::Capacity)?;
        if self.queue.len() >= MAX_SIGNALS
            || bytes > signaling::MAX_MESSAGE_BYTES.saturating_sub(self.bytes)
        {
            return Err(Error::Capacity);
        }
        if Instant::now() >= deadline {
            return Err(Error::TimedOut);
        }
        self.queue.push_back(Incoming {
            signal,
            receipt: Uuid::new_v4(),
            deadline,
            bytes,
            waiting: Some(Box::pin(delivery)),
        });
        self.bytes += bytes;
        Ok(())
    }

    /// Borrows the next envelope and its retained capacity future without restarting it.
    pub(super) fn front_mut(&mut self) -> Option<&mut Incoming> {
        self.queue.front_mut()
    }

    /// Records actual handoff before attempting a receipt; it can never deliver that signal again.
    pub(super) fn admitted(&mut self) {
        if let Some(front) = self.queue.front_mut() {
            front.waiting = None;
        }
    }

    /// Releases an envelope only after the SDK admitted its single receipt operation.
    pub(super) fn acknowledged(&mut self) {
        self.discard();
    }

    /// Releases the original front and its wire budget without creating delivery evidence.
    pub(super) fn discard(&mut self) {
        if let Some(front) = self.queue.pop_front() {
            self.bytes -= front.bytes;
        }
    }

    /// Drops held envelopes and capacity futures immediately on terminal cancellation.
    pub(super) fn clear(&mut self) {
        self.queue.clear();
        self.bytes = 0;
    }
}
