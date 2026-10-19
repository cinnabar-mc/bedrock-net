//! The existing concrete one-peer and accepting signaling owners, sharing one service driver.

use super::{Error, incoming::Batch};
use bedrock_services::signaling::ReceivedSignal;
use nethernet_tokio::{CallerServerSignalingDriver, CallerSignalingDriver, SignalRequest};
use std::time::Instant;

pub(super) enum Caller {
    Client(CallerSignalingDriver),
    Server(CallerServerSignalingDriver),
}

impl Caller {
    /// Receives one original transport request without introducing an intermediate queue.
    pub(super) async fn recv(&mut self) -> Option<SignalRequest> {
        match self {
            Self::Client(caller) => caller.recv().await,
            Self::Server(caller) => caller.recv().await,
        }
    }

    /// Reserves admission through the exact original route owner and retained envelope budget.
    pub(super) fn receive(
        &self,
        batch: &mut Batch,
        signal: ReceivedSignal,
        deadline: Instant,
    ) -> Result<(), Error> {
        match self {
            Self::Client(caller) => batch.push(caller, signal, deadline),
            Self::Server(caller) => batch.push_server(caller, signal, deadline),
        }
    }

    /// Retires all original routes and wakes outstanding transport requests.
    pub(super) fn close(&mut self) {
        match self {
            Self::Client(caller) => caller.close(),
            Self::Server(caller) => caller.close(),
        }
    }
}
