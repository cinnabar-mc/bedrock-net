//! One explicit fresh TURN request on the original accepting service driver.

use super::{Driver, Error};
use bedrock_services::signaling::{Failure, RequestId, TurnCredentials};
use std::{sync::Arc, time::Instant};

/// Opaque receipt for one refresh on the exact server that admitted it.
/// It retains no server, socket, account or credential owner.
#[must_use = "finish or explicitly cancel this original refresh, or close its server"]
pub struct TurnRefresh(Arc<()>);

pub(super) struct Refresh {
    pub(super) receipt: TurnRefresh,
    pub(super) request: RequestId,
    pub(super) deadline: Instant,
    pub(super) result: Option<Result<TurnCredentials, Error>>,
}

impl Refresh {
    /// Creates one identity shared only by this retained request and its caller's receipt.
    fn new(request: RequestId, deadline: Instant) -> (Self, TurnRefresh) {
        let identity = Arc::new(());
        let receipt = TurnRefresh(Arc::clone(&identity));
        (
            Self {
                receipt: TurnRefresh(identity),
                request,
                deadline,
                result: None,
            },
            receipt,
        )
    }

    /// Equal numeric SDK IDs from another socket do not identify this actual request.
    fn matches(&self, receipt: &TurnRefresh) -> bool {
        Arc::ptr_eq(&self.receipt.0, &receipt.0)
    }
}

impl Driver {
    /// Releases only the exact original refresh, including a completed credential result.
    pub(in crate::messaging) fn cancel_turn_refresh(
        &mut self,
        receipt: &TurnRefresh,
    ) -> Result<(), Error> {
        let request = self
            .refresh
            .as_ref()
            .filter(|refresh| refresh.matches(receipt))
            .ok_or(Error::Admission)?
            .request;
        self.socket.retire_credentials(request);
        self.refresh = None;
        Ok(())
    }

    /// Admits one genuine JSON-RPC TURN request without polling or replacing an earlier receipt.
    pub(in crate::messaging) fn begin_turn_refresh(
        &mut self,
        deadline: Instant,
    ) -> Result<TurnRefresh, Error> {
        if let Some(error) = self.terminal {
            return Err(error);
        }
        if self.refresh.is_some() || self.socket.legacy_network_id().is_some() {
            return Err(Error::Admission);
        }
        if Instant::now() >= deadline {
            return Err(Error::TimedOut);
        }
        let request = self
            .socket
            .request_credentials(deadline)
            .map_err(|_| Error::Admission)?;
        let (refresh, receipt) = Refresh::new(request, deadline);
        self.refresh = Some(refresh);
        Ok(receipt)
    }

    /// Resumes the same request while the existing driver advances signaling and control traffic.
    pub(in crate::messaging) async fn finish_turn_refresh(
        &mut self,
        receipt: &TurnRefresh,
    ) -> Result<TurnCredentials, Error> {
        if !self
            .refresh
            .as_ref()
            .is_some_and(|refresh| refresh.matches(receipt))
        {
            return Err(Error::Admission);
        }
        let mut steps = 0;
        loop {
            if let Some(error) = self.terminal {
                self.refresh = None;
                return Err(error);
            }
            let refresh = self.refresh.as_ref().expect("original refresh retained");
            if !refresh.result.as_ref().is_some_and(Result::is_err)
                && Instant::now() >= refresh.deadline
            {
                self.socket.cancel(refresh.request);
                self.refresh = None;
                return Err(Error::TimedOut);
            }
            if let Some(result) = self
                .refresh
                .as_mut()
                .and_then(|refresh| refresh.result.take())
            {
                self.refresh = None;
                let credentials = result?;
                return credentials
                    .valid(Instant::now())
                    .then_some(credentials)
                    .ok_or(Error::Ice);
            }
            if let Err(error) = self.advance().await {
                self.terminal = Some(error);
                self.close();
            }
            steps += 1;
            if steps == bedrock_services::signaling::MAX_BATCH_MESSAGES {
                tokio::task::yield_now().await;
                steps = 0;
            }
        }
    }
}

/// Converts only a correlated TURN result; unrelated service requests retain their own mappings.
pub(super) fn failure(failure: Failure) -> Error {
    match failure {
        Failure::TimedOut => Error::TimedOut,
        _ => Error::Ice,
    }
}

#[cfg(test)]
mod tests;
