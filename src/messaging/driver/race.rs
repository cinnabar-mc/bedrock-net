//! The service socket and the retained transport admission share one progress owner.

use super::{Error, SocketStep};
use nethernet_tokio::CallerSignalingError;
use std::{
    future::{Future, poll_fn},
    task::Poll,
};

/// Ready service actions; pending state remains in the two existing owners.
pub(super) struct Progress {
    pub(super) socket: Option<Result<SocketStep, Error>>,
    pub(super) admitted: Option<Result<(), CallerSignalingError>>,
}

/// Polls both owners on each turn, retaining both ready results.
/// A failed admission stops before further socket work; successful handoff survives a simultaneous close.
pub(super) async fn step(
    socket: impl Future<Output = Result<SocketStep, Error>>,
    admission: impl Future<Output = Result<(), CallerSignalingError>>,
) -> Progress {
    tokio::pin!(socket, admission);
    poll_fn(|cx| {
        let admitted = match admission.as_mut().poll(cx) {
            Poll::Ready(result) => Some(result),
            Poll::Pending => None,
        };
        if admitted.as_ref().is_some_and(Result::is_err) {
            return Poll::Ready(Progress {
                socket: None,
                admitted,
            });
        }
        let socket = match socket.as_mut().poll(cx) {
            Poll::Ready(result) => Some(result),
            Poll::Pending => None,
        };
        if admitted.is_some() || socket.is_some() {
            Poll::Ready(Progress { socket, admitted })
        } else {
            Poll::Pending
        }
    })
    .await
}
