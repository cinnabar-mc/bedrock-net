//! The service socket and the retained transport admission share one progress owner.

use super::{Error, SocketStep};
use nethernet_tokio::CallerSignalingError;
use std::future::Future;

/// Ready service actions; pending state remains in the two existing owners.
pub(super) struct Progress {
    pub(super) socket: Option<Result<SocketStep, Error>>,
    pub(super) admitted: Option<Result<(), CallerSignalingError>>,
}

/// Drives service I/O and the original retained delivery without rebuilding either owner.
pub(super) async fn step(
    socket: impl Future<Output = Result<SocketStep, Error>>,
    admission: impl Future<Output = Result<(), CallerSignalingError>>,
) -> Progress {
    tokio::select! {
        biased;
        event = socket => Progress { socket: Some(event), admitted: None },
        admitted = admission => Progress { socket: None, admitted: Some(admitted) },
    }
}
