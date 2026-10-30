// SPDX-License-Identifier: MIT

//! Accepted transports share local capacity, commit and receipt semantics.

use bytes::Bytes;
use futures::future::BoxFuture;
use std::io;

pub(crate) struct SendPermit(pub(super) nethernet_tokio::SendPermit);

impl SendPermit {
    /// Commits exactly once without yielding; the receipt grants no peer-delivery claim.
    pub(crate) fn commit(self, message: Bytes) -> io::Result<BoxFuture<'static, io::Result<()>>> {
        let receipt = self
            .0
            .commit(nethernet_tokio::session::Channel::Reliable, message)
            .map_err(io::Error::other)?;
        Ok(Box::pin(async move {
            receipt.acknowledged().await.map_err(io::Error::other)
        }))
    }
}
