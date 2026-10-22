// SPDX-License-Identifier: MIT

//! Concrete accepted transports share local capacity, commit and receipt semantics.

use bytes::Bytes;
use futures::future::BoxFuture;
use std::io;

pub(crate) enum SendPermit {
    #[cfg(feature = "raknet")]
    RakNet(raknet_tokio::prelude::SendPermit),
    #[cfg(feature = "nethernet")]
    NetherNet(nethernet_tokio::SendPermit),
}

impl SendPermit {
    /// Commits exactly once without yielding; the returned receipt grants no peer-delivery claim.
    pub(crate) fn commit(self, message: Bytes) -> io::Result<BoxFuture<'static, io::Result<()>>> {
        match self {
            #[cfg(feature = "raknet")]
            Self::RakNet(permit) => {
                use raknet_tokio::prelude::{RakPriority, RakReliability};
                let mut receipt = permit
                    .commit(
                        message.to_vec().into_boxed_slice(),
                        RakReliability::ReliableOrdered,
                        RakPriority::Immediate,
                    )
                    .map_err(io::Error::other)?;
                Ok(Box::pin(async move {
                    receipt.admitted().await.map_err(io::Error::other)
                }))
            }
            #[cfg(feature = "nethernet")]
            Self::NetherNet(permit) => {
                let receipt = permit
                    .commit(nethernet_tokio::session::Channel::Reliable, message)
                    .map_err(io::Error::other)?;
                Ok(Box::pin(async move {
                    receipt.acknowledged().await.map_err(io::Error::other)
                }))
            }
        }
    }
}
