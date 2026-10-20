// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Parallel RakNet setup over caller-resolved alternatives.

use crate::transport::Transport;
use bedrock_net::raknet::{RakNetConnection, RakNetOptions};
use std::{io, net::SocketAddr};
use tokio::time::Instant;

/// Connects one real alternative under the first cutoff, dropping every losing socket.
/// DNS/route selection and MTU/congestion policy remain caller-owned.
pub async fn connect_resolved(
    addresses: impl Iterator<Item = SocketAddr>,
    options: RakNetOptions,
    deadline: Instant,
) -> io::Result<Transport> {
    super::resolved(addresses, false, deadline, |address| {
        let mut options = options.clone();
        async move {
            options.connect_timeout = options
                .connect_timeout
                .min(deadline.saturating_duration_since(Instant::now()));
            RakNetConnection::connect(address, options)
                .await
                .map(Transport::from_raknet)
                .map_err(io::Error::other)
        }
    })
    .await
}
