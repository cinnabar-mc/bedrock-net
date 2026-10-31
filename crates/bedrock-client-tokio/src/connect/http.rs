// SPDX-License-Identifier: MIT

//! One association using the caller's prepared HTTP signaling and actual trust/proof.

use nethernet_tokio::{ConnectionConfig, HttpSignaling, NetherClient};
use std::{io, time::Instant};

/// Keeps caller HTTP/TLS/egress policy and identity/trust unchanged through original setup.
/// The actual Ready client is returned for caller-owned first-use key approval before adoption.
pub async fn connect(
    signaling: HttpSignaling,
    endpoint: String,
    mut config: ConnectionConfig,
    deadline: tokio::time::Instant,
    credential_expires: Option<Instant>,
) -> io::Result<NetherClient> {
    let cancellation = config.cancel_token.clone();
    if cancellation.is_cancelled() {
        return Err(super::transport_error(
            nethernet_tokio::NetherError::Cancelled,
        ));
    }
    let deadline = credential_expires.map_or(deadline, |expires| deadline.min(expires.into()));
    super::check(deadline, credential_expires)?;
    config.timeouts.negotiation = config
        .timeouts
        .negotiation
        .min(deadline.saturating_duration_since(tokio::time::Instant::now()));
    let result = super::before_deadline(deadline, async {
        NetherClient::connect_with(signaling, endpoint, config)
            .await
            .map_err(super::transport_error)
    })
    .await;
    if cancellation.is_cancelled() {
        return Err(super::transport_error(
            nethernet_tokio::NetherError::Cancelled,
        ));
    }
    super::check(deadline, credential_expires)?;
    result
}
