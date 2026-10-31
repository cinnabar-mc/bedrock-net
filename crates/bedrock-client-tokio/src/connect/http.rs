// SPDX-License-Identifier: MIT

//! One association using the caller's prepared HTTP signaling and actual trust/proof.

use nethernet_tokio::signaling::http::{
    ClientInfo,
    probe::{HttpProbe, ProbeCache, ProbeError, ProbeSelection},
};
use nethernet_tokio::{ConnectionConfig, HttpSignaling, NetherClient};
use std::{io, time::Instant};

/// Caller-owned discovery, cache and HTTP policy shared by addressed joins.
#[derive(Clone)]
pub struct HttpDialer {
    probe: HttpProbe,
    local_id: String,
    client_info: Option<ClientInfo>,
    cache: Option<ProbeCache>,
}

impl HttpDialer {
    /// Uses the probe's same redirect-free client for signaling, preserving TLS and egress policy.
    pub fn new(probe: HttpProbe, local_id: String) -> Self {
        Self {
            probe,
            local_id,
            client_info: None,
            cache: None,
        }
    }

    /// Shares only the caller's cache for this same HTTP/TLS/egress policy.
    pub fn with_cache(mut self, cache: ProbeCache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Retains optional game metadata on the selected signaling owner.
    pub fn with_client_info(mut self, info: ClientInfo) -> Self {
        self.client_info = Some(info);
        self
    }

    /// Probes the addressed server and retains its exact choice through settings and Login.
    /// Port zero means omitted. Neither probe nor dial failure selects another transport.
    pub async fn connect(
        &self,
        host: &str,
        port: u16,
        config: ConnectionConfig,
        deadline: tokio::time::Instant,
        credential_expires: Option<Instant>,
    ) -> io::Result<AddressedConnection> {
        if config.cancel_token.is_cancelled() {
            return Err(super::transport_error(
                nethernet_tokio::NetherError::Cancelled,
            ));
        }
        let deadline = credential_expires.map_or(deadline, |expires| deadline.min(expires.into()));
        super::check(deadline, credential_expires)?;
        let selection = tokio::select! {
            biased;
            _ = config.cancel_token.cancelled() => return Err(super::transport_error(nethernet_tokio::NetherError::Cancelled)),
            selection = self.probe.select(host, port, self.cache.as_ref(), deadline) => selection,
        };
        let selection = match selection {
            Ok(selection) => selection,
            Err(error) => {
                super::check(deadline, credential_expires)?;
                return Err(probe_error(error));
            }
        };
        let attempt = HttpAttempt {
            selection,
            succeeded: false,
        };
        let mut signaling = self.probe.signaling(self.local_id.clone());
        if let Some(info) = &self.client_info {
            signaling = signaling.with_client_info(info.clone());
        }
        let client = connect(
            signaling,
            attempt.selection.endpoint().to_owned(),
            config,
            deadline,
            credential_expires,
        )
        .await?;
        Ok(AddressedConnection { client, attempt })
    }
}

/// The actual Ready client and its pending Bedrock Login receipt.
/// Dropping it before successful Login invalidates only its own cache entry.
pub struct AddressedConnection {
    client: NetherClient,
    attempt: HttpAttempt,
}

impl AddressedConnection {
    /// Borrows the actual association for caller-owned server key approval before adoption.
    pub fn client(&self) -> &NetherClient {
        &self.client
    }

    /// Returns the chosen Login URL with exactly one explicit port, including scheme defaults.
    pub fn login_address(&self) -> String {
        self.attempt.selection.login_address()
    }

    /// Moves the original association and failure receipt into the standard Bedrock adapter.
    pub fn into_transport(self) -> crate::transport::Transport {
        let mut transport = crate::transport::Transport::from_http(self.client);
        transport.http_attempt = Some(self.attempt);
        transport
    }
}

/// Holds one selected entry until the original settings/Login continuation succeeds.
pub(crate) struct HttpAttempt {
    selection: ProbeSelection,
    succeeded: bool,
}

impl HttpAttempt {
    /// Supplies selected metadata before signing without changing unrelated raw claims.
    pub(crate) fn login_claims(
        &self,
        claims: &serde_json::value::RawValue,
    ) -> io::Result<Box<serde_json::value::RawValue>> {
        let mut claims = bedrock_net::login::client_data::RawClientData::from_raw(claims)?;
        claims.insert("ServerAddress", self.selection.login_address().into())?;
        serde_json::value::to_raw_value(&claims).map_err(io::Error::other)
    }

    /// Keeps the selected entry only after the original Login continuation completed.
    pub(crate) fn complete(mut self) {
        self.succeeded = true;
    }
}

impl Drop for HttpAttempt {
    /// Failure or cancellation cannot leave a failed settings/Login choice cached.
    fn drop(&mut self) {
        if !self.succeeded {
            self.selection.forget();
        }
    }
}

/// Exposes an inspectable discovery cause with coarse ordinary formatting.
fn probe_error(error: ProbeError) -> io::Error {
    let kind = match &error {
        ProbeError::TimedOut => io::ErrorKind::TimedOut,
        ProbeError::Request(cause) if cause.is_timeout() => io::ErrorKind::TimedOut,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

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

#[cfg(test)]
mod tests;
