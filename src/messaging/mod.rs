//! Optional, caller-polled Player Messaging to NetherNet runtime composition.
//!
//! Authentication and upgrade acquisition stay with the application's selected
//! account. This owner starts no tasks or runtime. It drives the existing SDK
//! socket alongside the existing NetherNet client and retains both through play.
//! Dropping it retires its service socket, pending signaling and transport handles.

mod driver;
mod incoming;
mod socket;

use bedrock_services::signaling::{
    Event, Failure,
    websocket::{MessagingSocket, SocketError},
};
use bytes::Bytes;
use driver::Driver;
use nethernet_tokio::{
    CallerSignaling, CallerSignalingConfig, ClientIceConfig, ConnectionConfig, NetherClient,
    Session,
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Instant,
};
use uuid::Uuid;
use zeroize::Zeroize;

/// Redacted composition failures; no token, SDP, URL, identity or TURN credential is retained.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The target, bounds or signed transport policy was incomplete.
    #[error("invalid messaging transport configuration")]
    Configuration,
    /// The original caller deadline elapsed.
    #[error("messaging transport timed out")]
    TimedOut,
    /// A protected service socket failed with a redacted cause.
    #[error(transparent)]
    Messaging(#[from] SocketError),
    /// The SDK refused local request admission before bytes were written.
    #[error("messaging request admission failed")]
    Admission,
    /// A retained service batch exceeds the SDK's count or wire-byte ceiling.
    #[error("messaging retained input capacity exceeded")]
    Capacity,
    /// A bounded signaling route could not admit a message.
    #[error("messaging transport signaling failed")]
    Signaling,
    /// Service-provided ICE endpoints could not be admitted or resolved.
    #[error("messaging transport ICE configuration failed")]
    Ice,
    /// The existing NetherNet transport failed.
    #[error("messaging transport failed")]
    Transport,
    /// The service or transport owner closed.
    #[error("messaging transport closed")]
    Closed,
}

/// One signed NetherNet connection and the authenticated messaging socket that carries its signals.
/// It has no Debug implementation because the signaling owner retains sensitive SDP.
pub struct MessagingConnection {
    client: NetherClient,
    driver: Driver,
    receive: ReceiveState,
}

enum ReceiveState {
    Open,
    Draining(Option<Error>),
    Done,
}

/// A selected account's already protected socket and one explicit peer route.
/// No connection attempt begins until the caller supplies its signed SDP policy.
pub struct PreparedMessaging {
    socket: MessagingSocket,
    local_network_id: u64,
    peer: Uuid,
}

impl PreparedMessaging {
    /// Captures the exact network ID used at upgrade and rejects an absent peer identity.
    pub fn new(socket: MessagingSocket, local_network_id: u64, peer: Uuid) -> Result<Self, Error> {
        if peer.is_nil() {
            return Err(Error::Configuration);
        }
        Ok(Self {
            socket,
            local_network_id,
            peer,
        })
    }

    /// Returns the authenticated envelope route expected for this connection.
    pub fn peer(&self) -> Uuid {
        self.peer
    }

    /// Moves the protected socket into its sole connection owner.
    pub async fn connect(
        self,
        config: ConnectionConfig,
        deadline: Instant,
    ) -> Result<MessagingConnection, Error> {
        MessagingConnection::connect(
            self.socket,
            self.local_network_id,
            self.peer,
            config,
            deadline,
        )
        .await
    }
}

impl MessagingConnection {
    /// Connects once to an explicit peer using the same local network ID supplied at socket upgrade.
    ///
    /// Supply signed SDP identity and peer trust in `config`; unsigned answers are refused.
    /// The original deadline bounds TURN acquisition, DNS and connection establishment.
    /// TURN lifetimes are handed off unchanged. No automatic ambiguous retry occurs.
    pub async fn connect(
        mut socket: MessagingSocket,
        local_network_id: u64,
        peer: Uuid,
        mut config: ConnectionConfig,
        deadline: Instant,
    ) -> Result<Self, Error> {
        if peer.is_nil()
            || config.identity.is_none()
            || config.server_trust.is_none()
            || config.allow_unsigned_answers
        {
            return Err(Error::Configuration);
        }
        if tokio::time::Instant::now().into_std() >= deadline {
            return Err(Error::TimedOut);
        }
        let cancellation = config.cancel_token.clone();
        let connecting = tokio::time::timeout_at(deadline.into(), async {
            let ice = acquire_ice(&mut socket, &config, deadline).await?;
            config.client_ice = Some(ice);
            config.attempts = 1;
            let caller_config = CallerSignalingConfig::default();
            let (caller, caller_driver) = CallerSignaling::new(
                local_network_id.to_string(),
                peer.to_string(),
                caller_config,
            )
            .map_err(|_| Error::Configuration)?;
            let mut driver = Driver::new(
                socket,
                caller_driver,
                peer,
                caller_config.send_timeout,
                deadline,
            );
            let client = driver
                .run(NetherClient::connect_with(caller, peer.to_string(), config))
                .await?
                .map_err(|_| Error::Transport)?;
            if let Some(error) = driver.failure() {
                let _ = client.close().await;
                return Err(error);
            }
            admit_established_connection(deadline, async {
                driver.close();
                let _ = client.close().await;
            })
            .await?;
            driver.established();
            Ok(Self {
                client,
                driver,
                receive: ReceiveState::Open,
            })
        });
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(Error::Closed),
            result = connecting => result.map_err(|_| Error::TimedOut)?,
        }
    }

    /// Clones the existing transport handle; recv or maintain must continue driving this owner.
    pub fn session(&self) -> Session {
        self.client.session()
    }

    /// Drives service/control/signaling while application receive capacity is unavailable.
    /// This consumes no application data and starts no task. A service terminal is
    /// staged for recv to drain the existing accepted reliable FIFO before reporting it.
    /// It completes once after staging a service failure; later maintenance calls
    /// remain pending while recv owns terminal reporting.
    /// Canceling it preserves the socket and all retained signaling admission waits.
    pub async fn maintain(&mut self) {
        if !matches!(self.receive, ReceiveState::Open) {
            return std::future::pending().await;
        }
        if let Err(error) = self.driver.run(std::future::pending::<()>()).await {
            self.fail_service(error).await;
        }
    }

    /// Receives reliable data while service heartbeats, receipts and late ICE signals progress.
    /// Cancellation preserves the SDK socket's partial frame and the transport's queued data.
    pub async fn recv(&mut self) -> Result<Option<Bytes>, Error> {
        if matches!(self.receive, ReceiveState::Done) {
            return Ok(None);
        }
        if matches!(self.receive, ReceiveState::Draining(_)) {
            return self.drain().await;
        }
        let result = self.driver.run(self.client.recv()).await;
        let failure = match &result {
            Err(error) => Some(*error),
            Ok(_) => self.driver.failure(),
        };
        if let Some(failure) = failure {
            self.fail_service(failure).await;
            if let Ok(Ok(Some(message))) = result {
                return Ok(Some(message));
            }
            return self.drain().await;
        }
        let result = result?.map_err(|_| Error::Transport);
        if !matches!(&result, Ok(Some(_))) {
            self.receive = ReceiveState::Done;
            self.driver.close();
            let _ = self.client.close().await;
        }
        result
    }

    /// Closes the transport; dropping this owner also retires its messaging socket immediately.
    pub async fn close(&mut self) -> Result<(), Error> {
        if matches!(self.receive, ReceiveState::Open) {
            self.receive = ReceiveState::Draining(None);
        }
        self.driver.close();
        self.client.close().await.map_err(|_| Error::Transport)
    }

    /// Retires service and transport admission while retaining the already accepted receive prefix.
    async fn fail_service(&mut self, failure: Error) {
        self.receive = ReceiveState::Draining(Some(failure));
        self.driver.close();
        let _ = self.client.close().await;
    }

    /// Drains the transport's existing bounded accepted FIFO before publishing one service failure or EOF.
    async fn drain(&mut self) -> Result<Option<Bytes>, Error> {
        match self.client.recv().await {
            Ok(Some(message)) => Ok(Some(message)),
            result => {
                let state = std::mem::replace(&mut self.receive, ReceiveState::Done);
                match state {
                    ReceiveState::Draining(Some(error)) => Err(error),
                    _ => result.map_err(|_| Error::Transport),
                }
            }
        }
    }
}

/// Guards the final connection handoff, retiring both owned edges when its original deadline elapsed.
async fn admit_established_connection(
    deadline: Instant,
    close: impl std::future::Future<Output = ()>,
) -> Result<(), Error> {
    if tokio::time::Instant::now().into_std() >= deadline {
        close.await;
        Err(Error::TimedOut)
    } else {
        Ok(())
    }
}

/// Acquires the SDK's original credential lifetime before the peer can send an offer response.
async fn acquire_ice(
    socket: &mut MessagingSocket,
    config: &ConnectionConfig,
    deadline: Instant,
) -> Result<ClientIceConfig, Error> {
    let request = socket
        .request_credentials(deadline)
        .map_err(|_| Error::Admission)?;
    loop {
        if let Event::Completed {
            request: completed,
            result,
        } = socket.drive().await?
            && completed == request
        {
            result.map_err(|failure| match failure {
                Failure::TimedOut => Error::TimedOut,
                _ => Error::Ice,
            })?;
            break;
        }
    }
    let credentials = socket.credentials().ok_or(Error::Ice)?;
    if credentials.servers().len() > nethernet::session::MAX_ICE_SERVERS {
        return Err(Error::Ice);
    }
    let expires = credentials.expires_at();
    let servers = AcquiredServers(
        credentials
            .servers()
            .iter()
            .map(|server| nethernet_tokio::IceServer {
                username: server.username().to_owned(),
                password: server.password().to_owned(),
                urls: server.urls().to_vec(),
            })
            .collect(),
    );
    let mut ice = match &config.client_ice {
        Some(configured) => ClientIceConfig {
            ice: nethernet::session::IceConfig {
                servers: Vec::new(),
                gather_timeout: configured.ice.gather_timeout,
                policy: configured.ice.policy,
            },
            bind_addr: configured.bind_addr,
        },
        None => ClientIceConfig {
            ice: nethernet::session::IceConfig::default(),
            bind_addr: None,
        },
    };
    let resolution = nethernet_tokio::resolve_ice_servers(
        &servers.0,
        ice.bind_addr
            .unwrap_or(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
        expires,
        deadline,
    );
    tokio::pin!(resolution);
    ice.ice.servers = loop {
        tokio::select! {
            result = &mut resolution => break result.map_err(|_| Error::Ice)?,
            event = socket.drive() => { event?; },
        }
    };
    Ok(ice)
}

/// Erases temporary service credential copies after DNS, including cancellation/error paths.
struct AcquiredServers(Vec<nethernet_tokio::IceServer>);

impl Drop for AcquiredServers {
    fn drop(&mut self) {
        for server in &mut self.0 {
            server.username.zeroize();
            server.password.zeroize();
        }
    }
}

#[cfg(test)]
mod tests;
