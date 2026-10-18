//! Optional, caller-polled Player Messaging to NetherNet runtime composition.
//!
//! Authentication and upgrade acquisition stay with the application's selected
//! account. This owner starts no tasks or runtime. It drives the existing SDK
//! socket alongside the existing NetherNet client and retains both through play.
//! Dropping it retires its service socket, pending signaling and transport handles.

mod driver;

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
            || Instant::now() >= deadline
        {
            return Err(Error::Configuration);
        }
        let cancellation = config.cancel_token.clone();
        let connecting = tokio::time::timeout_at(deadline.into(), async {
            let ice = acquire_ice(&mut socket, &config, deadline).await?;
            config.client_ice = Some(ice);
            config.attempts = 1;
            let (caller, caller_driver) = CallerSignaling::new(
                local_network_id.to_string(),
                peer.to_string(),
                CallerSignalingConfig::default(),
            )
            .map_err(|_| Error::Configuration)?;
            let mut driver = Driver::new(socket, caller_driver, peer);
            let client = driver
                .run(NetherClient::connect_with(caller, peer.to_string(), config))
                .await?
                .map_err(|_| Error::Transport)?;
            Ok(Self { client, driver })
        });
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(Error::Closed),
            result = connecting => result.map_err(|_| Error::TimedOut)?,
        }
    }

    /// Clones the existing transport handle; receive calls must continue driving this owner.
    pub fn session(&self) -> Session {
        self.client.session()
    }

    /// Receives reliable data while service heartbeats, receipts and late ICE signals progress.
    /// Cancellation preserves the SDK socket's partial frame and the transport's queued data.
    pub async fn recv(&mut self) -> Result<Option<Bytes>, Error> {
        let result = self
            .driver
            .run(self.client.recv())
            .await
            .and_then(|result| result.map_err(|_| Error::Transport));
        if !matches!(&result, Ok(Some(_))) {
            self.driver.close();
            let _ = self.client.close().await;
        }
        result
    }

    /// Closes the transport; dropping this owner also retires its messaging socket immediately.
    pub async fn close(&mut self) -> Result<(), Error> {
        self.driver.close();
        self.client.close().await.map_err(|_| Error::Transport)
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
        {
            if completed == request {
                result.map_err(|failure| match failure {
                    Failure::TimedOut => Error::TimedOut,
                    _ => Error::Ice,
                })?;
                break;
            }
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
