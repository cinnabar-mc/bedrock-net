//! Concrete probe transports and their connection proof-key ownership.

use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use bedrock_net::BatchHeader;
use bedrock_net::raknet::{RakNetConnection, RakNetOptions};
use bytes::Bytes;
use nethernet_tokio::{
    ConnectionConfig, HttpSignaling, LanConfig, LanSignaling, NetherClient, SelfSignedIdentity,
    TokenTrust,
};
use p384::ecdsa::SigningKey;
use p384::elliptic_curve::Generate;
use rand::rngs::SysRng;

use crate::{HANDSHAKE_TIMEOUT, OFFLINE_IDENTITY_LIFETIME};

const LAN_CONNECTION_TYPE: u8 = 4;

pub(super) enum Transport {
    RakNet {
        connection: RakNetConnection,
        key: Arc<SigningKey>,
    },
    NetherNetLan {
        connection: NetherClient,
        key: Arc<SigningKey>,
        nonce: String,
    },
    NetherNet {
        connection: NetherClient,
        key: Arc<SigningKey>,
    },
}

impl Transport {
    /// Establishes transport and retains the proof key used by its application Login.
    pub(super) async fn connect(kind: &str, address: SocketAddr) -> Result<Self, Box<dyn Error>> {
        match kind {
            "raknet" => {
                let key = Arc::new(
                    SigningKey::try_generate_from_rng(&mut SysRng).map_err(io::Error::other)?,
                );
                let connection =
                    RakNetConnection::connect(address, RakNetOptions::default()).await?;
                Ok(Self::RakNet { connection, key })
            }
            "nethernet-lan" => Self::connect_lan(address).await,
            "nethernet" => {
                let _ = rustls::crypto::ring::default_provider().install_default();
                let http = reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(HANDSHAKE_TIMEOUT)
                    .build()?;
                let signaling = HttpSignaling::with_client(rand::random::<u64>().to_string(), http);
                let key = Arc::new(
                    SigningKey::try_generate_from_rng(&mut SysRng).map_err(io::Error::other)?,
                );
                let identity = Arc::new(SelfSignedIdentity::from_key(
                    Arc::clone(&key),
                    SystemTime::now(),
                    OFFLINE_IDENTITY_LIFETIME,
                )?);
                let config = ConnectionConfig {
                    identity: Some(identity.clone()),
                    server_trust: Some(TokenTrust::Any),
                    attempts: 1,
                    ..ConnectionConfig::default()
                };
                let connection =
                    NetherClient::connect_with(signaling, format!("http://{address}"), config)
                        .await?;
                Ok(Self::NetherNet { connection, key })
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transport must be raknet, nethernet or nethernet-lan",
            )
            .into()),
        }
    }

    /// Discovers only the requested local fixture and honors its offline admission metadata.
    async fn connect_lan(address: SocketAddr) -> Result<Self, Box<dyn Error>> {
        if !address.ip().is_loopback() || !address.is_ipv4() || address.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the LAN probe requires an IPv4 loopback discovery endpoint",
            )
            .into());
        }
        let signaling = LanSignaling::with_config(
            rand::random(),
            SocketAddr::new(address.ip(), 0),
            LanConfig {
                broadcast_address: Some(address),
                ..LanConfig::default()
            },
        )
        .await?;
        let mut polls = tokio::time::interval(std::time::Duration::from_millis(50));
        let (id, data) = loop {
            polls.tick().await;
            let mut target = None;
            for (id, data) in signaling.discover().await {
                if signaling.get_address(id).await == Some(address) {
                    target = Some((id, data));
                    break;
                }
            }
            if let Some(target) = target {
                break target;
            }
        };
        // These wire fields are AcceptsSelfSignedAuth and Nonce in the pinned Go decoder.
        if !data.flag_b || data.session_id.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the local peer did not advertise self-signed admission with a nonce",
            )
            .into());
        }
        if data.connection_type != LAN_CONNECTION_TYPE {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the local peer does not advertise LAN signaling",
            )
            .into());
        }
        if data.protocol_version != u32::try_from(bedrock_protocol::PROTOCOL_VERSION)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the local peer advertises a different protocol version",
            )
            .into());
        }
        let key =
            Arc::new(SigningKey::try_generate_from_rng(&mut SysRng).map_err(io::Error::other)?);
        let config = ConnectionConfig {
            allow_unsigned_answers: true,
            attempts: 1,
            ..ConnectionConfig::default()
        };
        let connection = NetherClient::connect_with(signaling, id.to_string(), config).await?;
        Ok(Self::NetherNetLan {
            connection,
            key,
            nonce: data.session_id,
        })
    }

    /// Carries the discovered admission challenge into caller-owned Login metadata.
    pub(super) fn nonce(&self) -> &str {
        match self {
            Self::NetherNetLan { nonce, .. } => nonce,
            _ => "",
        }
    }

    /// Shares the original key allocation used by the transport, never private key material.
    pub(super) fn key(&self) -> Arc<SigningKey> {
        match self {
            Self::RakNet { key, .. }
            | Self::NetherNetLan { key, .. }
            | Self::NetherNet { key, .. } => Arc::clone(key),
        }
    }

    /// Selects the batch envelope owned by the network library.
    pub(super) fn header(&self) -> BatchHeader {
        match self {
            Self::RakNet { .. } => BatchHeader::RakNet,
            Self::NetherNet { .. } | Self::NetherNetLan { .. } => BatchHeader::NetherNet,
        }
    }

    /// RakNet uses application ciphers; NetherNet relies on its DTLS transport.
    pub(super) fn batch_encryption(&self) -> bool {
        matches!(self, Self::RakNet { .. })
    }

    /// Sends after admission; the probe never races this against another send.
    pub(super) async fn send(&mut self, message: Bytes) -> Result<(), Box<dyn Error>> {
        match self {
            Self::RakNet { connection, .. } => {
                connection.wait_send_capacity(message.len()).await?;
                connection.queue_send(message)?;
            }
            Self::NetherNet { connection, .. } | Self::NetherNetLan { connection, .. } => {
                connection.send(message).await?
            }
        }
        Ok(())
    }

    /// Reads one complete transport message without splitting its batch boundary.
    pub(super) async fn recv(&mut self) -> Result<Bytes, Box<dyn Error>> {
        match self {
            Self::RakNet { connection, .. } => Ok(connection.recv().await?),
            Self::NetherNet { connection, .. } | Self::NetherNetLan { connection, .. } => {
                connection.recv().await?.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "NetherNet closed during the probe",
                    )
                    .into()
                })
            }
        }
    }

    /// Completes normal close; dropping the owner also releases cancellation state.
    pub(super) async fn close(self) -> Result<(), Box<dyn Error>> {
        match self {
            Self::RakNet { mut connection, .. } => connection.close().await?,
            Self::NetherNet { connection, .. } | Self::NetherNetLan { connection, .. } => {
                let mut retired = connection.close();
                while retired.reliable.recv().await?.is_some() {}
                while retired.unreliable.recv().await?.is_some() {}
            }
        }
        Ok(())
    }
}
