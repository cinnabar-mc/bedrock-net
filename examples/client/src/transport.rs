//! Concrete probe transports and their connection proof-key ownership.

use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use bedrock_client_tokio::transport::Transport;
use bedrock_net::raknet::{RakNetConnection, RakNetOptions};
use nethernet_tokio::{
    ConnectionConfig, HttpSignaling, LanConfig, LanSignaling, NetherClient, SelfSignedIdentity,
    TokenTrust,
};
use p384::ecdsa::SigningKey;
use p384::elliptic_curve::Generate;
use rand::rngs::SysRng;

use crate::{HANDSHAKE_TIMEOUT, OFFLINE_IDENTITY_LIFETIME};

const LAN_CONNECTION_TYPE: u8 = 4;

/// Establishes transport and retains the proof key used by its application Login.
pub(super) async fn connect(
    kind: &str,
    address: SocketAddr,
) -> Result<(Transport, Arc<SigningKey>), Box<dyn Error>> {
    match kind {
        "raknet" => {
            let key =
                Arc::new(SigningKey::try_generate_from_rng(&mut SysRng).map_err(io::Error::other)?);
            let connection = RakNetConnection::connect(address, RakNetOptions::default()).await?;
            Ok((Transport::from_raknet(connection), key))
        }
        "nethernet-lan" => connect_lan(address).await,
        "nethernet" => {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let http = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(HANDSHAKE_TIMEOUT)
                .build()?;
            let signaling = HttpSignaling::with_client(rand::random::<u64>().to_string(), http);
            let key =
                Arc::new(SigningKey::try_generate_from_rng(&mut SysRng).map_err(io::Error::other)?);
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
                NetherClient::connect_with(signaling, format!("http://{address}"), config).await?;
            Ok((Transport::from_http(connection), key))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "transport must be raknet, nethernet or nethernet-lan",
        )
        .into()),
    }
}

/// Discovers only the requested local fixture and honors its offline admission metadata.
async fn connect_lan(address: SocketAddr) -> Result<(Transport, Arc<SigningKey>), Box<dyn Error>> {
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
    let key = Arc::new(SigningKey::try_generate_from_rng(&mut SysRng).map_err(io::Error::other)?);
    let config = ConnectionConfig {
        allow_unsigned_answers: true,
        attempts: 1,
        ..ConnectionConfig::default()
    };
    let connection = NetherClient::connect_with(signaling, id.to_string(), config).await?;
    Ok((Transport::from_lan(connection, data.session_id), key))
}

#[cfg(test)]
mod tests;
