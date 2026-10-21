//! Concrete probe transports and their connection proof-key ownership.

use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use bedrock_client_tokio::transport::Transport;
use bedrock_net::raknet::RakNetOptions;
use nethernet_tokio::{ConnectionConfig, HttpSignaling, SelfSignedIdentity, TokenTrust};
use p384::ecdsa::SigningKey;
use p384::elliptic_curve::Generate;
use rand::rngs::SysRng;

use crate::{HANDSHAKE_TIMEOUT, OFFLINE_IDENTITY_LIFETIME};

/// Establishes transport and retains the proof key used by its application Login.
pub(super) async fn connect(
    kind: &str,
    address: SocketAddr,
    deadline: tokio::time::Instant,
) -> Result<(Transport, Arc<SigningKey>), Box<dyn Error>> {
    match kind {
        "raknet" => {
            let key =
                Arc::new(SigningKey::try_generate_from_rng(&mut SysRng).map_err(io::Error::other)?);
            let transport = bedrock_client_tokio::connect::raknet::connect_resolved(
                std::iter::once(address),
                RakNetOptions::default(),
                deadline,
            )
            .await?;
            Ok((transport, key))
        }
        "nethernet-lan" => connect_lan(address, deadline).await,
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
            let connection = bedrock_client_tokio::connect::http::connect(
                signaling,
                format!("http://{address}"),
                config,
                deadline,
                None,
            )
            .await?;
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
async fn connect_lan(
    address: SocketAddr,
    deadline: tokio::time::Instant,
) -> Result<(Transport, Arc<SigningKey>), Box<dyn Error>> {
    if !address.ip().is_loopback() || !address.is_ipv4() || address.port() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the LAN probe requires an IPv4 loopback discovery endpoint",
        )
        .into());
    }
    let options = bedrock_client_tokio::connect::lan::DirectedLanConfig {
        connection: ConnectionConfig {
            allow_unsigned_answers: true,
            attempts: 1,
            ..Default::default()
        },
        selection: bedrock_client_tokio::connect::lan::LanSelection::SelfSigned,
        max_nonce_bytes: 0, // Original direct-offline discovery requires a nonce without a byte cap.
        credential_expires: None,
    };
    let (transport, _) =
        bedrock_client_tokio::connect::lan::connect_directed(address, &options, deadline).await?;
    let key = Arc::new(SigningKey::try_generate_from_rng(&mut SysRng).map_err(io::Error::other)?);
    Ok((transport, key))
}

#[cfg(test)]
mod tests;
