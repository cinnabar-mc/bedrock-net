//! Concrete probe transports and their connection proof-key ownership.

use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use bedrock_client_tokio::transport::Transport;
use nethernet_tokio::{
    ClientIceConfig, ConnectionConfig, SelfSignedIdentity, TokenTrust,
    signaling::http::probe::HttpProbe,
};
use p384::ecdsa::SigningKey;
use p384::elliptic_curve::Generate;
use rand::rngs::SysRng;

use crate::{HANDSHAKE_TIMEOUT, OFFLINE_IDENTITY_LIFETIME};

/// Retains the same signing owner for a self-signed SDP offer and the later offline Login.
fn offline_proof() -> Result<(Arc<SigningKey>, Arc<SelfSignedIdentity>), Box<dyn Error>> {
    let key = Arc::new(SigningKey::try_generate_from_rng(&mut SysRng).map_err(io::Error::other)?);
    let identity = Arc::new(SelfSignedIdentity::from_key(
        Arc::clone(&key),
        SystemTime::now(),
        OFFLINE_IDENTITY_LIFETIME,
    )?);
    Ok((key, identity))
}

/// Establishes transport and retains the proof key used by its application Login.
pub(super) async fn connect(
    kind: &str,
    address: SocketAddr,
    deadline: tokio::time::Instant,
) -> Result<(Transport, Arc<SigningKey>), Box<dyn Error>> {
    match kind {
        "nethernet-lan" => connect_lan(address, deadline).await,
        "nethernet" => {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let probe = HttpProbe::new(reqwest::Client::builder().timeout(HANDSHAKE_TIMEOUT))?;
            let dialer = bedrock_client_tokio::connect::http::HttpDialer::new(
                probe,
                rand::random::<u64>().to_string(),
            );
            let (key, identity) = offline_proof()?;
            let config = ConnectionConfig {
                identity: Some(identity),
                server_trust: Some(TokenTrust::Any),
                client_ice: address.ip().is_loopback().then(|| ClientIceConfig {
                    turn_streams: Vec::new(),
                    turn_tls: None,
                    ice: Default::default(),
                    bind_addr: Some(SocketAddr::new(address.ip(), 0)),
                }),
                attempts: 1,
                ..ConnectionConfig::default()
            };
            let connection = dialer
                .connect(
                    &address.ip().to_string(),
                    address.port(),
                    config,
                    deadline,
                    None,
                )
                .await?;
            Ok((connection.into_transport(), key))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "transport must be nethernet or nethernet-lan",
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
    let (key, identity) = offline_proof()?;
    let options = bedrock_client_tokio::connect::lan::DirectedLanConfig {
        connection: ConnectionConfig {
            identity: Some(identity),
            client_ice: Some(ClientIceConfig {
                turn_streams: Vec::new(),
                turn_tls: None,
                ice: Default::default(),
                bind_addr: Some(SocketAddr::new(address.ip(), 0)),
            }),
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
    Ok((transport, key))
}

#[cfg(test)]
mod tests;
