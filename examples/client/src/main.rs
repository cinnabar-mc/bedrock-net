//! Requests network settings using protocolgen's packet types over native transports.

use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bedrock_net::raknet::{RakNetConnection, RakNetOptions};
use bedrock_net::{
    BatchCodec, BatchHeader, BatchLimits, CompressionAlgorithm, CompressionSettings, DecodeOutcome,
};
use bedrock_protocol::packets::{NetworkSettings, RequestNetworkSettings};
use bedrock_protocol::wire::{Decode, Encode, I32BE, PacketHeader, Reader, Writer};
use bytes::Bytes;
use nethernet_tokio::{
    ConnectionConfig, HttpSignaling, NetherClient, SelfSignedIdentity, TokenTrust,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const OFFLINE_IDENTITY_LIFETIME: Duration = Duration::from_secs(3600);

/// Owns the evaluated transport for this standalone probe.
enum Transport {
    RakNet(RakNetConnection),
    NetherNet(NetherClient),
}

impl Transport {
    /// Establishes transport state without account services or detached probe tasks.
    async fn connect(kind: &str, address: SocketAddr) -> Result<Self, Box<dyn Error>> {
        match kind {
            "raknet" => Ok(Self::RakNet(
                RakNetConnection::connect(address, RakNetOptions::default()).await?,
            )),
            "nethernet" => {
                let _ = rustls::crypto::ring::default_provider().install_default();
                let http = reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(HANDSHAKE_TIMEOUT)
                    .build()?;
                let signaling = HttpSignaling::with_client(rand::random::<u64>().to_string(), http);
                let identity =
                    SelfSignedIdentity::new(SystemTime::now(), OFFLINE_IDENTITY_LIFETIME)?;
                let config = ConnectionConfig {
                    identity: Some(Arc::new(identity)),
                    server_trust: Some(TokenTrust::Any),
                    attempts: 1,
                    ..ConnectionConfig::default()
                };
                Ok(Self::NetherNet(
                    NetherClient::connect_with(signaling, format!("http://{address}"), config)
                        .await?,
                ))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transport must be raknet or nethernet",
            )
            .into()),
        }
    }

    /// Selects the envelope already owned by the batch codec.
    fn header(&self) -> BatchHeader {
        match self {
            Self::RakNet(_) => BatchHeader::RakNet,
            Self::NetherNet(_) => BatchHeader::NetherNet,
        }
    }

    /// Sends once after admission; the probe does not race this operation against another send.
    async fn send(&mut self, message: Bytes) -> Result<(), Box<dyn Error>> {
        match self {
            Self::RakNet(connection) => {
                connection.wait_send_capacity(message.len()).await?;
                connection.queue_send(message)?;
            }
            Self::NetherNet(connection) => connection.send(message).await?,
        }
        Ok(())
    }

    /// Reads one complete transport message, preserving its batch boundary.
    async fn recv(&mut self) -> Result<Bytes, Box<dyn Error>> {
        match self {
            Self::RakNet(connection) => Ok(connection.recv().await?),
            Self::NetherNet(connection) => connection.recv().await?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "NetherNet closed before settings",
                )
                .into()
            }),
        }
    }

    /// Releases the probe's transport; dropping it also owns cancellation cleanup.
    async fn close(&mut self) -> Result<(), Box<dyn Error>> {
        match self {
            Self::RakNet(connection) => connection.close().await?,
            Self::NetherNet(connection) => connection.close().await?,
        }
        Ok(())
    }
}

/// Runs a bounded settings probe; account credentials and game assets are not needed.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let kind = arguments.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: bedrock-probe <raknet|nethernet> IP:PORT",
        )
    })?;
    let address: SocketAddr = arguments
        .next()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: bedrock-probe <raknet|nethernet> IP:PORT",
            )
        })?
        .parse()?;
    if arguments.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "unexpected argument").into());
    }
    tokio::time::timeout(HANDSHAKE_TIMEOUT, probe(&kind, address)).await??;
    Ok(())
}

/// Exchanges generated packets, then releases the transport without entering login.
async fn probe(kind: &str, address: SocketAddr) -> Result<(), Box<dyn Error>> {
    let mut connection = Transport::connect(kind, address).await?;
    let limits = BatchLimits::default();
    let mut codec = BatchCodec::new(connection.header(), limits);
    let request = RequestNetworkSettings {
        client_network_version: I32BE(bedrock_protocol::PROTOCOL_VERSION),
    };
    let mut packet = Vec::new();
    let mut writer = Writer::with_limit(&mut packet, limits.max_decoded_bytes);
    writer.write_var_u32(PacketHeader::new(RequestNetworkSettings::ID).to_raw())?;
    request.encode(&mut writer)?;
    for batch in codec.encode(&[packet])? {
        connection.send(batch).await?;
    }

    let settings = receive_settings(&mut connection, &codec).await?;
    let algorithm = match CompressionAlgorithm::try_from(settings.compression_algorithm.to_raw()) {
        Ok(algorithm) => algorithm,
        Err(error) => {
            eprintln!("{error}; using the Go baseline's DEFLATE fallback");
            CompressionAlgorithm::Deflate
        }
    };
    codec.enable_compression(CompressionSettings {
        algorithm,
        threshold: settings.compression_threshold.0,
    });
    println!(
        "requested_protocol={} compression={algorithm:?} threshold={}",
        bedrock_protocol::PROTOCOL_VERSION,
        settings.compression_threshold.0
    );
    connection.close().await?;
    Ok(())
}

/// Reads the pre-login response, logging unused well-framed packets without exposing their bodies.
async fn receive_settings(
    connection: &mut Transport,
    codec: &BatchCodec,
) -> Result<NetworkSettings, Box<dyn Error>> {
    loop {
        let message: Bytes = connection.recv().await?;
        let packets = match codec.decode(message)? {
            DecodeOutcome::Packets(packets) => packets,
            DecodeOutcome::Dropped(reason) => {
                eprintln!("dropped batch: {reason:?}");
                continue;
            }
        };
        for packet in packets {
            let mut reader = Reader::from_shared(&packet);
            let header = PacketHeader::from_raw(reader.read_var_u32()?);
            if header.id == NetworkSettings::ID {
                let settings = NetworkSettings::decode(&mut reader)?;
                if reader.remaining() != 0 {
                    eprintln!("unused NetworkSettings bytes: {}", reader.remaining());
                }
                return Ok(settings);
            }
            eprintln!("unused packet before network settings: {}", header.id);
        }
    }
}
