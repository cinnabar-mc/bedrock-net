//! Exercises generated settings and optional offline Login over native transports.

mod session;
mod transport;

use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bedrock_net::login::{OfflineIdentity, encode_offline_request, finish_key_exchange};
use bedrock_net::{BatchLimits, CompressionAlgorithm, CompressionSettings};
use bedrock_protocol::enums::PlayStatusType;
use bedrock_protocol::packets::{
    ClientCacheStatus, ClientToServerHandshake, Disconnect, Login, NetworkSettings,
    PacketViolationWarning, PlayStatus, RequestNetworkSettings, ResourcePacksInfo,
    ServerToClientHandshake,
};
use bedrock_protocol::wire::{Decode, I32BE, PacketHeader, Reader};
use rand::TryRng;
use serde_json::value::RawValue;

use session::Session;
use transport::Transport;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const OFFLINE_IDENTITY_LIFETIME: Duration = Duration::from_secs(3600);
const PROBE_NAME: &str = "RustProbe";
const PROBE_UUID: &str = "00000000-0000-4000-8000-000000000001";
const SKIN_SIDE: usize = 64;
const SKIN_PIXEL: [u8; 4] = [0x80, 0x80, 0x80, 0xff];
const SKIN_GEOMETRY: &str = r#"{"format_version":"1.12.0","minecraft:geometry":[{"description":{"identifier":"geometry.humanoid.custom","texture_width":64,"texture_height":64},"bones":[{"name":"root","pivot":[0,0,0],"cubes":[{"origin":[-4,0,-2],"size":[8,24,4],"uv":[0,0]}]}]}]}"#;
const USAGE: &str =
    "usage: bedrock-probe <raknet|nethernet|nethernet-lan> IP:PORT [--offline-login]";

/// Runs a bounded probe with synthetic metadata and no account credentials.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let kind = arguments
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, USAGE))?;
    let address: SocketAddr = arguments
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, USAGE))?
        .parse()?;
    let login = match arguments.next().as_deref() {
        None => false,
        Some("--offline-login") => true,
        Some(_) => return Err(io::Error::new(io::ErrorKind::InvalidInput, USAGE).into()),
    };
    if arguments.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, USAGE).into());
    }
    tokio::time::timeout(HANDSHAKE_TIMEOUT, probe(&kind, address, login)).await??;
    Ok(())
}

/// Negotiates settings and, when requested, stops after Login acceptance and the pack offer.
async fn probe(kind: &str, address: SocketAddr, login: bool) -> Result<(), Box<dyn Error>> {
    let mut session = Session::new(Transport::connect(kind, address).await?);
    session
        .send(
            RequestNetworkSettings::ID,
            &RequestNetworkSettings {
                client_network_version: I32BE(bedrock_protocol::PROTOCOL_VERSION),
            },
        )
        .await?;
    let settings = receive_settings(&mut session).await?;
    let algorithm = match CompressionAlgorithm::try_from(settings.compression_algorithm.to_raw()) {
        Ok(algorithm) => algorithm,
        Err(error) => {
            eprintln!("{error}; using the Go baseline's DEFLATE fallback");
            CompressionAlgorithm::Deflate
        }
    };
    session.enable_compression(CompressionSettings {
        algorithm,
        threshold: settings.compression_threshold.0,
    });
    println!(
        "requested_protocol={} compression={algorithm:?} threshold={}",
        bedrock_protocol::PROTOCOL_VERSION,
        settings.compression_threshold.0
    );
    if login {
        let client_data = client_data(kind, address, session.transport.nonce())?;
        let identity = OfflineIdentity {
            display_name: PROBE_NAME,
            identity: PROBE_UUID,
            xuid: "",
            playfab_id: "",
            playfab_title_id: "",
        };
        let request = encode_offline_request(
            session.transport.key(),
            &identity,
            &client_data,
            SystemTime::now(),
            BatchLimits::default().max_decoded_bytes,
        )?;
        session
            .send(
                Login::ID,
                &Login {
                    client_network_version: I32BE(bedrock_protocol::PROTOCOL_VERSION),
                    connection_request: request,
                },
            )
            .await?;
        receive_login(&mut session).await?;
    }
    session.transport.close().await?;
    Ok(())
}

/// Keeps metadata construction in the caller; the skin is an original solid-color fixture.
fn client_data(
    kind: &str,
    address: SocketAddr,
    nonce: &str,
) -> Result<Box<RawValue>, Box<dyn Error>> {
    let mut random = [0; 16];
    rand::rngs::SysRng
        .try_fill_bytes(&mut random)
        .map_err(io::Error::other)?;
    let device_id = uuid::Builder::from_random_bytes(random).into_uuid();
    let server_address = match kind {
        "nethernet" => format!("http://{address}:{}", address.port()),
        _ => address.to_string(),
    };
    let document = bedrock_auth::ClientData {
        client_random_id: 0,
        nonce: nonce.into(),
        current_input_mode: 2,
        default_input_mode: 2,
        device_model: "Rust probe".into(),
        device_os: 1,
        platform_type: 1,
        device_id: device_id.simple().to_string(),
        game_version: bedrock_protocol::GAME_VERSION.into(),
        language_code: "en_GB".into(),
        self_signed_id: device_id.to_string(),
        server_address,
        skin_data: STANDARD.encode(SKIN_PIXEL.repeat(SKIN_SIDE * SKIN_SIDE)),
        skin_image_height: SKIN_SIDE as i32,
        skin_image_width: SKIN_SIDE as i32,
        skin_id: format!("{device_id}_Probe"),
        skin_geometry: STANDARD.encode(SKIN_GEOMETRY),
        skin_geometry_version: STANDARD.encode("1.14.60"),
        skin_resource_patch: STANDARD
            .encode(br#"{"geometry":{"default":"geometry.humanoid.custom"}}"#),
        skin_colour: "#0".into(),
        arm_size: "wide".into(),
        third_party_name: PROBE_NAME.into(),
        max_view_distance: 16,
        memory_tier: 4,
        ..bedrock_auth::ClientData::default()
    };
    Ok(RawValue::from_string(serde_json::to_string(&document)?)?)
}

/// Reads settings while retaining later packets from the same batch for the next phase.
async fn receive_settings(session: &mut Session) -> Result<NetworkSettings, Box<dyn Error>> {
    loop {
        let packet = session.next_packet().await?;
        let mut reader = Reader::from_shared(&packet);
        let header = PacketHeader::from_raw(reader.read_var_u32()?);
        if header.id == NetworkSettings::ID {
            let settings = NetworkSettings::decode(&mut reader)?;
            log_unused(&reader);
            return Ok(settings);
        }
        eprintln!("unused packet before network settings: {}", header.id);
    }
}

/// Handles optional encryption and proves reception of compressed post-Login data.
async fn receive_login(session: &mut Session) -> Result<(), Box<dyn Error>> {
    let mut accepted = false;
    let mut offered = false;
    let mut encrypted = false;
    let mut handshake_complete = false;
    loop {
        let packet = session.next_packet().await?;
        let mut reader = Reader::from_shared(&packet);
        let header = PacketHeader::from_raw(reader.read_var_u32()?);
        match header.id {
            ServerToClientHandshake::ID => {
                let handshake = ServerToClientHandshake::decode(&mut reader)?;
                if handshake_complete {
                    eprintln!("ignored duplicate server handshake");
                    continue;
                }
                let ciphers = finish_key_exchange(
                    session.transport.key(),
                    handshake.handshake_web_token.to_str()?,
                    BatchLimits::default().max_decoded_bytes,
                )?;
                handshake_complete = true;
                if session.transport.batch_encryption() {
                    session.enable_encryption(ciphers)?;
                    encrypted = true;
                }
                session
                    .send(ClientToServerHandshake::ID, &ClientToServerHandshake {})
                    .await?;
            }
            PlayStatus::ID => {
                let status = PlayStatus::decode(&mut reader)?.status;
                println!("login_status={}", status.to_raw());
                match status {
                    PlayStatusType::Loginsuccess if !accepted => {
                        accepted = true;
                        session
                            .send(
                                ClientCacheStatus::ID,
                                &ClientCacheStatus {
                                    is_cache_supported: false,
                                },
                            )
                            .await?;
                    }
                    PlayStatusType::Loginsuccess => {}
                    PlayStatusType::Playerspawn => {}
                    _ => {
                        return Err(io::Error::other(format!(
                            "Login failed with status {}",
                            status.to_raw()
                        ))
                        .into());
                    }
                }
            }
            ResourcePacksInfo::ID => {
                let packs = ResourcePacksInfo::decode(&mut reader)?;
                println!(
                    "resource_pack_offer={} required={}",
                    packs.resource_packs.len(),
                    packs.resource_pack_required
                );
                offered = true;
            }
            Disconnect::ID => {
                let disconnect = Disconnect::decode(&mut reader)?;
                return Err(io::Error::other(format!(
                    "server disconnected during Login, reason {}",
                    disconnect.reason.to_raw()
                ))
                .into());
            }
            PacketViolationWarning::ID => {
                let warning = PacketViolationWarning::decode(&mut reader)?;
                eprintln!(
                    "violation packet={} severity={} type={}",
                    warning.violation_packet_id.0,
                    warning.violation_severity.to_raw(),
                    warning.violation_type.to_raw()
                );
            }
            _ => {
                eprintln!("unused packet during Login: {}", header.id);
                continue;
            }
        }
        log_unused(&reader);
        if accepted && offered {
            println!("offline_login=accepted encryption={encrypted}");
            return Ok(());
        }
    }
}

/// Counts uninterpreted trailing data without printing packet contents.
fn log_unused(reader: &Reader<'_>) {
    if reader.remaining() != 0 {
        eprintln!("unused packet bytes: {}", reader.remaining());
    }
}
