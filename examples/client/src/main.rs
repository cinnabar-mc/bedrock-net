//! Exercises generated settings and optional offline Login over native transports.

mod session;
mod transport;

use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bedrock_client::handshake::{
    ClientHandshake, ClientKeyExchange, ClientLogin, ClientLoginReady, ClientPackOffer,
    ClientSettings, HandshakeOptions, LoginEvent, OfferEvent, SettingsEvent,
};
use bedrock_net::login::OfflineIdentity;
use bedrock_net::{BatchLimits, BatchPhase, CompressionSettings, Negotiated};
use bedrock_protocol::{
    enums::PlayStatusType,
    packets,
    wire::{PacketHeader, Peer, Reader},
};
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
    let transport = Transport::connect(kind, address).await?;
    let configured = ClientHandshake::new(
        transport.key(),
        HandshakeOptions {
            batch_encryption: transport.batch_encryption(),
            max_login_bytes: BatchLimits::default().max_decoded_bytes,
            ..Default::default()
        },
    )?;
    let mut session = Session::new(transport);
    let (settings, request) = configured.start()?;
    session.send(request.into()).await?;
    let (ready, compression) = receive_settings(&mut session, settings).await?;
    let mut session = session.negotiate(compression);
    println!(
        "requested_protocol={} compression={:?} threshold={}",
        bedrock_protocol::PROTOCOL_VERSION,
        compression.algorithm,
        compression.threshold
    );
    if login {
        let metadata = client_data(kind, address, session.transport.nonce())?;
        let (pending, request) = ready.login_offline(
            &OfflineIdentity {
                display_name: PROBE_NAME,
                identity: PROBE_UUID,
                xuid: "",
                playfab_id: "",
                playfab_title_id: "",
            },
            &metadata,
            SystemTime::now(),
        )?;
        session.send(request.into()).await?;
        receive_login(&mut session, pending).await?;
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

/// Retains the actual settings owner and unread FIFO until its typed Login handoff.
async fn receive_settings(
    session: &mut Session,
    mut settings: ClientSettings,
) -> Result<(ClientLoginReady, CompressionSettings), Box<dyn Error>> {
    loop {
        match settings.receive(next_negotiation_packet(session).await?)? {
            SettingsEvent::Ready { login, compression } => return Ok((login, compression)),
            SettingsEvent::Pending {
                settings: next,
                packet,
            } => {
                eprintln!(
                    "unused packet before network settings: {}",
                    packet.id() as u32
                );
                settings = next;
            }
        }
    }
}

/// Observes Login acceptance and the real pack offer without starting a download.
async fn receive_login(
    session: &mut Session<Negotiated>,
    mut login: ClientLogin,
) -> Result<(), Box<dyn Error>> {
    let mut accepted = false;
    let mut encrypted = false;
    loop {
        let packet = next_negotiation_packet(session).await?;
        accepted |= is_login_success(&packet);
        match login.receive(packet)? {
            LoginEvent::Send {
                login: next,
                packets,
            } => {
                send_responses(session, packets).await?;
                login = next;
            }
            LoginEvent::KeyExchange(exchange) => {
                let (next, installed) = apply_exchange(session, exchange).await?;
                encrypted |= installed;
                login = next;
            }
            LoginEvent::Packs {
                cache_status,
                packs,
            } => {
                if let Some(status) = cache_status {
                    session.send(status.into()).await?;
                }
                println!("admitted_pack_offer={}", packs.offers().count());
                return finish_offer(session, packs, accepted, encrypted).await;
            }
            LoginEvent::Unhandled {
                login: next,
                packet,
            } => {
                eprintln!("unused packet during Login: {}", packet.id() as u32);
                login = next;
            }
        }
    }
}

/// Preserves the original late control owner when the offer precedes LoginSuccess.
async fn finish_offer(
    session: &mut Session<Negotiated>,
    mut offer: ClientPackOffer,
    mut accepted: bool,
    mut encrypted: bool,
) -> Result<(), Box<dyn Error>> {
    while !accepted {
        let packet = next_negotiation_packet(session).await?;
        accepted |= is_login_success(&packet);
        match offer.receive_control(packet)? {
            OfferEvent::Send {
                offer: next,
                packets,
            } => {
                send_responses(session, packets).await?;
                offer = next;
            }
            OfferEvent::KeyExchange(exchange) => {
                let (next, installed) = apply_exchange(session, exchange).await?;
                encrypted |= installed;
                offer = next;
            }
            OfferEvent::Unhandled {
                offer: next,
                packet,
            } => {
                eprintln!("unused packet after offer: {}", packet.id() as u32);
                offer = next;
            }
        }
    }
    println!("offline_login=accepted encryption={encrypted}");
    Ok(())
}

/// Applies the exact verified streams and acknowledgment before returning the same continuation.
async fn apply_exchange<C>(
    session: &mut Session<Negotiated>,
    exchange: ClientKeyExchange<C>,
) -> Result<(C, bool), Box<dyn Error>> {
    let (continuation, ciphers, response) = exchange.into_parts();
    let encrypted = if let Some(ciphers) = ciphers {
        session.enable_encryption(*ciphers)?;
        true
    } else {
        false
    };
    session.send(response.into()).await?;
    Ok((continuation, encrypted))
}

/// Sends original generated effects in order, without another batching or cipher owner.
async fn send_responses(
    session: &mut Session<Negotiated>,
    packets: Vec<packets::Packet>,
) -> Result<(), Box<dyn Error>> {
    for packet in packets {
        session.send(packet).await?;
    }
    Ok(())
}

/// Logs only a numeric status, leaving refusal policy with the actual client owner.
fn is_login_success(packet: &packets::Packet) -> bool {
    if let packets::Packet::PlayStatus(status) = packet {
        println!("login_status={}", status.status.to_raw());
        status.status == PlayStatusType::Loginsuccess
    } else {
        false
    }
}

/// Decodes only negotiation input while bounded framing/FIFO remain in the existing session.
/// Unknown or unused well-formed entries are counted locally without dumping their bodies.
async fn next_negotiation_packet<S: BatchPhase>(
    session: &mut Session<S>,
) -> Result<packets::Packet, Box<dyn Error>> {
    loop {
        let bytes = session.next_packet().await?;
        let mut reader = Reader::from_shared(&bytes);
        let header = PacketHeader::from_raw(reader.read_var_u32()?);
        let Some(id) = packets::PacketId::from_raw(header.id) else {
            eprintln!("unused unknown packet: {}", header.id);
            continue;
        };
        if !matches!(
            id,
            packets::PacketId::NetworkSettings
                | packets::PacketId::PlayStatus
                | packets::PacketId::ServerToClientHandshake
                | packets::PacketId::ResourcePacksInfo
                | packets::PacketId::Disconnect
                | packets::PacketId::PacketViolationWarning
        ) {
            eprintln!("unused packet during negotiation: {}", header.id);
            continue;
        }
        let packet = packets::Packet::decode_from(header.id, Peer::Server, &mut reader)?;
        log_unused(&reader);
        match packet {
            packets::Packet::Disconnect(disconnect) => {
                return Err(io::Error::other(format!(
                    "server disconnected during negotiation, reason {}",
                    disconnect.reason.to_raw()
                ))
                .into());
            }
            packets::Packet::PacketViolationWarning(warning) => eprintln!(
                "violation packet={} severity={} type={}",
                warning.violation_packet_id.0,
                warning.violation_severity.to_raw(),
                warning.violation_type.to_raw()
            ),
            packet => return Ok(packet),
        }
    }
}

/// Counts uninterpreted trailing data without printing packet contents.
fn log_unused(reader: &Reader<'_>) {
    if reader.remaining() != 0 {
        eprintln!("unused packet bytes: {}", reader.remaining());
    }
}
