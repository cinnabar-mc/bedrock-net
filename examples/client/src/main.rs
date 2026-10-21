//! Exercises generated settings and optional offline Login over native transports.

#[cfg(test)]
mod interop_tests;
mod transport;

use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bedrock_client::handshake::{ClientHandshake, HandshakeOptions};
use bedrock_client_tokio::handshake::{self, LoginData, Observation};
use bedrock_net::BatchLimits;
use bedrock_net::login::OfflineIdentity;
use bedrock_protocol::{enums::PlayStatusType, packets, wire::Peer};
use rand::TryRng;
use serde_json::value::RawValue;

use bedrock_client_tokio::connection::Connection;

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
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    tokio::time::timeout_at(deadline, probe(&kind, address, login, deadline)).await??;
    Ok(())
}

/// Negotiates settings and, when requested, stops after Login acceptance and the pack offer.
async fn probe(
    kind: &str,
    address: SocketAddr,
    login: bool,
    deadline: tokio::time::Instant,
) -> Result<(), Box<dyn Error>> {
    let (transport, key) = crate::transport::connect(kind, address, deadline).await?;
    let configured = ClientHandshake::new(
        key,
        HandshakeOptions {
            batch_encryption: transport.batch_encryption(),
            max_login_bytes: BatchLimits::default().max_decoded_bytes,
            ..Default::default()
        },
    )?;
    let mut session = Connection::new(
        transport,
        BatchLimits::default(),
        bedrock_protocol::wire::Limits::receiving_from(Peer::Server),
        BatchLimits::default().max_decoded_bytes,
    );
    let mut accepted = false;
    let (ready, compression) = handshake::settings(&mut session, configured, &mut |event| {
        observe(event, &mut accepted)
    })
    .await?;
    println!(
        "requested_protocol={} compression={:?} threshold={}",
        bedrock_protocol::PROTOCOL_VERSION,
        compression.algorithm,
        compression.threshold
    );
    if login {
        let metadata = client_data(kind, address, session.transport().nonce())?;
        let input = LoginData::Offline {
            identity: OfflineIdentity {
                display_name: PROBE_NAME,
                identity: PROBE_UUID,
                xuid: "",
                playfab_id: "",
                playfab_title_id: "",
            },
            claims: &metadata,
            now: SystemTime::now(),
        };
        match handshake::login(&mut session, ready, input, &mut |event| {
            observe(event, &mut accepted)
        })
        .await?
        {
            Some(mut offer) => {
                println!("admitted_pack_offer={}", offer.offers().count());
                while !accepted {
                    offer = handshake::offer_control(&mut session, offer, &mut |event| {
                        observe(event, &mut accepted)
                    })
                    .await?;
                }
                println!(
                    "offline_login=accepted encryption={}",
                    session.has_batch_ciphers()
                );
            }
            None => println!(
                "startup_without_pack_offer=true encryption={}",
                session.has_batch_ciphers()
            ),
        }
    }
    session.transport_mut().finish_close().await?;
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
        "nethernet" => format!("http://{address}"),
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

/// Records only original numeric metadata; it cannot replace packets or alter admission.
fn observe(event: Observation<'_>, accepted: &mut bool) {
    match event {
        Observation::Unknown(header) => eprintln!("unused unknown packet: {}", header.id),
        Observation::Received(_, packet) => {
            *accepted |= is_login_success(packet);
            if let packets::Packet::PacketViolationWarning(warning) = packet {
                eprintln!(
                    "violation packet={} severity={} type={}",
                    warning.violation_packet_id.0,
                    warning.violation_severity.to_raw(),
                    warning.violation_type.to_raw(),
                );
            }
        }
        Observation::Sent(_) => {}
    }
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
