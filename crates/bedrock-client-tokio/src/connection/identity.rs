// SPDX-License-Identifier: MIT

//! Wire metadata applied during the connection's existing outbound framing pass.

use bedrock_protocol::{
    enums::TextPacketType,
    packets::{self, PacketId},
    types::TextData,
    wire,
};
use bytes::Bytes;
use std::io;

/// Already validated Login metadata, without account, membership or authentication authority.
#[derive(Clone)]
pub struct WireIdentity {
    /// The canonical signed player name used by chat packets.
    pub display_name: String,
    /// The canonical signed Xbox identity used by chat packets.
    pub xuid: String,
    /// The canonical player UUID used by skin packets.
    pub uuid: String,
}

/// Rewrites only identity-bearing entries; every other original byte remains shared.
pub(super) fn entry(
    frame: wire::RawFrame,
    identity: Option<&WireIdentity>,
    maximum: usize,
) -> io::Result<Bytes> {
    if let Some(identity) = identity {
        let header = frame.header();
        if matches!(header.id, packets::Text::ID | packets::PlayerSkin::ID) {
            let id = PacketId::from_raw(header.id).expect("known identity packet");
            let body = frame.body();
            let limits = wire::Limits::receiving_from(wire::Peer::Client);
            let mut reader = wire::Reader::from_shared(&body).with_limits(&limits);
            let mut packet =
                packets::Packet::decode_body(id, &mut reader).map_err(io::Error::other)?;
            reader.expect_consumed().map_err(io::Error::other)?;
            if normalize(&mut packet, identity) {
                let mut encoded = Vec::new();
                wire::encode_frame_with(&mut encoded, header, maximum, |writer| {
                    packet.encode(writer)
                })
                .map_err(io::Error::other)?;
                return without_length(Bytes::from(encoded));
            }
        }
    }
    without_length(frame.frame().clone())
}

fn without_length(entry: Bytes) -> io::Result<Bytes> {
    let mut reader = wire::Reader::from_shared(&entry);
    reader.read_var_u32().map_err(io::Error::other)?;
    Ok(entry.slice(reader.position()..))
}

/// Preserves message/skin content and changes only the canonical chat name/XUID or player UUID.
fn normalize(packet: &mut packets::Packet, identity: &WireIdentity) -> bool {
    match packet {
        packets::Packet::Text(text) if !identity.display_name.is_empty() => {
            if let TextData::AuthorAndMessage {
                message_type: TextPacketType::Chat,
                player_name,
                ..
            } = &mut text.body
                && (*player_name != identity.display_name.as_str()
                    || text.sender_xuid != identity.xuid.as_str())
            {
                *player_name = identity.display_name.as_str().into();
                text.sender_xuid = identity.xuid.as_str().into();
                return true;
            }
        }
        packets::Packet::PlayerSkin(skin) => {
            if let Ok(uuid) = uuid::Uuid::parse_str(&identity.uuid)
                && skin.uuid != uuid
            {
                skin.uuid = uuid;
                return true;
            }
        }
        _ => {}
    }
    false
}
