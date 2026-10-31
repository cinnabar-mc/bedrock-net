//! Shared packet views and optional decoding for direct batch forwarding.

use bedrock_net::BatchPackets;
use bedrock_protocol::{packets, wire};
use bytes::Bytes;
use std::io;

/// One packet's original bytes and optional generated decoding result.
pub struct RawPacket {
    /// Original packet header and body, sharing the received batch allocation.
    pub data: Bytes,
    /// Header fields; ignored bits remain present in `data`.
    pub header: wire::PacketHeader,
    /// Absent for unselected IDs; a failed selected decode retains the original `data`.
    pub decoded: Option<io::Result<Box<packets::Packet>>>,
}

/// One received network batch, or its unread remainder after packet-at-a-time reads.
pub struct RawBatch {
    body: Bytes,
    packets: Vec<RawPacket>,
}

impl RawBatch {
    /// Classifies a validated batch, decoding only selected bodies under the caller's field limits.
    /// Decoding never advances negotiation or disconnect policy; the caller handles selected controls.
    pub fn from_packets(
        packets: BatchPackets,
        limits: &wire::Limits,
        mut select: impl FnMut(u32) -> bool,
    ) -> io::Result<Self> {
        let body = packets.body().clone();
        let packets = packets
            .map(|data| {
                let (header, offset) = header(&data)?;
                let decoded = select(header.id).then(|| {
                    let id = packets::PacketId::from_raw(header.id)
                        .ok_or_else(|| invalid("unknown selected packet ID"))?;
                    let payload = data.slice(offset..);
                    let mut reader = wire::Reader::from_shared(&payload).with_limits(limits);
                    let packet =
                        packets::Packet::decode_body(id, &mut reader).map_err(io::Error::other)?;
                    reader.expect_consumed().map_err(io::Error::other)?;
                    Ok(Box::new(packet))
                });
                Ok(RawPacket {
                    data,
                    header,
                    decoded,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self { body, packets })
    }

    /// Borrows packets in their original order, including selected decoding failures.
    pub fn packets(&self) -> &[RawPacket] {
        &self.packets
    }

    /// Transfers the original length-prefixed body without encoding packet fields again.
    pub fn into_body(self) -> Bytes {
        self.body
    }
}

/// Reads only framing, retaining Go's low-32-bit and noncanonical header encodings.
pub(super) fn header(data: &[u8]) -> io::Result<(wire::PacketHeader, usize)> {
    let mut value = 0;
    for (index, byte) in data.iter().copied().take(5).enumerate() {
        value |= u32::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((wire::PacketHeader::from_raw(value), index + 1));
        }
    }
    Err(invalid("invalid raw packet header"))
}

/// Reports malformed raw metadata without retaining its payload in diagnostics.
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
