//! Connection-wide observations selected before packet-body decoding.

use super::raw;
use bedrock_protocol::wire;
use std::io;

/// Direction of a raw observation on this connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketDirection {
    /// Bytes received from the peer, before header filtering or selected decoding.
    Received,
    /// Bytes accepted for the connection's outgoing batch encoding.
    Sent,
}

/// Borrowed wire data; retaining the payload requires an explicit caller-owned copy.
pub struct PacketObservation<'a> {
    /// Original header fields.
    pub header: wire::PacketHeader,
    /// Direction relative to the observed connection.
    pub direction: PacketDirection,
    /// Original payload without its packet header, never a mutable decoding alias.
    pub payload: &'a [u8],
}

/// A copied set of 10-bit packet interests and a synchronous read-only callback.
pub struct PacketObserver {
    ids: [u64; 16],
    callback: Box<dyn FnMut(PacketObservation<'_>) + Send>,
}

impl PacketObserver {
    /// Copies interests before I/O; rejects IDs which cannot fit in a packet header.
    /// Callbacks must not block and are never invoked for unrelated IDs or replayed input.
    pub fn new(
        ids: impl IntoIterator<Item = u32>,
        callback: impl FnMut(PacketObservation<'_>) + Send + 'static,
    ) -> io::Result<Self> {
        let mut interests = [0; 16];
        for id in ids {
            if id >= 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "observed packet ID exceeds 1023",
                ));
            }
            interests[(id >> 6) as usize] |= 1 << (id & 63);
        }
        Ok(Self {
            ids: interests,
            callback: Box::new(callback),
        })
    }

    /// Borrows only a matching packet's payload, without copying or decoding its fields.
    pub(super) fn observe(&mut self, direction: PacketDirection, data: &[u8]) {
        let Ok((header, offset)) = raw::header(data) else {
            return;
        };
        if self.ids[(header.id >> 6) as usize] & (1 << (header.id & 63)) != 0 {
            (self.callback)(PacketObservation {
                header,
                direction,
                payload: &data[offset..],
            });
        }
    }
}
