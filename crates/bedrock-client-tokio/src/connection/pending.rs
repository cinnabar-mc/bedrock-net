// SPDX-License-Identifier: MIT

//! Original received FIFO with lazy validated batches and bounded replayed prefixes.

use bedrock_net::{BatchCodec, BatchLimits, BatchPackets, DecodeOutcome};
use bedrock_protocol::wire;
use bytes::Bytes;
use std::{collections::VecDeque, io};

#[derive(Default)]
pub(super) struct PendingPackets {
    entries: VecDeque<Entry>,
}

enum Entry {
    Packet(Bytes),
    Batch(BatchPackets),
}

impl PendingPackets {
    /// Retains one actual validated wire batch without collecting its packet metadata.
    pub(super) fn push_batch(&mut self, packets: BatchPackets) {
        if !packets.is_empty() {
            self.entries.push_back(Entry::Batch(packets));
        }
    }

    /// Restores an original consumed prefix ahead of every unread batch sibling.
    pub(super) fn push_front(&mut self, packet: Bytes) {
        self.entries.push_front(Entry::Packet(packet));
    }

    /// Borrows the next original packet, preserving it until its consumer commits.
    pub(super) fn front(&mut self) -> Option<&Bytes> {
        self.discard_empty();
        match self.entries.front_mut()? {
            Entry::Packet(packet) => Some(packet),
            Entry::Batch(packets) => packets.front(),
        }
    }

    /// Commits exactly one original packet without advancing another FIFO entry.
    pub(super) fn pop_front(&mut self) -> Option<Bytes> {
        self.discard_empty();
        match self.entries.front_mut()? {
            Entry::Batch(packets) => {
                let packet = packets.next();
                if BatchPackets::is_empty(packets) {
                    self.entries.pop_front();
                }
                return packet;
            }
            Entry::Packet(_) => {}
        }
        let Entry::Packet(packet) = self.entries.pop_front()? else {
            unreachable!("the original front was a replayed packet")
        };
        Some(packet)
    }

    /// Takes one unread network boundary; replayed prefixes form a separate synthetic batch.
    pub(super) fn take_batch(&mut self) -> io::Result<Option<BatchPackets>> {
        self.discard_empty();
        let Some(entry) = self.entries.pop_front() else {
            return Ok(None);
        };
        match entry {
            Entry::Batch(packets) => Ok(Some(packets)),
            Entry::Packet(packet) => {
                let mut body = Vec::new();
                let mut next = Some(packet);
                while let Some(packet) = next {
                    wire::Writer::new(&mut body)
                        .write_byte_slice(&packet)
                        .map_err(io::Error::other)?;
                    next = if matches!(self.entries.front(), Some(Entry::Packet(_))) {
                        let Some(Entry::Packet(packet)) = self.entries.pop_front() else {
                            unreachable!()
                        };
                        Some(packet)
                    } else {
                        None
                    };
                }
                let DecodeOutcome::Packets { packets, .. } = BatchCodec::new(BatchLimits {
                    max_encoded_bytes: body.len(),
                    max_decoded_bytes: body.len(),
                    ..BatchLimits::default()
                })
                .decode(Bytes::from(body))
                .map_err(io::Error::other)?
                else {
                    unreachable!("plain replay cannot drop compression")
                };
                Ok(Some(packets))
            }
        }
    }

    /// Releases exhausted batch cursors while preserving the next original payload.
    fn discard_empty(&mut self) {
        loop {
            let empty = match self.entries.front_mut() {
                Some(Entry::Batch(packets)) => BatchPackets::is_empty(packets),
                _ => false,
            };
            if !empty {
                return;
            }
            drop(self.entries.pop_front());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peeking_packet_reads_and_replay_keep_the_unread_network_boundary() {
        let original = Bytes::from_static(&[2, 10, 2, 2, 10, 4]);
        let DecodeOutcome::Packets { packets, .. } = BatchCodec::new(BatchLimits::default())
            .decode(original.clone())
            .unwrap()
        else {
            unreachable!()
        };
        let mut pending = PendingPackets::default();
        pending.push_batch(packets);
        assert_eq!(pending.front().unwrap(), &[10, 2][..]);
        assert_eq!(pending.pop_front().unwrap(), &[10, 2][..]);
        pending.push_front(Bytes::from_static(&[10, 6]));
        let replay = pending.take_batch().unwrap().unwrap();
        assert_eq!(replay.collect::<Vec<_>>(), [Bytes::from_static(&[10, 6])]);
        let rest = pending.take_batch().unwrap().unwrap();
        assert_eq!(rest.body(), &original.slice(3..));
        assert_eq!(rest.body().as_ptr(), original.slice(3..).as_ptr());
        assert_eq!(rest.collect::<Vec<_>>(), [Bytes::from_static(&[10, 4])]);
        assert!(pending.take_batch().unwrap().is_none());
    }
}
