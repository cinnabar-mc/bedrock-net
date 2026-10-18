use bytes::{Buf, Bytes};

use crate::compression::{self, CompressionAlgorithm, CompressionSettings};
use crate::{BatchError, DropReason};

const RAKNET_BATCH_HEADER: u8 = 0xfe;
const DEFAULT_DECODED_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_PACKET_COUNT: usize = 1600;

/// The batch envelope used by a transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchHeader {
    /// A leading `0xfe` byte precedes the batch payload.
    RakNet,
    /// The transport carries the payload without a batch marker.
    NetherNet,
}

impl BatchHeader {
    /// Returns the transport marker excluded from encrypted batch bodies.
    pub const fn marker(self) -> Option<u8> {
        match self {
            Self::RakNet => Some(RAKNET_BATCH_HEADER),
            Self::NetherNet => None,
        }
    }
}

/// Resource ceilings applied before packets are exposed to the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchLimits {
    /// Maximum wire message size, including envelope bytes.
    pub max_encoded_bytes: usize,
    /// Maximum total length-prefixed packet bytes after decompression.
    pub max_decoded_bytes: usize,
    /// Maximum nonempty packets in one decoded or encoded batch.
    pub max_packets: usize,
}

impl Default for BatchLimits {
    fn default() -> Self {
        Self {
            // Compression can expand an incompressible body; the wire allowance is separate.
            max_encoded_bytes: DEFAULT_DECODED_BYTES * 2,
            max_decoded_bytes: DEFAULT_DECODED_BYTES,
            max_packets: DEFAULT_PACKET_COUNT,
        }
    }
}

/// One fully validated batch, or a compression failure the caller must count and skip.
#[derive(Debug)]
pub enum DecodeOutcome {
    /// Encoded packets in wire order and diagnostics for skipped empty entries.
    #[non_exhaustive]
    Packets {
        /// Packet headers and undecoded bodies, sharing the batch allocation.
        packets: Vec<Bytes>,
        /// Empty incoming entries skipped; the caller should count/log these.
        skipped_empty_packets: usize,
    },
    /// A discarded batch; later batches on the same connection remain readable.
    Dropped(DropReason),
}

mod phase_private {
    pub trait Sealed {}
}

/// Byte framing before the one-time compression transition.
#[derive(Debug)]
pub struct Plain(());

/// Byte framing after actual negotiated settings have been installed once.
#[derive(Debug)]
pub struct Negotiated(CompressionSettings);

/// Sealed codec phases, allowing generic framing without a public phase cast.
pub trait BatchPhase: phase_private::Sealed {
    /// Reads installed settings; it grants no mutation or authentication authority.
    fn compression(&self) -> Option<CompressionSettings>;
}
impl phase_private::Sealed for Plain {}
impl phase_private::Sealed for Negotiated {}
impl BatchPhase for Plain {
    fn compression(&self) -> Option<CompressionSettings> {
        None
    }
}
impl BatchPhase for Negotiated {
    fn compression(&self) -> Option<CompressionSettings> {
        Some(self.0)
    }
}

/// Runtime-independent batch framing and negotiated compression.
///
/// The caller owns packet serialization, network I/O, logging and scheduling.
/// Before compression is enabled, no compression marker is consumed or emitted.
#[derive(Debug)]
pub struct BatchCodec<S = Plain> {
    header: BatchHeader,
    limits: BatchLimits,
    phase: S,
}

impl BatchCodec<Plain> {
    /// Creates a codec for a new connection before NetworkSettings.
    pub const fn new(header: BatchHeader, limits: BatchLimits) -> Self {
        Self {
            header,
            limits,
            phase: Plain(()),
        }
    }

    /// Consumes plaintext framing into its single negotiated compression configuration.
    /// Incoming batches still choose their own declared algorithm.
    ///
    /// ```compile_fail
    /// fn configure_twice(codec: bedrock_net::BatchCodec, settings: bedrock_net::CompressionSettings) {
    ///     let configured = codec.negotiate(settings);
    ///     let _again = configured.negotiate(settings);
    /// }
    /// ```
    pub const fn negotiate(self, settings: CompressionSettings) -> BatchCodec<Negotiated> {
        BatchCodec {
            header: self.header,
            limits: self.limits,
            phase: Negotiated(settings),
        }
    }
}

impl<S: BatchPhase> BatchCodec<S> {
    /// Encodes packets as consecutive batches, splitting by count and decoded size.
    ///
    /// Packet slices include their packet headers and exclude their length prefixes.
    /// Empty input produces no batches. All results preserve packet order.
    ///
    /// # Errors
    /// Returns an error for empty or oversized packets, zero packet capacity,
    /// compression failures or an encoded batch exceeding the wire limit.
    pub fn encode<P: AsRef<[u8]>>(&self, packets: &[P]) -> Result<Vec<Bytes>, BatchError> {
        if !packets.is_empty() && self.limits.max_packets == 0 {
            return Err(BatchError::TooManyPackets { maximum: 0 });
        }
        let mut batches = Vec::new();
        let mut body = Vec::new();
        let mut count = 0;
        for packet in packets {
            let packet = packet.as_ref();
            if packet.is_empty() {
                return Err(BatchError::EmptyPacket);
            }
            let length = u32::try_from(packet.len())
                .map_err(|_| BatchError::PacketTooLarge(packet.len()))?;
            let prefix_len = ((u32::BITS - length.leading_zeros()).div_ceil(7)) as usize;
            let entry_len =
                packet
                    .len()
                    .checked_add(prefix_len)
                    .ok_or(BatchError::DecodedTooLarge {
                        maximum: self.limits.max_decoded_bytes,
                    })?;
            if entry_len > self.limits.max_decoded_bytes {
                return Err(BatchError::DecodedTooLarge {
                    maximum: self.limits.max_decoded_bytes,
                });
            }
            if count != 0
                && (count == self.limits.max_packets
                    || entry_len > self.limits.max_decoded_bytes - body.len())
            {
                batches.push(self.encode_body(&body)?);
                body.clear();
                count = 0;
            }
            write_length(length, &mut body);
            body.extend_from_slice(packet);
            count += 1;
        }
        if count != 0 {
            batches.push(self.encode_body(&body)?);
        }
        Ok(batches)
    }

    /// Decodes a complete transport message without decoding packet bodies.
    ///
    /// Successful packets share the batch allocation. Validation completes before
    /// returning any packets, so a framing error cannot dispatch a partial batch.
    /// Empty server entries are skipped and counted, retaining the byte bounds.
    ///
    /// # Errors
    /// Returns an error for malformed envelopes or packet lengths, missing
    /// compression headers, or exceeded size/count limits. Invalid compression
    /// instead returns [`DecodeOutcome::Dropped`].
    pub fn decode(&self, mut message: Bytes) -> Result<DecodeOutcome, BatchError> {
        self.check_encoded_size(message.len())?;
        if self.header == BatchHeader::RakNet {
            match message.first().copied() {
                Some(RAKNET_BATCH_HEADER) => message.advance(1),
                Some(actual) => return Err(BatchError::InvalidBatchHeader(actual)),
                None => return Err(BatchError::MissingBatchHeader),
            }
        }
        if self.phase.compression().is_some() {
            let id = message
                .first()
                .copied()
                .ok_or(BatchError::MissingCompressionHeader)?;
            message.advance(1);
            message = match compression::decompress(id, message, self.limits.max_decoded_bytes)? {
                Ok(body) => body,
                Err(reason) => return Ok(DecodeOutcome::Dropped(reason)),
            };
        }
        if message.len() > self.limits.max_decoded_bytes {
            return Err(BatchError::DecodedTooLarge {
                maximum: self.limits.max_decoded_bytes,
            });
        }
        let (packets, skipped_empty_packets) = split_packets(message, self.limits.max_packets)?;
        Ok(DecodeOutcome::Packets {
            packets,
            skipped_empty_packets,
        })
    }

    /// Wraps an already bounded length-prefixed body in its transport/compression envelope.
    fn encode_body(&self, body: &[u8]) -> Result<Bytes, BatchError> {
        let mut message = Vec::new();
        if self.header == BatchHeader::RakNet {
            message.push(RAKNET_BATCH_HEADER);
        }
        if let Some(settings) = self.phase.compression() {
            let algorithm = if body.len() < usize::from(settings.threshold) {
                CompressionAlgorithm::None
            } else {
                settings.algorithm
            };
            message.push(algorithm.batch_id());
            if algorithm != CompressionAlgorithm::None {
                message.extend_from_slice(&compression::compress(algorithm, body)?);
            } else {
                message.extend_from_slice(body);
            }
        } else {
            message.extend_from_slice(body);
        }
        self.check_encoded_size(message.len())?;
        Ok(Bytes::from(message))
    }

    /// Applies the same wire bound to received and encoded messages.
    fn check_encoded_size(&self, actual: usize) -> Result<(), BatchError> {
        if actual > self.limits.max_encoded_bytes {
            return Err(BatchError::EncodedTooLarge {
                actual,
                maximum: self.limits.max_encoded_bytes,
            });
        }
        Ok(())
    }
}

/// Validates packet boundaries in full, keeping each packet as a slice of the input.
fn split_packets(body: Bytes, maximum: usize) -> Result<(Vec<Bytes>, usize), BatchError> {
    let mut packets = Vec::new();
    let mut skipped_empty_packets = 0;
    let mut offset = 0;
    while offset < body.len() {
        let (length, prefix) = read_length(&body[offset..], offset)?;
        offset += prefix;
        let length = usize::try_from(length).map_err(|_| BatchError::TruncatedPacket {
            declared: usize::MAX,
            remaining: body.len() - offset,
        })?;
        if length == 0 {
            skipped_empty_packets += 1;
            continue;
        }
        if packets.len() == maximum {
            return Err(BatchError::TooManyPackets { maximum });
        }
        if length > body.len() - offset {
            return Err(BatchError::TruncatedPacket {
                declared: length,
                remaining: body.len() - offset,
            });
        }
        packets.push(body.slice(offset..offset + length));
        offset += length;
    }
    Ok((packets, skipped_empty_packets))
}

/// Reads a bounded u32 envelope length; packet headers remain the protocol codec's responsibility.
fn read_length(bytes: &[u8], offset: usize) -> Result<(u32, usize), BatchError> {
    let mut value = 0;
    for (index, byte) in bytes.iter().copied().take(5).enumerate() {
        if index == 4 && byte > 0x0f {
            return Err(BatchError::InvalidPacketLength { offset });
        }
        value |= u32::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    Err(BatchError::InvalidPacketLength { offset })
}

/// Writes the shortest u32 packet-length prefix.
fn write_length(mut length: u32, out: &mut Vec<u8>) {
    while length >= 0x80 {
        out.push((length as u8) | 0x80);
        length >>= 7;
    }
    out.push(length as u8);
}
