use std::sync::Mutex;

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
    /// Also the incoming ceiling until a negotiated codec's
    /// [`BatchCodec::with_incoming_decoded_limit`] overrides that direction.
    pub max_decoded_bytes: usize,
    /// Maximum packets in one outgoing batch; larger groups split in order.
    pub max_packets: usize,
    /// Optional maximum nonempty packets in one incoming batch.
    /// Some enables accepting-side checks, including rejection of empty entries.
    /// None retains the byte bounds and skips empty entries without imposing the outgoing split ceiling.
    pub max_incoming_packets: Option<usize>,
}

impl Default for BatchLimits {
    fn default() -> Self {
        Self {
            // Compression can expand an incompressible body; the wire allowance is separate.
            max_encoded_bytes: DEFAULT_DECODED_BYTES * 2,
            max_decoded_bytes: DEFAULT_DECODED_BYTES,
            max_packets: DEFAULT_PACKET_COUNT,
            max_incoming_packets: None,
        }
    }
}

/// One length-validated batch, or a compression failure the caller must count and skip.
#[derive(Debug)]
pub enum DecodeOutcome {
    /// Encoded packets in wire order and diagnostics for skipped empty entries.
    #[non_exhaustive]
    Packets {
        /// Length-validated encoded packets, sliced lazily from the original allocation.
        /// Packet-header and body decoding remain the caller's responsibility.
        packets: BatchPackets,
        /// Empty incoming entries skipped; the caller should count/log these.
        skipped_empty_packets: usize,
    },
    /// A discarded batch; later batches on the same connection remain readable.
    Dropped(DropReason),
}

/// Diagnostics after synchronously visiting a complete validated batch.
#[derive(Debug)]
pub enum VisitOutcome {
    /// All nonempty packets were delivered in wire order.
    Packets {
        /// Number of packets delivered.
        count: usize,
        /// Empty entries skipped, for caller diagnostics.
        skipped_empty_packets: usize,
    },
    /// A discarded compressed batch; no callback ran.
    Dropped(DropReason),
}

/// One length-validated batch body, retaining only its unread cursor and packet count.
///
/// Each yielded packet shares the original allocation, without a per-packet
/// collection. Dropping or exhausting the iterator releases its unread body;
/// a previously yielded slice can still retain the entire batch allocation.
pub struct BatchPackets {
    body: Bytes,
    remaining: usize,
}

impl BatchPackets {
    /// Reports whether every nonempty packet has been consumed.
    pub fn is_empty(&self) -> bool {
        self.remaining == 0
    }
}

impl Iterator for BatchPackets {
    type Item = Bytes;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        loop {
            let (length, prefix) = read_length(&self.body, 0)
                .expect("the complete immutable batch was validated before iteration");
            self.body.advance(prefix);
            if length == 0 {
                continue;
            }
            let length = usize::try_from(length).expect("validated packet length fits usize");
            let packet = self.body.split_to(length);
            self.remaining -= 1;
            if self.remaining == 0 {
                self.body = Bytes::new();
            }
            return Some(packet);
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for BatchPackets {}
impl std::iter::FusedIterator for BatchPackets {}

impl std::fmt::Debug for BatchPackets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchPackets")
            .field("remaining", &self.remaining)
            .field("unread_bytes", &self.body.len())
            .finish()
    }
}

mod phase_private {
    use super::{BatchError, CompressionAlgorithm};

    pub trait Sealed {
        /// Replaces a framed batch body with its independent compressed block.
        fn compress(
            &self,
            _: CompressionAlgorithm,
            _: &mut Vec<u8>,
            _: usize,
        ) -> Result<(), BatchError> {
            unreachable!("plaintext batches do not use compression")
        }
        /// Borrows bounded scratch for synchronous Snappy packet visits.
        fn snappy_scratch(&mut self) -> &mut Vec<u8> {
            unreachable!("plaintext batches do not use compression")
        }
    }
}

/// Byte framing before the one-time compression transition.
#[derive(Debug)]
pub struct Plain(());

/// Byte framing after actual negotiated settings have been installed once.
pub struct Negotiated {
    settings: CompressionSettings,
    snappy_scratch: Vec<u8>,
    snappy_encoder: Mutex<Option<Box<compression::SnappyEncoder>>>,
}

impl std::fmt::Debug for Negotiated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Negotiated")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

/// Sealed codec phases, allowing generic framing without a public phase cast.
pub trait BatchPhase: phase_private::Sealed {
    /// Reads installed settings; it grants no mutation or authentication authority.
    fn compression(&self) -> Option<CompressionSettings>;
}
impl phase_private::Sealed for Plain {}
impl phase_private::Sealed for Negotiated {
    /// Reuses only Snappy scratch and appends its completed block without a temporary vector.
    fn compress(
        &self,
        algorithm: CompressionAlgorithm,
        message: &mut Vec<u8>,
        offset: usize,
    ) -> Result<(), BatchError> {
        let mut encoder = (algorithm == CompressionAlgorithm::Snappy).then(|| {
            self.snappy_encoder
                .lock()
                .unwrap_or_else(|error| error.into_inner())
        });
        let compressed = match encoder.as_mut() {
            Some(encoder) => encoder
                .get_or_insert_with(Box::default)
                .compress(&message[offset..])?,
            None => std::borrow::Cow::Owned(compression::compress(algorithm, &message[offset..])?),
        };
        message.truncate(offset);
        message.extend_from_slice(&compressed);
        Ok(())
    }
    #[inline]
    fn snappy_scratch(&mut self) -> &mut Vec<u8> {
        &mut self.snappy_scratch
    }
}

impl BatchPhase for Plain {
    fn compression(&self) -> Option<CompressionSettings> {
        None
    }
}
impl BatchPhase for Negotiated {
    fn compression(&self) -> Option<CompressionSettings> {
        Some(self.settings)
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
    max_incoming_decoded_bytes: usize,
    phase: S,
}

impl BatchCodec<Plain> {
    /// Creates a codec for a new connection before `NetworkSettings`.
    pub const fn new(header: BatchHeader, limits: BatchLimits) -> Self {
        Self {
            header,
            limits,
            max_incoming_decoded_bytes: limits.max_decoded_bytes,
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
            max_incoming_decoded_bytes: self.max_incoming_decoded_bytes,
            phase: Negotiated {
                settings,
                snappy_scratch: Vec::new(),
                snappy_encoder: Mutex::new(None),
            },
        }
    }
}

impl BatchCodec<Negotiated> {
    /// Sets the incoming decoded-byte ceiling after compression negotiation.
    ///
    /// Outgoing byte/count limits, the wire ceiling and incoming packet-count
    /// policy stay unchanged. Zero permits only an empty decoded body.
    #[must_use]
    pub const fn with_incoming_decoded_limit(mut self, maximum: usize) -> Self {
        self.max_incoming_decoded_bytes = maximum;
        self
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
        let mut batches = Vec::new();
        self.encode_into(packets, &mut batches)?;
        Ok(batches)
    }

    /// Replaces previously consumed batches, reusing uniquely owned output buffers.
    /// Shared batches keep their original bytes. Send each result immediately in order;
    /// keep unsent results until delivery instead of recycling them in another call.
    ///
    /// # Errors
    /// Returns the same errors as [`Self::encode`] and clears `batches` on failure.
    pub fn encode_into<P: AsRef<[u8]>>(
        &self,
        packets: &[P],
        batches: &mut Vec<Bytes>,
    ) -> Result<(), BatchError> {
        let result = self.encode_reusing(packets, batches);
        if result.is_err() {
            batches.clear();
        }
        result
    }

    /// Writes each caller's packet view once and clears partial groups on failure.
    fn encode_reusing<P: AsRef<[u8]>>(
        &self,
        packets: &[P],
        batches: &mut Vec<Bytes>,
    ) -> Result<(), BatchError> {
        if packets.is_empty() {
            batches.clear();
            return Ok(());
        }
        if self.limits.max_packets == 0 {
            return Err(BatchError::TooManyPackets { maximum: 0 });
        }
        let mut index = 0;
        let mut message = self.start_batch(batches.get_mut(index).map(std::mem::take));
        let prefix = message.len();
        let mut count = 0;
        for packet in packets {
            let packet = packet.as_ref();
            if packet.is_empty() {
                return Err(BatchError::EmptyPacket);
            }
            let length = u32::try_from(packet.len())
                .map_err(|_| BatchError::PacketTooLarge(packet.len()))?;
            let entry_len = packet
                .len()
                .checked_add(((u32::BITS - length.leading_zeros()).div_ceil(7)) as usize)
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
                    || entry_len > self.limits.max_decoded_bytes - (message.len() - prefix))
            {
                self.finish_batch(message, batches, index)?;
                index += 1;
                message = self.start_batch(batches.get_mut(index).map(std::mem::take));
                count = 0;
            }
            message.reserve(entry_len.saturating_add(8));
            write_length(length, &mut message);
            message.extend_from_slice(packet);
            count += 1;
        }
        self.finish_batch(message, batches, index)?;
        batches.truncate(index + 1);
        Ok(())
    }

    /// Decodes a complete transport message without decoding packet bodies.
    ///
    /// Successful packets share the batch allocation. All entry lengths are
    /// validated before returning any packets, so a framing error cannot dispatch
    /// a partial batch. Packet headers and bodies are not decoded here.
    /// Empty server entries are skipped and counted, retaining the byte bounds.
    ///
    /// # Errors
    /// Returns an error for malformed envelopes or packet lengths, missing
    /// compression headers, or exceeded size/count limits. Invalid compression
    /// instead returns [`DecodeOutcome::Dropped`].
    pub fn decode(&self, message: Bytes) -> Result<DecodeOutcome, BatchError> {
        let (id, body) = self.strip_envelope(message)?;
        self.decode_payload(id, body)
    }

    /// Visits a complete validated batch without transferring packet ownership.
    ///
    /// Small Snappy batches reuse connection scratch. Other batches retain the
    /// storage used by [`Self::decode`] until callbacks finish. No callback runs
    /// before the complete batch passes framing and resource checks.
    ///
    /// # Errors
    /// Returns the same errors and dropped-batch diagnostics as [`Self::decode`].
    pub fn decode_with(
        &mut self,
        message: Bytes,
        mut visit: impl FnMut(&[u8]),
    ) -> Result<VisitOutcome, BatchError> {
        let (id, body) = self.strip_envelope(message)?;
        if id == Some(CompressionAlgorithm::Snappy.batch_id())
            && let Ok(length) = snap::raw::decompress_len(&body)
            && length <= 65536
        {
            if length > self.max_incoming_decoded_bytes {
                return Err(BatchError::DecodedTooLarge {
                    maximum: self.max_incoming_decoded_bytes,
                });
            }
            let maximum = self.limits.max_incoming_packets;
            let scratch = self.phase.snappy_scratch();
            // Keep near-limit batches from doubling the retained allocation.
            if length > scratch.capacity() {
                scratch.reserve_exact(length - scratch.len());
            }
            scratch.resize(length, 0);
            if let Err(error) = compression::decompress_snappy_into(&body, scratch) {
                return Ok(VisitOutcome::Dropped(DropReason::InvalidSnappy(error)));
            }
            let (count, skipped_empty_packets) = validate_packets(scratch, maximum)?;
            visit_packets(scratch, count, &mut visit);
            return Ok(VisitOutcome::Packets {
                count,
                skipped_empty_packets,
            });
        }
        match self.decode_payload(id, body)? {
            DecodeOutcome::Packets {
                packets,
                skipped_empty_packets,
            } => {
                let count = packets.len();
                visit_packets(&packets.body, count, &mut visit);
                Ok(VisitOutcome::Packets {
                    count,
                    skipped_empty_packets,
                })
            }
            DecodeOutcome::Dropped(reason) => Ok(VisitOutcome::Dropped(reason)),
        }
    }

    /// Checks the wire ceiling and removes transport and negotiated algorithm markers.
    fn strip_envelope(&self, mut message: Bytes) -> Result<(Option<u8>, Bytes), BatchError> {
        self.check_encoded_size(message.len())?;
        if self.header == BatchHeader::RakNet {
            match message.first().copied() {
                Some(RAKNET_BATCH_HEADER) => message.advance(1),
                Some(actual) => return Err(BatchError::InvalidBatchHeader(actual)),
                None => return Err(BatchError::MissingBatchHeader),
            }
        }
        let id = if self.phase.compression().is_some() {
            let id = message
                .first()
                .copied()
                .ok_or(BatchError::MissingCompressionHeader)?;
            message.advance(1);
            Some(id)
        } else {
            None
        };
        Ok((id, message))
    }

    /// Validates an envelope-stripped batch while preserving owned packet lifetimes.
    fn decode_payload(
        &self,
        id: Option<u8>,
        mut message: Bytes,
    ) -> Result<DecodeOutcome, BatchError> {
        if let Some(id) = id {
            message = match compression::decompress(id, message, self.max_incoming_decoded_bytes)? {
                Ok(body) => body,
                Err(reason) => return Ok(DecodeOutcome::Dropped(reason)),
            };
        }
        if message.len() > self.max_incoming_decoded_bytes {
            return Err(BatchError::DecodedTooLarge {
                maximum: self.max_incoming_decoded_bytes,
            });
        }
        let (count, skipped_empty_packets) =
            validate_packets(&message, self.limits.max_incoming_packets)?;
        let packets = BatchPackets {
            body: if count == 0 { Bytes::new() } else { message },
            remaining: count,
        };
        Ok(DecodeOutcome::Packets {
            packets,
            skipped_empty_packets,
        })
    }

    /// Reclaims an unshared output and starts its transport/compression envelope.
    fn start_batch(&self, recycled: Option<Bytes>) -> Vec<u8> {
        let mut message = recycled
            .filter(Bytes::is_unique)
            .map(Vec::from)
            .unwrap_or_default();
        message.clear();
        if self.header == BatchHeader::RakNet {
            message.push(RAKNET_BATCH_HEADER);
        }
        if self.phase.compression().is_some() {
            message.push(CompressionAlgorithm::None.batch_id());
        }
        message
    }

    /// Compresses a complete group, retains checksum space, and replaces its recycled slot.
    fn finish_batch(
        &self,
        mut message: Vec<u8>,
        batches: &mut Vec<Bytes>,
        index: usize,
    ) -> Result<(), BatchError> {
        if let Some(settings) = self.phase.compression() {
            let marker = usize::from(self.header == BatchHeader::RakNet);
            let body = &message[marker + 1..];
            if body.len() >= usize::from(settings.threshold)
                && settings.algorithm != CompressionAlgorithm::None
            {
                self.phase
                    .compress(settings.algorithm, &mut message, marker + 1)?;
                message[marker] = settings.algorithm.batch_id();
                let retained = message.len().saturating_add(8);
                if message.capacity() > retained.saturating_mul(2).max(4096) {
                    message.shrink_to(retained);
                }
            }
        }
        self.check_encoded_size(message.len())?;
        message.reserve(8);
        let message = Bytes::from(message);
        if let Some(slot) = batches.get_mut(index) {
            *slot = message;
        } else {
            batches.push(message);
        }
        Ok(())
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

/// Visits validated packet bytes without allocating ownership handles.
fn visit_packets(mut body: &[u8], count: usize, visit: &mut impl FnMut(&[u8])) {
    for _ in 0..count {
        loop {
            let (length, prefix) = read_length(body, 0)
                .expect("the complete immutable batch was validated before iteration");
            let (entry, rest) = body.split_at(prefix + length as usize);
            body = rest;
            if length != 0 {
                visit(&entry[prefix..]);
                break;
            }
        }
    }
}

/// Validates all boundaries and counts before exposing a cursor, without allocating packet metadata.
#[inline]
fn validate_packets(body: &[u8], maximum: Option<usize>) -> Result<(usize, usize), BatchError> {
    let mut count = 0;
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
            if maximum.is_some() {
                return Err(BatchError::EmptyPacket);
            }
            skipped_empty_packets += 1;
            continue;
        }
        if let Some(maximum) = maximum
            && count == maximum
        {
            return Err(BatchError::TooManyPackets { maximum });
        }
        if length > body.len() - offset {
            return Err(BatchError::TruncatedPacket {
                declared: length,
                remaining: body.len() - offset,
            });
        }
        count += 1;
        offset += length;
    }
    Ok((count, skipped_empty_packets))
}

/// Reads up to five bytes, retaining the low 32 bits like the peer decoder; packet headers remain the protocol codec's responsibility.
#[inline]
fn read_length(bytes: &[u8], offset: usize) -> Result<(u32, usize), BatchError> {
    if let Some(&byte) = bytes.first()
        && byte < 0x80
    {
        return Ok((u32::from(byte), 1));
    }
    let mut value = 0;
    for (index, byte) in bytes.iter().copied().take(5).enumerate() {
        value |= u32::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    Err(BatchError::InvalidPacketLength { offset })
}

/// Writes the shortest u32 packet-length prefix.
pub(crate) fn write_length(mut length: u32, out: &mut Vec<u8>) {
    while length >= 0x80 {
        out.push((length as u8) | 0x80);
        length >>= 7;
    }
    out.push(length as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a codec whose outgoing scratch limit matches one small Snappy block.
    fn bounded(algorithm: CompressionAlgorithm) -> BatchCodec<Negotiated> {
        BatchCodec::new(
            BatchHeader::RakNet,
            BatchLimits {
                max_decoded_bytes: 65536,
                ..BatchLimits::default()
            },
        )
        .negotiate(CompressionSettings {
            algorithm,
            threshold: 0,
        })
    }

    #[test]
    fn retained_snappy_decode_scratch_stays_within_one_block() {
        let mut codec = bounded(CompressionAlgorithm::Snappy);
        for length in [65532, 65533, 3] {
            let input = vec![0x42; length];
            let wire = codec
                .encode(std::slice::from_ref(&input))
                .unwrap()
                .pop()
                .unwrap();
            let DecodeOutcome::Packets { packets, .. } = codec.decode(wire.clone()).unwrap() else {
                panic!("valid batch dropped");
            };
            assert_eq!(
                packets.collect::<Vec<_>>(),
                [Bytes::copy_from_slice(&input)]
            );
            let mut visits = 0;
            codec
                .decode_with(wire, |packet| {
                    assert_eq!(packet, input);
                    visits += 1;
                })
                .unwrap();
            assert_eq!(visits, 1);
            assert!(codec.phase.snappy_scratch.capacity() <= 65536);
        }
    }
}
