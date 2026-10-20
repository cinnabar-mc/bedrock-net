use bytes::Bytes;
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};

use crate::{BatchError, DropReason};

mod snappy;

const DEFLATE_ID: u8 = 0;
const SNAPPY_ID: u8 = 1;
const UNCOMPRESSED_ID: u8 = u8::MAX;
// Keep each small matching table and input block within a small working set.
const SNAPPY_MATCH_BYTES: usize = 8192;

/// Algorithms accepted in NetworkSettings and batch compression headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompressionAlgorithm {
    /// Raw DEFLATE, named Zlib by the protocol.
    Deflate,
    /// A raw Snappy block.
    Snappy,
    /// Uncompressed bytes with the no-compression marker.
    None,
}

impl CompressionAlgorithm {
    /// Returns the algorithm's NetworkSettings identifier.
    pub const fn network_id(self) -> u16 {
        match self {
            Self::Deflate => DEFLATE_ID as u16,
            Self::Snappy => SNAPPY_ID as u16,
            Self::None => u16::MAX,
        }
    }

    /// Returns the algorithm's single-byte batch marker.
    pub(crate) const fn batch_id(self) -> u8 {
        match self {
            Self::Deflate => DEFLATE_ID,
            Self::Snappy => SNAPPY_ID,
            Self::None => UNCOMPRESSED_ID,
        }
    }
}

impl TryFrom<u16> for CompressionAlgorithm {
    type Error = UnknownCompressionAlgorithm;

    fn try_from(id: u16) -> Result<Self, Self::Error> {
        match id {
            id if id == u16::from(DEFLATE_ID) => Ok(Self::Deflate),
            id if id == u16::from(SNAPPY_ID) => Ok(Self::Snappy),
            u16::MAX => Ok(Self::None),
            _ => Err(UnknownCompressionAlgorithm(id)),
        }
    }
}

/// An unsupported NetworkSettings compression identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("unknown network compression algorithm {0}")]
pub struct UnknownCompressionAlgorithm(pub u16);

/// Outgoing compression selected by the network handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompressionSettings {
    /// Algorithm used for outgoing batches at or above the threshold.
    pub algorithm: CompressionAlgorithm,
    /// Uncompressed batch byte count below which compression is bypassed.
    pub threshold: u16,
}

/// Per-connection scratch and lazily allocated compressors, reset between independent batches.
#[derive(Default)]
pub(crate) struct Encoder {
    pub(crate) body: Vec<u8>,
    flate: Option<Compress>,
    snappy: snappy::Encoder,
    small_snappy: Option<(snipsnap::raw::Encoder, Vec<u8>)>,
}

impl Encoder {
    /// Appends compressed scratch bytes directly to the transport envelope.
    pub(crate) fn compress(
        &mut self,
        algorithm: CompressionAlgorithm,
        out: &mut Vec<u8>,
    ) -> Result<(), BatchError> {
        match algorithm {
            CompressionAlgorithm::Deflate => {
                let encoder = self
                    .flate
                    .get_or_insert_with(|| Compress::new(Compression::fast(), false));
                encoder.reset();
                let mut input = self.body.as_slice();
                loop {
                    out.reserve(8192);
                    let before = encoder.total_in();
                    let before_out = out.len();
                    let status = encoder
                        .compress_vec(input, out, FlushCompress::Finish)
                        .map_err(|error| BatchError::Deflate(std::io::Error::other(error)))?;
                    input = &input[(encoder.total_in() - before) as usize..];
                    if status == Status::StreamEnd {
                        break;
                    }
                    if encoder.total_in() == before && out.len() == before_out {
                        return Err(BatchError::Deflate(std::io::Error::other(
                            "DEFLATE compressor made no progress",
                        )));
                    }
                }
            }
            CompressionAlgorithm::Snappy => {
                if self.body.len() <= 65536 {
                    let (encoder, scratch) = self
                        .small_snappy
                        .get_or_insert_with(|| (snipsnap::raw::Encoder::new(), Vec::new()));
                    // Independent match blocks share one raw Snappy length prefix.
                    crate::batch::write_length(self.body.len() as u32, out);
                    for block in self.body.chunks(SNAPPY_MATCH_BYTES) {
                        let maximum = snap::raw::max_compress_len(block.len());
                        if maximum > scratch.len() {
                            scratch.reserve_exact(maximum - scratch.len());
                            scratch.resize(maximum, 0);
                        }
                        let length = match encoder.compress(block, scratch) {
                            Ok(length) => length,
                            Err(_) => snap::raw::Encoder::new()
                                .compress(block, scratch)
                                .map_err(BatchError::Snappy)?,
                        };
                        let header = scratch[..length]
                            .iter()
                            .position(|byte| byte & 128 == 0)
                            .expect("encoder emits a complete block length")
                            + 1;
                        out.extend_from_slice(&scratch[header..length]);
                    }
                } else if snap::raw::max_compress_len(self.body.len()) == 0 {
                    let compressed = snap::raw::Encoder::new()
                        .compress_vec(&self.body)
                        .map_err(BatchError::Snappy)?;
                    out.extend_from_slice(&compressed);
                } else {
                    self.snappy.compress(&self.body, out);
                }
            }
            CompressionAlgorithm::None => out.extend_from_slice(&self.body),
        }
        Ok(())
    }
}

impl std::fmt::Debug for Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encoder").finish_non_exhaustive()
    }
}

/// Decodes into initialized storage whose length matches the already checked declaration.
pub(crate) fn decompress_snappy_into(body: &[u8], output: &mut [u8]) -> Result<(), snap::Error> {
    if snappy::decompress_into(body, output).is_some() {
        return Ok(());
    }
    snap::raw::Decoder::new()
        .decompress(body, output)
        .map(|_| ())
}

/// Bounds decompression and distinguishes a discarded payload from a fatal limit violation.
pub(crate) fn decompress(
    id: u8,
    body: Bytes,
    maximum: usize,
    decoder: &std::sync::Mutex<Option<Decompress>>,
) -> Result<Result<Bytes, DropReason>, BatchError> {
    match id {
        DEFLATE_ID => {
            let mut decoder = decoder.lock().unwrap_or_else(|error| error.into_inner());
            let flate = decoder.get_or_insert_with(|| Decompress::new(false));
            flate.reset(false);
            inflate(flate, &body, maximum)
        }
        SNAPPY_ID => {
            let length = match snap::raw::decompress_len(&body) {
                Ok(length) => length,
                Err(error) => return Ok(Err(DropReason::InvalidSnappy(error))),
            };
            if length > maximum {
                return Err(BatchError::DecodedTooLarge { maximum });
            }
            if let Some(decoded) = snappy::decompress(&body, length) {
                return Ok(Ok(decoded));
            }
            Ok(snap::raw::Decoder::new()
                .decompress_vec(&body)
                .map(Bytes::from)
                .map_err(DropReason::InvalidSnappy))
        }
        UNCOMPRESSED_ID => {
            if body.len() > maximum {
                return Err(BatchError::DecodedTooLarge { maximum });
            }
            Ok(Ok(body))
        }
        _ => Ok(Err(DropReason::UnknownCompression(id))),
    }
}

/// Inflates incrementally, requiring a final block and stopping at the decoded-byte limit.
fn inflate(
    decoder: &mut Decompress,
    body: &[u8],
    maximum: usize,
) -> Result<Result<Bytes, DropReason>, BatchError> {
    let mut input = body;
    let ceiling = maximum.saturating_add(1);
    let mut decoded = Vec::with_capacity(body.len().saturating_mul(2).max(8192).min(ceiling));
    loop {
        if decoded.len() == decoded.capacity() {
            decoded.reserve_exact(decoded.len().max(8192).min(ceiling - decoded.len()));
        }
        let before_in = decoder.total_in();
        let before_out = decoded.len();
        let status = decoder.decompress_vec(input, &mut decoded, FlushDecompress::None);
        // Each delta is bounded by this call's input slice and available output capacity.
        let consumed = usize::try_from(decoder.total_in() - before_in)
            .expect("consumed bytes fit the input slice");
        if decoded.len() > maximum {
            return Err(BatchError::DecodedTooLarge { maximum });
        }
        let status = match status {
            Ok(status) => status,
            Err(error) => return Ok(Err(DropReason::InvalidDeflate(error))),
        };
        input = &input[consumed..];
        if status == Status::StreamEnd {
            return Ok(Ok(Bytes::from(decoded)));
        }
        if consumed == 0 && decoded.len() == before_out {
            return Ok(Err(DropReason::TruncatedDeflate));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_snappy_match_blocks_keep_one_length_and_bounded_scratch() {
        let mut encoder = Encoder::default();
        for length in [8191, 8192, 8193, 65535, 65536, 1] {
            encoder.body = (0..length).map(|index| (index % 251) as u8).collect();
            let mut out = Vec::new();
            encoder
                .compress(CompressionAlgorithm::Snappy, &mut out)
                .unwrap();
            assert_eq!(
                snap::raw::Decoder::new().decompress_vec(&out).unwrap(),
                encoder.body
            );
            let (_, scratch) = encoder.small_snappy.as_ref().unwrap();
            assert!(scratch.len() <= snap::raw::max_compress_len(SNAPPY_MATCH_BYTES));
            assert!(scratch.capacity() <= snap::raw::max_compress_len(SNAPPY_MATCH_BYTES));
        }
    }
}
