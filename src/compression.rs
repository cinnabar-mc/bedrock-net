use std::borrow::Cow;
#[cfg(target_family = "wasm")]
use std::io::Write;

use bytes::Bytes;
#[cfg(target_family = "wasm")]
use flate2::write::DeflateEncoder;
use flate2::{Decompress, FlushDecompress, Status};

use crate::{BatchError, DropReason};

mod snappy;

const DEFLATE_ID: u8 = 0;
const SNAPPY_ID: u8 = 1;
const UNCOMPRESSED_ID: u8 = u8::MAX;

/// Algorithms accepted in `NetworkSettings` and batch compression headers.
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
    /// Returns the algorithm's `NetworkSettings` identifier.
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

/// An unsupported `NetworkSettings` compression identifier.
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

/// Compresses a batch body without adding any protocol headers.
pub(crate) fn compress(
    algorithm: CompressionAlgorithm,
    body: &[u8],
) -> Result<Vec<u8>, BatchError> {
    match algorithm {
        CompressionAlgorithm::Deflate => compress_deflate(body),
        CompressionAlgorithm::Snappy => {
            SnappyEncoder::default().compress(body).map(Cow::into_owned)
        }
        CompressionAlgorithm::None => Ok(body.to_vec()),
    }
}

/// Reusable matching tables and initialized output for independent Snappy batches.
#[derive(Default)]
pub(crate) struct SnappyEncoder(snappy::Encoder);

impl SnappyEncoder {
    /// Compresses one whole input, resetting matching state before emitting its own block.
    pub(crate) fn compress(&mut self, body: &[u8]) -> Result<Cow<'_, [u8]>, BatchError> {
        let maximum = snap::raw::max_compress_len(body.len());
        if maximum == 0 {
            return snap::raw::Encoder::new()
                .compress_vec(body)
                .map(Cow::Owned)
                .map_err(BatchError::Snappy);
        }
        Ok(self.0.compress(body))
    }
}

/// Compresses one complete native batch using raw DEFLATE at level six.
#[cfg(not(target_family = "wasm"))]
fn compress_deflate(body: &[u8]) -> Result<Vec<u8>, BatchError> {
    let mut encoder = libdeflater::Compressor::new(libdeflater::CompressionLvl::new(6).unwrap());
    let mut out = vec![0; encoder.deflate_compress_bound(body.len())];
    let length = encoder
        .deflate_compress(body, &mut out)
        .map_err(|error| BatchError::Deflate(std::io::Error::other(error)))?;
    out.truncate(length);
    Ok(out)
}

/// Keeps level-six compression portable on WebAssembly without a native dependency.
#[cfg(target_family = "wasm")]
fn compress_deflate(body: &[u8]) -> Result<Vec<u8>, BatchError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), flate2::Compression::new(6));
    encoder.write_all(body).map_err(BatchError::Deflate)?;
    encoder.finish().map_err(BatchError::Deflate)
}

/// Uses the checked hot loop before falling back to the reference decoder's diagnostics.
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
) -> Result<Result<Bytes, DropReason>, BatchError> {
    match id {
        DEFLATE_ID => inflate(&body, maximum),
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
fn inflate(body: &[u8], maximum: usize) -> Result<Result<Bytes, DropReason>, BatchError> {
    let mut decoder = Decompress::new(false);
    let mut input = body;
    let mut decoded = Vec::new();
    let mut scratch = [0; 8192];
    loop {
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let status = decoder.decompress(input, &mut scratch, FlushDecompress::None);
        // Each delta is bounded by this call's input or fixed-size output slice.
        let consumed = usize::try_from(decoder.total_in() - before_in)
            .expect("consumed bytes fit the input slice");
        let produced = usize::try_from(decoder.total_out() - before_out)
            .expect("produced bytes fit the scratch buffer");
        if produced > maximum - decoded.len() {
            return Err(BatchError::DecodedTooLarge { maximum });
        }
        let status = match status {
            Ok(status) => status,
            Err(error) => return Ok(Err(DropReason::InvalidDeflate(error))),
        };
        decoded.extend_from_slice(&scratch[..produced]);
        input = &input[consumed..];
        if status == Status::StreamEnd {
            return Ok(Ok(Bytes::from(decoded)));
        }
        if consumed == 0 && produced == 0 {
            return Ok(Err(DropReason::TruncatedDeflate));
        }
    }
}
