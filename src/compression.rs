use std::borrow::Cow;
#[cfg(target_family = "wasm")]
use std::io::Write;

use bytes::Bytes;
#[cfg(target_family = "wasm")]
use flate2::write::DeflateEncoder;
use flate2::{Decompress, FlushDecompress, Status};

use crate::{BatchError, DropReason};

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
        CompressionAlgorithm::Snappy => snap::raw::Encoder::new()
            .compress_vec(body)
            .map_err(BatchError::Snappy),
        CompressionAlgorithm::None => Ok(body.to_vec()),
    }
}

/// Largest input whose compressed block the encoder retains between batches.
const RETAINED_SNAPPY_INPUT: usize = 65536;

/// Reusable Snappy tables and bounded output for independent batches.
pub(crate) struct SnappyEncoder {
    encoder: snap::raw::Encoder,
    output: Vec<u8>,
}

impl Default for SnappyEncoder {
    fn default() -> Self {
        Self {
            encoder: snap::raw::Encoder::new(),
            output: Vec::new(),
        }
    }
}

impl SnappyEncoder {
    /// Returns one independent block; only inputs up to 64 KiB borrow retained output.
    pub(crate) fn compress(&mut self, body: &[u8]) -> Result<Cow<'_, [u8]>, BatchError> {
        if body.len() > RETAINED_SNAPPY_INPUT {
            return self
                .encoder
                .compress_vec(body)
                .map(Cow::Owned)
                .map_err(BatchError::Snappy);
        }
        let maximum = snap::raw::max_compress_len(body.len());
        if self.output.len() < maximum {
            self.output.reserve_exact(maximum - self.output.len());
            self.output.resize(maximum, 0);
        }
        let length = self
            .encoder
            .compress(body, &mut self.output)
            .map_err(BatchError::Snappy)?;
        Ok(Cow::Borrowed(&self.output[..length]))
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

/// Decodes a block into output sized from its validated header.
pub(crate) fn decompress_snappy_into(body: &[u8], output: &mut [u8]) -> Result<(), snap::Error> {
    snap::raw::Decoder::new()
        .decompress(body, output)
        .map(|_| ())
}

/// Returns the payload of a block holding exactly one literal of `length` bytes.
/// Shares the received storage for incompressible batches instead of copying it.
fn snappy_literal(body: &Bytes, length: usize) -> Option<Bytes> {
    let header = body.iter().position(|byte| byte & 0x80 == 0)? + 1;
    let (&tag, rest) = body.get(header..)?.split_first()?;
    let code = usize::from(tag >> 2);
    let prefix = match code {
        _ if tag & 3 != 0 => return None,
        0..60 => 0,
        _ => code - 59,
    };
    let mut encoded = [0; 4];
    encoded[..prefix].copy_from_slice(rest.get(..prefix)?);
    let literal = if prefix == 0 {
        code
    } else {
        u32::from_le_bytes(encoded) as usize
    };
    (literal.checked_add(1)? == length && rest.len() - prefix == length)
        .then(|| body.slice(body.len() - length..))
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
            if let Some(literal) = snappy_literal(&body, length) {
                return Ok(Ok(literal));
            }
            let mut decoded = vec![0; length];
            Ok(decompress_snappy_into(&body, &mut decoded)
                .map(|()| Bytes::from(decoded))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic inputs at every retained-output and block boundary.
    fn inputs() -> impl Iterator<Item = Vec<u8>> {
        let mut state = 0x9e37_79b9_u32;
        let mut random = move || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        };
        let sizes = [
            0, 1, 2, 31, 32, 33, 1023, 1024, 1025, 4095, 4096, 4097, 16383, 16384, 16385, 65535,
            65536, 65537, 131_072, 200_003,
        ];
        sizes.into_iter().flat_map(move |size| {
            let noise: Vec<u8> = (0..size).map(|_| random()).collect();
            let letters: Vec<u8> = noise
                .iter()
                .map(|byte| b"ACGT"[usize::from(byte & 3)])
                .collect();
            let mut mixed = noise.clone();
            for (index, byte) in mixed.iter_mut().enumerate() {
                if index % 97 > 13 {
                    *byte = (index % 251) as u8;
                }
            }
            [
                noise,
                vec![0x42; size],
                (0..size).map(|index| (index % 251) as u8).collect(),
                letters,
                mixed,
            ]
        })
    }

    #[test]
    fn snappy_blocks_round_trip_within_bounds_and_stay_independent() {
        let mut reused = SnappyEncoder::default();
        for input in inputs() {
            let wire = reused.compress(&input).unwrap().into_owned();
            assert!(wire.len() <= snap::raw::max_compress_len(input.len()));
            assert_eq!(SnappyEncoder::default().compress(&input).unwrap(), wire);
            assert_eq!(
                compress(CompressionAlgorithm::Snappy, &input).unwrap(),
                wire
            );
            let decoded = decompress(SNAPPY_ID, wire.into(), input.len()).unwrap();
            assert_eq!(decoded.unwrap(), input);
            assert!(reused.output.capacity() <= snap::raw::max_compress_len(RETAINED_SNAPPY_INPUT));
        }
    }

    #[test]
    fn single_literal_blocks_share_received_storage() {
        for length in [1, 60, 61, 256, 257, 65536, 65537] {
            let payload: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
            let code = (length - 1) as u32;
            for width in 0..=4_usize {
                if (width == 0 && code >= 60) || (width > 0 && u64::from(code) >> (8 * width) != 0)
                {
                    continue;
                }
                let mut body = Vec::new();
                crate::batch::write_length(length as u32, &mut body);
                if width == 0 {
                    body.push((code as u8) << 2);
                } else {
                    body.push(((59 + width) as u8) << 2);
                    body.extend_from_slice(&code.to_le_bytes()[..width]);
                }
                body.extend_from_slice(&payload);
                let body = Bytes::from(body);
                let decoded = decompress(SNAPPY_ID, body.clone(), length)
                    .unwrap()
                    .unwrap();
                assert_eq!(decoded, payload);
                assert_eq!(decoded.as_ptr(), body[body.len() - length..].as_ptr());
                let mut trailing = body.to_vec();
                trailing.push(0);
                assert!(
                    decompress(SNAPPY_ID, trailing.into(), length)
                        .unwrap()
                        .is_err()
                );
            }
        }
    }
}
