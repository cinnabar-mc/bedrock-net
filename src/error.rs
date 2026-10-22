use thiserror::Error;

/// A batch encoding failure or fatal decoding failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BatchError {
    /// A `RakNet` message had no batch marker.
    #[error("missing batch header")]
    MissingBatchHeader,
    /// A `RakNet` message had a different batch marker.
    #[error("invalid batch header {0:#04x}")]
    InvalidBatchHeader(u8),
    /// Compression was enabled but no algorithm byte followed.
    #[error("missing compression header")]
    MissingCompressionHeader,
    /// The wire message exceeded the configured input/output bound.
    #[error("encoded batch has {actual} bytes, maximum {maximum}")]
    EncodedTooLarge {
        /// Message length, including transport and compression headers.
        actual: usize,
        /// Configured wire limit.
        maximum: usize,
    },
    /// A batch exceeded the configured uncompressed bound.
    #[error("decoded batch exceeds {maximum} bytes")]
    DecodedTooLarge {
        /// Configured decoded limit.
        maximum: usize,
    },
    /// A batch held too many packet entries.
    #[error("batch exceeds {maximum} packets")]
    TooManyPackets {
        /// Configured packet-count limit.
        maximum: usize,
    },
    /// A packet length was truncated or did not terminate within five bytes.
    #[error("invalid packet length at byte {offset}")]
    InvalidPacketLength {
        /// Offset of the length prefix within the decoded batch.
        offset: usize,
    },
    /// A packet length exceeded the bytes remaining in the batch.
    #[error("packet declares {declared} bytes, only {remaining} remain")]
    TruncatedPacket {
        /// Declared packet length.
        declared: usize,
        /// Bytes remaining after the prefix.
        remaining: usize,
    },
    /// An outgoing packet or an accepting-side incoming entry contained no packet bytes.
    #[error("empty packet")]
    EmptyPacket,
    /// An outgoing packet length could not fit a u32 prefix.
    #[error("packet length {0} cannot be represented as u32")]
    PacketTooLarge(usize),
    /// Outgoing DEFLATE compression failed.
    #[error("compress deflate: {0}")]
    Deflate(#[source] std::io::Error),
    /// Outgoing Snappy compression failed.
    #[error("compress snappy: {0}")]
    Snappy(#[source] snap::Error),
}

/// Why one compressed batch was discarded without ending the connection.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DropReason {
    /// The algorithm byte is not implemented.
    #[error("unknown compression algorithm {0:#04x}")]
    UnknownCompression(u8),
    /// A raw DEFLATE stream was invalid.
    #[error("invalid deflate: {0}")]
    InvalidDeflate(#[source] flate2::DecompressError),
    /// A raw DEFLATE stream ended before its final block.
    #[error("truncated deflate stream")]
    TruncatedDeflate,
    /// A raw Snappy block was invalid.
    #[error("invalid snappy: {0}")]
    InvalidSnappy(#[source] snap::Error),
}
