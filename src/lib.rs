#![doc = include_str!("../README.md")]

mod batch;
mod compression;
mod error;

pub use batch::{BatchCodec, BatchHeader, BatchLimits, DecodeOutcome};
pub use compression::{CompressionAlgorithm, CompressionSettings, UnknownCompressionAlgorithm};
pub use error::{BatchError, DropReason};
