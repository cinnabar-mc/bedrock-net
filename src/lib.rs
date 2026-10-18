#![doc = include_str!("../README.md")]

mod batch;
mod compression;
pub mod encryption;
mod error;
#[cfg(feature = "raknet")]
pub mod raknet;

pub use batch::{BatchCodec, BatchHeader, BatchLimits, DecodeOutcome};
pub use compression::{CompressionAlgorithm, CompressionSettings, UnknownCompressionAlgorithm};
pub use error::{BatchError, DropReason};
