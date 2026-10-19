#![doc = include_str!("../README.md")]

mod batch;
mod compression;
pub mod encryption;
mod error;
#[cfg(feature = "login")]
pub mod login;
#[cfg(feature = "messaging")]
pub mod messaging;
#[cfg(feature = "raknet")]
pub mod raknet;

pub use batch::{
    BatchCodec, BatchHeader, BatchLimits, BatchPackets, BatchPhase, DecodeOutcome, Negotiated,
    Plain,
};
pub use compression::{CompressionAlgorithm, CompressionSettings, UnknownCompressionAlgorithm};
pub use error::{BatchError, DropReason};
