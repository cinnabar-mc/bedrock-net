#![doc = include_str!("../README.md")]

mod batch;
mod compression;
mod error;
#[cfg(feature = "login")]
pub mod login;
#[cfg(feature = "messaging")]
pub mod messaging;

pub use batch::{
    BatchCodec, BatchLimits, BatchPackets, BatchPhase, DecodeOutcome, Negotiated, Plain,
    VisitOutcome,
};
pub use compression::{CompressionAlgorithm, CompressionSettings, UnknownCompressionAlgorithm};
pub use error::{BatchError, DropReason};
