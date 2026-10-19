#![doc = include_str!("../README.md")]

mod handoff;
pub mod jsonc;

pub use handoff::{RelayPack, ResourcePackArchive, ResourcePackContentKey, ResourcePackHandoff};

/// Default maximum UTF-8 bytes retained for an advertised pack version.
pub const MAX_PACK_VERSION_BYTES: usize = 256;
