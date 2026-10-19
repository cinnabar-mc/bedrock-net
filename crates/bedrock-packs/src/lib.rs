#![doc = include_str!("../README.md")]

mod handoff;
pub mod jsonc;

pub use handoff::{RelayPack, ResourcePackArchive, ResourcePackContentKey, ResourcePackHandoff};

/// Default maximum archives retained from one server offer.
pub const MAX_PACKS: usize = 32;
/// Default maximum compressed bytes retained for one archive.
pub const MAX_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;
/// Default maximum compressed archive bytes retained for one selected stack.
pub const MAX_STACK_ARCHIVE_BYTES: usize = 128 * 1024 * 1024;
/// Default maximum UTF-8 bytes retained for an advertised pack version.
pub const MAX_PACK_VERSION_BYTES: usize = 256;
