//! Sequential original-archive delivery with one explicit read/flush boundary.

use super::{ServerSessionError as Error, ServerSessionEvent as Event, bounded_metadata};
use crate::packs::{PackTransferLimits, builtins};
use bedrock_protocol::{packets, types::ResourcePackClientResponseData, wire};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const DEFAULT_CHUNK_SIZE: u32 = 100 * 1024;
const MAX_CHUNK_SIZE: u32 = 10 * 1024 * 1024;

#[cfg(test)]
mod tests;

/// Original compressed content and adapter-owned pack classification, without Debug disclosure.
#[derive(Clone)]
pub struct ServerPackContent {
    storage: Storage,
    size: u64,
    hash: Bytes,
    pack_type: u8,
    premium: bool,
}

#[derive(Clone)]
enum Storage {
    Memory(Bytes),
    External,
}

impl ServerPackContent {
    /// Takes the original archive allocation, trimming spare capacity and hashing it once.
    /// Clones share immutable bytes/hash so the world can reuse content across accepted sessions.
    /// Pack type/premium policy comes from the actual world adapter, not inferred client data.
    pub fn new(archive: Vec<u8>, pack_type: u8, premium: bool) -> Self {
        let hash = Bytes::copy_from_slice(&Sha256::digest(&archive));
        let size = archive.len() as u64;
        Self {
            storage: Storage::Memory(Bytes::from(archive.into_boxed_slice())),
            size,
            hash,
            pack_type,
            premium,
        }
    }

    /// Describes an already validated disk/adapter archive without loading it into memory.
    /// The adapter retains the original source lease and serves only requested ranges.
    /// This asserts caller metadata; the core also hashes supplied external bytes in sequence.
    pub fn external(size: u64, sha256: [u8; 32], pack_type: u8, premium: bool) -> Self {
        Self {
            storage: Storage::External,
            size,
            hash: Bytes::copy_from_slice(&sha256),
            pack_type,
            premium,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ChunkPosition {
    archive: usize,
    chunk: u32,
    offset: u64,
    bytes: usize,
}

/// One non-cloneable original-source read, not a world/admission capability.
pub(super) struct ServerChunkRequest {
    position: ChunkPosition,
}

impl ServerChunkRequest {
    /// Index in the original offer/content order; use the same retained source lease.
    pub(super) fn archive_index(&self) -> usize {
        self.position.archive
    }
    /// Original compressed byte offset, without interpreting the archive or content key.
    pub(super) fn offset(&self) -> u64 {
        self.position.offset
    }
    /// Exact nonzero bytes required, bounded by chunk_size and the original archive tail.
    pub(super) fn byte_len(&self) -> usize {
        self.position.bytes
    }
}

struct PendingRead {
    position: ChunkPosition,
    name: wire::Str,
}

/// The exact selected-world offer/stack and original contents aligned with offer order.
/// The adapter validates manifests/content keys; this owner validates wire/transfer consistency.
pub struct ServerPackSnapshot {
    /// Generated capabilities and advertised metadata; moved unchanged into the offer.
    pub offer: packets::ResourcePacksInfo,
    /// Generated application order, subpacks and required policy; moved unchanged into the final stack.
    pub stack: packets::ResourcePackStack,
    /// One original memory/external archive descriptor per offer, in exactly that order.
    pub contents: Vec<ServerPackContent>,
}

/// Caller-selected bounded delivery. The defaults follow the pinned Go delivery owner.
#[derive(Clone, Copy, Debug)]
pub struct ServerPackDelivery {
    /// Shared archive/count/version limits, without client acquisition or cache ownership.
    pub limits: PackTransferLimits,
    /// Maximum payload in one chunk. Zero uses 100 KiB; values above 10 MiB are capped.
    pub chunk_size: u32,
    /// Byte ceiling for generated offer, stack, world definitions and each chunk.
    pub max_metadata_bytes: usize,
}

impl Default for ServerPackDelivery {
    fn default() -> Self {
        Self {
            limits: PackTransferLimits::default(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_metadata_bytes: bedrock_net::BatchLimits::default().max_decoded_bytes,
        }
    }
}

struct Archive {
    id: uuid::Uuid,
    version: String,
    name: wire::Str,
    content: ServerPackContent,
}

enum Phase {
    Offer,
    Transferring,
    Downloaded,
    Stack,
    Complete,
}

pub(super) struct Delivery {
    offer: Option<packets::ResourcePacksInfo>,
    stack: Option<packets::ResourcePackStack>,
    archives: Vec<Archive>,
    selected: Vec<usize>,
    current: usize,
    next_chunk: u32,
    awaiting_flush: bool,
    pending_read: Option<PendingRead>,
    digest: Sha256,
    options: ServerPackDelivery,
    phase: Phase,
}

impl Delivery {
    /// Checks the entire caller snapshot before any LoginSuccess or offer is emitted.
    pub(super) fn new(
        snapshot: ServerPackSnapshot,
        mut options: ServerPackDelivery,
    ) -> Result<Self, Error> {
        options.chunk_size = normalized_chunk_size(options.chunk_size);
        options
            .limits
            .validate()
            .map_err(|_| invalid("invalid accepting pack limits"))?;
        if u64::from(options.chunk_size) > options.limits.max_archive_bytes
            || options.max_metadata_bytes == 0
            || options.chunk_size as usize > options.max_metadata_bytes
            || snapshot.offer.resource_packs.len() != snapshot.contents.len()
            || snapshot.contents.len() > options.limits.max_packs
        {
            return Err(invalid(
                "invalid accepting pack snapshot or delivery bounds",
            ));
        }
        bounded_metadata(
            &snapshot.offer,
            packets::ResourcePacksInfo::ID,
            options.max_metadata_bytes,
        )?;
        bounded_metadata(
            &snapshot.stack,
            packets::ResourcePackStack::ID,
            options.max_metadata_bytes,
        )?;
        let mut total = 0_u64;
        let mut ids = BTreeSet::new();
        let mut archives = Vec::with_capacity(snapshot.contents.len());
        for (info, content) in snapshot.offer.resource_packs.iter().zip(snapshot.contents) {
            let id = info.pack_id_version.pack_uuid;
            let version = info
                .pack_id_version
                .pack_version
                .version
                .to_str()
                .map_err(|_| invalid("invalid accepting pack version"))?;
            let size = content.size;
            total = total
                .checked_add(size)
                .ok_or_else(|| invalid("accepting pack size overflow"))?;
            if id.is_nil()
                || !ids.insert(id)
                || version.is_empty()
                || version.len() > options.limits.max_version_bytes
                || size == 0
                || size != info.pack_size.0
                || size > options.limits.max_archive_bytes
                || total > options.limits.max_stack_bytes
                || chunk_count(size, options.chunk_size).is_none()
            {
                return Err(invalid(
                    "inconsistent accepting pack identity, size or budget",
                ));
            }
            let archive = Archive {
                id,
                version: version.to_owned(),
                name: format!("{id}_{version}").into(),
                content,
            };
            bounded_metadata(
                &archive.data_info(options.chunk_size),
                packets::ResourcePackDataInfo::ID,
                options.max_metadata_bytes,
            )?;
            // Reject an impossible canonical chunk before exposing the offer.
            // Emission separately checks the actual echoed request name.
            let largest_chunk = usize::try_from(size.min(u64::from(options.chunk_size)))
                .map_err(|_| invalid("accepting chunk size overflow"))?;
            let probe = match &archive.content.storage {
                Storage::Memory(bytes) => bytes.slice(..largest_chunk),
                Storage::External => {
                    let mut bytes = Vec::new();
                    bytes
                        .try_reserve_exact(largest_chunk)
                        .map_err(|_| invalid("accepting chunk validation allocation failed"))?;
                    bytes.resize(largest_chunk, 0);
                    Bytes::from(bytes)
                }
            };
            bounded_metadata(
                &packets::ResourcePackChunkData {
                    resource_name: archive.name.clone(),
                    chunk_data: probe,
                    ..Default::default()
                },
                packets::ResourcePackChunkData::ID,
                options.max_metadata_bytes,
            )?;
            archives.push(archive);
        }
        // Download count is bounded by the original offers; the stack may also select built-ins.
        let mut selected_ids = BTreeSet::new();
        for pack in &snapshot.stack.texture_pack_list {
            let id = uuid::Uuid::parse_str(
                pack.pack_id
                    .to_str()
                    .map_err(|_| invalid("invalid accepting stack identity"))?,
            )
            .map_err(|_| invalid("invalid accepting stack identity"))?;
            let version = pack
                .version
                .to_str()
                .map_err(|_| invalid("invalid accepting stack version"))?;
            if !selected_ids.insert(id)
                || version.is_empty()
                || version.len() > options.limits.max_version_bytes
                || (!archives.iter().any(|a| a.id == id && a.version == version)
                    && !builtins::contains(id, version))
            {
                return Err(invalid(
                    "accepting stack contains unavailable or duplicate content",
                ));
            }
        }
        Ok(Self {
            offer: Some(snapshot.offer),
            stack: Some(snapshot.stack),
            archives,
            selected: Vec::new(),
            current: 0,
            next_chunk: 0,
            awaiting_flush: false,
            pending_read: None,
            digest: Sha256::new(),
            options,
            phase: Phase::Offer,
        })
    }

    /// Moves the original offer once; selected bytes remain immutable for the entire connection.
    pub(super) fn start(&mut self) -> Result<packets::ResourcePacksInfo, Error> {
        self.offer.take().ok_or(Error::InvalidState)
    }

    /// Returns owned input while a read/flush prevents admission, instead of queueing it.
    pub(super) fn receive(&mut self, packet: packets::Packet) -> Result<Event, Error> {
        if !matches!(
            packet,
            packets::Packet::ResourcePackClientResponse(_)
                | packets::Packet::ResourcePackChunkRequest(_)
        ) {
            return Ok(Event::Unhandled(Box::new(packet)));
        }
        if matches!(&packet, packets::Packet::ResourcePackClientResponse(response)
            if matches!(response.response, ResourcePackClientResponseData::Cancel { .. }))
        {
            return Err(invalid("client refused accepting packs"));
        }
        if self.awaiting_flush || self.pending_read.is_some() {
            return Err(Error::InvalidState);
        }
        match packet {
            packets::Packet::ResourcePackClientResponse(response) => match response.response {
                ResourcePackClientResponseData::Cancel { .. } => {
                    Err(invalid("client refused accepting packs"))
                }
                ResourcePackClientResponseData::Downloading {
                    downloading_packs, ..
                } => {
                    if !matches!(self.phase, Phase::Offer)
                        || downloading_packs.is_empty()
                        || downloading_packs.len() > u16::MAX as usize
                    {
                        return Err(Error::InvalidState);
                    }
                    let mut selected = BTreeSet::new();
                    for name in downloading_packs {
                        let index = self.lookup(&name, true)?;
                        selected.insert(index);
                    }
                    self.selected = selected.into_iter().collect();
                    self.phase = Phase::Transferring;
                    Ok(Event::Send(vec![self.data_info().into()]))
                }
                ResourcePackClientResponseData::DownloadingFinished { .. } => {
                    if !matches!(self.phase, Phase::Offer | Phase::Downloaded) {
                        return Err(Error::InvalidState);
                    }
                    self.phase = Phase::Stack;
                    Ok(Event::Send(vec![
                        self.stack.take().ok_or(Error::InvalidState)?.into(),
                    ]))
                }
                ResourcePackClientResponseData::ResourcePackStackFinished { .. } => {
                    if !matches!(self.phase, Phase::Stack) {
                        return Err(Error::InvalidState);
                    }
                    self.phase = Phase::Complete;
                    self.archives.clear();
                    self.selected.clear();
                    Ok(Event::ReadyForWorld)
                }
            },
            packets::Packet::ResourcePackChunkRequest(request) => {
                if !matches!(self.phase, Phase::Transferring) {
                    return Err(Error::InvalidState);
                }
                let index = self.lookup(&request.resource_name, false)?;
                if index != self.selected[self.current]
                    || request.chunk.0 < 0
                    || request.chunk.0 as u32 != self.next_chunk
                {
                    return Err(invalid("invalid accepting pack chunk sequence"));
                }
                let archive = &self.archives[index];
                let offset = u64::from(self.next_chunk) * u64::from(self.options.chunk_size);
                if offset >= archive.content.size {
                    return Err(invalid("accepting chunk exceeds original archive"));
                }
                let position = ChunkPosition {
                    archive: index,
                    chunk: self.next_chunk,
                    offset,
                    bytes: usize::try_from(
                        (archive.content.size - offset).min(u64::from(self.options.chunk_size)),
                    )
                    .map_err(|_| invalid("accepting chunk size overflow"))?,
                };
                match &archive.content.storage {
                    Storage::Memory(bytes) => {
                        let start = usize::try_from(offset)
                            .map_err(|_| invalid("accepting chunk offset overflow"))?;
                        let chunk = bytes.slice(start..start + position.bytes);
                        self.emit_chunk(position, request.resource_name, chunk)
                    }
                    Storage::External => {
                        // This short control outlives its input, so release the peer's decoded batch.
                        self.pending_read = Some(PendingRead {
                            position,
                            name: Bytes::copy_from_slice(request.resource_name.as_bytes()).into(),
                        });
                        Ok(Event::ReadChunk(ServerChunkRequest { position }))
                    }
                }
            }
            _ => unreachable!("pack packet was classified"),
        }
    }

    /// Consumes only the current bounded original-source read; late/cross-position completions fail.
    pub(super) fn supply(
        &mut self,
        request: &ServerChunkRequest,
        bytes: Vec<u8>,
    ) -> Result<Event, Error> {
        let pending = self.pending_read.as_ref().ok_or(Error::InvalidState)?;
        if request.position != pending.position || bytes.len() != pending.position.bytes {
            return Err(invalid(
                "accepting external read does not match its pending range",
            ));
        }
        let pending = self.pending_read.take().expect("pending read checked");
        self.emit_chunk(
            pending.position,
            pending.name,
            Bytes::from(bytes.into_boxed_slice()),
        )
    }

    /// Shares the same one-chunk flush boundary for memory and external storage.
    fn emit_chunk(
        &mut self,
        position: ChunkPosition,
        name: wire::Str,
        bytes: Bytes,
    ) -> Result<Event, Error> {
        let archive = &self.archives[position.archive];
        if matches!(archive.content.storage, Storage::External) {
            self.digest.update(&bytes);
            if position.offset + bytes.len() as u64 == archive.content.size {
                let digest: [u8; 32] = self.digest.clone().finalize().into();
                if digest[..] != archive.content.hash[..] {
                    return Err(invalid(
                        "accepting external archive changed its advertised SHA-256",
                    ));
                }
            }
        }
        let packet = packets::ResourcePackChunkData {
            resource_name: name,
            chunk_id: wire::U32LE(position.chunk),
            byte_offset: wire::U64LE(position.offset),
            chunk_data: bytes,
        };
        bounded_metadata(
            &packet,
            packets::ResourcePackChunkData::ID,
            self.options.max_metadata_bytes,
        )?;
        self.awaiting_flush = true;
        Ok(Event::Chunk(packet))
    }

    /// Advances only after actual flush; the next pack metadata can follow the completed last chunk.
    pub(super) fn flushed(&mut self) -> Result<Vec<packets::Packet>, Error> {
        if !self.awaiting_flush || !matches!(self.phase, Phase::Transferring) {
            return Err(Error::InvalidState);
        }
        self.awaiting_flush = false;
        self.next_chunk += 1;
        let archive = &self.archives[self.selected[self.current]];
        if u64::from(self.next_chunk) * u64::from(self.options.chunk_size) < archive.content.size {
            return Ok(Vec::new());
        }
        self.current += 1;
        self.next_chunk = 0;
        self.digest = Sha256::new();
        if self.current == self.selected.len() {
            self.phase = Phase::Downloaded;
            Ok(Vec::new())
        } else {
            Ok(vec![self.data_info().into()])
        }
    }

    /// Reuses the selected output budget for actual world definition validation.
    pub(super) fn metadata_limit(&self) -> usize {
        self.options.max_metadata_bytes
    }

    /// Downloads require an exact optional version; chunk routing uses only UUID, like the Go owner.
    fn lookup(&self, name: &wire::Str, check_version: bool) -> Result<usize, Error> {
        if name.as_bytes().len()
            > uuid::fmt::Hyphenated::LENGTH
                .saturating_add(1)
                .saturating_add(self.options.limits.max_version_bytes)
        {
            return Err(invalid("accepting pack request identity exceeds its limit"));
        }
        let name = name
            .to_str()
            .map_err(|_| invalid("invalid accepting pack request identity"))?;
        let (id, version) = name
            .split_once('_')
            .map_or((name, None), |(id, v)| (id, Some(v)));
        let id = uuid::Uuid::parse_str(id)
            .map_err(|_| invalid("invalid accepting pack request identity"))?;
        let mut canonical = [0_u8; uuid::fmt::Hyphenated::LENGTH];
        if name.split('_').next() != Some(id.hyphenated().encode_lower(&mut canonical)) {
            return Err(invalid(
                "accepting pack request uses a different identity spelling",
            ));
        }
        self.archives
            .iter()
            .position(|a| {
                a.id == id
                    && (!check_version || version.is_none_or(|v| v.is_empty() || v == a.version))
            })
            .ok_or_else(|| invalid("accepting pack request was not advertised"))
    }

    /// Derives size/count/SHA only from the original selected archive, never a peer-provided value.
    fn data_info(&self) -> packets::ResourcePackDataInfo {
        let archive = &self.archives[self.selected[self.current]];
        archive.data_info(self.options.chunk_size)
    }
}

impl Archive {
    /// Uses the same immutable metadata for validation and every emitted DataInfo.
    fn data_info(&self, chunk_size: u32) -> packets::ResourcePackDataInfo {
        packets::ResourcePackDataInfo {
            resource_name: self.name.clone(),
            chunk_size: wire::U32LE(chunk_size),
            number_of_chunks: wire::U32LE(
                chunk_count(self.content.size, chunk_size).expect("validated archive count"),
            ),
            file_size: wire::U64LE(self.content.size),
            file_hash: self.content.hash.clone(),
            is_premium_pack: self.content.premium,
            pack_type: wire::U8(self.content.pack_type),
        }
    }
}

/// Uses only static diagnostics at the accepting peer boundary.
fn invalid(reason: &'static str) -> Error {
    Error::InvalidData(reason)
}

/// Uses the same pinned delivery default and maximum for all archive storage kinds.
fn normalized_chunk_size(chunk_size: u32) -> u32 {
    if chunk_size == 0 {
        DEFAULT_CHUNK_SIZE
    } else {
        chunk_size.min(MAX_CHUNK_SIZE)
    }
}

/// Each signed request index can address one of up to 2^31 chunks, matching the Go owner.
fn chunk_count(size: u64, chunk_size: u32) -> Option<u32> {
    if chunk_size == 0 {
        return None;
    }
    let count = size.div_ceil(u64::from(chunk_size));
    (count <= i32::MAX as u64 + 1).then_some(count as u32)
}
