//! Caller-driven chunk bookkeeping and server-selected stack assembly.

use super::{PackError, PackMetadata, PackTransferLimits, RetainedOffer};
use super::{invalid, pack_id};
use bedrock_packs::{ResourcePackArchive, ResourcePackHandoff};
use bedrock_protocol::{packets, types::PackInfoData, wire};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};

/// A completed transfer may be intentionally excluded from application admission.
pub(super) enum Completion {
    Archive(Arc<Vec<u8>>),
    Excluded,
}

/// Reserves offered archives and bounds size changes without making optional content mandatory.
pub(super) struct Budget {
    transferred: u64,
    retained: u64,
    limits: PackTransferLimits,
}

impl Budget {
    /// Reuses the transfer's admitted policy for final stack assembly.
    pub(super) fn limits(&self) -> PackTransferLimits {
        self.limits
    }

    /// Selects bounded first offers; excluded entries remain subject to final stack policy.
    pub(super) fn offers(
        offers: Vec<PackInfoData>,
        limits: PackTransferLimits,
    ) -> (Vec<Download>, Self) {
        let mut downloads = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut retained = 0_u64;
        let mut skipped = 0_usize;
        for offer in offers {
            let total = retained.checked_add(offer.pack_size.0);
            if seen.contains(&offer.pack_id_version.pack_uuid)
                || downloads.len() >= usize::from(u16::MAX)
                || limits
                    .max_packs
                    .is_some_and(|limit| downloads.len() >= limit)
                || limits
                    .max_archive_bytes
                    .is_some_and(|limit| offer.pack_size.0 > limit)
                || total.is_none_or(|total| {
                    total > isize::MAX as u64
                        || limits.max_stack_bytes.is_some_and(|limit| total > limit)
                        || limits.max_transfer_bytes.is_some_and(|limit| total > limit)
                })
            {
                skipped += 1;
                continue;
            }
            match Download::new(offer, limits) {
                Ok(download) => {
                    seen.insert(download.offer.pack_id_version.pack_uuid);
                    retained = total.expect("admitted offer total is representable");
                    downloads.push(download);
                }
                Err(_) => skipped += 1,
            }
        }
        if skipped != 0 {
            tracing::warn!(
                skipped,
                "skipped duplicate, invalid or over-budget pack offers"
            );
        }
        (
            downloads,
            Self {
                transferred: retained,
                retained,
                limits,
            },
        )
    }

    /// Commits actual preload retention and releases its entire in-band reservation.
    pub(super) fn preload(
        &mut self,
        download: &mut Download,
        archive: Vec<u8>,
    ) -> Result<(), PackError> {
        let size = archive.len() as u64;
        if download.complete.is_some() || size > download.size {
            return Err(invalid(
                "preloaded archive exceeds its offer or repeats completion",
            ));
        }
        let retained = self
            .retained
            .checked_sub(download.size)
            .and_then(|total| total.checked_add(size))
            .ok_or_else(|| invalid("pack admission accounting is invalid"))?;
        let transferred = self
            .transferred
            .checked_sub(download.size)
            .ok_or_else(|| invalid("pack transfer accounting is invalid"))?;
        self.retained = retained;
        self.transferred = transferred;
        download.size = size;
        download.complete = Some(Completion::Archive(Arc::new(archive)));
        Ok(())
    }

    /// Consumes a bounded transfer even when its updated size prevents application admission.
    pub(super) fn begin(
        &mut self,
        download: &mut Download,
        info: packets::ResourcePackDataInfo,
    ) -> Result<Vec<packets::ResourcePackChunkRequest>, PackError> {
        let transferred = self
            .transferred
            .checked_sub(download.size)
            .and_then(|total| total.checked_add(info.file_size.0))
            .filter(|total| {
                self.limits
                    .max_transfer_bytes
                    .is_none_or(|limit| *total <= limit)
            })
            .ok_or_else(|| invalid("pack transfers exceed memory budget"))?;
        let retained = self
            .retained
            .checked_sub(download.size)
            .ok_or_else(|| invalid("pack admission accounting is invalid"))?;
        let candidate = retained.checked_add(info.file_size.0);
        let retain = self
            .limits
            .max_archive_bytes
            .is_none_or(|limit| info.file_size.0 <= limit)
            && candidate.is_some_and(|total| {
                total <= isize::MAX as u64
                    && self
                        .limits
                        .max_stack_bytes
                        .is_none_or(|limit| total <= limit)
            });
        let size = info.file_size.0;
        let requests = download.begin(info, retain)?;
        self.transferred = transferred;
        self.retained = retained + if retain { size } else { 0 };
        Ok(requests)
    }
}

const FRAGMENT_PAGE_BYTES: u64 = 4096;
const CHUNKS_PER_BITMAP: u32 = 4096;

/// Sparse payload pages and chunk bits keep tiny reordered chunks from allocating one node each.
#[derive(Default)]
struct Fragments {
    pages: BTreeMap<u64, Vec<u8>>,
    received: BTreeMap<u32, Box<[u64; 64]>>,
}

impl Fragments {
    /// Checks receipt without tying request replenishment to contiguous writes.
    fn contains(&self, index: u32) -> bool {
        self.received
            .get(&(index / CHUNKS_PER_BITMAP))
            .is_some_and(|bits| {
                bits[(index % CHUNKS_PER_BITMAP / 64) as usize] & (1 << (index % 64)) != 0
            })
    }

    /// Clears one receipt bit and releases an empty bitmap page.
    fn take(&mut self, index: u32) -> bool {
        let key = index / CHUNKS_PER_BITMAP;
        let Some(bits) = self.received.get_mut(&key) else {
            return false;
        };
        let word = &mut bits[(index % CHUNKS_PER_BITMAP / 64) as usize];
        let mask = 1 << (index % 64);
        if *word & mask == 0 {
            return false;
        }
        *word &= !mask;
        if bits.iter().all(|word| *word == 0) {
            self.received.remove(&key);
        }
        true
    }

    /// Copies received bytes into lazy archive-offset pages, independent of chunk granularity.
    fn insert(
        &mut self,
        index: u32,
        mut offset: u64,
        size: u64,
        mut bytes: &[u8],
    ) -> Result<(), PackError> {
        while !bytes.is_empty() {
            let page = offset / FRAGMENT_PAGE_BYTES;
            let length = (size - page * FRAGMENT_PAGE_BYTES).min(FRAGMENT_PAGE_BYTES) as usize;
            let data = match self.pages.entry(page) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let mut data = Vec::new();
                    data.try_reserve_exact(length)
                        .map_err(|_| invalid("pack allocation failed"))?;
                    data.resize(length, 0);
                    entry.insert(data)
                }
            };
            let start = (offset % FRAGMENT_PAGE_BYTES) as usize;
            let copied = bytes.len().min(data.len() - start);
            data[start..start + copied].copy_from_slice(&bytes[..copied]);
            offset += copied as u64;
            bytes = &bytes[copied..];
        }
        let bits = self
            .received
            .entry(index / CHUNKS_PER_BITMAP)
            .or_insert_with(|| Box::new([0; 64]));
        bits[(index % CHUNKS_PER_BITMAP / 64) as usize] |= 1 << (index % 64);
        Ok(())
    }
}

pub(super) struct Download {
    pub(super) offer: PackInfoData,
    pub(super) name: wire::Str,
    pub(super) size: u64,
    pub(super) complete: Option<Completion>,
    chunk_size: u32,
    chunk_count: u32,
    hash: [u8; 32],
    digest: Sha256,
    retain: bool,
    requested: u32,
    received: u32,
    next_write: u32,
    fragments: Fragments,
    bytes: Vec<u8>,
    request_window: u32,
}

impl Download {
    /// Retains only validated offer identity; all bytes are reserved as they arrive.
    pub(super) fn new(offer: PackInfoData, limits: PackTransferLimits) -> Result<Self, PackError> {
        let version = offer
            .pack_id_version
            .pack_version
            .version
            .to_str()
            .map_err(|_| invalid("pack version is not UTF-8"))?;
        if version.is_empty() || version.len() > limits.max_version_bytes {
            return Err(invalid("pack version exceeds identity limit"));
        }
        if offer.pack_size.0 > isize::MAX as u64 {
            return Err(invalid("pack archive size is not representable"));
        }
        let name = format!("{}_{}", offer.pack_id_version.pack_uuid, version).into();
        Ok(Self {
            size: offer.pack_size.0,
            offer,
            name,
            complete: None,
            chunk_size: 0,
            chunk_count: 0,
            hash: [0; 32],
            digest: Sha256::new(),
            retain: true,
            requested: 0,
            received: 0,
            next_write: 0,
            fragments: Fragments::default(),
            bytes: Vec::new(),
            request_window: limits.request_window,
        })
    }

    /// Starts one bounded chunk transfer; the advertised count is informational.
    fn begin(
        &mut self,
        info: packets::ResourcePackDataInfo,
        retain: bool,
    ) -> Result<Vec<packets::ResourcePackChunkRequest>, PackError> {
        if self.chunk_size != 0 || self.complete.is_some() {
            return Err(invalid("repeated pack data info"));
        }
        self.check_name(&info.resource_name)?;
        if info.file_size.0 == 0
            || info.file_size.0 > isize::MAX as u64
            || info.chunk_size.0 == 0
            || info.file_hash.len() != 32
        {
            return Err(invalid("invalid pack size, chunk size or SHA-256"));
        }
        let count = info.file_size.0.div_ceil(info.chunk_size.0.into());
        self.chunk_count = u32::try_from(count)
            .ok()
            .filter(|count| *count <= i32::MAX as u32)
            .ok_or_else(|| invalid("pack chunk count exceeds transfer budget"))?;
        self.size = info.file_size.0;
        self.retain = retain;
        self.chunk_size = info.chunk_size.0;
        self.hash.copy_from_slice(&info.file_hash);
        // This short name outlives its packet, so release the packet's decoded batch.
        self.name = Bytes::copy_from_slice(info.resource_name.as_bytes()).into();
        Ok(self.requests())
    }

    /// Accepts requested chunks in any order and verifies the completed original archive.
    pub(super) fn chunk(
        &mut self,
        chunk: packets::ResourcePackChunkData,
    ) -> Result<Vec<packets::ResourcePackChunkRequest>, PackError> {
        self.check_name(&chunk.resource_name)?;
        let index = chunk.chunk_id.0;
        if self.chunk_size == 0 || index >= self.requested {
            return Err(invalid("pack chunk was not requested"));
        }
        if index < self.next_write || self.fragments.contains(index) {
            tracing::debug!("skipped duplicate pack chunk");
            return Ok(Vec::new());
        }
        let offset = u64::from(index) * u64::from(self.chunk_size);
        let expected = (self.size - offset).min(u64::from(self.chunk_size));
        if chunk.chunk_data.len() as u64 != expected {
            return Err(invalid("pack chunk length does not match remaining data"));
        }
        self.received += 1;
        if index == self.next_write {
            self.append(&chunk.chunk_data)?;
            self.next_write += 1;
            while self.fragments.take(self.next_write) {
                let start = u64::from(self.next_write) * u64::from(self.chunk_size);
                let end = (start + u64::from(self.chunk_size)).min(self.size);
                let mut offset = start;
                while offset < end {
                    let page = offset / FRAGMENT_PAGE_BYTES;
                    let position = (offset % FRAGMENT_PAGE_BYTES) as usize;
                    let bytes = self
                        .fragments
                        .pages
                        .get(&page)
                        .expect("received chunk has pages");
                    let length = (end - offset).min(bytes.len() as u64 - position as u64) as usize;
                    self.digest.update(&bytes[position..position + length]);
                    if self.retain {
                        self.bytes
                            .try_reserve(length)
                            .map_err(|_| invalid("pack allocation failed"))?;
                        self.bytes
                            .extend_from_slice(&bytes[position..position + length]);
                    }
                    offset += length as u64;
                }
                self.next_write += 1;
            }
            // A page can contain later chunks; release it only after its whole range is consumed.
            let consumed = (u64::from(self.next_write) * u64::from(self.chunk_size)).min(self.size);
            while let Some((&page, bytes)) = self.fragments.pages.first_key_value() {
                if page * FRAGMENT_PAGE_BYTES + bytes.len() as u64 > consumed {
                    break;
                }
                self.fragments.pages.pop_first();
            }
        } else {
            self.fragments
                .insert(index, offset, self.size, &chunk.chunk_data)?;
        }
        if self.next_write == self.chunk_count {
            if <[u8; 32]>::from(self.digest.clone().finalize()) != self.hash {
                return Err(invalid("downloaded pack SHA-256 mismatch"));
            }
            self.complete = Some(if self.retain {
                Completion::Archive(Arc::new(std::mem::take(&mut self.bytes)))
            } else {
                Completion::Excluded
            });
        }
        Ok(self.requests())
    }

    /// Writes one contiguous range without retaining its decoded batch allocation.
    fn append(&mut self, bytes: &[u8]) -> Result<(), PackError> {
        self.digest.update(bytes);
        if self.retain {
            self.bytes
                .try_reserve(bytes.len())
                .map_err(|_| invalid("pack allocation failed"))?;
            self.bytes.extend_from_slice(bytes);
        }
        Ok(())
    }

    /// Rejects a conflicting version suffix without interpreting the name as a path.
    fn check_name(&self, name: &wire::Str) -> Result<(), PackError> {
        let name = name
            .to_str()
            .map_err(|_| invalid("pack resource name is not UTF-8"))?;
        let id = pack_id(name)?;
        if id != self.offer.pack_id_version.pack_uuid {
            return Err(invalid("pack transfer identity differs from offer"));
        }
        if let Some((_, version)) = name.split_once('_')
            && version.as_bytes() != self.offer.pack_id_version.pack_version.version.as_bytes()
        {
            return Err(invalid("pack transfer version differs from offer"));
        }
        Ok(())
    }

    /// Replenishes the request window for every accepted chunk, regardless of order.
    fn requests(&mut self) -> Vec<packets::ResourcePackChunkRequest> {
        let mut requests = Vec::new();
        while self.requested < self.chunk_count
            && self.requested - self.received < self.request_window
        {
            requests.push(packets::ResourcePackChunkRequest {
                resource_name: self.name.clone(),
                chunk: wire::I32LE(self.requested as i32),
            });
            self.requested += 1;
        }
        requests
    }
}

/// Preserves final server order and per-stack subpack selection, excluding unselected offers.
pub(super) fn finish(
    mut downloads: BTreeMap<uuid::Uuid, Download>,
    mut stack: packets::ResourcePackStack,
    offer_required: bool,
    limits: PackTransferLimits,
    metadata: Option<RetainedOffer>,
    offer_order: &[uuid::Uuid],
) -> Result<(ResourcePackHandoff, Option<PackMetadata>), PackError> {
    let stack_required = stack.texture_pack_required;
    let required = offer_required || stack_required;
    if downloads
        .values()
        .any(|download| download.complete.is_none())
    {
        return Err(invalid("pack stack preceded completed downloads"));
    }
    let mut archives = Vec::with_capacity(
        limits
            .max_packs
            .map_or(stack.texture_pack_list.len(), |limit| {
                stack.texture_pack_list.len().min(limit)
            }),
    );
    let entries = std::mem::take(&mut stack.texture_pack_list);
    let mut retained_stack = metadata.as_ref().map(|_| stack);
    let mut retained_offers = BTreeMap::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut skipped = 0_usize;
    for pack in entries {
        let id = pack
            .pack_id
            .to_str()
            .ok()
            .and_then(|name| pack_id(name).ok());
        let Some(id) = id else {
            if stack_required {
                return Err(invalid("required stack identity is invalid"));
            }
            skipped += 1;
            continue;
        };
        if seen.contains(&id) {
            if stack_required {
                return Err(invalid("required stack contains a duplicate pack"));
            }
            skipped += 1;
            continue;
        }
        if downloads.get(&id).is_none_or(|download| {
            download.offer.pack_id_version.pack_version.version != pack.version
        }) {
            if super::builtins::contains(id, &pack.version.to_string_lossy()) {
                if let Some(stack) = &mut retained_stack {
                    stack.texture_pack_list.push(pack);
                }
                continue;
            }
            if stack_required {
                return Err(invalid("required stack contains an unavailable pack"));
            }
            skipped += 1;
            continue;
        }
        seen.insert(id);
        let download = downloads
            .remove(&id)
            .expect("matching stack offer is available");
        let complete = download
            .complete
            .ok_or_else(|| invalid("stack pack is incomplete"))?;
        let Completion::Archive(bytes) = complete else {
            if stack_required {
                return Err(invalid("required stack pack exceeds application budget"));
            }
            skipped += 1;
            continue;
        };
        let bytes =
            Arc::try_unwrap(bytes).map_err(|_| invalid("pack cache worker still owns archive"))?;
        archives.push(ResourcePackArchive::with_content_key(
            id,
            pack.version.to_string_lossy().into_owned(),
            pack.sub_pack_name.to_string_lossy().into_owned(),
            bytes,
            download.offer.content_key.as_bytes().to_vec(),
        ));
        if let Some(stack) = &mut retained_stack {
            let mut offer = download.offer;
            offer.pack_size = wire::U64LE(download.size);
            retained_offers.insert(id, offer);
            stack.texture_pack_list.push(pack);
        }
    }
    if skipped != 0 {
        tracing::warn!(skipped, "skipped unavailable or duplicate stack entries");
    }
    let metadata = metadata.map(|mut metadata| {
        metadata.offer.resource_packs = offer_order
            .iter()
            .filter_map(|id| retained_offers.remove(id))
            .collect();
        let data = metadata
            .offer
            .resource_packs
            .iter()
            .map(|offer| metadata.data.remove(&offer.pack_id_version.pack_uuid))
            .collect();
        PackMetadata {
            offer: metadata.offer,
            stack: super::retained::stack(
                retained_stack.expect("opt-in metadata retains the original stack"),
            ),
            data,
        }
    });
    Ok((
        ResourcePackHandoff::from_archives(archives).with_required(required),
        metadata,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn withheld_first_chunk_uses_lazy_pages_for_tiny_and_cross_page_chunks() {
        let bytes: Vec<u8> = (0..12_291).map(|index| (index % 251) as u8).collect();
        for retain in [false, true] {
            for chunk_size in [1, 3000, 5000] {
                let limits = PackTransferLimits {
                    request_window: 2,
                    max_archive_bytes: Some(if retain { bytes.len() as u64 } else { 1 }),
                    max_stack_bytes: Some(bytes.len() as u64),
                    max_transfer_bytes: Some(bytes.len() as u64),
                    ..Default::default()
                };
                let mut offer = PackInfoData::default();
                offer.pack_id_version.pack_uuid = uuid::Uuid::from_u128(1);
                offer.pack_id_version.pack_version.version = "1.0.0".into();
                offer.pack_size = wire::U64LE(1);
                let (mut downloads, mut budget) = Budget::offers(vec![offer], limits);
                let mut download = downloads.remove(0);
                let count = bytes.len().div_ceil(chunk_size);
                let name = download.name.clone();
                let requests = budget
                    .begin(
                        &mut download,
                        packets::ResourcePackDataInfo {
                            resource_name: name,
                            chunk_size: wire::U32LE(chunk_size as u32),
                            file_size: wire::U64LE(bytes.len() as u64),
                            file_hash: Bytes::copy_from_slice(&Sha256::digest(&bytes)),
                            ..Default::default()
                        },
                    )
                    .unwrap();
                assert_eq!(requests.len(), 2);
                for index in (1..count).chain(std::iter::once(0)) {
                    let start = index * chunk_size;
                    let packet = packets::ResourcePackChunkData {
                        resource_name: download.name.clone(),
                        chunk_id: wire::U32LE(index as u32),
                        chunk_data: Bytes::copy_from_slice(
                            &bytes[start..(start + chunk_size).min(bytes.len())],
                        ),
                        ..Default::default()
                    };
                    let requests = download.chunk(packet.clone()).unwrap();
                    assert_eq!(requests.len(), usize::from(index != 0 && index + 1 < count));
                    assert!(download.chunk(packet).unwrap().is_empty());
                    assert!(download.requested - download.received <= 2);
                    assert!(
                        download.fragments.pages.len()
                            <= bytes.len().div_ceil(FRAGMENT_PAGE_BYTES as usize)
                    );
                    assert!(
                        download
                            .fragments
                            .pages
                            .values()
                            .map(Vec::len)
                            .sum::<usize>()
                            <= bytes.len()
                    );
                    assert!(
                        download.fragments.received.len()
                            <= count.div_ceil(CHUNKS_PER_BITMAP as usize)
                    );
                    if index != 0 {
                        assert!(download.bytes.is_empty());
                    }
                }
                assert!(download.fragments.pages.is_empty());
                assert!(download.fragments.received.is_empty());
                match download.complete.unwrap() {
                    Completion::Archive(archive) => {
                        assert!(retain);
                        assert_eq!(archive.as_slice(), bytes);
                    }
                    Completion::Excluded => assert!(!retain),
                }
            }
        }
    }
}
