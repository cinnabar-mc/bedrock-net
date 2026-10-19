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
            if seen.contains(&offer.pack_id_version.pack_uuid)
                || downloads.len() >= limits.max_packs
                || offer.pack_size.0 > limits.max_archive_bytes
                || offer.pack_size.0 > limits.max_stack_bytes - retained
            {
                skipped += 1;
                continue;
            }
            match Download::new(offer, limits) {
                Ok(download) => {
                    seen.insert(download.offer.pack_id_version.pack_uuid);
                    retained += download.size;
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
            .filter(|total| *total <= self.limits.max_transfer_bytes)
            .ok_or_else(|| invalid("pack transfers exceed memory budget"))?;
        let retained = self
            .retained
            .checked_sub(download.size)
            .ok_or_else(|| invalid("pack admission accounting is invalid"))?;
        let retain = info.file_size.0 <= self.limits.max_archive_bytes
            && info.file_size.0 <= self.limits.max_stack_bytes - retained;
        let size = info.file_size.0;
        let requests = download.begin(info, retain)?;
        self.transferred = transferred;
        self.retained = retained + if retain { size } else { 0 };
        Ok(requests)
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
    next_write: u32,
    fragments: BTreeMap<u32, Bytes>,
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
            next_write: 0,
            fragments: BTreeMap::new(),
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
        if info.file_size.0 == 0 || info.chunk_size.0 == 0 || info.file_hash.len() != 32 {
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
        if index < self.next_write || self.fragments.contains_key(&index) {
            tracing::debug!("skipped duplicate pack chunk");
            return Ok(Vec::new());
        }
        let offset = u64::from(index) * u64::from(self.chunk_size);
        let expected = (self.size - offset).min(u64::from(self.chunk_size));
        if chunk.chunk_data.len() as u64 != expected {
            return Err(invalid("pack chunk length does not match remaining data"));
        }
        // A retained slice must not pin the decoded batch containing unrelated siblings.
        let bytes = if index == self.next_write {
            chunk.chunk_data
        } else {
            Bytes::copy_from_slice(&chunk.chunk_data)
        };
        self.fragments.insert(index, bytes);
        while let Some(bytes) = self.fragments.remove(&self.next_write) {
            self.digest.update(&bytes);
            if self.retain {
                self.bytes
                    .try_reserve(bytes.len())
                    .map_err(|_| invalid("pack allocation failed"))?;
                self.bytes.extend_from_slice(&bytes);
            }
            self.next_write += 1;
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

    /// Keeps a bounded contiguous request window, with no flush timer.
    fn requests(&mut self) -> Vec<packets::ResourcePackChunkRequest> {
        let mut requests = Vec::new();
        while self.requested < self.chunk_count
            && self.requested - self.next_write < self.request_window
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
    let required = offer_required || stack.texture_pack_required;
    if downloads
        .values()
        .any(|download| download.complete.is_none())
    {
        return Err(invalid("pack stack preceded completed downloads"));
    }
    let mut archives = Vec::with_capacity(stack.texture_pack_list.len().min(limits.max_packs));
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
            if required {
                return Err(invalid("required stack identity is invalid"));
            }
            skipped += 1;
            continue;
        };
        if seen.contains(&id) {
            if required {
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
            if required {
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
            if required {
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
