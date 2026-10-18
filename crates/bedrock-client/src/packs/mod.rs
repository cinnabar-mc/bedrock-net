//! Resource-pack negotiation without network, filesystem or runtime ownership.

mod builtins;
mod transfer;

pub use builtins::behavioral_baseline;

use bedrock_packs::ResourcePackHandoff;
use bedrock_protocol::{packets, types::PackInfoData, types::ResourcePackClientResponseData};
use std::{collections::BTreeMap, sync::Arc};
use thiserror::Error;
use transfer::{Budget, Completion, Download};

/// Default number of outstanding in-band chunk requests per pack.
pub const DEFAULT_REQUEST_WINDOW: u32 = 1024;

/// Caller-selected archive, transfer and request bounds, validated before admission.
#[derive(Clone, Copy, Debug)]
pub struct PackTransferLimits {
    /// Maximum distinct valid offers retained from one server.
    pub max_packs: usize,
    /// Maximum compressed bytes retained for one archive.
    pub max_archive_bytes: u64,
    /// Maximum compressed bytes retained across all offered archives.
    pub max_stack_bytes: u64,
    /// Maximum total in-band bytes accepted, including excluded archives.
    pub max_transfer_bytes: u64,
    /// Maximum UTF-8 bytes retained in one advertised version.
    pub max_version_bytes: usize,
    /// Maximum outstanding requested chunks per archive, at most 65,535.
    pub request_window: u32,
}

impl Default for PackTransferLimits {
    fn default() -> Self {
        Self {
            max_packs: bedrock_packs::MAX_PACKS,
            max_archive_bytes: bedrock_packs::MAX_ARCHIVE_BYTES as u64,
            max_stack_bytes: bedrock_packs::MAX_STACK_ARCHIVE_BYTES as u64,
            max_transfer_bytes: 2 * bedrock_packs::MAX_STACK_ARCHIVE_BYTES as u64,
            max_version_bytes: bedrock_packs::MAX_PACK_VERSION_BYTES,
            request_window: DEFAULT_REQUEST_WINDOW,
        }
    }
}

impl PackTransferLimits {
    /// Rejects impossible sizes and request windows before retaining server data.
    fn validate(self) -> Result<(), PackError> {
        if self.max_packs == 0
            || self.max_packs > u16::MAX as usize
            || self.max_archive_bytes == 0
            || self.max_stack_bytes == 0
            || self.max_stack_bytes > usize::MAX as u64
            || self.max_transfer_bytes < self.max_stack_bytes
            || self.max_version_bytes == 0
            || self.request_window == 0
            || self.request_window > u16::MAX.into()
        {
            return Err(PackError::InvalidLimits);
        }
        Ok(())
    }
}

/// A stable failure without server-controlled keys, URLs or archive contents.
#[derive(Debug, Error)]
pub enum PackError {
    /// A size or request-window configuration is invalid.
    #[error("invalid resource-pack transfer limits")]
    InvalidLimits,
    /// The requested operation does not belong to the active negotiation phase.
    #[error("resource-pack negotiation operation is out of sequence")]
    InvalidState,
    /// Malformed framing, hash failure or an unavailable required stack entry.
    #[error("{0}")]
    InvalidData(&'static str),
}

/// Immediate effects of one received packet; this owner never schedules a flush.
pub enum PackEvent {
    /// Generated responses and chunk requests to send in their existing order.
    Send(Vec<packets::Packet>),
    /// The final stack acknowledgment and server-ordered archive ownership.
    Finished {
        /// Send this acknowledgment before entering the next client phase.
        response: packets::ResourcePackClientResponse,
        /// Archives and keys for the caller's admission/application layer.
        handoff: ResourcePackHandoff,
    },
    /// A packet belonging to another client phase, returned without interpretation.
    Unhandled(Box<packets::Packet>),
}

enum Phase {
    Preloading,
    Downloading,
    Complete,
    Failed,
}

/// One offered stack, bounded acquisition state and ordered final handoff.
///
/// Cache and CDN I/O remain with the caller. Supply validated preloads before
/// `start`, then retain this same owner while processing generated packets. A
/// received-packet error is terminal; drop this owner and the enclosing join.
pub struct PackNegotiation {
    downloads: BTreeMap<uuid::Uuid, Download>,
    offer_order: Vec<uuid::Uuid>,
    budget: Budget,
    limits: PackTransferLimits,
    offer_required: bool,
    phase: Phase,
}

impl PackNegotiation {
    /// Admits bounded first offers without interpreting their URLs or content keys.
    ///
    /// # Errors
    /// Returns `InvalidLimits` for unusable caller configuration. Invalid,
    /// duplicate or oversized offers are skipped and logged; final required
    /// stack selection decides whether those omissions prevent joining.
    pub fn new(
        offer: packets::ResourcePacksInfo,
        limits: PackTransferLimits,
    ) -> Result<Self, PackError> {
        limits.validate()?;
        let (downloads, budget) = Budget::offers(offer.resource_packs, limits);
        let offer_order = downloads
            .iter()
            .map(|download| download.offer.pack_id_version.pack_uuid)
            .collect();
        Ok(Self {
            downloads: downloads
                .into_iter()
                .map(|download| (download.offer.pack_id_version.pack_uuid, download))
                .collect(),
            offer_order,
            budget,
            limits,
            offer_required: offer.resource_pack_required,
            phase: Phase::Preloading,
        })
    }

    /// Borrows admitted metadata in offer order for caller-owned cache/CDN lookup.
    pub fn offers(&self) -> impl Iterator<Item = &PackInfoData> {
        self.offer_order
            .iter()
            .filter_map(|id| self.downloads.get(id).map(|download| &download.offer))
    }

    /// Installs a caller-validated archive before requesting missing in-band data.
    ///
    /// The caller must validate the archive and its manifest identity against
    /// the corresponding offer. Offers contain no archive hash; this method
    /// checks byte bounds only. A failed preload leaves in-band fallback intact.
    ///
    /// # Errors
    /// Rejects unknown identities, repeated preloads, excess bytes, or use after
    /// `start`. The source allocation must not exceed the advertised byte size.
    pub fn supply_preloaded(&mut self, id: uuid::Uuid, archive: Vec<u8>) -> Result<(), PackError> {
        if !matches!(self.phase, Phase::Preloading) {
            return Err(PackError::InvalidState);
        }
        let download = self
            .downloads
            .get_mut(&id)
            .ok_or_else(|| invalid("preloaded pack was not advertised"))?;
        if download.complete.is_some() || archive.len() as u64 > download.size {
            return Err(invalid(
                "preloaded archive exceeds its offer or repeats completion",
            ));
        }
        download.complete = Some(Completion::Archive(Arc::new(archive)));
        Ok(())
    }

    /// Starts in-band negotiation exactly once, preserving original offer order.
    ///
    /// # Errors
    /// Returns `InvalidState` if preloading has already ended.
    pub fn start(&mut self) -> Result<packets::ResourcePackClientResponse, PackError> {
        if !matches!(self.phase, Phase::Preloading) {
            return Err(PackError::InvalidState);
        }
        let requested = self
            .offer_order
            .iter()
            .filter_map(|id| self.downloads.get(id))
            .filter(|download| download.complete.is_none())
            .map(|download| download.name.clone())
            .collect::<Vec<_>>();
        let response = if requested.is_empty() {
            finished()
        } else {
            ResourcePackClientResponseData::Downloading {
                response_type: "downloading".into(),
                downloading_packs: requested,
            }
        };
        self.phase = Phase::Downloading;
        Ok(packets::ResourcePackClientResponse { response })
    }

    /// Shares completed original bytes with a bounded caller-owned cache write.
    /// All such references must be dropped before receiving the final stack.
    pub fn completed_archive(&self, id: uuid::Uuid) -> Option<Arc<Vec<u8>>> {
        match &self.downloads.get(&id)?.complete {
            Some(Completion::Archive(bytes)) => Some(Arc::clone(bytes)),
            _ => None,
        }
    }

    /// Advances one packet, retaining all transfer state on this same owner.
    ///
    /// # Errors
    /// Rejects out-of-phase resource packets, unsolicited/inconsistent chunks,
    /// hash failures, premature stacks or an unavailable required stack entry.
    /// A received-packet error permanently ends this negotiation.
    pub fn receive(&mut self, packet: packets::Packet) -> Result<PackEvent, PackError> {
        if !matches!(self.phase, Phase::Downloading) {
            return Err(PackError::InvalidState);
        }
        let result = self.apply(packet);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }

    /// Dispatches only pack-owned packets; all other lifecycle handling stays outside.
    fn apply(&mut self, packet: packets::Packet) -> Result<PackEvent, PackError> {
        match packet {
            packets::Packet::ResourcePackDataInfo(info) => {
                let id = pack_id(
                    info.resource_name
                        .to_str()
                        .map_err(|_| invalid("pack identity is not UTF-8"))?,
                )?;
                let download = self
                    .downloads
                    .get_mut(&id)
                    .ok_or_else(|| invalid("pack data info was not advertised"))?;
                Ok(PackEvent::Send(
                    self.budget
                        .begin(download, info)?
                        .into_iter()
                        .map(packets::Packet::from)
                        .collect(),
                ))
            }
            packets::Packet::ResourcePackChunkData(chunk) => {
                let id = pack_id(
                    chunk
                        .resource_name
                        .to_str()
                        .map_err(|_| invalid("chunk pack was not advertised"))?,
                )?;
                let download = self
                    .downloads
                    .get_mut(&id)
                    .ok_or_else(|| invalid("chunk pack was not advertised"))?;
                let complete_before = download.complete.is_some();
                let mut responses = download
                    .chunk(chunk)?
                    .into_iter()
                    .map(packets::Packet::from)
                    .collect::<Vec<_>>();
                if !complete_before
                    && download.complete.is_some()
                    && self
                        .downloads
                        .values()
                        .all(|download| download.complete.is_some())
                {
                    responses.push(
                        packets::ResourcePackClientResponse {
                            response: finished(),
                        }
                        .into(),
                    );
                }
                Ok(PackEvent::Send(responses))
            }
            packets::Packet::ResourcePackStack(stack) => {
                let handoff = transfer::finish(
                    std::mem::take(&mut self.downloads),
                    stack,
                    self.offer_required,
                    self.limits,
                )?;
                self.phase = Phase::Complete;
                Ok(PackEvent::Finished {
                    response: packets::ResourcePackClientResponse {
                        response: ResourcePackClientResponseData::ResourcePackStackFinished {
                            response_type: "resourcepackstackfinished".into(),
                        },
                    },
                    handoff,
                })
            }
            other => Ok(PackEvent::Unhandled(Box::new(other))),
        }
    }
}

/// Produces the completion response after preloading or receiving the last chunk.
fn finished() -> ResourcePackClientResponseData {
    ResourcePackClientResponseData::DownloadingFinished {
        response_type: "downloadingfinished".into(),
    }
}

/// Accepts UUID or UUID_version names without interpreting server text as a path.
fn pack_id(name: &str) -> Result<uuid::Uuid, PackError> {
    uuid::Uuid::parse_str(name.split('_').next().unwrap_or(name))
        .map_err(|_| invalid("pack identity is not a UUID"))
}

/// Keeps malformed-input diagnostics independent of server-controlled secrets.
fn invalid(message: &'static str) -> PackError {
    PackError::InvalidData(message)
}

#[cfg(test)]
mod tests;
