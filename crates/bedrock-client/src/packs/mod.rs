//! Resource-pack negotiation without network, filesystem or runtime ownership.

pub(crate) mod builtins;
mod retained;
mod transfer;

#[cfg(test)]
mod retention_tests;

pub use builtins::{behavioral_baseline, builtin_packs};

use bedrock_packs::ResourcePackHandoff;
use bedrock_protocol::{packets, types::PackInfoData, types::ResourcePackClientResponseData};
use std::{collections::BTreeMap, sync::Arc};
use thiserror::Error;
use transfer::{Budget, Completion, Download};

/// Default number of outstanding in-band chunk requests per pack.
pub const DEFAULT_REQUEST_WINDOW: u32 = 100;

/// Caller-selected archive, transfer and request bounds, validated before admission.
/// Defaults admit complete server selections without inheriting local import policy;
/// framing, representable lengths, identity and request-window checks remain.
#[derive(Clone, Copy, Debug)]
pub struct PackTransferLimits {
    /// Optional maximum distinct valid offers retained from one server.
    pub max_packs: Option<usize>,
    /// Optional maximum compressed bytes retained for one archive.
    pub max_archive_bytes: Option<u64>,
    /// Optional maximum compressed bytes retained across all offered archives.
    pub max_stack_bytes: Option<u64>,
    /// Optional maximum total in-band bytes accepted, including excluded archives.
    pub max_transfer_bytes: Option<u64>,
    /// Maximum bytes retained in one advertised version.
    pub max_version_bytes: usize,
    /// Maximum outstanding requested chunks per archive, at most 65,535.
    pub request_window: u32,
}

impl Default for PackTransferLimits {
    fn default() -> Self {
        Self {
            max_packs: None,
            max_archive_bytes: None,
            max_stack_bytes: None,
            max_transfer_bytes: None,
            max_version_bytes: usize::MAX,
            request_window: DEFAULT_REQUEST_WINDOW,
        }
    }
}

impl PackTransferLimits {
    /// Rejects impossible sizes and request windows before retaining server data.
    pub(crate) fn validate(self) -> Result<(), PackError> {
        if self
            .max_packs
            .is_some_and(|limit| limit == 0 || limit > u16::MAX as usize)
            || self.max_archive_bytes == Some(0)
            || self
                .max_stack_bytes
                .is_some_and(|limit| limit == 0 || limit > usize::MAX as u64)
            || self.max_transfer_bytes == Some(0)
            || matches!((self.max_transfer_bytes, self.max_stack_bytes), (Some(transfer), Some(stack)) if transfer < stack)
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
    /// Malformed framing or an unavailable required stack entry.
    #[error("{0}")]
    InvalidData(&'static str),
}

/// Immediate effects of one received packet; this owner never schedules a flush.
pub enum PackEvent {
    /// Generated responses and chunk requests to send in their existing order.
    Send(Vec<packets::Packet>),
    /// An early stack to replay after `PackNegotiation::ready_for_stack` becomes true.
    /// Send each intervening `Send` effect before replaying this packet.
    DeferredStack(Box<packets::ResourcePackStack>),
    /// The final stack acknowledgment and server-ordered archive ownership.
    Finished(PackComplete),
    /// A packet belonging to another client phase, returned without interpretation.
    Unhandled(Box<packets::Packet>),
}

/// Admitted offers whose optional caller-validated preloads are still open.
/// No transfer can receive chunks until `start` consumes this owner.
#[must_use]
pub struct PackOffer {
    transfer: Transfer,
}

impl PackOffer {
    /// Validates bounds and retains first usable offers without interpreting URLs or keys.
    pub fn new(
        offer: packets::ResourcePacksInfo,
        limits: PackTransferLimits,
    ) -> Result<Self, PackError> {
        Ok(Self {
            transfer: Transfer::new(offer, limits, false)?,
        })
    }

    /// Keeps original metadata for relaying only the final acquired selections to another client.
    /// Transfer bounds, optional-pack leniency and required-stack validation remain unchanged.
    pub fn new_with_metadata(
        offer: packets::ResourcePacksInfo,
        limits: PackTransferLimits,
    ) -> Result<Self, PackError> {
        Ok(Self {
            transfer: Transfer::new(offer, limits, true)?,
        })
    }

    /// Borrows admitted metadata in original offer order for caller cache/CDN lookup.
    pub fn offers(&self) -> impl Iterator<Item = &PackInfoData> {
        self.transfer.offers()
    }

    /// Installs caller-validated original bytes; a failure preserves in-band fallback.
    /// Validate the archive and manifest identity against the offer before calling.
    /// Offers contain no archive hash; this method checks byte bounds, not content.
    pub fn supply_preloaded(&mut self, id: uuid::Uuid, archive: Vec<u8>) -> Result<(), PackError> {
        self.transfer.supply_preloaded(id, archive)
    }

    /// Consumes the preload capability and returns the original initial response.
    ///
    /// ```compile_fail
    /// fn preload_after_start(offer: bedrock_client::packs::PackOffer, id: uuid::Uuid) {
    ///     let (mut transfer, _) = offer.start().unwrap();
    ///     transfer.supply_preloaded(id, Vec::new()).unwrap();
    /// }
    /// ```
    pub fn start(
        mut self,
    ) -> Result<(PackNegotiation, packets::ResourcePackClientResponse), PackError> {
        let response = self.transfer.start()?;
        Ok((
            PackNegotiation {
                transfer: self.transfer,
            },
            response,
        ))
    }
}

/// Active bounded transfer. Only `PackOffer::start` can create this owner.
#[must_use]
pub struct PackNegotiation {
    transfer: Transfer,
}

impl PackNegotiation {
    /// Borrows original offers for caller-owned cache bookkeeping.
    pub fn offers(&self) -> impl Iterator<Item = &PackInfoData> {
        self.transfer.offers()
    }

    /// Shares completed original bytes with a bounded cache write.
    /// Release all shared references before processing the final stack.
    pub fn completed_archive(&self, id: uuid::Uuid) -> Option<Arc<Vec<u8>>> {
        self.transfer.completed_archive(id)
    }

    /// Whether all downloads completed and a deferred stack can now be replayed with `receive`.
    /// Release any shared cache-write archive references before replaying the stack.
    pub fn ready_for_stack(&self) -> bool {
        self.transfer.ready_for_stack()
    }

    /// Advances the existing transfer and returns unrelated packets intact.
    /// Any received-packet error permanently ends this owner.
    pub fn receive(&mut self, packet: packets::Packet) -> Result<PackEvent, PackError> {
        self.transfer.receive(packet)
    }
}

/// Owned result of actual final-stack processing, not a constructible data DTO.
#[must_use = "send the original stack acknowledgment before entering startup"]
pub struct PackComplete {
    response: packets::ResourcePackClientResponse,
    handoff: ResourcePackHandoff,
    metadata: Option<Box<PackMetadata>>,
}

/// Actual admitted metadata projected onto acquired selections; no diagnostics expose content keys.
pub struct PackMetadata {
    /// Original offer fields, selected entries in offer order, with actual archive sizes.
    pub offer: packets::ResourcePacksInfo,
    /// Original stack fields and selected entries in their original application order.
    pub stack: packets::ResourcePackStack,
    /// Original data information aligned with offer order; preloaded archives have no such packet.
    /// Pack classification/premium/hash fields are never inferred from absent wire information.
    pub data: Vec<Option<packets::ResourcePackDataInfo>>,
}

impl PackComplete {
    /// Consumes completed packs into a configured startup observer and original handoff data.
    /// The caller sends the stack acknowledgment before processing startup traffic.
    pub fn start_spawn(
        self,
        radius: packets::RequestChunkRadius,
    ) -> Result<
        (
            crate::spawn::SpawnNegotiation,
            packets::ResourcePackClientResponse,
            ResourcePackHandoff,
        ),
        crate::spawn::SpawnError,
    > {
        let startup = crate::spawn::SpawnNegotiation::new(radius)?;
        Ok((startup, self.response, self.handoff))
    }

    /// Transfers the exact acknowledgment and archives for actual adapter dispatch/application.
    /// The returned handoff is data, and cannot itself construct another completion capability.
    pub fn into_parts(self) -> (packets::ResourcePackClientResponse, ResourcePackHandoff) {
        (self.response, self.handoff)
    }

    /// Moves opt-in original metadata with the exact acknowledgment and acquired archive handoff.
    /// None is the unchanged default path; it does not mean a retained offer contained no packs.
    pub fn into_parts_with_metadata(
        self,
    ) -> (
        packets::ResourcePackClientResponse,
        ResourcePackHandoff,
        Option<PackMetadata>,
    ) {
        (
            self.response,
            self.handoff,
            self.metadata.map(|metadata| *metadata),
        )
    }
}

struct RetainedOffer {
    offer: packets::ResourcePacksInfo,
    data: BTreeMap<uuid::Uuid, packets::ResourcePackDataInfo>,
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
struct Transfer {
    downloads: BTreeMap<uuid::Uuid, Download>,
    offer_order: Vec<uuid::Uuid>,
    budget: Budget,
    offer_required: bool,
    metadata: Option<Box<RetainedOffer>>,
    phase: Phase,
}

impl Transfer {
    /// Admits bounded first offers without interpreting their URLs or content keys.
    ///
    /// # Errors
    /// Returns `InvalidLimits` for unusable caller configuration. Invalid,
    /// duplicate or oversized offers are skipped and logged; final required
    /// stack selection decides whether those omissions prevent joining.
    fn new(
        mut offer: packets::ResourcePacksInfo,
        limits: PackTransferLimits,
        retain_metadata: bool,
    ) -> Result<Self, PackError> {
        limits.validate()?;
        let (mut downloads, budget) =
            Budget::offers(std::mem::take(&mut offer.resource_packs), limits);
        if retain_metadata {
            for download in &mut downloads {
                download.offer = retained::pack(std::mem::take(&mut download.offer));
            }
        }
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
            offer_required: offer.resource_pack_required,
            metadata: retain_metadata.then(|| {
                Box::new(RetainedOffer {
                    offer: retained::offer(offer),
                    data: BTreeMap::new(),
                })
            }),
            phase: Phase::Preloading,
        })
    }

    /// Borrows admitted metadata in offer order for caller-owned cache/CDN lookup.
    fn offers(&self) -> impl Iterator<Item = &PackInfoData> {
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
    fn supply_preloaded(&mut self, id: uuid::Uuid, archive: Vec<u8>) -> Result<(), PackError> {
        if !matches!(self.phase, Phase::Preloading) {
            return Err(PackError::InvalidState);
        }
        let download = self
            .downloads
            .get_mut(&id)
            .ok_or_else(|| invalid("preloaded pack was not advertised"))?;
        self.budget.preload(download, archive)
    }

    /// Starts in-band negotiation exactly once, preserving original offer order.
    ///
    /// # Errors
    /// Returns `InvalidState` if preloading has already ended.
    fn start(&mut self) -> Result<packets::ResourcePackClientResponse, PackError> {
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
    fn completed_archive(&self, id: uuid::Uuid) -> Option<Arc<Vec<u8>>> {
        match &self.downloads.get(&id)?.complete {
            Some(Completion::Archive(bytes)) => Some(Arc::clone(bytes)),
            _ => None,
        }
    }

    /// Checks stack readiness without consuming any download or sending a response.
    fn ready_for_stack(&self) -> bool {
        matches!(self.phase, Phase::Downloading)
            && self
                .downloads
                .values()
                .all(|download| download.complete.is_some())
    }

    /// Advances one packet, retaining all transfer state on this same owner.
    ///
    /// # Errors
    /// Rejects out-of-phase resource packets, unsolicited/inconsistent chunks,
    /// or an unavailable required stack entry. Early stacks are returned for replay.
    /// A received-packet error permanently ends this negotiation.
    fn receive(&mut self, packet: packets::Packet) -> Result<PackEvent, PackError> {
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
                let id = resource_id(&info.resource_name)?;
                let download = self
                    .downloads
                    .get_mut(&id)
                    .ok_or_else(|| invalid("pack data info was not advertised"))?;
                let retained = self.metadata.as_ref().map(|_| info.clone());
                let requests = self.budget.begin(download, info)?;
                if let (Some(metadata), Some(info)) = (&mut self.metadata, retained) {
                    metadata.data.insert(id, retained::data(info));
                }
                Ok(PackEvent::Send(
                    requests.into_iter().map(packets::Packet::from).collect(),
                ))
            }
            packets::Packet::ResourcePackChunkData(chunk) => {
                let id = resource_id(&chunk.resource_name)?;
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
            packets::Packet::ResourcePackStack(stack) if !self.ready_for_stack() => {
                Ok(PackEvent::DeferredStack(Box::new(retained::stack(stack))))
            }
            packets::Packet::ResourcePackStack(stack) => {
                let (handoff, metadata) = transfer::finish(
                    std::mem::take(&mut self.downloads),
                    stack,
                    self.offer_required,
                    self.budget.limits(),
                    self.metadata.take().map(|metadata| *metadata),
                    &self.offer_order,
                )?;
                self.phase = Phase::Complete;
                Ok(PackEvent::Finished(PackComplete {
                    response: packets::ResourcePackClientResponse {
                        response: ResourcePackClientResponseData::ResourcePackStackFinished {
                            response_type: "resourcepackstackfinished".into(),
                        },
                    },
                    handoff,
                    metadata: metadata.map(Box::new),
                }))
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

/// Reads only the UUID prefix, so opaque version bytes cannot invalidate a transfer name.
fn resource_id(name: &bedrock_protocol::wire::Str) -> Result<uuid::Uuid, PackError> {
    let prefix = name
        .as_bytes()
        .split(|byte| *byte == b'_')
        .next()
        .unwrap_or_default();
    let prefix = std::str::from_utf8(prefix).map_err(|_| invalid("pack identity is not UTF-8"))?;
    pack_id(prefix)
}

/// Accepts UUID or `UUID_version` names without interpreting server text as a path.
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
