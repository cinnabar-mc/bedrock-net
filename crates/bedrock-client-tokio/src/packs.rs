// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Original pack wire loop, with caller-owned cache/CDN/storage operations.

use crate::{
    PacketIo,
    connection::Connection,
    error::NegotiationError,
    handshake::{self, Observation},
};
use bedrock_client::{
    handshake::{ClientPackOffer, ClientPacks, PacksEvent},
    packs::PackMetadata,
};
use bedrock_packs::ResourcePackHandoff;
use bedrock_protocol::{packets, types::PackInfoData};
use std::{io, sync::Arc};

/// Borrowed acquisition/storage operations; transport and protocol state remain on Connection.
pub trait PackIo: Send {
    /// Returns source-ordered optional verified original archive bytes for these exact offers.
    fn preload(
        &mut self,
        offers: &[PackInfoData],
    ) -> impl std::future::Future<Output = Vec<Option<Vec<u8>>>> + Send;
    /// Notifies once when the original pack owner has a completed archive; no payload copy.
    fn completed(&mut self, id: uuid::Uuid, archive: Arc<Vec<u8>>);
    /// Releases all shared store references before the same stack consumes exclusive archives.
    fn flush(&mut self) -> impl std::future::Future<Output = ()> + Send;
}

/// In-band-only acquisition with no cache, HTTP client or storage worker.
pub struct InBand;
impl PackIo for InBand {
    async fn preload(&mut self, offers: &[PackInfoData]) -> Vec<Option<Vec<u8>>> {
        (0..offers.len()).map(|_| None).collect()
    }
    fn completed(&mut self, _: uuid::Uuid, _: Arc<Vec<u8>>) {}
    async fn flush(&mut self) {}
}

/// The actual selected archive handoff and opt-in metadata from the original pack owner.
pub struct AcquiredPacks {
    /// Original selected archive bytes in the stack's application order.
    pub handoff: ResourcePackHandoff,
    /// Actual offer/stack/data fields, present only when the caller requested retention.
    pub metadata: Option<Box<PackMetadata>>,
}

/// Drives actual in-band transfer, late controls and stack replay on the original connection.
/// The caller retains its first overall deadline and drops the same I/O owner on cancellation.
pub async fn acquire(
    connection: &mut Connection,
    mut offer: ClientPackOffer,
    io: &mut impl PackIo,
    observe: &mut (impl FnMut(Observation<'_>) + Send),
) -> Result<AcquiredPacks, NegotiationError> {
    let offers = offer.offers().cloned().collect::<Vec<_>>();
    let preloads = wait_io(connection, io.preload(&offers)).await;
    if preloads.len() != offers.len() {
        return Err(NegotiationError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pack preload count differs from original offers",
        )));
    }
    for (original, archive) in offers.iter().zip(preloads) {
        if let Some(archive) = archive {
            offer.supply_preloaded(original.pack_id_version.pack_uuid, archive)?;
        }
    }
    let mut waiting = offers
        .iter()
        .map(|offer| offer.pack_id_version.pack_uuid)
        .collect::<Vec<_>>();
    let (mut negotiation, response) = offer.start()?;
    completed(&mut waiting, &negotiation, io);
    handshake::send_packets(connection, &[response.into()], None, observe).await?;
    connection.replay_deferred();
    let mut deferred_stack = false;
    loop {
        if deferred_stack && negotiation.ready_for_stack() {
            wait_io(connection, io.flush()).await;
            connection.replay_deferred();
            deferred_stack = false;
        }
        let (_, packet) = connection
            .next_packet_observed(observe)
            .await
            .map_err(NegotiationError::Io)?;
        if matches!(packet, packets::Packet::ResourcePackStack(_)) {
            wait_io(connection, io.flush()).await;
        }
        match negotiation.receive(packet)? {
            PacksEvent::Send { packs, packets } => {
                negotiation = packs;
                completed(&mut waiting, &negotiation, io);
                handshake::send_packets(connection, &packets, None, observe).await?;
            }
            PacksEvent::Finished(complete) => {
                let (response, handoff, metadata) = complete.into_parts_with_metadata();
                handshake::send_packets(connection, &[response.into()], None, observe).await?;
                return Ok(AcquiredPacks {
                    handoff,
                    metadata: metadata.map(Box::new),
                });
            }
            PacksEvent::KeyExchange(exchange) => {
                negotiation = handshake::apply_key_exchange(connection, exchange, observe).await?;
            }
            PacksEvent::DeferredStack { packs, stack } => {
                // Keep the actual raw frame in the original bounded FIFO, not another model queue.
                drop(stack);
                connection.defer_current().map_err(NegotiationError::Io)?;
                deferred_stack = true;
                negotiation = packs;
            }
            PacksEvent::Unhandled { packs, packet } => {
                handshake::defer_unhandled(connection, *packet)?;
                negotiation = packs;
            }
        }
    }
}

/// Progresses only the original transport beside one pinned caller operation.
pub async fn wait_io<T>(
    connection: &mut impl PacketIo,
    operation: impl std::future::Future<Output = T>,
) -> T {
    tokio::pin!(operation);
    loop {
        tokio::select! {
            biased;
            () = connection.maintain() => {},
            output = &mut operation => return output,
        }
    }
}

/// Removes only completed notification identities; all archive bytes remain in their original owner.
fn completed(waiting: &mut Vec<uuid::Uuid>, packs: &ClientPacks, io: &mut impl PackIo) {
    waiting.retain(|id| {
        if let Some(archive) = packs.completed_archive(*id) {
            io.completed(*id, archive);
            false
        } else {
            true
        }
    });
}
