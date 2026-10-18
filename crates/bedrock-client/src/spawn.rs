// Adapted from Cinnabar's startup owner, based on Jolyne (Axolotl Stack),
// Copyright (c) 2025 Jeremy Ianne, MIT License; see ../LICENSE-AXOLOTL.

//! Startup prerequisites without I/O, rendering policy or a retained play queue.

use bedrock_protocol::{enums::PlayStatusType, packets};

/// A malformed or repeated startup transition.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SpawnError {
    /// The caller supplied an unusable requested radius.
    #[error("requested startup chunk radius must be positive")]
    InvalidRequest,
    /// A later StartGame attempted to replace the local player's identity.
    #[error("conflicting StartGame runtime identity: first {first}, then {received}")]
    ConflictingRuntimeId {
        /// The first local-player runtime identifier.
        first: u64,
        /// The conflicting identifier in the repeated packet.
        received: u64,
    },
    /// The server advertised a nonpositive initial radius.
    #[error("invalid updated chunk radius {0}")]
    InvalidRadius(i32),
    /// The operation follows failure, completion or initialization.
    #[error("spawn operation is out of sequence")]
    InvalidState,
}

/// First definitions handed to application preparation as soon as both arrive.
pub struct StartupData {
    /// The first StartGame, never replaced by later packets.
    pub start_game: Box<packets::StartGame>,
    /// The first item table, never replaced by later custom-only/empty tables.
    pub item_registry: packets::ItemRegistry,
}

/// Server prerequisites are satisfied; presentation remains caller-owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpawnReady {
    /// Runtime identifier to acknowledge after presentation is ready.
    pub runtime_id: u64,
    /// Whether terrain input arrived while startup prerequisites were pending.
    pub terrain_received: bool,
}

/// Effects of one input, delivered together so no sibling action is lost.
#[derive(Default)]
pub struct SpawnUpdate {
    /// Send once when the first StartGame arrives; loading-screen policy is external.
    pub request_radius: Option<packets::RequestChunkRadius>,
    /// Start application preparation immediately when both first definitions arrive.
    pub startup: Option<StartupData>,
    /// Preserve this packet in the caller's bounded FIFO, ahead of unread input.
    ///
    /// Disconnect and Transfer are also returned here for immediate handling by
    /// the caller. The core does not interpret display text or validate routes.
    pub deferred: Option<Box<packets::Packet>>,
    /// Signals completion of the network prerequisites exactly once.
    pub ready: Option<SpawnReady>,
}

enum Phase {
    Active,
    Ready,
    Initialized,
    Failed,
}

/// A bounded owner of the first startup definitions and spawn prerequisites.
///
/// Call `receive` until `ready` is returned. Retain `deferred` packets separately
/// in wire order under the caller's byte bound; this owner never buffers play
/// traffic. The caller may prepare packs/world data on `startup` while continuing
/// input. Only call `finish_loading` when presentation is actually ready.
pub struct SpawnNegotiation {
    phase: Phase,
    radius_request: Option<packets::RequestChunkRadius>,
    runtime_id: Option<u64>,
    start_game: Option<Box<packets::StartGame>>,
    item_registry: Option<packets::ItemRegistry>,
    registry_seen: bool,
    startup_delivered: bool,
    radius_received: bool,
    player_spawn_received: bool,
    terrain_received: bool,
}

impl SpawnNegotiation {
    /// Uses the caller's already selected view-distance request without imposing renderer limits.
    ///
    /// # Errors
    /// Rejects a nonpositive requested radius. Advertised supported-radius
    /// policy remains with the caller; the generated packet is preserved.
    pub fn new(radius_request: packets::RequestChunkRadius) -> Result<Self, SpawnError> {
        if radius_request.chunk_radius.0 < 1 {
            return Err(SpawnError::InvalidRequest);
        }
        Ok(Self {
            phase: Phase::Active,
            radius_request: Some(radius_request),
            runtime_id: None,
            start_game: None,
            item_registry: None,
            registry_seen: false,
            startup_delivered: false,
            radius_received: false,
            player_spawn_received: false,
            terrain_received: false,
        })
    }

    /// Observes one generated packet and returns all immediate effects without a flush delay.
    ///
    /// # Errors
    /// Conflicting StartGame identity, invalid radius or use after completion
    /// ends the negotiation. The caller must stop on any terminal packet it
    /// receives through `deferred`, rather than continuing this state machine.
    pub fn receive(&mut self, packet: packets::Packet) -> Result<SpawnUpdate, SpawnError> {
        let result = self.receive_inner(packet);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }

    /// Creates the single initialization acknowledgment after presentation completes.
    ///
    /// The caller owns any loading-screen end notification and sends it before
    /// this response when its application policy requires it.
    ///
    /// # Errors
    /// Rejects premature, repeated or failed initialization.
    pub fn finish_loading(&mut self) -> Result<packets::SetLocalPlayerAsInitialized, SpawnError> {
        if !matches!(self.phase, Phase::Ready) {
            return Err(SpawnError::InvalidState);
        }
        self.phase = Phase::Initialized;
        Ok(packets::SetLocalPlayerAsInitialized {
            player_id: bedrock_protocol::types::ActorRuntimeID(
                self.runtime_id.expect("ready requires StartGame"),
            ),
        })
    }

    /// Retains definitions once and moves unrelated traffic straight back to the caller.
    fn receive_inner(&mut self, packet: packets::Packet) -> Result<SpawnUpdate, SpawnError> {
        if !matches!(self.phase, Phase::Active) {
            return Err(SpawnError::InvalidState);
        }
        let mut update = SpawnUpdate::default();
        match packet {
            packets::Packet::StartGame(start) => {
                let received = start.runtime_id.0;
                match self.runtime_id {
                    Some(first) if first != received => {
                        return Err(SpawnError::ConflictingRuntimeId { first, received });
                    }
                    Some(_) => {}
                    None => {
                        self.runtime_id = Some(received);
                        self.start_game = Some(start);
                        update.request_radius = self.radius_request.take();
                    }
                }
            }
            packets::Packet::ItemRegistry(registry) => {
                if !self.registry_seen {
                    self.registry_seen = true;
                    self.item_registry = Some(registry);
                }
            }
            packets::Packet::PlayStatus(status) => {
                if status.status == PlayStatusType::Playerspawn {
                    self.player_spawn_received = true;
                }
            }
            packets::Packet::ChunkRadiusUpdated(radius) => {
                if radius.chunk_radius.0 < 1 {
                    return Err(SpawnError::InvalidRadius(radius.chunk_radius.0));
                }
                self.radius_received = true;
                update.deferred = Some(Box::new(packets::Packet::ChunkRadiusUpdated(radius)));
            }
            other => {
                self.terrain_received |= matches!(
                    &other,
                    packets::Packet::NetworkChunkPublisherUpdate(_)
                        | packets::Packet::LevelChunk(_)
                        | packets::Packet::SubChunk(_)
                );
                update.deferred = Some(Box::new(other));
            }
        }
        if self.start_game.is_some() && self.item_registry.is_some() {
            update.startup = Some(StartupData {
                start_game: self.start_game.take().expect("checked above"),
                item_registry: self.item_registry.take().expect("checked above"),
            });
            self.startup_delivered = true;
        }
        if self.startup_delivered && self.radius_received && self.player_spawn_received {
            self.phase = Phase::Ready;
            update.ready = Some(SpawnReady {
                runtime_id: self.runtime_id.expect("startup requires StartGame"),
                terrain_received: self.terrain_received,
            });
        }
        Ok(update)
    }
}

#[cfg(test)]
mod tests;
