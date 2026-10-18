//! Actual selected-world definitions and original runtime-ID initialization.

use super::{ServerSessionError as Error, ServerSessionEvent as Event, bounded_metadata};
use bedrock_protocol::{enums::PlayStatusType, packets, wire};

/// Actual selected-world data and radius policy supplied by its adapter, without defaults or Debug.
pub struct ServerWorld {
    /// Original generated world/player definitions; never synthesized from client metadata.
    pub start_game: Box<packets::StartGame>,
    /// Original selected-world item definitions.
    pub items: packets::ItemRegistry,
    /// Original creative content sent after the initial radius response.
    pub creative: packets::CreativeContent,
    /// Maximum initial radius admitted by this world adapter.
    pub max_chunk_radius: i32,
    /// Optional selected-world override; otherwise use the bounded client request.
    pub initial_chunk_radius: Option<i32>,
}

pub(super) struct Startup {
    runtime_id: u64,
    max_radius: i32,
    fixed_radius: Option<i32>,
    radius: Option<i32>,
    creative: Option<packets::CreativeContent>,
    initialized: bool,
}

impl Startup {
    /// Validates actual generated output and retains only the immutable initialization identity.
    pub(super) fn new(
        world: ServerWorld,
        limit: usize,
    ) -> Result<(Self, Vec<packets::Packet>), Error> {
        if world.max_chunk_radius < 1
            || world
                .initial_chunk_radius
                .is_some_and(|r| r < 1 || r > world.max_chunk_radius)
        {
            return Err(Error::InvalidData("invalid accepting world radius policy"));
        }
        bounded_metadata(world.start_game.as_ref(), packets::StartGame::ID, limit)?;
        bounded_metadata(&world.items, packets::ItemRegistry::ID, limit)?;
        bounded_metadata(&world.creative, packets::CreativeContent::ID, limit)?;
        let runtime_id = world.start_game.runtime_id.0;
        let startup = Self {
            runtime_id,
            max_radius: world.max_chunk_radius,
            fixed_radius: world.initial_chunk_radius,
            radius: None,
            creative: Some(world.creative),
            initialized: false,
        };
        Ok((
            startup,
            vec![
                packets::Packet::StartGame(world.start_game),
                world.items.into(),
            ],
        ))
    }

    /// Requires radius negotiation before the exact original runtime-ID acknowledgment.
    pub(super) fn receive(&mut self, packet: packets::Packet) -> Result<Event, Error> {
        match packet {
            packets::Packet::RequestChunkRadius(request) => {
                if self.radius.is_some() || self.initialized || request.chunk_radius.0 < 1 {
                    return Err(Error::InvalidData(
                        "invalid or repeated accepting radius request",
                    ));
                }
                let radius = self
                    .fixed_radius
                    .unwrap_or(request.chunk_radius.0.min(self.max_radius));
                self.radius = Some(radius);
                Ok(Event::Send(vec![
                    packets::ChunkRadiusUpdated {
                        chunk_radius: wire::ZigZag32(radius),
                    }
                    .into(),
                    packets::PlayStatus {
                        status: PlayStatusType::Playerspawn,
                    }
                    .into(),
                    self.creative
                        .take()
                        .expect("first radius owns creative content")
                        .into(),
                ]))
            }
            packets::Packet::SetLocalPlayerAsInitialized(initialized) => {
                if self.radius.is_none()
                    || self.initialized
                    || initialized.player_id.0 != self.runtime_id
                {
                    return Err(Error::InvalidData(
                        "invalid accepting player initialization",
                    ));
                }
                self.initialized = true;
                Ok(Event::Ready)
            }
            packet => Ok(Event::Unhandled(Box::new(packet))),
        }
    }

    /// Transfers only the radius already committed by the actual initialization exchange.
    pub(super) fn radius(&self) -> i32 {
        self.radius.expect("ready requires initial radius")
    }
}
