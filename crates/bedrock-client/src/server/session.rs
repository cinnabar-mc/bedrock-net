//! Accepted Login retained through exact pack delivery and caller-selected world startup.

mod lifecycle;
mod packs;
mod relay;
mod spawn;

pub use lifecycle::{
    AcceptedSession, PendingServerChunk, PendingServerChunkRead, ServerInitialized,
    ServerPackEvent, ServerPacks, ServerSessionTransitionError, ServerSpawnEvent, ServerSpawning,
    ServerWorldReady,
};

use packs::ServerChunkRequest;
pub use packs::{ServerPackContent, ServerPackDelivery, ServerPackSnapshot};
pub use relay::{PendingServerRelay, ServerRelayInitialized, ServerRelayProgress, ServerRelaying};
pub use spawn::ServerWorld;

use super::{AuthenticatedLogin, LoginError, LoginVerifier, ServerHandshakeError};
use bedrock_protocol::{enums::PlayStatusType, packets, wire};
use std::time::{Instant, SystemTime};

/// A terminal accepting transition failure without peer metadata or content keys.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServerSessionError {
    /// The operation repeated or preceded its required wire boundary.
    #[error("accepting session operation is out of sequence")]
    InvalidState,
    /// The original caller deadline elapsed.
    #[error("accepting session deadline expired")]
    TimedOut,
    /// An inconsistent snapshot, request or startup packet cannot be admitted.
    #[error("{0}")]
    InvalidData(&'static str),
    /// The exact original provider credential no longer qualifies.
    #[error(transparent)]
    Login(#[from] LoginError),
    /// The original accepting Login handoff no longer qualifies.
    #[error(transparent)]
    Handshake(#[from] ServerHandshakeError),
}

/// Ordered effects; the caller retains its connection, approval and decoded packet siblings.
#[non_exhaustive]
enum ServerSessionEvent {
    /// Send these generated packets in order before reading another owned transition.
    Send(Vec<packets::Packet>),
    /// Flush this chunk, then call chunk_flushed with the actual completion time.
    Chunk(packets::ResourcePackChunkData),
    /// Read this bounded original external range, then supply_chunk once under the original deadline.
    /// The adapter retains its source lease; read failure/cancellation ends the connection.
    ReadChunk(ServerChunkRequest),
    /// Packs are acknowledged. Supply the actual selected world; this is not world authorization.
    ReadyForWorld,
    /// The client acknowledged its original runtime ID; finish performs final provider revalidation.
    Ready,
    /// Input owned by the adapter, including Disconnect/Transfer for immediate termination handling.
    Unhandled(Box<packets::Packet>),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Packs,
    World,
    Spawning,
    Ready,
    Failed,
}

/// Same original Login/grant/deadline retained across all owned pack/world continuations.
struct SessionEngine<A> {
    login: AuthenticatedLogin,
    grant: A,
    packs: packs::Delivery,
    world: Option<spawn::Startup>,
    deadline: Instant,
    phase: Phase,
    cache_enabled: bool,
}

impl<A> SessionEngine<A> {
    /// Wraps validated delivery and the actual consumed Login without renewing its deadline.
    fn new(
        login: AuthenticatedLogin,
        grant: A,
        mut packs: packs::Delivery,
        deadline: Instant,
    ) -> (Self, Vec<packets::Packet>) {
        let offer = packs
            .start()
            .expect("validated delivery owns its original offer");
        (
            Self {
                login,
                grant,
                packs,
                world: None,
                deadline,
                phase: Phase::Packs,
                cache_enabled: false,
            },
            vec![
                packets::PlayStatus {
                    status: PlayStatusType::Loginsuccess,
                }
                .into(),
                offer.into(),
            ],
        )
    }

    /// Processes one generated packet, retaining unrelated input at the adapter boundary.
    ///
    /// # Errors
    /// Rejects expiry, invalid pack/phase transitions, radius or runtime-ID mismatch.
    fn receive(
        &mut self,
        packet: packets::Packet,
        now: Instant,
    ) -> Result<ServerSessionEvent, ServerSessionError> {
        let result = self.receive_inner(packet, now);
        self.terminal(result)
    }

    /// Records actual chunk flush before advancing the original archive.
    /// Send any returned next-pack DataInfo before retrying retained input.
    ///
    /// # Errors
    /// Rejects expiry or a missing/repeated chunk acknowledgment.
    fn chunk_flushed(&mut self, now: Instant) -> Result<Vec<packets::Packet>, ServerSessionError> {
        let result = (|| {
            self.require(Phase::Packs, now)?;
            self.packs.flushed()
        })();
        self.terminal(result)
    }

    /// Completes the one original external read without accepting replacement identity or excess bytes.
    /// The exact pending request is consumed; the last external fragment must finish its advertised SHA.
    ///
    /// # Errors
    /// Rejects expiry, stale/out-of-phase read completion, wrong length or changed original content.
    fn supply_chunk(
        &mut self,
        request: &ServerChunkRequest,
        bytes: Vec<u8>,
        now: Instant,
    ) -> Result<ServerSessionEvent, ServerSessionError> {
        let result = (|| {
            self.require(Phase::Packs, now)?;
            self.packs.supply(request, bytes)
        })();
        self.terminal(result)
    }

    /// Starts the actual adapter-selected world only after the stack acknowledgment.
    /// Rechecks the original provider credential before emitting its real definitions.
    ///
    /// # Errors
    /// Rejects expiry, invalid world bounds, repeated/out-of-phase startup or changed credentials.
    fn start_world(
        &mut self,
        world: ServerWorld,
        verifier: &impl LoginVerifier,
        now: Instant,
        utc: SystemTime,
    ) -> Result<ServerSessionEvent, ServerSessionError> {
        let result = (|| {
            self.require(Phase::World, now)?;
            self.login.revalidate(verifier, utc)?;
            let (startup, packets) = spawn::Startup::new(world, self.packs.metadata_limit())?;
            self.world = Some(startup);
            self.phase = Phase::Spawning;
            Ok(ServerSessionEvent::Send(packets))
        })();
        self.terminal(result)
    }

    /// Revalidates the actual initialized owner before final application attachment.
    fn check_finish(
        &mut self,
        verifier: &impl LoginVerifier,
        now: Instant,
        utc: SystemTime,
    ) -> Result<(), ServerSessionError> {
        let result = (|| {
            self.require(Phase::Ready, now)?;
            self.login
                .revalidate(verifier, utc)
                .map_err(ServerSessionError::from)
        })();
        self.terminal(result)
    }

    /// Keeps pack and spawn transitions on the same accepted owner and absolute deadline.
    fn receive_inner(
        &mut self,
        packet: packets::Packet,
        now: Instant,
    ) -> Result<ServerSessionEvent, ServerSessionError> {
        self.check_live(now)?;
        if let packets::Packet::ClientCacheStatus(status) = packet {
            self.cache_enabled = status.is_cache_supported;
            return Ok(ServerSessionEvent::Send(Vec::new()));
        }
        let owned_phase = match &packet {
            packets::Packet::ResourcePackClientResponse(_)
            | packets::Packet::ResourcePackChunkRequest(_) => Some(Phase::Packs),
            packets::Packet::RequestChunkRadius(_)
            | packets::Packet::SetLocalPlayerAsInitialized(_) => Some(Phase::Spawning),
            _ => None,
        };
        if owned_phase.is_some_and(|phase| phase != self.phase) {
            return Err(ServerSessionError::InvalidState);
        }
        let event = match self.phase {
            Phase::Packs => self.packs.receive(packet)?,
            Phase::Spawning => self
                .world
                .as_mut()
                .expect("spawning requires world")
                .receive(packet)?,
            _ => return Ok(ServerSessionEvent::Unhandled(Box::new(packet))),
        };
        match event {
            ServerSessionEvent::ReadyForWorld => self.phase = Phase::World,
            ServerSessionEvent::Ready => self.phase = Phase::Ready,
            _ => {}
        }
        Ok(event)
    }

    /// Rejects an elapsed original deadline or a previously terminal owner before any transition.
    fn check_live(&mut self, now: Instant) -> Result<(), ServerSessionError> {
        if now >= self.deadline {
            return Err(ServerSessionError::TimedOut);
        }
        if matches!(self.phase, Phase::Failed) {
            return Err(ServerSessionError::InvalidState);
        }
        Ok(())
    }

    /// Enforces an explicit one-shot producer boundary without a hidden await.
    fn require(&mut self, phase: Phase, now: Instant) -> Result<(), ServerSessionError> {
        self.check_live(now)?;
        if self.phase != phase {
            return Err(ServerSessionError::InvalidState);
        }
        Ok(())
    }

    /// Seals any fallible public transition instead of allowing a partial retry.
    fn terminal<T>(
        &mut self,
        result: Result<T, ServerSessionError>,
    ) -> Result<T, ServerSessionError> {
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }
}

/// Validates generated local metadata without retaining value-bearing codec errors or excess output.
fn bounded_metadata(
    value: &impl wire::Encode,
    id: u32,
    limit: usize,
) -> Result<(), ServerSessionError> {
    let mut encoded = Vec::new();
    wire::encode_frame_with(
        &mut encoded,
        wire::PacketHeader {
            id,
            sender_subclient: 0,
            target_subclient: 0,
        },
        limit,
        |writer| value.encode(writer),
    )
    .map_err(|_| ServerSessionError::InvalidData("accepting metadata exceeds its wire budget"))?;
    if encoded.len() > limit {
        return Err(ServerSessionError::InvalidData(
            "accepting metadata exceeds its wire budget",
        ));
    }
    Ok(())
}
