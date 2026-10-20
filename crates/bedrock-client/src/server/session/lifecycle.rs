//! Owned pack IO and actual selected-world handoffs over one original accepting engine.

use super::{
    AuthenticatedLogin, LoginPolicy, LoginVerifier, ServerChunkRequest, ServerPackDelivery,
    ServerPackSnapshot, ServerSessionError as Error, ServerSessionEvent as Event,
    ServerSessionOutput, ServerWorld, SessionEngine, packs,
};
use crate::server::ServerPacksReady;
use bedrock_protocol::packets;
use std::{
    fmt,
    time::{Instant, SystemTime},
};

impl<A> ServerPacksReady<A> {
    /// Validates the original selected snapshot before advertising any pack or LoginSuccess.
    /// Revalidates Login under its unchanged deadline. Application grant validity belongs
    /// to the caller and must be checked again at actual sends/attachment after waits.
    pub fn start_packs(
        self,
        snapshot: ServerPackSnapshot,
        delivery: ServerPackDelivery,
        verifier: &impl LoginVerifier,
        now: Instant,
        utc: SystemTime,
    ) -> Result<ServerSessionOutput<ServerPacks<A>>, ServerSessionTransitionError<Self>> {
        let delivery = match packs::Delivery::new(snapshot, delivery) {
            Ok(delivery) => delivery,
            Err(cause) => return Err(failure(self, cause)),
        };
        let accepted = match self.finish(verifier, now, utc) {
            Ok(accepted) => accepted,
            Err(failed) => {
                let (owner, cause) = failed.into_parts();
                return Err(failure(owner, cause.into()));
            }
        };
        let deadline = accepted.deadline();
        let (login, grant) = accepted.into_parts();
        let (engine, packets) = SessionEngine::new(login, grant, delivery, deadline);
        Ok((
            ServerPacks {
                engine: Box::new(engine),
            },
            packets,
        ))
    }
}

/// Actual Login completion and selected pack delivery, before any selected-world startup.
#[must_use]
pub struct ServerPacks<A, L = AuthenticatedLogin> {
    engine: Box<SessionEngine<A, L>>,
}

/// One packet's effects and its sole original session continuation.
pub enum ServerPackEvent<A, L = AuthenticatedLogin> {
    /// Send these packets in order before further peer input.
    Send {
        /// The same delivery owner, without a renewed deadline.
        session: ServerPacks<A, L>,
        /// Actual generated metadata/stack output.
        packets: Vec<packets::Packet>,
    },
    /// The immutable memory chunk awaits actual adapter write/flush.
    Chunk(PendingServerChunk<A, L>),
    /// The original external source lease must supply this bounded range.
    ReadChunk(PendingServerChunkRead<A, L>),
    /// Actual stack acknowledgment; only this owner can start the selected world.
    WorldReady(ServerWorldReady<A, L>),
    /// Handle terminal/unrelated input immediately, before resuming the returned owner.
    Unhandled {
        /// Same original delivery state and deadline.
        session: ServerPacks<A, L>,
        /// Untouched decoded input; no new application queue is retained.
        packet: Box<packets::Packet>,
    },
}

impl<A, L> ServerPacks<A, L> {
    /// Borrows the original Login capability and signed nonce for current application authority.
    pub fn login(&self) -> &L {
        &self.engine.login
    }
    /// Borrows the actual caller-trusted grant; this library does not prove hosted membership.
    pub fn grant(&self) -> &A {
        &self.engine.grant
    }
    /// Returns the original handshake deadline, also bounding adapter reads/writes.
    pub fn deadline(&self) -> Instant {
        self.engine.deadline
    }

    /// Processes one actual generated pack/control packet with no request queue.
    /// Read/write effects own this entire continuation until completed or retired.
    pub fn receive(
        mut self,
        packet: packets::Packet,
        now: Instant,
    ) -> Result<ServerPackEvent<A, L>, ServerSessionTransitionError<Self>> {
        let event = match self.engine.receive(packet, now) {
            Ok(event) => event,
            Err(cause) => return Err(failure(self, cause)),
        };
        Ok(match event {
            Event::Send(packets) => ServerPackEvent::Send {
                session: self,
                packets,
            },
            Event::Chunk(packet) => ServerPackEvent::Chunk(PendingServerChunk {
                engine: self.engine,
                packet,
            }),
            Event::ReadChunk(request) => ServerPackEvent::ReadChunk(PendingServerChunkRead {
                engine: self.engine,
                request,
            }),
            Event::ReadyForWorld => ServerPackEvent::WorldReady(ServerWorldReady {
                engine: self.engine,
            }),
            Event::Unhandled(packet) => ServerPackEvent::Unhandled {
                session: self,
                packet,
            },
            Event::Ready => unreachable!("pack delivery cannot initialize the player"),
        })
    }
}

/// One external range and its whole accepting continuation, not a separately mixable read token.
/// The caller retains its immutable archive lease and existing decoded siblings during IO.
///
/// ```compile_fail
/// fn feed_during_read<A, L>(read: bedrock_client::server::session::PendingServerChunkRead<A, L>,
///     packet: bedrock_protocol::packets::Packet, now: std::time::Instant) {
///     read.receive(packet, now);
/// }
/// ```
#[must_use = "complete the original bounded read or retire the accepting connection"]
pub struct PendingServerChunkRead<A, L = AuthenticatedLogin> {
    engine: Box<SessionEngine<A, L>>,
    request: ServerChunkRequest,
}

impl<A, L> PendingServerChunkRead<A, L> {
    /// Borrows the original Login for application authority rechecks after IO.
    pub fn login(&self) -> &L {
        &self.engine.login
    }
    /// Borrows the actual retained caller grant.
    pub fn grant(&self) -> &A {
        &self.engine.grant
    }
    /// Bounds this same original read/write attempt; it is never renewed by completion.
    pub fn deadline(&self) -> Instant {
        self.engine.deadline
    }
    /// Index in the original offer/content order, identifying the adapter-held source lease.
    pub fn archive_index(&self) -> usize {
        self.request.archive_index()
    }
    /// Original compressed source offset.
    pub fn offset(&self) -> u64 {
        self.request.offset()
    }
    /// Exact nonzero byte count bounded by the selected chunk limit and archive tail.
    pub fn byte_len(&self) -> usize {
        self.request.byte_len()
    }

    /// Supplies only this original range; the last external bytes must finish its advertised SHA.
    /// A failed read completion retains a sealed failed owner, never a retryable fresh attempt.
    pub fn supply(
        mut self,
        bytes: Vec<u8>,
        now: Instant,
    ) -> Result<PendingServerChunk<A, L>, ServerSessionTransitionError<Self>> {
        let event = match self.engine.supply_chunk(&self.request, bytes, now) {
            Ok(event) => event,
            Err(cause) => return Err(failure(self, cause)),
        };
        let Event::Chunk(packet) = event else {
            unreachable!("a validated original read emits exactly one chunk");
        };
        Ok(PendingServerChunk {
            engine: self.engine,
            packet,
        })
    }
}

/// Original chunk packet and the sole continuation that can advance after its actual flush.
#[must_use = "flush this exact chunk before consuming its delivery continuation"]
pub struct PendingServerChunk<A, L = AuthenticatedLogin> {
    engine: Box<SessionEngine<A, L>>,
    packet: packets::ResourcePackChunkData,
}

impl<A, L> PendingServerChunk<A, L> {
    /// Borrows the immutable chunk for actual adapter send/flush.
    pub fn packet(&self) -> &packets::ResourcePackChunkData {
        &self.packet
    }
    /// Borrows original player identity for current application policy rechecks.
    pub fn login(&self) -> &L {
        &self.engine.login
    }
    /// Borrows the original caller-trusted grant.
    pub fn grant(&self) -> &A {
        &self.engine.grant
    }
    /// Returns the unchanged original deadline for actual IO.
    pub fn deadline(&self) -> Instant {
        self.engine.deadline
    }

    /// Consumes the real adapter's successful write/flush contract once.
    /// Pure code cannot prove socket IO. Failure retains this exact packet/owner for retirement.
    pub fn flushed(
        mut self,
        now: Instant,
    ) -> Result<ServerSessionOutput<ServerPacks<A, L>>, ServerSessionTransitionError<Self>> {
        let packets = match self.engine.chunk_flushed(now) {
            Ok(packets) => packets,
            Err(cause) => return Err(failure(self, cause)),
        };
        Ok((
            ServerPacks {
                engine: self.engine,
            },
            packets,
        ))
    }
}

/// Actual final-stack acknowledgment, before supplying a real selected world's definitions.
#[must_use]
pub struct ServerWorldReady<A, L = AuthenticatedLogin> {
    engine: Box<SessionEngine<A, L>>,
}

impl<A, L> ServerWorldReady<A, L> {
    /// Borrows the unchanged original Login capability and signed nonce.
    pub fn login(&self) -> &L {
        &self.engine.login
    }
    /// Borrows actual caller authority for the real selected-world handoff.
    pub fn grant(&self) -> &A {
        &self.engine.grant
    }
    /// Returns the original accepting deadline.
    pub fn deadline(&self) -> Instant {
        self.engine.deadline
    }

    /// Relays an actual upstream world's startup without generating world or spawn packets.
    /// The adapter retains original bytes and acknowledges each real forward with `flushed`.
    /// No initialized session exists until the original runtime ID and startup controls crossed
    /// their corresponding wire boundaries and the client's final acknowledgment is forwarded.
    pub fn relay_world(
        mut self,
        verifier: &impl LoginPolicy<L>,
        now: Instant,
        utc: SystemTime,
    ) -> Result<super::ServerRelaying<A, L>, ServerSessionTransitionError<Self>> {
        let result = (|| {
            self.engine.require(super::Phase::World, now)?;
            verifier.revalidate(&self.engine.login, utc)?;
            Ok(())
        })();
        if let Err(cause) = self.engine.terminal(result) {
            return Err(failure(self, cause));
        }
        Ok(super::ServerRelaying::new(self.engine))
    }

    /// Starts only the caller-selected real world after provider revalidation.
    /// The caller rechecks current grant/world authority after waits; no default world exists.
    pub fn start_world(
        mut self,
        world: ServerWorld,
        verifier: &impl LoginPolicy<L>,
        now: Instant,
        utc: SystemTime,
    ) -> Result<ServerSessionOutput<ServerSpawning<A, L>>, ServerSessionTransitionError<Self>> {
        let event = match self.engine.start_world(world, verifier, now, utc) {
            Ok(event) => event,
            Err(cause) => return Err(failure(self, cause)),
        };
        let Event::Send(packets) = event else {
            unreachable!("validated selected-world startup emits definitions");
        };
        Ok((
            ServerSpawning {
                engine: self.engine,
            },
            packets,
        ))
    }
}

/// Actual selected-world definitions were produced; observes radius and exact runtime-ID initialization.
#[must_use]
pub struct ServerSpawning<A, L = AuthenticatedLogin> {
    engine: Box<SessionEngine<A, L>>,
}

/// Startup effects preserving actual selected-world/player identity and the same continuation.
pub enum ServerSpawnEvent<A, L = AuthenticatedLogin> {
    /// Send original radius/spawn/creative output in order.
    Send {
        /// Same original startup observer.
        session: ServerSpawning<A, L>,
        /// Actual generated output from that selected-world policy.
        packets: Vec<packets::Packet>,
    },
    /// Exact initialization was observed; final provider/application handoff remains explicit.
    Initialized(ServerInitialized<A, L>),
    /// Handle terminal/unrelated input immediately before resuming the observer.
    Unhandled {
        /// Same original startup state.
        session: ServerSpawning<A, L>,
        /// Untouched decoded input.
        packet: Box<packets::Packet>,
    },
}

impl<A, L> ServerSpawning<A, L> {
    /// Borrows the original Login capability and signed nonce.
    pub fn login(&self) -> &L {
        &self.engine.login
    }
    /// Borrows original caller authority before later IO/attachment.
    pub fn grant(&self) -> &A {
        &self.engine.grant
    }
    /// Returns the original accepting deadline.
    pub fn deadline(&self) -> Instant {
        self.engine.deadline
    }

    /// Observes actual radius/runtime-ID input, returning unrelated packets intact.
    pub fn receive(
        mut self,
        packet: packets::Packet,
        now: Instant,
    ) -> Result<ServerSpawnEvent<A, L>, ServerSessionTransitionError<Self>> {
        let event = match self.engine.receive(packet, now) {
            Ok(event) => event,
            Err(cause) => return Err(failure(self, cause)),
        };
        Ok(match event {
            Event::Send(packets) => ServerSpawnEvent::Send {
                session: self,
                packets,
            },
            Event::Ready => ServerSpawnEvent::Initialized(ServerInitialized {
                engine: self.engine,
            }),
            Event::Unhandled(packet) => ServerSpawnEvent::Unhandled {
                session: self,
                packet,
            },
            _ => unreachable!("startup cannot perform pack-delivery transitions"),
        })
    }
}

/// Actual runtime-ID initialization, with original Login/grant still awaiting final handoff checks.
#[must_use]
pub struct ServerInitialized<A, L = AuthenticatedLogin> {
    engine: Box<SessionEngine<A, L>>,
}

impl<A, L> ServerInitialized<A, L> {
    /// Borrows the original Login capability and signed nonce.
    pub fn login(&self) -> &L {
        &self.engine.login
    }
    /// Borrows caller authority for actual final world attachment.
    pub fn grant(&self) -> &A {
        &self.engine.grant
    }
    /// Returns the original accepting deadline.
    pub fn deadline(&self) -> Instant {
        self.engine.deadline
    }

    /// Revalidates the original provider credential before transferring actual initialized data.
    /// This proves completed protocol initialization, not real world membership or attachment.
    pub fn finish(
        mut self,
        verifier: &impl LoginPolicy<L>,
        now: Instant,
        utc: SystemTime,
    ) -> Result<AcceptedSession<A, L>, ServerSessionTransitionError<Self>> {
        if let Err(cause) = self.engine.check_finish(verifier, now, utc) {
            return Err(failure(self, cause));
        }
        let SessionEngine {
            login,
            grant,
            cache_enabled,
            world,
            ..
        } = *self.engine;
        Ok(AcceptedSession {
            login,
            grant,
            client_cache_enabled: cache_enabled,
            chunk_radius: world
                .expect("initialized owner retains actual world")
                .radius(),
        })
    }
}

/// Verified actual protocol handoff, carrying original player identity and caller-trusted grant.
/// No public constructor or field can fabricate initialization or hosted membership.
pub struct AcceptedSession<A, L = AuthenticatedLogin> {
    login: L,
    grant: A,
    client_cache_enabled: bool,
    chunk_radius: i32,
}

impl<A, L> AcceptedSession<A, L> {
    /// Takes only a relay continuation that already checked its real initialization and provider.
    pub(super) fn from_relay(engine: SessionEngine<A, L>, chunk_radius: i32) -> Self {
        Self {
            login: engine.login,
            grant: engine.grant,
            client_cache_enabled: engine.cache_enabled,
            chunk_radius,
        }
    }

    /// Borrows original Login capability and signed client metadata.
    pub fn login(&self) -> &L {
        &self.login
    }
    /// Borrows original caller-trusted authority; real attachment must recheck it.
    pub fn grant(&self) -> &A {
        &self.grant
    }
    /// Returns the last actual client blob-cache declaration.
    pub fn client_cache_enabled(&self) -> bool {
        self.client_cache_enabled
    }
    /// Returns the initial radius actually negotiated under selected-world policy.
    pub fn chunk_radius(&self) -> i32 {
        self.chunk_radius
    }
    /// Transfers original identity/grant and observed cache/radius data to the real adapter.
    pub fn into_parts(self) -> (L, A, bool, i32) {
        (
            self.login,
            self.grant,
            self.client_cache_enabled,
            self.chunk_radius,
        )
    }
}

/// A fallible accepting transition retains its original output/grant/owner for retirement.
/// Failed protocol owners remain sealed; recovery cannot renew deadlines or permissions.
pub struct ServerSessionTransitionError<C> {
    owner: Box<C>,
    cause: Error,
}

impl<C> ServerSessionTransitionError<C> {
    /// Recovers the original continuation and redacted failure, without resetting it.
    pub fn into_parts(self) -> (C, Error) {
        (*self.owner, self.cause)
    }
}
impl<C> fmt::Debug for ServerSessionTransitionError<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerSessionTransitionError")
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}
impl<C> fmt::Display for ServerSessionTransitionError<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.cause, f)
    }
}
impl<C> std::error::Error for ServerSessionTransitionError<C> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

/// Keeps failure diagnostics independent of credential/content/grant values.
pub(super) fn failure<C>(owner: C, cause: Error) -> ServerSessionTransitionError<C> {
    ServerSessionTransitionError {
        owner: Box::new(owner),
        cause,
    }
}

#[cfg(test)]
#[path = "typed_tests.rs"]
mod typed_tests;
