//! Caller-owned upstream startup; generated controls advance only after their real forward flush.

use super::{
    AcceptedSession, AuthenticatedLogin, LoginPolicy, Phase, ServerSessionError as Error,
    ServerSessionTransitionError, SessionEngine, bounded_metadata, lifecycle::failure,
};
use crate::server::ServerPacksReady;
use bedrock_protocol::{enums::PlayStatusType, packets};
use std::time::{Instant, SystemTime};

impl<A, L> ServerPacksReady<A, L> {
    /// Relays a caller-selected upstream with no advertised pack phase.
    /// Revalidates the original Login and retains its grant/deadline. The returned
    /// LoginSuccess must be sent and flushed before any upstream startup is forwarded.
    /// This creates no offer, stack acknowledgment, selected world or initialization.
    ///
    /// # Errors
    /// Rejects an insufficient metadata bound, expiry or changed provider identity.
    pub fn relay_without_packs(
        self,
        max_metadata_bytes: usize,
        verifier: &impl LoginPolicy<L>,
        now: Instant,
        utc: SystemTime,
    ) -> Result<PendingServerRelay<A, L>, ServerSessionTransitionError<Self>> {
        if max_metadata_bytes == 0 {
            return Err(failure(
                self,
                Error::InvalidData("zero relay metadata limit"),
            ));
        }
        let success = packets::PlayStatus {
            status: PlayStatusType::Loginsuccess,
        };
        if let Err(cause) = bounded_metadata(&success, packets::PlayStatus::ID, max_metadata_bytes)
        {
            return Err(failure(self, cause));
        }
        let accepted = match self.finish(verifier, now, utc) {
            Ok(accepted) => accepted,
            Err(failed) => {
                let (owner, cause) = failed.into_parts();
                return Err(failure(owner, cause.into()));
            }
        };
        let deadline = accepted.deadline();
        let (login, grant) = accepted.into_parts();
        Ok(PendingServerRelay {
            session: ServerRelaying::new(Box::new(SessionEngine {
                login,
                grant,
                packs: None,
                metadata_limit: max_metadata_bytes,
                world: None,
                deadline,
                phase: Phase::World,
                cache_enabled: false,
            })),
            packet: success.into(),
            effect: Effect::None,
        })
    }
}

/// The original accepting Login and grant observing a real upstream world's startup.
/// This owner generates no world, radius, item, creative or spawn response.
#[must_use]
pub struct ServerRelaying<A, L = AuthenticatedLogin> {
    engine: Box<SessionEngine<A, L>>,
    runtime_id: Option<u64>,
    radius: Option<i32>,
    requested: bool,
    items: bool,
    spawned: bool,
}

/// One original control or initial LoginSuccess and its sole continuation, awaiting actual flush.
/// Raw headers/bytes and pipelined siblings remain with the adapter, under its original byte bound.
///
/// ```compile_fail
/// fn advance_before_flush(pending: bedrock_client::server::session::PendingServerRelay<()>,
///                         packet: bedrock_protocol::packets::Packet, now: std::time::Instant) {
///     pending.forward_client(packet, now);
/// }
/// ```
#[must_use = "forward the original control and flush before advancing its continuation"]
pub struct PendingServerRelay<A, L = AuthenticatedLogin> {
    session: ServerRelaying<A, L>,
    packet: packets::Packet,
    effect: Effect,
}

/// Only completed original forwards can continue startup or expose actual initialization.
pub enum ServerRelayProgress<A, L = AuthenticatedLogin> {
    /// Continue observing the same real upstream and client under the unchanged deadline.
    Continue(ServerRelaying<A, L>),
    /// The client's exact initialization reached the original upstream; revalidate before attaching.
    Initialized(ServerRelayInitialized<A, L>),
}

/// Actual forwarded initialization, retaining its original provider/grant for the final check.
#[must_use]
pub struct ServerRelayInitialized<A, L = AuthenticatedLogin> {
    session: ServerRelaying<A, L>,
}

enum Effect {
    None,
    Runtime(u64),
    Radius(i32),
    Requested,
    Items,
    Spawned,
    Cache(bool),
    Initialized,
}

impl<A, L> ServerRelaying<A, L> {
    /// Takes original Login/grant after actual packs or explicit absence, without creating a world.
    pub(super) fn new(engine: Box<SessionEngine<A, L>>) -> Self {
        Self {
            engine,
            runtime_id: None,
            radius: None,
            requested: false,
            items: false,
            spawned: false,
        }
    }

    /// Borrows the original Login capability and signed client data.
    pub fn login(&self) -> &L {
        &self.engine.login
    }

    /// Borrows original application authority for the adapter's adjacent forward commit check.
    pub fn grant(&self) -> &A {
        &self.engine.grant
    }

    /// Returns the same absolute accepting deadline, including all pending forwards.
    pub fn deadline(&self) -> Instant {
        self.engine.deadline
    }

    /// Prepares an original upstream control for forwarding to the accepted client.
    /// Only startup controls need decoding; unrelated raw packets can stay with the adapter.
    /// Handle actual Disconnect/Transfer immediately instead of advancing this observer.
    pub fn forward_server(
        mut self,
        packet: packets::Packet,
        now: Instant,
    ) -> Result<PendingServerRelay<A, L>, ServerSessionTransitionError<Self>> {
        let effect = (|| {
            self.engine.require(Phase::World, now)?;
            Ok(match &packet {
                packets::Packet::StartGame(start) => {
                    bounded_metadata(start.as_ref(), packets::StartGame::ID, self.limit())?;
                    if self.runtime_id.is_some_and(|id| id != start.runtime_id.0) {
                        return Err(Error::InvalidData("conflicting relayed runtime ID"));
                    }
                    Effect::Runtime(start.runtime_id.0)
                }
                packets::Packet::ItemRegistry(_) => Effect::Items,
                packets::Packet::ChunkRadiusUpdated(radius) => {
                    if radius.chunk_radius.0 < 1 {
                        return Err(Error::InvalidData("invalid relayed chunk radius"));
                    }
                    Effect::Radius(radius.chunk_radius.0)
                }
                packets::Packet::PlayStatus(status)
                    if status.status == PlayStatusType::Playerspawn =>
                {
                    Effect::Spawned
                }
                _ => Effect::None,
            })
        })();
        self.pending(packet, effect)
    }

    /// Prepares an actual accepted client control for forwarding to the same upstream.
    /// A matching Initialized remains pending until that exact original packet is flushed upstream.
    pub fn forward_client(
        mut self,
        packet: packets::Packet,
        now: Instant,
    ) -> Result<PendingServerRelay<A, L>, ServerSessionTransitionError<Self>> {
        let effect = (|| {
            self.engine.require(Phase::World, now)?;
            Ok(match &packet {
                packets::Packet::RequestChunkRadius(request) => {
                    if self.runtime_id.is_none() || request.chunk_radius.0 < 1 {
                        return Err(Error::InvalidData("invalid relayed radius request"));
                    }
                    Effect::Requested
                }
                packets::Packet::ClientCacheStatus(status) => {
                    Effect::Cache(status.is_cache_supported)
                }
                packets::Packet::SetLocalPlayerAsInitialized(initialized) => {
                    if self.runtime_id != Some(initialized.player_id.0)
                        || self.radius.is_none()
                        || !self.requested
                        || !self.items
                        || !self.spawned
                    {
                        return Err(Error::InvalidData("invalid relayed player initialization"));
                    }
                    Effect::Initialized
                }
                _ => Effect::None,
            })
        })();
        self.pending(packet, effect)
    }

    /// Keeps failure and the sole original owner together rather than exposing a retryable state.
    fn pending(
        mut self,
        packet: packets::Packet,
        effect: Result<Effect, Error>,
    ) -> Result<PendingServerRelay<A, L>, ServerSessionTransitionError<Self>> {
        match self.engine.terminal(effect) {
            Ok(effect) => Ok(PendingServerRelay {
                session: self,
                packet,
                effect,
            }),
            Err(cause) => Err(failure(self, cause)),
        }
    }

    /// Uses the original accepting metadata ceiling rather than a new relay size policy.
    fn limit(&self) -> usize {
        self.engine.metadata_limit
    }
}

impl<A, L> PendingServerRelay<A, L> {
    /// Borrows the exact decoded control; the adapter may forward its matching original raw bytes.
    pub fn packet(&self) -> &packets::Packet {
        &self.packet
    }

    /// Borrows original identity for application/provider checks after actual IO waits.
    pub fn login(&self) -> &L {
        self.session.login()
    }

    /// Borrows original application authority before the actual synchronous send commit.
    pub fn grant(&self) -> &A {
        self.session.grant()
    }

    /// Returns the original cutoff; cancellation of a borrowed adapter wait cannot renew it.
    pub fn deadline(&self) -> Instant {
        self.session.deadline()
    }

    /// Records only successful forwarding/flush of this exact original control.
    /// Canceling before this call retains the whole pending continuation for explicit retirement.
    pub fn flushed(
        mut self,
        now: Instant,
    ) -> Result<ServerRelayProgress<A, L>, ServerSessionTransitionError<Self>> {
        let result = self.session.engine.require(Phase::World, now);
        if let Err(cause) = self.session.engine.terminal(result) {
            return Err(failure(self, cause));
        }
        match self.effect {
            Effect::None => {}
            Effect::Runtime(id) => self.session.runtime_id = Some(id),
            Effect::Radius(radius) => self.session.radius = Some(radius),
            Effect::Requested => self.session.requested = true,
            Effect::Items => self.session.items = true,
            Effect::Spawned => self.session.spawned = true,
            Effect::Cache(enabled) => self.session.engine.cache_enabled = enabled,
            Effect::Initialized => {
                self.session.engine.phase = Phase::Ready;
                return Ok(ServerRelayProgress::Initialized(ServerRelayInitialized {
                    session: self.session,
                }));
            }
        }
        Ok(ServerRelayProgress::Continue(self.session))
    }
}

impl<A, L> ServerRelayInitialized<A, L> {
    /// Borrows the same original Login capability before final attachment.
    pub fn login(&self) -> &L {
        self.session.login()
    }

    /// Borrows original application authority for the caller's final adjacent commit check.
    pub fn grant(&self) -> &A {
        self.session.grant()
    }

    /// Returns the unchanged original accepting deadline.
    pub fn deadline(&self) -> Instant {
        self.session.deadline()
    }

    /// Rechecks the original Login policy after actual initialization was forwarded upstream.
    /// This proves protocol progress, not hosted membership or permission to publish occupancy.
    pub fn finish(
        mut self,
        verifier: &impl LoginPolicy<L>,
        now: Instant,
        utc: SystemTime,
    ) -> Result<AcceptedSession<A, L>, ServerSessionTransitionError<Self>> {
        if let Err(cause) = self.session.engine.check_finish(verifier, now, utc) {
            return Err(failure(self, cause));
        }
        let radius = self
            .session
            .radius
            .expect("initialized relay observed a radius");
        Ok(AcceptedSession::from_relay(*self.session.engine, radius))
    }
}
