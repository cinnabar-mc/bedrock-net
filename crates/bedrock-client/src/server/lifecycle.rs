//! Consumed accepting capabilities; provider verification and caller authorization remain distinct.

use super::{
    AuthenticatedLogin, BatchDecryptor, BatchEncryptor, CompressionSettings, Engine, EngineEvent,
    LoginVerifier, ServerHandshakeError, ServerHandshakeOptions, ServerKeyExchangeHandoff,
    SigningKey, VerifyingKey, packets,
};
use std::{
    fmt,
    sync::Arc,
    time::{Instant, SystemTime},
};

/// Awaiting the actual network settings request under one original accepting deadline.
///
/// ```compile_fail
/// fn accept_before_verification(pending: bedrock_client::server::ServerHandshake) {
///     let _accepted = pending.accept();
/// }
/// ```
#[must_use]
pub struct ServerHandshake {
    engine: Box<Engine>,
}

impl ServerHandshake {
    /// Validates configuration and retains the original server proof/transport binding.
    /// Transport binding is caller-trusted input, not inferred from an unverified SDP/header.
    pub fn new(
        key: impl Into<Arc<SigningKey>>,
        transport_key: Option<VerifyingKey>,
        options: ServerHandshakeOptions,
        deadline: Instant,
        now: Instant,
    ) -> Result<Self, ServerHandshakeError> {
        Ok(Self {
            engine: Box::new(Engine::new(key, transport_key, options, deadline, now)?),
        })
    }

    /// Borrows the same key allocation for actual signed transport admission.
    pub fn key(&self) -> &SigningKey {
        self.engine.key()
    }

    /// Processes settings input without exposing Login acceptance before verification.
    pub fn receive(
        mut self,
        packet: packets::Packet,
        verifier: &impl LoginVerifier,
        now: Instant,
        utc: SystemTime,
    ) -> Result<ServerSettingsEvent, ServerHandshakeError> {
        match self.engine.receive(packet, verifier, now, utc)? {
            EngineEvent::NetworkSettings {
                packet,
                compression,
            } => Ok(ServerSettingsEvent::Settings(PendingServerSettings {
                engine: self.engine,
                packet,
                compression,
            })),
            EngineEvent::Refused(packet) => Ok(ServerSettingsEvent::Refused(packet)),
            EngineEvent::Unhandled(packet) => Ok(ServerSettingsEvent::Unhandled {
                handshake: self,
                packet,
            }),
            _ => Err(ServerHandshakeError::InvalidState),
        }
    }
}

/// Actual settings response or unrelated/terminal input, without a completed Login capability.
pub enum ServerSettingsEvent {
    /// The original plaintext send/flush continuation.
    Settings(PendingServerSettings),
    /// Send this uncompressed refusal and retire the connection.
    Refused(packets::PlayStatus),
    /// Retain the same awaiting owner and handle the returned input immediately.
    Unhandled {
        /// The original settings observer.
        handshake: ServerHandshake,
        /// Unrelated or terminal input, without interpretation.
        packet: Box<packets::Packet>,
    },
}

/// Original uncompressed settings response and the sole Login continuation.
#[must_use = "send and flush the exact settings response before consuming this continuation"]
pub struct PendingServerSettings {
    engine: Box<Engine>,
    packet: packets::NetworkSettings,
    compression: CompressionSettings,
}

impl PendingServerSettings {
    /// Borrows the actual response for uncompressed adapter dispatch.
    pub fn packet(&self) -> &packets::NetworkSettings {
        &self.packet
    }
    /// Settings to install once on that same retained codec after plaintext flush.
    pub fn compression(&self) -> CompressionSettings {
        self.compression
    }

    /// Consumes the adapter's completed send/flush/codec-installation contract.
    /// A pure core cannot prove an external socket operation; no Flushed marker is constructible.
    /// Failure returns the same original pending response and owner for retirement.
    pub fn flushed(mut self, now: Instant) -> Result<ServerLogin, ServerTransitionError<Self>> {
        if let Err(error) = self.engine.compression_installed(now) {
            return Err(ServerTransitionError {
                owner: Box::new(self),
                error,
            });
        }
        Ok(ServerLogin {
            engine: self.engine,
        })
    }
}

/// Actual settings are complete; this owner can observe Login but cannot authorize an unverified peer.
#[must_use]
pub struct ServerLogin {
    engine: Box<Engine>,
}

/// Verified Login or unrelated input returned with its original observer.
pub enum ServerLoginEvent {
    /// Successful provider, client-signature and optional transport-key verification.
    Verified(VerifiedLogin),
    /// Handle terminal/unrelated input before continuing the same observer.
    Unhandled {
        /// The original Login observer.
        login: ServerLogin,
        /// Unrelated or terminal input returned intact.
        packet: Box<packets::Packet>,
    },
}

impl ServerLogin {
    /// Uses the existing configured verifier, never a default/self-asserted peer policy.
    pub fn receive(
        mut self,
        packet: packets::Packet,
        verifier: &impl LoginVerifier,
        now: Instant,
        utc: SystemTime,
    ) -> Result<ServerLoginEvent, ServerHandshakeError> {
        match self.engine.receive(packet, verifier, now, utc)? {
            EngineEvent::LoginVerified => Ok(ServerLoginEvent::Verified(VerifiedLogin {
                engine: self.engine,
            })),
            EngineEvent::Unhandled(packet) => Ok(ServerLoginEvent::Unhandled {
                login: self,
                packet,
            }),
            _ => Err(ServerHandshakeError::InvalidState),
        }
    }
}

/// Actual authenticated Login, before any caller world/member authorization.
#[must_use]
pub struct VerifiedLogin {
    engine: Box<Engine>,
}

impl VerifiedLogin {
    /// Borrows the original provider identity/key and client-signed nonce for real application policy.
    pub fn login(&self) -> &AuthenticatedLogin {
        verified(&self.engine)
    }
    /// Original absolute deadline; approval waits cannot renew it.
    pub fn deadline(&self) -> Instant {
        self.engine.deadline
    }

    /// Runs explicit caller authority and retains its concrete grant separately from crypto proof.
    /// This never claims the library proved hosted membership or a running-world opening.
    /// Denial preserves the original verified owner and caller cause.
    pub fn authorize<A, E>(
        self,
        authorize: impl FnOnce(&AuthenticatedLogin) -> Result<A, E>,
    ) -> Result<ApprovedLogin<A>, AuthorizationFailure<E>> {
        match authorize(self.login()) {
            Ok(grant) => Ok(ApprovedLogin {
                engine: self.engine,
                grant,
            }),
            Err(cause) => Err(AuthorizationFailure {
                login: self,
                cause: Box::new(cause),
            }),
        }
    }
}

/// Caller authorization denial, with no grant/account/nonce formatted in diagnostics.
pub struct AuthorizationFailure<E> {
    login: VerifiedLogin,
    cause: Box<E>,
}
impl<E> AuthorizationFailure<E> {
    /// Recovers the original Login and caller cause; no server exchange or pack was advertised.
    pub fn into_parts(self) -> (VerifiedLogin, E) {
        (self.login, *self.cause)
    }
}
impl<E> fmt::Debug for AuthorizationFailure<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizationFailure")
    }
}
impl<E> fmt::Display for AuthorizationFailure<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("caller refused accepting Login")
    }
}
impl<E: std::error::Error + 'static> std::error::Error for AuthorizationFailure<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

/// Verified Login and the actual caller-trusted grant; no public constructor bypasses authorization.
#[must_use]
pub struct ApprovedLogin<A> {
    engine: Box<Engine>,
    grant: A,
}

impl<A> ApprovedLogin<A> {
    /// Borrows the real caller grant for current policy rechecks after waits.
    pub fn grant(&self) -> &A {
        &self.grant
    }
    /// Borrows the original Login bound to that grant.
    pub fn login(&self) -> &AuthenticatedLogin {
        verified(&self.engine)
    }

    /// Revalidates original credentials/deadline before creating the sole exchange.
    /// The caller rechecks its grant immediately before this transition and later handoffs.
    pub fn accept(
        mut self,
        verifier: &impl LoginVerifier,
        salt: Option<&[u8; 16]>,
        now: Instant,
        utc: SystemTime,
    ) -> Result<ServerApprovalEvent<A>, ServerTransitionError<Self>> {
        let event = match self.engine.accept(verifier, salt, now, utc) {
            Ok(event) => event,
            Err(error) => {
                return Err(ServerTransitionError {
                    owner: Box::new(self),
                    error,
                });
            }
        };
        match event {
            EngineEvent::KeyExchange { packet, ciphers } => {
                Ok(ServerApprovalEvent::KeyExchange(PendingServerKeyExchange {
                    engine: self.engine,
                    grant: self.grant,
                    packet,
                    ciphers,
                }))
            }
            EngineEvent::ReadyForPacks => Ok(ServerApprovalEvent::Ready(ServerPacksReady {
                engine: self.engine,
                grant: self.grant,
            })),
            _ => Err(ServerTransitionError {
                owner: Box::new(self),
                error: ServerHandshakeError::InvalidState,
            }),
        }
    }
}

/// One actual exchange or the encrypted-transport skip, preserving the original authorization grant.
pub enum ServerApprovalEvent<A> {
    /// Send/flush plaintext before installing its exact derived cipher streams.
    KeyExchange(PendingServerKeyExchange<A>),
    /// An explicitly encrypted transport needs no additional batch acknowledgment.
    Ready(ServerPacksReady<A>),
}

/// The original plaintext server token, derived streams and acknowledged-Login continuation.
#[must_use = "flush plaintext before installing the streams and reading the acknowledgment"]
pub struct PendingServerKeyExchange<A> {
    engine: Box<Engine>,
    grant: A,
    packet: packets::ServerToClientHandshake,
    ciphers: Box<(BatchEncryptor, BatchDecryptor)>,
}
impl<A> PendingServerKeyExchange<A> {
    /// Borrows the original signed token for the single plaintext dispatch.
    pub fn packet(&self) -> &packets::ServerToClientHandshake {
        &self.packet
    }
    /// Borrows original caller authorization for policy checks before dispatch.
    pub fn grant(&self) -> &A {
        &self.grant
    }

    /// Consumes actual plaintext flush, returning streams to install before polling acknowledgment.
    /// On failure the exact original token/streams/grant remain owned by the error for retirement.
    pub fn flushed(
        mut self,
        now: Instant,
    ) -> Result<ServerKeyExchangeHandoff<A>, ServerTransitionError<Self>> {
        if let Err(error) = self.engine.encryption_installed(now) {
            return Err(ServerTransitionError {
                owner: Box::new(self),
                error,
            });
        }
        Ok((
            ServerAcknowledgment {
                engine: self.engine,
                grant: self.grant,
            },
            self.ciphers,
        ))
    }
}

/// Cipher streams belong to the adapter; only the actual encrypted acknowledgment completes Login.
#[must_use]
pub struct ServerAcknowledgment<A> {
    engine: Box<Engine>,
    grant: A,
}

/// Actual acknowledgment completion or an intact unrelated sibling.
pub enum ServerAcknowledgmentEvent<A> {
    /// The provider was revalidated at the original acknowledgment boundary.
    Ready(ServerPacksReady<A>),
    /// Retain the same observer and handle unrelated/terminal input immediately.
    Unhandled {
        /// The original acknowledgment observer and grant.
        acknowledgment: ServerAcknowledgment<A>,
        /// Unrelated or terminal input returned intact.
        packet: Box<packets::Packet>,
    },
}
impl<A> ServerAcknowledgment<A> {
    /// Borrows the caller grant for actual policy rechecks before further input/handoff.
    pub fn grant(&self) -> &A {
        &self.grant
    }
    /// Processes the acknowledgment under the original provider and absolute deadline.
    pub fn receive(
        mut self,
        packet: packets::Packet,
        verifier: &impl LoginVerifier,
        now: Instant,
        utc: SystemTime,
    ) -> Result<ServerAcknowledgmentEvent<A>, ServerTransitionError<Self>> {
        let event = match self.engine.receive(packet, verifier, now, utc) {
            Ok(event) => event,
            Err(error) => {
                return Err(ServerTransitionError {
                    owner: Box::new(self),
                    error,
                });
            }
        };
        match event {
            EngineEvent::ReadyForPacks => Ok(ServerAcknowledgmentEvent::Ready(ServerPacksReady {
                engine: self.engine,
                grant: self.grant,
            })),
            EngineEvent::Unhandled(packet) => Ok(ServerAcknowledgmentEvent::Unhandled {
                acknowledgment: self,
                packet,
            }),
            _ => Err(ServerTransitionError {
                owner: Box::new(self),
                error: ServerHandshakeError::InvalidState,
            }),
        }
    }
}

/// Actual Login/cipher completion and the original caller grant, before any pack/world advertisement.
#[must_use]
pub struct ServerPacksReady<A> {
    engine: Box<Engine>,
    grant: A,
}
impl<A> ServerPacksReady<A> {
    /// Borrows the original authenticated player/nonce, never host-account or client-asserted identity.
    pub fn login(&self) -> &AuthenticatedLogin {
        verified(&self.engine)
    }
    /// Borrows actual caller authority for rechecks at subsequent capacity/preparation waits.
    pub fn grant(&self) -> &A {
        &self.grant
    }
    /// Original deadline carried into any subsequent accepting owner.
    pub fn deadline(&self) -> Instant {
        self.engine.deadline
    }

    /// Revalidates and consumes Login readiness once; this advertises no packs or world.
    /// The caller must still recheck its grant at actual attachment/dispatch after awaits.
    pub fn finish(
        mut self,
        verifier: &impl LoginVerifier,
        now: Instant,
        utc: SystemTime,
    ) -> Result<AcceptedLogin<A>, ServerTransitionError<Self>> {
        if let Err(error) = self.engine.check_packs(verifier, now, utc) {
            return Err(ServerTransitionError {
                owner: Box::new(self),
                error,
            });
        }
        Ok(AcceptedLogin {
            login: self
                .engine
                .login
                .take()
                .expect("ready handoff retains its verified Login"),
            grant: self.grant,
            deadline: self.engine.deadline,
        })
    }
}

/// Consumed authenticated Login and caller grant; this is not world attachment/initialization.
pub struct AcceptedLogin<A> {
    login: AuthenticatedLogin,
    grant: A,
    deadline: Instant,
}
impl<A> AcceptedLogin<A> {
    /// Borrows the original authenticated Login for an actual adapter consumer.
    pub fn login(&self) -> &AuthenticatedLogin {
        &self.login
    }
    /// Borrows the caller-trusted grant; its validity still belongs to that authority.
    pub fn grant(&self) -> &A {
        &self.grant
    }
    /// Original deadline, without renewal at the handoff.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    /// Transfers original Login and grant to the real adapter, without inventing world admission.
    pub fn into_parts(self) -> (AuthenticatedLogin, A) {
        (self.login, self.grant)
    }
}

/// Fallible transition retaining its exact original owner/output for retirement or permitted retry.
pub struct ServerTransitionError<C> {
    owner: Box<C>,
    error: ServerHandshakeError,
}
impl<C> ServerTransitionError<C> {
    /// Recovers the retained owner/output and original redacted cause.
    /// Failed protocol owners remain failed; recovery never resets permission or a deadline.
    pub fn into_parts(self) -> (C, ServerHandshakeError) {
        (*self.owner, self.error)
    }
}
impl<C> fmt::Debug for ServerTransitionError<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerTransitionError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl<C> fmt::Display for ServerTransitionError<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, f)
    }
}
impl<C> std::error::Error for ServerTransitionError<C> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Public states reach this borrow only through actual provider verification.
fn verified(engine: &Engine) -> &AuthenticatedLogin {
    engine
        .login
        .as_ref()
        .expect("verified capability retains its original authenticated Login")
}
