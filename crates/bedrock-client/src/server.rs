//! Caller-driven accepting Login; owned pack/world startup continues in [`session`].

use bedrock_net::{
    CompressionAlgorithm, CompressionSettings,
    encryption::{BatchDecryptor, BatchEncryptor},
    login::{self, AuthenticatedLogin, LoginError, LoginVerifier},
};
use bedrock_protocol::{PROTOCOL_VERSION, enums::PlayStatusType, packets, wire};
use p384::ecdsa::{SigningKey, VerifyingKey};
use std::{
    sync::Arc,
    time::{Instant, SystemTime},
};

mod lifecycle;
mod offline;
mod policy;
pub use offline::OfflinePolicy;
pub use policy::{HandshakePolicy, LoginPolicy};

/// Owned accepting pack delivery and selected-world startup after the actual Login handoff.
pub mod session;
pub use lifecycle::{
    AcceptedLogin, ApprovedLogin, AuthorizationFailure, PendingServerKeyExchange,
    PendingServerSettings, ServerAcknowledgment, ServerAcknowledgmentEvent, ServerApprovalEvent,
    ServerHandshake, ServerLogin, ServerLoginEvent, ServerPacksReady, ServerSettingsEvent,
    ServerTransitionError, VerifiedLogin,
};

/// The acknowledgment continuation and its exact outgoing/incoming cipher streams after plaintext flush.
pub type ServerKeyExchangeHandoff<A, L = AuthenticatedLogin> = (
    ServerAcknowledgment<A, L>,
    Box<(BatchEncryptor, BatchDecryptor)>,
);

/// Fixed accepting capabilities; the caller supplies the original deadline and server proof key.
#[derive(Clone, Copy, Debug)]
pub struct ServerHandshakeOptions {
    /// Compression installed only after sending and flushing NetworkSettings uncompressed.
    pub compression: CompressionSettings,
    /// Whether the accepted transport also needs the Bedrock batch cipher.
    pub batch_encryption: bool,
    /// Complete Login request and server token byte ceiling.
    pub max_login_bytes: usize,
}

impl Default for ServerHandshakeOptions {
    fn default() -> Self {
        Self {
            compression: CompressionSettings {
                algorithm: CompressionAlgorithm::Deflate,
                threshold: 256,
            },
            batch_encryption: true,
            max_login_bytes: bedrock_net::BatchLimits::default().max_decoded_bytes,
        }
    }
}

/// A terminal accepting transition failure; diagnostics contain no account or metadata.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServerHandshakeError {
    /// An operation arrived before its prerequisite or repeated a consumed transition.
    #[error("accepting handshake operation is out of sequence")]
    InvalidState,
    /// A zero byte ceiling cannot admit a Login.
    #[error("accepting handshake Login budget is zero")]
    InvalidLimit,
    /// The original caller deadline has been reached; it is never renewed by progress.
    #[error("accepting handshake deadline expired")]
    TimedOut,
    /// Supplied transport binding and final signed Login exchange key differ.
    #[error("accepting Login proof does not match its transport")]
    TransportKeyMismatch,
    /// Encryption requires fresh caller-owned sixteen-byte entropy before creating an exchange.
    #[error("accepting handshake salt is unavailable")]
    MissingSalt,
    /// Provider, signed client data or encryption setup failed.
    #[error(transparent)]
    Login(#[from] LoginError),
}

/// Ordered caller effects. No effect grants access to a world or advertises packs.
#[non_exhaustive]
enum EngineEvent {
    /// Send/flush this packet uncompressed, then install compression and acknowledge that transition.
    NetworkSettings {
        /// Generated current-version response.
        packet: packets::NetworkSettings,
        /// Settings for the same retained batch codec.
        compression: CompressionSettings,
    },
    /// Send this uncompressed refusal and close; no Login/cipher/pack transition remains possible.
    Refused(packets::PlayStatus),
    /// Inspect `login()` and obtain current application authorization before calling `accept`.
    LoginVerified,
    /// Send/flush the plaintext token, install both streams, then call `encryption_installed`.
    KeyExchange {
        /// Unencrypted generated server token, after negotiated compression.
        packet: packets::ServerToClientHandshake,
        /// Outgoing then incoming streams, installed exactly once on this connection.
        ciphers: Box<(BatchEncryptor, BatchDecryptor)>,
    },
    /// Login and any encrypted acknowledgment are complete; prepare the original world/pack snapshot.
    /// Recheck application approval after awaits before advertising LoginSuccess or any packs.
    ReadyForPacks,
    /// Return unrelated packets unchanged, including Disconnect/Transfer for immediate caller handling.
    Unhandled(Box<packets::Packet>),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Initial,
    Compression,
    Login,
    Approval,
    Cipher,
    Acknowledgment,
    Packs,
    Failed,
}

/// One accepting Login and cipher lifetime without I/O, a clock, queues or issuer discovery.
///
/// The caller retains all decoded batch siblings and applies effects in order.
/// An explicit policy validates Login; it never substitutes for
/// current application authorization. For provider-authenticated hosted worlds, use
/// `login().xuid()` and its original signed nonce to obtain/recheck the current
/// membership/world/account approval. A service card, invite or SDP alone is
/// insufficient. Recheck that approval at actual pack/world handoff after waits.
///
/// This owner stops before server pack advertisement/delivery and world startup.
/// No LoginSuccess is emitted before the caller prepares its actual pack offer.
struct Engine<L = AuthenticatedLogin> {
    key: Arc<SigningKey>,
    transport_key: Option<VerifyingKey>,
    options: ServerHandshakeOptions,
    deadline: Instant,
    phase: Phase,
    login: Option<L>,
}

impl<L> Engine<L> {
    /// Retains one caller-generated server key and optional transport-authenticated peer key.
    ///
    /// `deadline` is absolute in the caller's monotonic clock; all later operations
    /// take that same clock's `now`. `transport_key` comes from verified transport
    /// admission, never an arbitrary SDP/header claim.
    ///
    /// # Errors
    /// Rejects a zero Login budget or deadline already reached.
    fn new(
        key: impl Into<Arc<SigningKey>>,
        transport_key: Option<VerifyingKey>,
        options: ServerHandshakeOptions,
        deadline: Instant,
        now: Instant,
    ) -> Result<Self, ServerHandshakeError> {
        if options.max_login_bytes == 0 {
            return Err(ServerHandshakeError::InvalidLimit);
        }
        if now >= deadline {
            return Err(ServerHandshakeError::TimedOut);
        }
        Ok(Self {
            key: key.into(),
            transport_key,
            options,
            deadline,
            phase: Phase::Initial,
            login: None,
        })
    }

    /// Borrows the one server key, permitting a signed transport to share its existing Arc allocation.
    fn key(&self) -> &SigningKey {
        &self.key
    }

    /// Borrows the verified joining player's original identity/nonce while authorization is pending.
    #[cfg(test)]
    fn login(&self) -> Option<&L> {
        self.login.as_ref()
    }

    /// Processes one generated packet, returning unrelated input to the caller's original FIFO.
    ///
    /// # Errors
    /// Deadline, protocol, provider/signature, transport binding and sequence errors are terminal.
    fn receive(
        &mut self,
        packet: packets::Packet,
        verifier: &impl HandshakePolicy<L>,
        now: Instant,
        utc: SystemTime,
    ) -> Result<EngineEvent, ServerHandshakeError> {
        let result = self.receive_inner(packet, verifier, now, utc);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }

    /// Commits the caller's completed uncompressed send/flush and retained codec transition.
    ///
    /// # Errors
    /// Rejects expiry, failure or an operation outside the NetworkSettings boundary.
    fn compression_installed(&mut self, now: Instant) -> Result<(), ServerHandshakeError> {
        self.require(Phase::Compression, now)?;
        self.phase = Phase::Login;
        Ok(())
    }

    /// Accepts only after the caller's current application authorization, without an internal await.
    ///
    /// Revalidates the exact provider credential immediately before creating the
    /// single exchange. Supply fresh caller entropy when batch encryption is
    /// enabled; an encrypted transport can omit salt and receives ReadyForPacks.
    ///
    /// # Errors
    /// Expiry, repeated/out-of-sequence use, provider/key changes or missing salt end this handshake.
    fn accept(
        &mut self,
        verifier: &impl HandshakePolicy<L>,
        salt: Option<&[u8; 16]>,
        now: Instant,
        utc: SystemTime,
    ) -> Result<EngineEvent, ServerHandshakeError> {
        let result = self.accept_inner(verifier, salt, now, utc);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }

    /// Commits plaintext server-token flush and the single installation of both batch cipher streams.
    ///
    /// # Errors
    /// Rejects expiry or a repeated/out-of-sequence cipher transition.
    fn encryption_installed(&mut self, now: Instant) -> Result<(), ServerHandshakeError> {
        self.require(Phase::Cipher, now)?;
        self.phase = Phase::Acknowledgment;
        Ok(())
    }

    /// Transfers the original Login once at the pack-preparation policy boundary.
    ///
    /// Caller owns later pack/session deadlines and must retain/recheck actual
    /// application approval before publishing LoginSuccess/ResourcePacksInfo.
    ///
    /// # Errors
    /// Rejects an incomplete/expired handshake or changed/expired provider credential.
    #[cfg(test)]
    fn finish(
        mut self,
        verifier: &impl HandshakePolicy<L>,
        now: Instant,
        utc: SystemTime,
    ) -> Result<L, ServerHandshakeError> {
        self.check_packs(verifier, now, utc)?;
        self.login.take().ok_or(ServerHandshakeError::InvalidState)
    }

    /// Rechecks original provider identity without consuming the grant/credential on failure.
    fn check_packs(
        &mut self,
        verifier: &impl LoginPolicy<L>,
        now: Instant,
        utc: SystemTime,
    ) -> Result<(), ServerHandshakeError> {
        let result = (|| {
            self.require(Phase::Packs, now)?;
            verifier.revalidate(
                self.login
                    .as_ref()
                    .ok_or(ServerHandshakeError::InvalidState)?,
                utc,
            )?;
            Ok(())
        })();
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }

    /// Performs protocol-owned transitions, preserving unhandled packet ownership.
    fn receive_inner(
        &mut self,
        packet: packets::Packet,
        verifier: &impl HandshakePolicy<L>,
        now: Instant,
        utc: SystemTime,
    ) -> Result<EngineEvent, ServerHandshakeError> {
        self.check_live(now)?;
        match packet {
            packets::Packet::RequestNetworkSettings(request) => {
                self.require(Phase::Initial, now)?;
                if request.client_network_version.0 != PROTOCOL_VERSION {
                    self.phase = Phase::Failed;
                    let status = if request.client_network_version.0 > PROTOCOL_VERSION {
                        PlayStatusType::LoginfailedServerold
                    } else {
                        PlayStatusType::LoginfailedClientold
                    };
                    return Ok(EngineEvent::Refused(packets::PlayStatus { status }));
                }
                self.phase = Phase::Compression;
                Ok(EngineEvent::NetworkSettings {
                    packet: packets::NetworkSettings {
                        compression_threshold: wire::U16LE(self.options.compression.threshold),
                        compression_algorithm: self
                            .options
                            .compression
                            .algorithm
                            .network_id()
                            .into(),
                        ..Default::default()
                    },
                    compression: self.options.compression,
                })
            }
            packets::Packet::Login(packet) => {
                self.require(Phase::Login, now)?;
                // RequestNetworkSettings owns version negotiation; Login's superseded version is ignored.
                let login = verifier.parse(
                    &packet.connection_request,
                    utc,
                    self.options.max_login_bytes,
                )?;
                if self
                    .transport_key
                    .as_ref()
                    .is_some_and(|key| verifier.exchange_key(&login) != Some(key))
                {
                    return Err(ServerHandshakeError::TransportKeyMismatch);
                }
                self.login = Some(login);
                self.phase = Phase::Approval;
                Ok(EngineEvent::LoginVerified)
            }
            packets::Packet::ClientToServerHandshake(_) => {
                self.require(Phase::Acknowledgment, now)?;
                verifier.revalidate(
                    self.login
                        .as_ref()
                        .ok_or(ServerHandshakeError::InvalidState)?,
                    utc,
                )?;
                self.phase = Phase::Packs;
                Ok(EngineEvent::ReadyForPacks)
            }
            packet => Ok(EngineEvent::Unhandled(Box::new(packet))),
        }
    }

    /// Consumes the sole acceptance transition after synchronous caller authorization.
    fn accept_inner(
        &mut self,
        verifier: &impl HandshakePolicy<L>,
        salt: Option<&[u8; 16]>,
        now: Instant,
        utc: SystemTime,
    ) -> Result<EngineEvent, ServerHandshakeError> {
        self.require(Phase::Approval, now)?;
        let login = self
            .login
            .as_ref()
            .ok_or(ServerHandshakeError::InvalidState)?;
        verifier.revalidate(login, utc)?;
        if !self.options.batch_encryption {
            self.phase = Phase::Packs;
            return Ok(EngineEvent::ReadyForPacks);
        }
        let salt = salt.ok_or(ServerHandshakeError::MissingSalt)?;
        let (token, ciphers) = login::begin_key_exchange(
            &self.key,
            verifier
                .exchange_key(login)
                .ok_or(LoginError::UnsupportedExchangeCurve)?,
            salt,
            self.options.max_login_bytes,
        )?;
        self.phase = Phase::Cipher;
        Ok(EngineEvent::KeyExchange {
            packet: packets::ServerToClientHandshake {
                handshake_web_token: token.into(),
            },
            ciphers: Box::new(ciphers),
        })
    }

    /// Enforces the original absolute admission deadline without renewing it for received progress.
    fn check_live(&mut self, now: Instant) -> Result<(), ServerHandshakeError> {
        if now >= self.deadline {
            self.phase = Phase::Failed;
            return Err(ServerHandshakeError::TimedOut);
        }
        if matches!(self.phase, Phase::Failed) {
            return Err(ServerHandshakeError::InvalidState);
        }
        Ok(())
    }

    /// Fences explicit codec/acceptance transitions before taking or deriving any owned secret.
    fn require(&mut self, expected: Phase, now: Instant) -> Result<(), ServerHandshakeError> {
        self.check_live(now)?;
        if self.phase != expected {
            self.phase = Phase::Failed;
            return Err(ServerHandshakeError::InvalidState);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
