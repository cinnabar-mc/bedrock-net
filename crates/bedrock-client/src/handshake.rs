//! Network negotiation and key exchange, driven one generated packet at a time.

use std::{sync::Arc, time::SystemTime};

use bedrock_net::{
    CompressionAlgorithm, CompressionSettings,
    encryption::{BatchDecryptor, BatchEncryptor},
    login::{self, LoginError, OfflineIdentity},
};
use bedrock_protocol::{PROTOCOL_VERSION, enums::PlayStatusType, packets, wire};
use p384::ecdsa::SigningKey;
use serde_json::value::RawValue;

use crate::packs::{PackError, PackOffer, PackTransferLimits};

mod lifecycle;
pub use lifecycle::{
    ClientHandshake, ClientKeyExchange, ClientLogin, ClientLoginReady, ClientPackOffer,
    ClientPacks, ClientSettings, LoginEvent, LoginPreparationError, OfferEvent, PacksEvent,
    SettingsEvent,
};

/// Transport and application capabilities fixed for one handshake.
#[derive(Clone, Copy, Debug)]
pub struct HandshakeOptions {
    /// Whether this transport requires the Bedrock batch cipher, in addition to key verification.
    pub batch_encryption: bool,
    /// Whether the client implements the Bedrock blob cache.
    pub blob_cache: bool,
    /// Maximum Login request and server handshake token size.
    pub max_login_bytes: usize,
    /// Resource-pack acquisition limits for this session.
    pub packs: PackTransferLimits,
}

impl Default for HandshakeOptions {
    fn default() -> Self {
        Self {
            batch_encryption: true,
            blob_cache: false,
            max_login_bytes: bedrock_net::BatchLimits::default().max_decoded_bytes,
            packs: PackTransferLimits::default(),
        }
    }
}

/// A failed protocol transition; diagnostics contain no credentials or client data.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HandshakeError {
    /// The operation is not valid in this phase.
    #[error("client handshake operation is out of sequence")]
    InvalidState,
    /// The caller supplied a zero Login byte budget.
    #[error("client handshake Login budget is zero")]
    InvalidLimit,
    /// The server attempted another key exchange on the same connection.
    #[error("repeated server key exchange")]
    RepeatedKeyExchange,
    /// The server sent a non-UTF-8 handshake token.
    #[error("server handshake token is not UTF-8")]
    InvalidTokenText,
    /// The server refused Login, with its generated status retained.
    #[error("server refused Login: {0:?}")]
    LoginRefused(PlayStatusType),
    /// Signing, verification or Login serialization failed.
    #[error(transparent)]
    Login(#[from] LoginError),
    /// The resource-pack offer could not be admitted.
    #[error(transparent)]
    Packs(#[from] PackError),
}

/// Ordered work for the caller; this core never writes, flushes or reads a clock.
#[non_exhaustive]
enum EngineEvent {
    /// Install this setting on the retained batch codec before sending Login.
    Compression(CompressionSettings),
    /// Send these generated responses immediately, in their existing order.
    Send(Vec<packets::Packet>),
    /// Install the directional streams before sending the acknowledgment.
    ///
    /// `ciphers` is absent for transports that already encrypt the application
    /// stream. The server token is still verified in that case.
    KeyExchange {
        /// Outgoing then incoming stream; retain both for this connection.
        ciphers: Option<Box<(BatchEncryptor, BatchDecryptor)>>,
        /// The first response after the cipher transition.
        response: packets::ClientToServerHandshake,
    },
    /// Supply optional validated preloads, then drive this existing pack owner.
    Packs {
        /// Send once before starting the pack negotiation, when present.
        cache_status: Option<packets::ClientCacheStatus>,
        /// Bounded transfer and stack state; cache and CDN I/O remain external.
        negotiation: PackOffer,
    },
    /// The server began startup without advertising a resource-pack phase.
    Startup(Box<packets::StartGame>),
    /// The packet is owned by the caller, including early PlayerSpawn, Disconnect and Transfer.
    Unhandled(Box<packets::Packet>),
}

#[derive(Clone, Copy)]
enum Phase {
    Initial,
    NetworkSettings,
    LoginReady,
    Login,
    Packs,
    Complete,
    Failed,
}

/// One proof-key owner across transport authentication, Login and server exchange.
///
/// Send `start()`, pass received packets to `receive`, and install the returned
/// compression before calling one of the Login methods. They sign with this
/// same key. After the offer, drive the returned [`PackOffer`]; route its
/// unhandled packets through this handshake so late LoginSuccess and key
/// exchange remain on the same owner. Retain returned startup packets for the
/// spawn owner; handle Disconnect and Transfer at the application boundary.
/// Any received-packet error ends this handshake.
///
/// The caller owns transport I/O, endpoint/account trust, client-data schema,
/// UTC, deadline, cancellation and bounded buffering of unread packet siblings.
struct Engine {
    key: Arc<SigningKey>,
    options: HandshakeOptions,
    phase: Phase,
    key_exchanged: bool,
    cache_sent: bool,
    retain_pack_metadata: bool,
}

impl Engine {
    /// Retains the acquired proof key or shares its existing allocation with signed transport.
    /// No private key material is cloned and no replacement identity is generated.
    ///
    /// # Errors
    /// Rejects a zero Login/token byte budget before retaining the key.
    fn new(
        key: impl Into<Arc<SigningKey>>,
        options: HandshakeOptions,
    ) -> Result<Self, HandshakeError> {
        if options.max_login_bytes == 0 {
            return Err(HandshakeError::InvalidLimit);
        }
        Ok(Self {
            key: key.into(),
            options,
            phase: Phase::Initial,
            key_exchanged: false,
            cache_sent: false,
            retain_pack_metadata: false,
        })
    }

    /// Borrows the same proof key for identity-aware transport admission.
    fn key(&self) -> &SigningKey {
        &self.key
    }

    /// Starts uncompressed negotiation exactly once using the generated protocol version.
    ///
    /// # Errors
    /// Rejects a repeated start or use after failure.
    fn start(&mut self) -> Result<packets::RequestNetworkSettings, HandshakeError> {
        if !matches!(self.phase, Phase::Initial) {
            return Err(HandshakeError::InvalidState);
        }
        self.phase = Phase::NetworkSettings;
        Ok(packets::RequestNetworkSettings {
            client_network_version: wire::I32BE(PROTOCOL_VERSION),
        })
    }

    /// Signs and returns an offline Login after compression negotiation.
    ///
    /// # Errors
    /// Rejects an out-of-sequence call or invalid/oversized caller metadata. A
    /// signing error leaves Login ready; no response or cipher was consumed.
    fn login_offline(
        &mut self,
        identity: &OfflineIdentity<'_>,
        client_data: &RawValue,
        now: SystemTime,
    ) -> Result<packets::Login, HandshakeError> {
        self.require_login_ready()?;
        let request = login::encode_offline_request(
            &self.key,
            identity,
            client_data,
            now,
            self.options.max_login_bytes,
        )?;
        Ok(self.login_packet(request))
    }

    /// Signs Login client data with the proof key used to acquire this credential.
    ///
    /// This formatter does not verify the issuer, account binding or credential
    /// deadline. The account owner must validate those immediately before actual
    /// transport admission, including any capacity wait after this method.
    ///
    /// # Errors
    /// Rejects an out-of-sequence call or invalid/oversized caller metadata.
    fn login_authenticated(
        &mut self,
        multiplayer_token: &str,
        client_data: &RawValue,
    ) -> Result<packets::Login, HandshakeError> {
        self.require_login_ready()?;
        let request = login::encode_authenticated_request(
            &self.key,
            multiplayer_token,
            client_data,
            self.options.max_login_bytes,
        )?;
        Ok(self.login_packet(request))
    }

    /// Advances one received packet without taking ownership of any batch FIFO.
    ///
    /// # Errors
    /// A malformed exchange, repeated transition, refused Login or invalid pack
    /// offer is terminal. Keep all packets from the current decoded batch on
    /// the caller's FIFO, even when this method returns a codec transition.
    fn receive(&mut self, packet: packets::Packet) -> Result<EngineEvent, HandshakeError> {
        let result = self.receive_inner(packet);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }

    /// Handles protocol-owned packets while returning unrelated packets unchanged.
    fn receive_inner(&mut self, packet: packets::Packet) -> Result<EngineEvent, HandshakeError> {
        if matches!(self.phase, Phase::Initial | Phase::Complete | Phase::Failed) {
            return Err(HandshakeError::InvalidState);
        }
        match packet {
            packets::Packet::NetworkSettings(settings) => {
                if !matches!(self.phase, Phase::NetworkSettings) {
                    return Err(HandshakeError::InvalidState);
                }
                let raw = settings.compression_algorithm.to_raw();
                let algorithm = CompressionAlgorithm::try_from(raw).unwrap_or_else(|_| {
                    tracing::warn!(
                        algorithm = raw,
                        "unknown negotiated compression; using DEFLATE"
                    );
                    CompressionAlgorithm::Deflate
                });
                self.phase = Phase::LoginReady;
                Ok(EngineEvent::Compression(CompressionSettings {
                    algorithm,
                    threshold: settings.compression_threshold.0,
                }))
            }
            packets::Packet::ServerToClientHandshake(handshake) => {
                self.require_login_sent()?;
                if self.key_exchanged {
                    return Err(HandshakeError::RepeatedKeyExchange);
                }
                let token = handshake
                    .handshake_web_token
                    .to_str()
                    .map_err(|_| HandshakeError::InvalidTokenText)?;
                let ciphers =
                    login::finish_key_exchange(&self.key, token, self.options.max_login_bytes)?;
                self.key_exchanged = true;
                Ok(EngineEvent::KeyExchange {
                    ciphers: self.options.batch_encryption.then(|| Box::new(ciphers)),
                    response: packets::ClientToServerHandshake {},
                })
            }
            packets::Packet::PlayStatus(status) if status.status == PlayStatusType::Playerspawn => {
                Ok(EngineEvent::Unhandled(Box::new(status.into())))
            }
            packets::Packet::PlayStatus(status) => {
                if status.status != PlayStatusType::Loginsuccess {
                    return Err(HandshakeError::LoginRefused(status.status));
                }
                self.require_login_sent()?;
                Ok(EngineEvent::Send(
                    self.cache_status()
                        .map(packets::Packet::ClientCacheStatus)
                        .into_iter()
                        .collect(),
                ))
            }
            packets::Packet::ResourcePacksInfo(offer) if matches!(self.phase, Phase::Login) => {
                let negotiation = if self.retain_pack_metadata {
                    PackOffer::new_with_metadata(offer, self.options.packs)?
                } else {
                    PackOffer::new(offer, self.options.packs)?
                };
                let cache_status = self.cache_status();
                self.phase = Phase::Packs;
                Ok(EngineEvent::Packs {
                    cache_status,
                    negotiation,
                })
            }
            packets::Packet::StartGame(start_game) if matches!(self.phase, Phase::Login) => {
                self.phase = Phase::Complete;
                Ok(EngineEvent::Startup(start_game))
            }
            other => Ok(EngineEvent::Unhandled(Box::new(other))),
        }
    }

    /// Requires the single Login construction point after negotiated settings.
    fn require_login_ready(&self) -> Result<(), HandshakeError> {
        if matches!(self.phase, Phase::LoginReady) {
            Ok(())
        } else {
            Err(HandshakeError::InvalidState)
        }
    }

    /// Keeps server exchange after Login, including unhandled packets during packs.
    fn require_login_sent(&self) -> Result<(), HandshakeError> {
        if matches!(self.phase, Phase::Login | Phase::Packs) {
            Ok(())
        } else {
            Err(HandshakeError::InvalidState)
        }
    }

    /// Commits the successful Login construction and preserves the generated wire identity.
    fn login_packet(&mut self, connection_request: bytes::Bytes) -> packets::Login {
        self.phase = Phase::Login;
        packets::Login {
            client_network_version: wire::I32BE(PROTOCOL_VERSION),
            connection_request,
        }
    }

    /// Emits the connection capability exactly once regardless of LoginSuccess/offer order.
    fn cache_status(&mut self) -> Option<packets::ClientCacheStatus> {
        if std::mem::replace(&mut self.cache_sent, true) {
            None
        } else {
            Some(packets::ClientCacheStatus {
                is_cache_supported: self.options.blob_cache,
            })
        }
    }
}

#[cfg(test)]
mod tests;
