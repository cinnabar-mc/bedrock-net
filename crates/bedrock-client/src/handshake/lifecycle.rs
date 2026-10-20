//! Public consumed capabilities around the single private handshake implementation.

use super::{Engine, EngineEvent, HandshakeError, HandshakeOptions};
use crate::packs::{PackComplete, PackError, PackEvent, PackNegotiation, PackOffer};
use bedrock_net::{
    CompressionSettings,
    encryption::{BatchDecryptor, BatchEncryptor},
    login::OfflineIdentity,
};
use bedrock_protocol::{packets, types::PackInfoData};
use p384::ecdsa::SigningKey;
use serde_json::value::RawValue;
use std::{fmt, sync::Arc, time::SystemTime};

/// Configuration for one original proof-key lifetime, before settings negotiation.
#[must_use]
pub struct ClientHandshake {
    engine: Box<Engine>,
}

impl ClientHandshake {
    /// Validates options and retains the original key allocation without cloning private material.
    pub fn new(
        key: impl Into<Arc<SigningKey>>,
        options: HandshakeOptions,
    ) -> Result<Self, HandshakeError> {
        Ok(Self {
            engine: Box::new(Engine::new(key, options)?),
        })
    }

    /// Borrows the original proof for caller-owned transport admission.
    pub fn key(&self) -> &SigningKey {
        self.engine.key()
    }

    /// Retains actual admitted pack offer/stack/data metadata for an upstream relay handoff.
    /// Default desktop/client negotiation retains only its existing archive handoff.
    pub fn retain_pack_metadata(mut self) -> Self {
        self.engine.retain_pack_metadata = true;
        self
    }

    /// Consumes configuration into the single uncompressed settings request.
    ///
    /// ```compile_fail
    /// fn start_twice(configured: bedrock_client::handshake::ClientHandshake) {
    ///     let _first = configured.start();
    ///     let _second = configured.start();
    /// }
    /// ```
    pub fn start(
        mut self,
    ) -> Result<(ClientSettings, packets::RequestNetworkSettings), HandshakeError> {
        let packet = self.engine.start()?;
        Ok((
            ClientSettings {
                engine: self.engine,
            },
            packet,
        ))
    }
}

/// Actual settings negotiation; Login construction is unavailable on this owner.
///
/// ```compile_fail
/// fn login_before_settings(settings: bedrock_client::handshake::ClientSettings,
///                          metadata: &serde_json::value::RawValue) {
///     let _login = settings.login_authenticated("credential", metadata);
/// }
/// ```
#[must_use]
pub struct ClientSettings {
    engine: Box<Engine>,
}

/// Packet progress or the actual parsed settings handoff.
pub enum SettingsEvent {
    /// Retain this same owner and return unrelated input to the caller's FIFO.
    Pending {
        /// The original pending settings owner.
        settings: ClientSettings,
        /// Unrelated input returned without interpretation.
        packet: Box<packets::Packet>,
    },
    /// Install compression on the same codec before constructing Login.
    Ready {
        /// Readiness produced only by the actual settings packet.
        login: ClientLoginReady,
        /// Install once on the retained batch codec before Login dispatch.
        compression: CompressionSettings,
    },
}

impl ClientSettings {
    /// Consumes one packet and returns the same pending owner or actual Login readiness.
    pub fn receive(mut self, packet: packets::Packet) -> Result<SettingsEvent, HandshakeError> {
        match self.engine.receive(packet)? {
            EngineEvent::Compression(compression) => Ok(SettingsEvent::Ready {
                login: ClientLoginReady {
                    engine: self.engine,
                },
                compression,
            }),
            EngineEvent::Unhandled(packet) => Ok(SettingsEvent::Pending {
                settings: self,
                packet,
            }),
            _ => Err(HandshakeError::InvalidState),
        }
    }
}

/// Actual negotiated settings and the single proof retained for Login construction.
#[must_use]
pub struct ClientLoginReady {
    engine: Box<Engine>,
}

impl ClientLoginReady {
    /// Formats offline Login, consuming readiness only when formatting succeeds.
    pub fn login_offline(
        mut self,
        identity: &OfflineIdentity<'_>,
        client_data: &RawValue,
        now: SystemTime,
    ) -> Result<(ClientLogin, packets::Login), LoginPreparationError> {
        match self.engine.login_offline(identity, client_data, now) {
            Ok(packet) => Ok((
                ClientLogin {
                    engine: self.engine,
                },
                packet,
            )),
            Err(error) => Err(LoginPreparationError { ready: self, error }),
        }
    }

    /// Formats the exact acquired credential with the original key.
    /// The caller still verifies account/proof/expiry at actual transport admission.
    pub fn login_authenticated(
        mut self,
        token: &str,
        client_data: &RawValue,
    ) -> Result<(ClientLogin, packets::Login), LoginPreparationError> {
        match self.engine.login_authenticated(token, client_data) {
            Ok(packet) => Ok((
                ClientLogin {
                    engine: self.engine,
                },
                packet,
            )),
            Err(error) => Err(LoginPreparationError { ready: self, error }),
        }
    }
}

/// A pre-dispatch formatting error retains the same ready key and can be retried deliberately.
pub struct LoginPreparationError {
    ready: ClientLoginReady,
    error: HandshakeError,
}

impl LoginPreparationError {
    /// Recovers the unchanged ready owner and original redacted cause; no Login was dispatched.
    pub fn into_parts(self) -> (ClientLoginReady, HandshakeError) {
        (self.ready, self.error)
    }
}
impl fmt::Debug for LoginPreparationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginPreparationError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl fmt::Display for LoginPreparationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, f)
    }
}
impl std::error::Error for LoginPreparationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Login was constructed with the original key; only post-Login controls are available.
#[must_use]
pub struct ClientLogin {
    engine: Box<Engine>,
}

/// The sole verified key-exchange continuation, not a publicly constructible installed marker.
#[must_use = "install streams and send the original acknowledgment before continuing input"]
pub struct ClientKeyExchange<C> {
    continuation: C,
    ciphers: Option<Box<(BatchEncryptor, BatchDecryptor)>>,
    response: packets::ClientToServerHandshake,
}

impl<C> ClientKeyExchange<C> {
    /// Moves the exact streams, acknowledgment and continuation to the adapter.
    /// Install both streams before sending the acknowledgment and before polling the continuation.
    /// This is an explicit caller I/O contract, not proof of a socket operation.
    pub fn into_parts(
        self,
    ) -> (
        C,
        Option<Box<(BatchEncryptor, BatchDecryptor)>>,
        packets::ClientToServerHandshake,
    ) {
        (self.continuation, self.ciphers, self.response)
    }
}

/// Ordered effects, each retaining the actual next owner rather than an unchecked state flag.
pub enum LoginEvent {
    /// Send these responses and retain the same Login/control owner.
    Send {
        /// The same original post-Login control owner.
        login: ClientLogin,
        /// Immediate responses in their original order.
        packets: Vec<packets::Packet>,
    },
    /// Apply the sole verified exchange before continuing with its retained owner.
    KeyExchange(ClientKeyExchange<ClientLogin>),
    /// Retain actual post-Login control together with the admitted preload owner.
    Packs {
        /// Send once before starting pack transfer, when present.
        cache_status: Option<packets::ClientCacheStatus>,
        /// The actual admitted offer and original late Login control.
        packs: ClientPackOffer,
    },
    /// Begin startup from an actual StartGame when no pack offer was received.
    /// Preserve this packet on the caller's original bounded FIFO; no pack acknowledgment is due.
    Startup {
        /// The actual received packet; it does not grant spawn or presentation readiness.
        start_game: Box<packets::StartGame>,
    },
    /// Return unrelated startup or terminal input to the caller without consuming it.
    Unhandled {
        /// The same pending Login owner.
        login: ClientLogin,
        /// Startup or terminal input returned without interpretation.
        packet: Box<packets::Packet>,
    },
}

impl ClientLogin {
    /// Borrows the original proof for caller-owned diagnostics/admission, without replacing it.
    pub fn key(&self) -> &SigningKey {
        self.engine.key()
    }

    /// Processes actual post-Login input; a received-packet error retires this owner.
    pub fn receive(mut self, packet: packets::Packet) -> Result<LoginEvent, HandshakeError> {
        match self.engine.receive(packet)? {
            EngineEvent::Send(packets) => Ok(LoginEvent::Send {
                login: self,
                packets,
            }),
            EngineEvent::KeyExchange { ciphers, response } => {
                Ok(LoginEvent::KeyExchange(ClientKeyExchange {
                    continuation: self,
                    ciphers,
                    response,
                }))
            }
            EngineEvent::Packs {
                cache_status,
                negotiation,
            } => Ok(LoginEvent::Packs {
                cache_status,
                packs: ClientPackOffer {
                    engine: self.engine,
                    offer: negotiation,
                },
            }),
            EngineEvent::Startup(start_game) => Ok(LoginEvent::Startup { start_game }),
            EngineEvent::Unhandled(packet) => Ok(LoginEvent::Unhandled {
                login: self,
                packet,
            }),
            EngineEvent::Compression(_) => Err(HandshakeError::InvalidState),
        }
    }
}

/// Preload capability with the original late Login/key-exchange owner retained.
#[must_use]
pub struct ClientPackOffer {
    engine: Box<Engine>,
    offer: PackOffer,
}

/// Late controls while preload/early-stop policy remains caller-owned.
pub enum OfferEvent {
    /// Send in order while retaining the original preload/control owner.
    Send {
        /// The same original admitted offer and proof key.
        offer: ClientPackOffer,
        /// Immediate original Login responses.
        packets: Vec<packets::Packet>,
    },
    /// Install the verified exchange before continuing the same offer.
    KeyExchange(ClientKeyExchange<ClientPackOffer>),
    /// Preserve unrelated input in the caller's existing FIFO.
    Unhandled {
        /// The same preload/control owner.
        offer: ClientPackOffer,
        /// Unrelated or terminal input returned intact.
        packet: Box<packets::Packet>,
    },
}

impl ClientPackOffer {
    /// Borrows original admitted metadata for actual caller cache/CDN acquisition.
    pub fn offers(&self) -> impl Iterator<Item = &PackInfoData> {
        self.offer.offers()
    }

    /// Installs caller-validated bytes before the transfer starts.
    pub fn supply_preloaded(&mut self, id: uuid::Uuid, archive: Vec<u8>) -> Result<(), PackError> {
        self.offer.supply_preloaded(id, archive)
    }

    /// Progresses actual late Login controls without starting the pack transfer.
    /// Unrelated pack/startup input remains caller-owned until transfer starts.
    pub fn receive_control(
        mut self,
        packet: packets::Packet,
    ) -> Result<OfferEvent, HandshakeError> {
        match self.engine.receive(packet)? {
            EngineEvent::Send(packets) => Ok(OfferEvent::Send {
                offer: self,
                packets,
            }),
            EngineEvent::KeyExchange { ciphers, response } => {
                Ok(OfferEvent::KeyExchange(ClientKeyExchange {
                    continuation: self,
                    ciphers,
                    response,
                }))
            }
            EngineEvent::Unhandled(packet) => Ok(OfferEvent::Unhandled {
                offer: self,
                packet,
            }),
            _ => Err(HandshakeError::InvalidState),
        }
    }

    /// Consumes preload permission and keeps late controls on the same key owner.
    pub fn start(self) -> Result<(ClientPacks, packets::ResourcePackClientResponse), PackError> {
        let (transfer, response) = self.offer.start()?;
        Ok((
            ClientPacks {
                engine: self.engine,
                transfer,
            },
            response,
        ))
    }
}

/// In-band pack transfer plus the original late Login/control owner.
#[must_use]
pub struct ClientPacks {
    engine: Box<Engine>,
    transfer: PackNegotiation,
}

/// Ordered transfer/control work, with actual complete archive ownership.
pub enum PacksEvent {
    /// Send in order and continue with this same owner.
    Send {
        /// The same transfer and late Login control owner.
        packs: ClientPacks,
        /// Immediate responses in their existing order.
        packets: Vec<packets::Packet>,
    },
    /// Install the existing verified exchange before continuing the same transfer.
    KeyExchange(ClientKeyExchange<ClientPacks>),
    /// Preserve an early stack for replay when this same owner's `ready_for_stack` is true.
    DeferredStack {
        /// The original pending transfer/control owner.
        packs: ClientPacks,
        /// The exact stack fields, detached from unrelated decoded batch storage.
        stack: Box<packets::ResourcePackStack>,
    },
    /// The original stack acknowledgment and selected archive ownership.
    Finished(PackComplete),
    /// Preserve this input ahead of unread siblings; terminal handling stays with the caller.
    Unhandled {
        /// The same pending transfer/control owner.
        packs: ClientPacks,
        /// Unrelated input preserved for the caller's bounded FIFO.
        packet: Box<packets::Packet>,
    },
}

impl ClientPacks {
    /// Borrows original offers for cache bookkeeping without reopening preload capability.
    pub fn offers(&self) -> impl Iterator<Item = &PackInfoData> {
        self.transfer.offers()
    }

    /// Shares completed bytes with a bounded cache write; release references before the stack.
    pub fn completed_archive(&self, id: uuid::Uuid) -> Option<Arc<Vec<u8>>> {
        self.transfer.completed_archive(id)
    }

    /// Whether all downloads completed and a deferred stack can be replayed with `receive`.
    /// Send pending transfer responses and release shared cache references before replaying.
    pub fn ready_for_stack(&self) -> bool {
        self.transfer.ready_for_stack()
    }

    /// Processes transfer and late Login controls through their original private implementations.
    pub fn receive(mut self, packet: packets::Packet) -> Result<PacksEvent, HandshakeError> {
        match self.transfer.receive(packet)? {
            PackEvent::Send(packets) => Ok(PacksEvent::Send {
                packs: self,
                packets,
            }),
            PackEvent::DeferredStack(stack) => Ok(PacksEvent::DeferredStack { packs: self, stack }),
            PackEvent::Finished(complete) => Ok(PacksEvent::Finished(complete)),
            PackEvent::Unhandled(packet) => match self.engine.receive(*packet)? {
                EngineEvent::Send(packets) => Ok(PacksEvent::Send {
                    packs: self,
                    packets,
                }),
                EngineEvent::KeyExchange { ciphers, response } => {
                    Ok(PacksEvent::KeyExchange(ClientKeyExchange {
                        continuation: self,
                        ciphers,
                        response,
                    }))
                }
                EngineEvent::Unhandled(packet) => Ok(PacksEvent::Unhandled {
                    packs: self,
                    packet,
                }),
                _ => Err(HandshakeError::InvalidState),
            },
        }
    }
}
