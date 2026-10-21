// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Typed driver causes with coarse error messages.
//!
//! Disconnect and Transfer retain their actual server-controlled presentation/target
//! fields for caller policy; those payloads are not content-free diagnostics.

/// The retained encoded startup prefix exceeded its caller-owned byte limit.
#[derive(Debug, thiserror::Error)]
#[error("deferred packet prefix exceeds its byte limit")]
pub struct DeferredLimit {
    /// Required aggregate encoded bytes, including each original length prefix.
    pub actual: usize,
    /// The caller's original aggregate bound.
    pub maximum: usize,
}

#[cfg(any(feature = "raknet", feature = "nethernet"))]
/// A retained protocol/transport cause at the caller's negotiation boundary.
#[derive(Debug, thiserror::Error)]
pub enum NegotiationError {
    /// A read, framing, codec or local-state failure.
    #[error("negotiation I/O failed")]
    Io(#[source] std::io::Error),
    /// A response write failed; callers may preserve an already-received terminal first.
    #[error("negotiation response write failed")]
    Write(#[source] std::io::Error),
    /// The original consumed handshake rejected the received transition.
    #[error(transparent)]
    Handshake(#[from] bedrock_client::handshake::HandshakeError),
    /// The original pack owner rejected caller-supplied archive bytes.
    #[error(transparent)]
    Packs(#[from] bedrock_client::packs::PackError),
    /// The actual decoded server disconnect, for caller-owned presentation.
    #[error("server ended negotiation")]
    Disconnect(Box<bedrock_protocol::packets::Disconnect>),
    /// A well-formed server-directed target; following it remains caller policy.
    #[error("server requested a transfer")]
    Transfer(bedrock_client::transfer::TransferTarget),
}
