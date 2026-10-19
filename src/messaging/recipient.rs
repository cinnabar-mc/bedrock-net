//! Explicit service dialect and the original peer route, without guessing from its text.

use uuid::Uuid;

/// The exact authenticated signaling route selected before transport negotiation.
/// A legacy network ID is distinct from a Player Messaging account UUID.
#[derive(Clone)]
pub enum Recipient {
    /// A Player Messaging envelope sender/recipient, with explicit peer receipts.
    Messaging(Uuid),
    /// An original legacy service network route, with service delivery outcomes.
    Legacy(String),
}

impl Recipient {
    /// Returns whether this is the original string-routed service dialect.
    pub(super) fn is_legacy(&self) -> bool {
        matches!(self, Self::Legacy(_))
    }

    /// Moves the actual selected route into the existing transport bridge.
    pub(super) fn network_id(&self) -> String {
        match self {
            Self::Messaging(peer) => peer.to_string(),
            Self::Legacy(peer) => peer.clone(),
        }
    }
}
