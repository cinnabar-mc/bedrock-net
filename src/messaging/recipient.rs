//! The authenticated Player Messaging peer route.

use uuid::Uuid;

/// The exact authenticated signaling route selected before transport negotiation.
#[derive(Clone)]
pub enum Recipient {
    /// A Player Messaging envelope sender/recipient, with explicit peer receipts.
    Messaging(Uuid),
}

impl Recipient {
    /// Moves the actual selected route into the existing transport bridge.
    pub(super) fn network_id(&self) -> String {
        match self {
            Self::Messaging(peer) => peer.to_string(),
        }
    }
}
