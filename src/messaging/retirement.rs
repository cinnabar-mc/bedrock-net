//! Established transport lifetime retained across final handoff and caller-owned session clones.

use nethernet_tokio::{NetherClient, Session};

/// Keeps the exact ready transport reachable through fallible handoff and the messaging lifetime.
pub(super) struct SessionRetirement {
    session: Session,
}

impl SessionRetirement {
    /// Captures only the existing ready transport; no signaling, task or replacement is created.
    pub(super) fn new(client: &NetherClient) -> Self {
        Self {
            session: client.session(),
        }
    }

    /// Returns a handle whose useful lifetime remains bounded by its messaging owner.
    pub(super) fn session(&self) -> Session {
        self.session.clone()
    }
}

impl Drop for SessionRetirement {
    fn drop(&mut self) {
        self.session.start_close();
    }
}

#[cfg(test)]
mod tests;
