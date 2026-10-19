//! Established transport lifetime retained across final handoff and caller-owned established sender clones.

use nethernet_tokio::{NetherClient, SessionSender};

/// Keeps the exact ready transport reachable through fallible handoff and the messaging lifetime.
pub(super) struct SessionRetirement {
    sender: SessionSender,
}

impl SessionRetirement {
    /// Captures only the existing ready transport; no signaling, task or replacement is created.
    pub(super) fn new(client: &NetherClient) -> Self {
        Self {
            sender: client.sender(),
        }
    }

    /// Returns a handle whose useful lifetime remains bounded by its messaging owner.
    pub(super) fn sender(&self) -> SessionSender {
        self.sender.clone()
    }

    /// Requests teardown on the exact established actor without consuming its accepted FIFO.
    pub(super) fn start_close(&self) {
        self.sender.start_close();
    }
}

impl Drop for SessionRetirement {
    fn drop(&mut self) {
        self.sender.start_close();
    }
}

#[cfg(test)]
mod tests;
