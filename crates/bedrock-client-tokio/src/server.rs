// SPDX-License-Identifier: MIT

//! Packet I/O for an accepted `NetherNet` session.
//!
//! [`AcceptingConnection`] retains batching and unread packets while the
//! application drives [`ServerHandshake`]. Use [`prepare_packets`](AcceptingConnection::prepare_packets)
//! to send returned effects before advancing pending handshake states.

use crate::connection::send::{PreparedSend, SendRetirement};
use crate::{
    connection::{Connection, expired},
    transport::Transport,
};

#[cfg(all(feature = "nethernet", any(test, feature = "test-support")))]
pub mod test_support;
#[cfg(all(test, feature = "nethernet"))]
mod tests;
use bedrock_client::server::{ServerHandshake, ServerHandshakeOptions};
use bedrock_net::{BatchLimits, CompressionSettings};
use bedrock_protocol::{packets, wire};
use bytes::Bytes;
use p384::ecdsa::SigningKey;
use std::{io, sync::Arc, time::Instant};

/// Reads and writes generated packets on one accepted transport session.
///
/// The returned handshake performs Login verification. Your application separately
/// authorizes the player and supplies packs and world data.
#[must_use]
pub struct AcceptingConnection {
    connection: Connection,
    skipped: u64,
}

/// Local send admission ended; the same already accepted receive prefix can still drain.
#[must_use]
pub struct RetiredAcceptingConnection {
    connection: Connection,
}

impl AcceptingConnection {
    /// Wraps an accepted `NetherNet` association and binds Login to its verified SDP key.
    /// Supply the server proof key used by signaling. DTLS protects this association.
    #[cfg(feature = "nethernet")]
    pub async fn from_nether(
        accepted: nethernet_tokio::AcceptedSession,
        key: Arc<SigningKey>,
        options: ServerHandshakeOptions,
        max_deferred_bytes: usize,
        deadline: Instant,
    ) -> io::Result<(Self, ServerHandshake)> {
        let player = wait(deadline, accepted.session.player())
            .await?
            .ok_or_else(denied)?;
        let transport_key = player.client_public_key().map_err(|_| denied())?;
        let handshake = ServerHandshake::new(
            key,
            Some(transport_key),
            options,
            deadline,
            tokio::time::Instant::now().into_std(),
        )
        .map_err(|_| denied())?;
        Ok((
            Self::from_transport(Transport::from_accepted(accepted), max_deferred_bytes),
            handshake,
        ))
    }

    /// Binds the same accepted wire/count limits before either transport's first packet.
    fn from_transport(transport: Transport, max_deferred_bytes: usize) -> Self {
        let defaults = BatchLimits::default();
        let limits = BatchLimits {
            max_incoming_packets: Some(defaults.max_packets),
            ..defaults
        };
        Self {
            connection: Connection::new(
                transport,
                limits,
                wire::Limits::receiving_from(wire::Peer::Client),
                max_deferred_bytes,
            ),
            skipped: 0,
        }
    }

    /// Reads one primary generated packet while retaining every original batch sibling.
    /// Unknown or secondary packets the accepting owner does not use are counted and skipped.
    pub async fn receive(&mut self, deadline: Instant) -> io::Result<packets::Packet> {
        loop {
            let raw = self.receive_raw(deadline).await?;
            let mut reader = wire::Reader::from_shared(&raw);
            let header =
                wire::PacketHeader::from_raw(reader.read_var_u32().map_err(|_| invalid())?);
            let id = packets::PacketId::from_raw(header.id);
            if header.sender_subclient != 0 || header.target_subclient != 0 || id.is_none() {
                self.skipped = self.skipped.saturating_add(1);
                tracing::debug!(skipped = self.skipped, "skipped unused accepting packet");
                continue;
            }
            let body = raw.slice(reader.position()..);
            return self
                .connection
                .decode_body(id.expect("classified packet"), &body)
                .map_err(|_| invalid());
        }
    }

    /// Borrows the original Login request for bounded application-owned admission work.
    /// Other packets have no Login request; this grants no authenticated identity or world access.
    pub fn login_request(packet: &packets::Packet) -> Option<&[u8]> {
        match packet {
            packets::Packet::Login(login) => Some(&login.connection_request),
            _ => None,
        }
    }

    /// Ends decoded peer terminals and counts known input unused by the accepting continuation.
    pub fn handle_unhandled(&mut self, packet: &packets::Packet) -> io::Result<()> {
        if matches!(
            packet,
            packets::Packet::Disconnect(_) | packets::Packet::Transfer(_)
        ) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "native hosted peer ended",
            ));
        }
        self.skipped = self.skipped.saturating_add(1);
        tracing::debug!(id = ?packet.id(), skipped = self.skipped, "skipped unused native hosted packet");
        Ok(())
    }

    /// Installs only the settings whose exact plaintext response has actually flushed.
    pub fn compression_flushed(&mut self, settings: CompressionSettings) -> io::Result<()> {
        self.connection.enable_compression(settings)
    }

    /// Takes the original complete packet header/body; no decode/re-encode changes play packets.
    pub async fn receive_raw(&mut self, deadline: Instant) -> io::Result<Bytes> {
        self.connection.next_raw_before(deadline).await
    }

    /// Waits for ordinary initialized play without imposing a new idle timeout.
    pub async fn receive_play(&mut self) -> io::Result<Bytes> {
        self.connection.next_raw().await
    }

    /// Borrows this same wire owner for protocol adapters that retain their own continuations.
    /// This grants no authenticated identity, application admission or hosted-world authority.
    /// Keep the original owner and check current authority before every synchronous send commit.
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    /// Consumes local send capability and retains the actual accepted receiver and decoded FIFO.
    pub fn begin_close(mut self) -> RetiredAcceptingConnection {
        self.connection.transport_mut().retire_accepted();
        RetiredAcceptingConnection {
            connection: self.connection,
        }
    }

    /// Encodes typed effects once without admitting a command.
    /// Rejects another retained effect or a locally retired send direction.
    /// Empty input completes locally; entries that fail bounded serialization are logged and skipped.
    /// Nonempty input with no encoded entries is rejected.
    /// Larger groups split under the original codec's per-batch limits as one retained effect.
    pub fn prepare_packets(
        &mut self,
        packets: Vec<packets::Packet>,
        deadline: Instant,
    ) -> io::Result<PreparedSend<'_>> {
        let mut body = Vec::new();
        for packet in &packets {
            let header = wire::PacketHeader {
                id: packet.id() as u32,
                sender_subclient: 0,
                target_subclient: 0,
            };
            if let Err(error) = self
                .connection
                .append_packet_frame(&mut body, header, packet)
            {
                tracing::warn!(id = ?packet.id(), %error, "skipping an outbound packet that failed to encode");
            }
        }
        if !packets.is_empty() && body.is_empty() {
            return Err(invalid());
        }
        let frames = wire::Frames::new(Bytes::from(body), packets.len());
        self.connection.prepare_frames(frames, deadline)
    }

    /// Prepares one encoded packet, applying configured identity normalization.
    pub fn prepare_raw(
        &mut self,
        packet: Bytes,
        deadline: Instant,
    ) -> io::Result<PreparedSend<'_>> {
        let body = self.connection.raw_body(packet).map_err(|_| invalid())?;
        self.connection.prepare_body(body, deadline)
    }

    /// Resumes the exact cursor, permit or receipt retained by an earlier borrowed operation.
    pub fn resume_send(&mut self) -> io::Result<PreparedSend<'_>> {
        self.connection.resume_send()
    }

    /// Seals new local commits and caps settlement by the first cleanup and original send cutoffs.
    /// This does not close the association. Settle its receipt before calling `begin_close`.
    pub fn begin_send_retirement(&mut self, deadline: Instant) -> SendRetirement<'_> {
        self.connection.begin_send_retirement(deadline)
    }
}

impl RetiredAcceptingConnection {
    /// Drains the original prefix without minting another established send capability.
    pub async fn receive_raw(&mut self, deadline: Instant) -> io::Result<Bytes> {
        self.connection.next_raw_before(deadline).await
    }
    /// Completes original transport retirement without starting a replacement association.
    pub async fn finish_close(&mut self, deadline: Instant) -> io::Result<()> {
        wait(deadline, self.connection.transport_mut().finish_close()).await?
    }
}

/// Keeps every wait under its original edge deadline, including a late ready result.
async fn wait<T>(deadline: Instant, future: impl std::future::Future<Output = T>) -> io::Result<T> {
    if tokio::time::Instant::now().into_std() >= deadline {
        return Err(expired());
    }
    let result = tokio::time::timeout_at(deadline.into(), future)
        .await
        .map_err(|_| expired())?;
    if tokio::time::Instant::now().into_std() >= deadline {
        return Err(expired());
    }
    Ok(result)
}

/// Reports malformed accepting input without signed metadata or provider diagnostics.
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid native accepting packet",
    )
}
/// Reports only the failed authority class.
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "native accepting identity rejected",
    )
}
