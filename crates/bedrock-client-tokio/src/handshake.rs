// SPDX-License-Identifier: MIT

//! Caller-driven wire effects over the original consuming client handshake.

use crate::{connection::Connection, error::NegotiationError};
use bedrock_client::{
    handshake::{
        ClientHandshake, ClientKeyExchange, ClientLogin, ClientLoginReady, ClientPackOffer,
        LoginEvent, OfferEvent, SettingsEvent,
    },
    transfer::TransferTarget,
};
use bedrock_net::{CompressionSettings, login::OfflineIdentity};
use bedrock_protocol::{packets, wire};
use bytes::Bytes;
use serde_json::value::RawValue;
use std::{
    io,
    time::{Instant, SystemTime},
};

#[cfg(all(test, feature = "nethernet"))]
mod tests;

/// Borrowed observations of original I/O; callbacks cannot replace a packet or grant authority.
pub enum Observation<'a> {
    /// An unknown numeric ID on an otherwise valid original header.
    Unknown(wire::PacketHeader),
    /// One actually decoded original server packet, before its consumed transition.
    Received(wire::PacketHeader, &'a packets::Packet),
    /// One original generated effect vector after every write completed successfully.
    Sent(&'a [packets::Packet]),
}

/// Caller-validated Login input, signed with the proof key retained by `ClientLoginReady`.
pub enum LoginData<'a> {
    /// Account/issuer/key binding and this absolute credential deadline remain caller authority.
    Authenticated {
        /// Original opaque credential whose issuer/account/key binding the caller verified.
        token: &'a str,
        /// Caller-owned metadata constructed after settings, signed without rewriting.
        claims: &'a RawValue,
        /// Original absolute credential cutoff, retained through transport capacity admission.
        deadline: Instant,
    },
    /// Explicit offline identity and caller UTC; no online or membership authority is implied.
    Offline {
        /// Explicit caller-selected offline identity; it grants no online account authority.
        identity: OfflineIdentity<'a>,
        /// Caller-owned metadata constructed after settings, signed without rewriting.
        claims: &'a RawValue,
        /// Caller UTC used by the original offline Login formatter.
        now: SystemTime,
    },
}

/// Flushes original settings output and installs compression before caller metadata is constructed.
/// Keep this wait under the caller's original overall deadline. Canceling this borrowed
/// future does not close Connection; the caller must retire or drop that same owner.
pub async fn settings(
    connection: &mut Connection,
    configured: ClientHandshake,
    observe: &mut (impl FnMut(Observation<'_>) + Send),
) -> Result<(ClientLoginReady, CompressionSettings), NegotiationError> {
    let (mut settings, request) = configured.start()?;
    send_packets(connection, &[request.into()], None, observe).await?;
    loop {
        let (_, packet) = connection
            .next_packet_observed(observe)
            .await
            .map_err(NegotiationError::Io)?;
        match settings.receive(packet)? {
            SettingsEvent::Ready { login, compression } => {
                connection
                    .enable_compression(compression)
                    .map_err(NegotiationError::Io)?;
                return Ok((login, compression));
            }
            SettingsEvent::Pending {
                settings: next,
                packet,
            } => {
                defer_unhandled(connection, *packet)?;
                settings = next;
            }
        }
    }
}

/// Signs and sends Login once, then retains the same key/ciphers/FIFO through offer or `StartGame`.
/// Metadata is supplied only after `settings` returned the real `LoginReady` continuation.
pub async fn login(
    connection: &mut Connection,
    ready: ClientLoginReady,
    input: LoginData<'_>,
    observe: &mut (impl FnMut(Observation<'_>) + Send),
) -> Result<Option<ClientPackOffer>, NegotiationError> {
    let (prepared, deadline) = match input {
        LoginData::Authenticated {
            token,
            claims,
            deadline,
        } => {
            if Instant::now() >= deadline {
                return Err(NegotiationError::Write(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    crate::transport::ExpiredAdmission,
                )));
            }
            (ready.login_authenticated(token, claims), Some(deadline))
        }
        LoginData::Offline {
            identity,
            claims,
            now,
        } => (ready.login_offline(&identity, claims, now), None),
    };
    let (login, packet) =
        prepared.map_err(|error| NegotiationError::Handshake(error.into_parts().1))?;
    send_packets(connection, &[packet.into()], deadline, observe).await?;
    receive_login(connection, login, observe).await
}

/// Drives the original post-Login continuation without introducing another phase machine.
async fn receive_login(
    connection: &mut Connection,
    mut login: ClientLogin,
    observe: &mut (impl FnMut(Observation<'_>) + Send),
) -> Result<Option<ClientPackOffer>, NegotiationError> {
    loop {
        let (_, packet) = connection
            .next_packet_observed(observe)
            .await
            .map_err(NegotiationError::Io)?;
        match login.receive(packet)? {
            LoginEvent::Send {
                login: next,
                packets,
            } => {
                send_packets(connection, &packets, None, observe).await?;
                login = next;
            }
            LoginEvent::KeyExchange(exchange) => {
                login = apply_key_exchange(connection, exchange, observe).await?;
            }
            LoginEvent::Packs {
                cache_status,
                packs,
            } => {
                if let Some(status) = cache_status {
                    send_packets(connection, &[status.into()], None, observe).await?;
                }
                return Ok(Some(packs));
            }
            LoginEvent::Startup { start_game } => {
                defer_unhandled(connection, packets::Packet::StartGame(start_game))?;
                return Ok(None);
            }
            LoginEvent::Unhandled {
                login: next,
                packet,
            } => {
                defer_unhandled(connection, *packet)?;
                login = next;
            }
        }
    }
}

/// Services one actual late Login/control packet while an admitted offer remains caller-owned.
/// This supports callers that stop after offer acceptance without starting pack acquisition.
pub async fn offer_control(
    connection: &mut Connection,
    offer: ClientPackOffer,
    observe: &mut (impl FnMut(Observation<'_>) + Send),
) -> Result<ClientPackOffer, NegotiationError> {
    let (_, packet) = connection
        .next_packet_observed(observe)
        .await
        .map_err(NegotiationError::Io)?;
    match offer.receive_control(packet)? {
        OfferEvent::Send { offer, packets } => {
            send_packets(connection, &packets, None, observe).await?;
            Ok(offer)
        }
        OfferEvent::KeyExchange(exchange) => {
            apply_key_exchange(connection, exchange, observe).await
        }
        OfferEvent::Unhandled { offer, packet } => {
            defer_unhandled(connection, *packet)?;
            Ok(offer)
        }
    }
}

/// Installs the existing verified streams before flushing their original acknowledgment.
pub(crate) async fn apply_key_exchange<C>(
    connection: &mut Connection,
    exchange: ClientKeyExchange<C>,
    observe: &mut (impl FnMut(Observation<'_>) + Send),
) -> Result<C, NegotiationError> {
    let (continuation, ciphers, response) = exchange.into_parts();
    if let Some(ciphers) = ciphers {
        connection
            .enable_encryption(*ciphers)
            .map_err(NegotiationError::Io)?;
    }
    send_packets(connection, &[response.into()], None, observe).await?;
    Ok(continuation)
}

/// Encodes and flushes the original effect order under the same outgoing count/body limits.
pub(crate) async fn send_packets(
    connection: &mut Connection,
    packets: &[packets::Packet],
    deadline: Option<Instant>,
    observe: &mut (impl FnMut(Observation<'_>) + Send),
) -> Result<(), NegotiationError> {
    if connection.max_packets() == 0 {
        return Err(NegotiationError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "zero packet count limit",
        )));
    }
    let mut body = Vec::new();
    let mut count = 0;
    for packet in packets {
        let entry = connection
            .packet_body(packet, wire::Peer::Client, 0, 0)
            .map_err(NegotiationError::Io)?;
        if !body.is_empty()
            && (count == connection.max_packets()
                || body
                    .len()
                    .checked_add(entry.len())
                    .is_none_or(|bytes| bytes > connection.max_decoded_bytes()))
        {
            connection
                .send_body_until(Bytes::from(std::mem::take(&mut body)), deadline)
                .await
                .map_err(NegotiationError::Write)?;
            count = 0;
        }
        body.extend_from_slice(&entry);
        count += 1;
    }
    if !body.is_empty() {
        connection
            .send_body_until(Bytes::from(body), deadline)
            .await
            .map_err(NegotiationError::Write)?;
    }
    observe(Observation::Sent(packets));
    Ok(())
}

/// Keeps actual terminals typed and unused input on the existing aggregate-bounded raw FIFO.
pub(crate) fn defer_unhandled(
    connection: &mut Connection,
    packet: packets::Packet,
) -> Result<(), NegotiationError> {
    match packet {
        packets::Packet::Disconnect(packet) => Err(NegotiationError::Disconnect(Box::new(packet))),
        packets::Packet::Transfer(packet) => {
            match TransferTarget::from_target(
                &packet.server_address.to_string_lossy(),
                packet.server_port.0,
                packet.reload_world,
            ) {
                Ok(target) => Err(NegotiationError::Transfer(target)),
                Err(reason) => {
                    let skipped = connection.record_skip();
                    tracing::warn!(?reason, skipped, "skipped unusable negotiation transfer");
                    Ok(())
                }
            }
        }
        _ => connection.defer_current().map_err(NegotiationError::Io),
    }
}
