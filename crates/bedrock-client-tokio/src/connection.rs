// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Compression, encryption and packet FIFO retained for the entire connection.

use self::deferred::DeferredFrames;
use super::PacketIo;
use super::transport::Transport;
use bedrock_net::encryption::{BatchDecryptor, BatchEncryptor};
use bedrock_net::{BatchCodec, BatchError, BatchLimits, CompressionSettings, DecodeOutcome};
use bedrock_protocol::{packets, wire};
use bytes::{Bytes, BytesMut};
use std::io;

mod codec;
mod deferred;
pub mod identity;
mod pending;
use codec::Codec;
use pending::PendingPackets;
#[cfg(feature = "nethernet")]
pub mod send;
#[cfg(feature = "nethernet")]
use send::{PendingSend, RetirementState};

/// One caller-driven codec, cipher and original received FIFO.
pub struct Connection {
    pub(super) transport: Transport,
    codec: Option<Codec>,
    limits: BatchLimits,
    incoming_decoded_limit: usize,
    pending: PendingPackets,
    current: Option<Bytes>,
    deferred: DeferredFrames,
    receive_limits: wire::Limits,
    ciphers: Option<(BatchEncryptor, BatchDecryptor)>,
    #[cfg(feature = "nethernet")]
    pending_send: Option<PendingSend>,
    #[cfg(feature = "nethernet")]
    send_retirement: Option<RetirementState>,
    send_sealed: bool,
    negotiation_skips: u64,
    ingress: Ingress,
    identity: Option<identity::WireIdentity>,
    #[cfg(any(test, feature = "test-support"))]
    observed_batches: Option<BatchLifetimes>,
}

/// Separates opaque accepting input from the packets consumed by upstream client owners.
#[derive(Clone, Copy)]
enum Ingress {
    Raw,
    Known,
    Primary,
}

#[cfg(any(test, feature = "test-support"))]
pub mod observation;
#[cfg(any(test, feature = "test-support"))]
use observation::{BatchLifetimes, OBSERVE_BATCHES, ObservedBatch};

impl Connection {
    /// Binds the caller's wire, field and deferred-prefix limits before any codec transition.
    /// Incoming decoded limits remain unchanged until actual compression settings are installed.
    pub fn new(
        mut transport: Transport,
        limits: BatchLimits,
        receive_limits: wire::Limits,
        max_deferred_bytes: usize,
    ) -> Self {
        transport.configure_limits(limits);
        Self {
            codec: Some(Codec::Plain(BatchCodec::new(transport.header(), limits))),
            transport,
            limits,
            incoming_decoded_limit: limits.max_decoded_bytes,
            pending: PendingPackets::default(),
            current: None,
            deferred: DeferredFrames::new(max_deferred_bytes),
            receive_limits,
            ciphers: None,
            #[cfg(feature = "nethernet")]
            pending_send: None,
            #[cfg(feature = "nethernet")]
            send_retirement: None,
            send_sealed: false,
            negotiation_skips: 0,
            ingress: Ingress::Raw,
            identity: None,
            #[cfg(any(test, feature = "test-support"))]
            observed_batches: OBSERVE_BATCHES.try_with(std::sync::Arc::clone).ok(),
        }
    }

    /// Records an incoming-only ceiling, activated by the original settings transition.
    pub fn with_incoming_decoded_limit(mut self, maximum: usize) -> Self {
        self.incoming_decoded_limit = maximum;
        self
    }

    /// Skips unknown generated packet IDs at the same original FIFO front.
    pub fn known_packets(&mut self) {
        self.ingress = Ingress::Known;
    }

    /// Counts a caller-classified unused packet on the same original receive observation.
    pub fn record_skip(&mut self) -> u64 {
        self.negotiation_skips = self.negotiation_skips.saturating_add(1);
        self.negotiation_skips
    }

    /// Borrows the real transport for read-only metadata or explicit lifecycle operations.
    pub fn transport(&self) -> &Transport {
        &self.transport
    }
    /// Borrows the same retained lifecycle owner, without creating another transport.
    pub fn transport_mut(&mut self) -> &mut Transport {
        &mut self.transport
    }
    /// Installs already validated wire metadata; this grants no account or session authority.
    pub fn set_identity(&mut self, identity: identity::WireIdentity) {
        self.identity = Some(identity);
    }

    /// Keeps ordinary writes/settings from replacing an unfinished or terminal effect.
    fn ensure_send_idle(&self) -> io::Result<()> {
        if self.send_sealed {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "native accepting send is sealed",
            ));
        }
        #[cfg(feature = "nethernet")]
        if self.pending_send.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native accepting send is still retained",
            ));
        }
        Ok(())
    }

    /// Admits only primary-player input; typed reads separately skip unknown IDs.
    pub fn primary_only(&mut self) {
        self.ingress = Ingress::Primary;
    }

    /// Instruments actual received batch ownership without replacing transport or codec behavior.
    #[cfg(any(test, feature = "test-support"))]
    pub fn observe_batches(&mut self, observations: BatchLifetimes) {
        self.observed_batches = Some(observations);
    }

    /// Adds only a weak lifetime observation around the same real socket bytes before decoding.
    #[cfg(any(test, feature = "test-support"))]
    fn observe_batch(&self, bytes: Bytes) -> Bytes {
        let Some(observations) = &self.observed_batches else {
            return bytes;
        };
        let lifetime = std::sync::Arc::new(());
        observations
            .lock()
            .unwrap()
            .push((bytes.len(), std::sync::Arc::downgrade(&lifetime)));
        Bytes::from_owner(ObservedBatch {
            bytes,
            _lifetime: lifetime,
        })
    }

    /// The shared decoded-byte bound for Login and subsequent packets.
    pub fn max_decoded_bytes(&self) -> usize {
        self.limits.max_decoded_bytes
    }

    /// Applies negotiated compression without replacing unread packets.
    pub fn enable_compression(&mut self, settings: CompressionSettings) -> io::Result<()> {
        self.ensure_send_idle()?;
        let current = self.codec.take().expect("codec transition is synchronous");
        match current {
            Codec::Plain(codec) => {
                self.codec = Some(Codec::Negotiated(
                    codec
                        .negotiate(settings)
                        .with_incoming_decoded_limit(self.incoming_decoded_limit),
                ));
                Ok(())
            }
            configured @ Codec::Negotiated(_) => {
                self.codec = Some(configured);
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "repeated network settings",
                ))
            }
        }
    }

    /// Borrows the actual codec; its only move occurs in a synchronous settings transition.
    fn codec(&self) -> &Codec {
        self.codec
            .as_ref()
            .expect("codec transition is synchronous")
    }

    /// Installs both directional streams once, before the client handshake acknowledgment.
    pub fn enable_encryption(
        &mut self,
        ciphers: (BatchEncryptor, BatchDecryptor),
    ) -> io::Result<()> {
        self.ensure_send_idle()?;
        if self.ciphers.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "repeated server key exchange",
            ));
        }
        self.ciphers = Some(ciphers);
        Ok(())
    }

    /// Encodes without restarting a finite Login credential deadline.
    pub async fn send_body_until(
        &mut self,
        body: Bytes,
        deadline: Option<std::time::Instant>,
    ) -> io::Result<()> {
        self.ensure_send_idle()?;
        for message in self.encode_body(body)? {
            let message = self.encrypt_message(message)?;
            self.transport.send_until(message, deadline).await?;
        }
        Ok(())
    }

    /// Encodes one generated packet into this original codec/cipher owner and flushes it.
    /// The caller supplies the actual wire direction and original subclient header.
    pub async fn send_packet(
        &mut self,
        packet: &packets::Packet,
        sender: wire::Peer,
        sender_subclient: u8,
        target_subclient: u8,
    ) -> io::Result<()> {
        self.ensure_send_idle()?;
        let mut body = Vec::new();
        let id = packet.id();
        if !id.direction().permits(sender) {
            return Err(io::Error::other(wire::EncodeError::UnexpectedDirection(
                id as u32,
            )));
        }
        let header = wire::PacketHeader {
            id: id as u32,
            sender_subclient,
            target_subclient,
        };
        wire::encode_frame_with(&mut body, header, self.limits.max_decoded_bytes, |writer| {
            packet.encode(writer)
        })
        .map_err(io::Error::other)?;
        self.send_body_until(Bytes::from(body), None).await
    }

    /// Encodes the original bounded packet entries once on the current codec.
    fn encode_body(&self, body: Bytes) -> io::Result<Vec<Bytes>> {
        Self::check_body_size(&body, self.limits.max_decoded_bytes)?;
        let entries = wire::Frames::new(body, self.limits.max_packets)
            .map(|frame| {
                let frame = frame.map_err(io::Error::other)?;
                identity::entry(frame, self.identity.as_ref(), self.limits.max_decoded_bytes)
            })
            .collect::<io::Result<Vec<_>>>()?;
        self.codec().encode(&entries).map_err(io::Error::other)
    }

    /// Advances the sole original directional cipher and checks its actual envelope size.
    fn encrypt_message(&mut self, mut message: Bytes) -> io::Result<Bytes> {
        if let Some((encryptor, _)) = &mut self.ciphers {
            let marker = self.transport.header().marker();
            let body = if marker.is_some() {
                message.slice(1..)
            } else {
                message
            };
            message = envelope(marker, encryptor.encrypt(body).map_err(io::Error::other)?);
            self.check_wire_size(&message)?;
        }
        Ok(message)
    }

    /// Frames one original raw packet under the same decoded-body limit.
    pub fn raw_body(&self, raw: Bytes) -> io::Result<Bytes> {
        let limit = self.max_decoded_bytes();
        let mut framed = Vec::new();
        wire::Writer::with_limit(&mut framed, limit)
            .write_len_var_u32(raw.len())
            .map_err(io::Error::other)?;
        if raw.is_empty()
            || framed
                .len()
                .checked_add(raw.len())
                .is_none_or(|n| n > limit)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid native raw packet",
            ));
        }
        framed.extend_from_slice(&raw);
        Ok(Bytes::from(framed))
    }

    /// Refuses an oversized queue item before it can retain connection capacity.
    pub fn check_body_size(body: &[u8], maximum: usize) -> io::Result<()> {
        if body.len() > maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native outgoing batch exceeds decoded byte limit",
            ));
        }
        Ok(())
    }

    /// Reads a complete batch, retaining decoded siblings across every protocol transition.
    async fn fill(&mut self) -> io::Result<()> {
        while !self.pending_ready()? {
            let mut message = self.transport.recv().await?;
            self.check_wire_size(&message)?;
            if let Some((_, decryptor)) = &mut self.ciphers {
                let marker = self.transport.header().marker();
                let body = if let Some(marker) = marker {
                    let actual = *message
                        .first()
                        .ok_or_else(|| io::Error::other(BatchError::MissingBatchHeader))?;
                    if actual != marker {
                        return Err(io::Error::other(BatchError::InvalidBatchHeader(actual)));
                    }
                    message.slice(1..)
                } else {
                    message
                };
                message = envelope(marker, decryptor.decrypt(body).map_err(io::Error::other)?);
            }
            #[cfg(any(test, feature = "test-support"))]
            let message = self.observe_batch(message);
            match self.codec().decode(message).map_err(io::Error::other)? {
                DecodeOutcome::Packets {
                    packets,
                    skipped_empty_packets,
                    ..
                } => {
                    if skipped_empty_packets != 0 {
                        tracing::debug!(
                            skipped_empty_packets,
                            "skipped empty native batch entries"
                        );
                    }
                    self.pending.push_batch(packets);
                }
                DecodeOutcome::Dropped(reason) => tracing::debug!(?reason, "dropped native batch"),
            }
        }
        Ok(())
    }

    /// Filters only the actual FIFO front, keeping one lazy cursor behind every replayed prefix.
    fn pending_ready(&mut self) -> io::Result<bool> {
        while let Some(packet) = self.pending.front() {
            if matches!(self.ingress, Ingress::Raw) {
                return Ok(true);
            }
            let mut reader = wire::Reader::from_shared(packet);
            let header =
                wire::PacketHeader::from_raw(reader.read_var_u32().map_err(io::Error::other)?);
            let admitted = match self.ingress {
                Ingress::Raw => true,
                Ingress::Known => packets::PacketId::from_raw(header.id).is_some(),
                Ingress::Primary => header.sender_subclient == 0 && header.target_subclient == 0,
            };
            if admitted {
                return Ok(true);
            }
            drop(self.pending.pop_front());
            self.negotiation_skips = self.negotiation_skips.saturating_add(1);
            tracing::debug!(
                id = header.id,
                sender = header.sender_subclient,
                target = header.target_subclient,
                skipped = self.negotiation_skips,
                "skipped unused native packet"
            );
        }
        Ok(false)
    }

    /// Restores early raw frames ahead of unread siblings on this same FIFO.
    pub fn replay_deferred(&mut self) {
        for packet in self.take_deferred().into_iter().rev() {
            self.pending.push_front(deferred::encoded(&packet));
        }
    }

    /// Removes one original complete header/body while retaining siblings for the next call.
    pub async fn next_raw(&mut self) -> io::Result<Bytes> {
        self.current = None;
        self.fill().await?;
        let bytes = self.pending.pop_front().expect("fill supplies packets");
        self.current = Some(bytes.clone());
        Ok(bytes)
    }

    /// Restores actual already-consumed handoff frames ahead of the original unread siblings.
    pub fn prepend_raw(&mut self, packets: Vec<Bytes>) {
        for packet in packets.into_iter().rev() {
            self.pending.push_front(packet);
        }
    }

    /// Restores an unconsumed actual terminal before retiring a partial relay negotiation.
    pub fn replay_current(&mut self) {
        if let Some(bytes) = self.current.take() {
            self.pending.push_front(bytes);
        }
    }

    /// Releases an already consumed packet after its separate handoff owner has been committed.
    pub fn finish_current(&mut self) {
        self.current = None;
    }

    /// Borrows the last consumed complete header/body for caller-owned terminal projection.
    pub fn current_raw(&self) -> Option<&Bytes> {
        self.current.as_ref()
    }

    /// Shares the original header/body and skips only unknown IDs under the existing policy.
    pub async fn next_known_raw(&mut self) -> io::Result<(wire::PacketHeader, Bytes)> {
        loop {
            let bytes = self.next_raw().await?;
            self.current = None;
            let mut reader = wire::Reader::from_shared(&bytes);
            let header =
                wire::PacketHeader::from_raw(reader.read_var_u32().map_err(io::Error::other)?);
            let Some(_) = packets::PacketId::from_raw(header.id) else {
                self.negotiation_skips = self.negotiation_skips.saturating_add(1);
                tracing::debug!(
                    skipped = self.negotiation_skips,
                    id = header.id,
                    "skipped unused native negotiation packet"
                );
                continue;
            };
            let body = bytes.slice(reader.position()..);
            self.current = Some(bytes);
            return Ok((header, body));
        }
    }

    /// Decodes one generated packet under the caller's field limits, retaining batch siblings.
    pub async fn next_packet(&mut self) -> io::Result<(wire::PacketHeader, packets::Packet)> {
        let (header, body) = self.next_known_raw().await?;
        let id = packets::PacketId::from_raw(header.id).expect("known generated packet");
        let data = self
            .decode_body(id, &body)
            .inspect_err(|_| self.current = None)?;
        Ok((header, data))
    }

    /// Decodes only a selected body with the original caller's field limits.
    pub fn decode_body(&self, id: packets::PacketId, body: &Bytes) -> io::Result<packets::Packet> {
        let mut reader = wire::Reader::from_shared(body).with_limits(&self.receive_limits);
        let packet = packets::Packet::decode_body(id, &mut reader).map_err(io::Error::other)?;
        reader.expect_consumed().map_err(io::Error::other)?;
        Ok(packet)
    }

    /// Moves the same current raw packet into the original aggregate bounded prefix.
    pub fn defer_current(&mut self) -> io::Result<()> {
        let bytes = self.current.take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "native deferred packet has no received frame",
            )
        })?;
        self.deferred.push(bytes)
    }

    /// Borrows retained generated frames without decoding their bodies or granting admission.
    pub fn deferred(&self) -> &[wire::RawFrame] {
        self.deferred.as_slice()
    }

    /// Transfers the original prefix once, ahead of packets not yet consumed by negotiation.
    pub fn take_deferred(&mut self) -> Vec<wire::RawFrame> {
        self.current = None;
        self.deferred.take()
    }

    /// Checks ciphertext input before decrypting or allocating decoded state.
    fn check_wire_size(&self, message: &[u8]) -> io::Result<()> {
        if message.len() > self.limits.max_encoded_bytes {
            return Err(io::Error::other(BatchError::EncodedTooLarge {
                actual: message.len(),
                maximum: self.limits.max_encoded_bytes,
            }));
        }
        Ok(())
    }
}

/// Restores the cleartext marker around a directional cipher body when required.
fn envelope(marker: Option<u8>, body: Bytes) -> Bytes {
    if let Some(marker) = marker {
        let mut message = BytesMut::with_capacity(body.len() + 1);
        message.extend_from_slice(&[marker]);
        message.extend_from_slice(&body);
        message.freeze()
    } else {
        body
    }
}

impl PacketIo for Connection {
    fn observe_rtt(&self) -> Option<super::rtt::RoundTripTime> {
        self.transport.observe_rtt()
    }

    /// Advances the cipher only inside this owner's uninterrupted write operation.
    async fn send_body(&mut self, body: Bytes) -> io::Result<()> {
        self.send_body_until(body, None).await
    }

    /// Reframes a bounded prefix or one larger negotiated incoming packet on the same FIFO.
    async fn recv_body(&mut self) -> io::Result<Bytes> {
        self.fill().await?;
        let mut body = Vec::new();
        let mut accepted = 0;
        while accepted < self.limits.max_packets {
            match self.pending_ready() {
                Ok(true) => {}
                Ok(false) => break,
                // The original malformed front remains pending after this accepted prefix.
                Err(_) if accepted != 0 => break,
                Err(error) => return Err(error),
            }
            let checkpoint = body.len();
            let limit = if accepted == 0 && matches!(self.codec(), Codec::Negotiated(_)) {
                self.incoming_decoded_limit
            } else {
                self.limits.max_decoded_bytes
            };
            let remaining = limit.saturating_sub(checkpoint);
            let packet = self.pending.front().expect("validated original front");
            let result = wire::Writer::with_limit(&mut body, remaining).write_byte_slice(packet);
            if let Err(error) = result {
                body.truncate(checkpoint);
                if accepted == 0 {
                    return Err(io::Error::other(error));
                }
                break;
            }
            drop(self.pending.pop_front());
            accepted += 1;
            if body.len() > self.limits.max_decoded_bytes {
                break;
            }
        }
        Ok(Bytes::from(body))
    }

    /// Keeps protected service progress alive without decoding or consuming game input.
    async fn maintain(&mut self) {
        self.transport.maintain().await;
    }

    /// Ends the actual transport, without starting another connection.
    async fn close(&mut self) -> io::Result<()> {
        self.transport.close().await
    }
}

#[cfg(test)]
mod tests;
