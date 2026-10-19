//! Probe packet pump with retained FIFO and one pair of cipher directions.

use std::error::Error;
use std::io;

use bedrock_net::encryption::{BatchDecryptor, BatchEncryptor};
use bedrock_net::{
    BatchCodec, BatchError, BatchLimits, BatchPackets, BatchPhase, CompressionSettings,
    DecodeOutcome, Negotiated, Plain,
};
use bedrock_protocol::{
    packets,
    wire::{PacketHeader, Writer},
};
use bytes::{Bytes, BytesMut};

use crate::transport::Transport;

pub(super) struct Session<S = Plain> {
    pub(super) transport: Transport,
    codec: BatchCodec<S>,
    limits: BatchLimits,
    pending: Option<BatchPackets>,
    ciphers: Option<(BatchEncryptor, BatchDecryptor)>,
}

impl Session<Plain> {
    /// Owns the transport and preserves complete packets across handshake transitions.
    pub(super) fn new(transport: Transport) -> Self {
        let limits = BatchLimits::default();
        Self {
            codec: BatchCodec::new(transport.header(), limits),
            transport,
            limits,
            pending: None,
            ciphers: None,
        }
    }

    /// Consumes the same transport/FIFO into the one negotiated compression configuration.
    pub(super) fn negotiate(self, settings: CompressionSettings) -> Session<Negotiated> {
        Session {
            transport: self.transport,
            codec: self.codec.negotiate(settings),
            limits: self.limits,
            pending: self.pending,
            ciphers: self.ciphers,
        }
    }
}

impl<S: BatchPhase> Session<S> {
    /// Installs both fresh directions only once; duplicate control packets cannot reset them.
    pub(super) fn enable_encryption(
        &mut self,
        ciphers: (BatchEncryptor, BatchDecryptor),
    ) -> io::Result<()> {
        if self.ciphers.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "batch ciphers are already installed",
            ));
        }
        self.ciphers = Some(ciphers);
        Ok(())
    }

    /// Serializes one generated packet and sends each resulting batch in order.
    pub(super) async fn send(&mut self, packet: packets::Packet) -> Result<(), Box<dyn Error>> {
        let mut bytes = Vec::new();
        let mut writer = Writer::with_limit(&mut bytes, self.limits.max_decoded_bytes);
        writer.write_var_u32(PacketHeader::new(packet.id() as u32).to_raw())?;
        packet.encode(&mut writer)?;
        for mut message in self.codec.encode(&[bytes])? {
            if let Some((encryptor, _)) = &mut self.ciphers {
                let marker = self.transport.header().marker();
                let body = if marker.is_some() {
                    message.slice(1..)
                } else {
                    message
                };
                message = envelope(marker, encryptor.encrypt(body)?);
                check_wire_size(&message, self.limits)?;
            }
            self.transport.send(message).await?;
        }
        Ok(())
    }

    /// Drains the current batch before reading another; compression drops still consume cipher state.
    pub(super) async fn next_packet(&mut self) -> Result<Bytes, Box<dyn Error>> {
        loop {
            if let Some(packet) = self.pending.as_mut().and_then(Iterator::next) {
                return Ok(packet);
            }
            self.pending = None;
            let mut message = self.transport.recv().await?;
            check_wire_size(&message, self.limits)?;
            if let Some((_, decryptor)) = &mut self.ciphers {
                let marker = self.transport.header().marker();
                let body = if let Some(marker) = marker {
                    let actual = *message.first().ok_or(BatchError::MissingBatchHeader)?;
                    if actual != marker {
                        return Err(BatchError::InvalidBatchHeader(actual).into());
                    }
                    message.slice(1..)
                } else {
                    message
                };
                message = envelope(marker, decryptor.decrypt(body)?);
            }
            match self.codec.decode(message)? {
                DecodeOutcome::Packets {
                    packets,
                    skipped_empty_packets,
                    ..
                } => {
                    if skipped_empty_packets != 0 {
                        eprintln!("skipped {skipped_empty_packets} empty batch entries");
                    }
                    self.pending = Some(packets);
                }
                DecodeOutcome::Dropped(reason) => eprintln!("dropped batch: {reason:?}"),
            }
        }
    }
}

/// Restores the cleartext transport marker around a cipher body, when one is required.
fn envelope(marker: Option<u8>, body: Bytes) -> Bytes {
    if let Some(marker) = marker {
        let mut message = BytesMut::new();
        message.extend_from_slice(&[marker]);
        message.extend_from_slice(&body);
        message.freeze()
    } else {
        body
    }
}

/// Bounds wire input before decryption and output before sending.
fn check_wire_size(message: &[u8], limits: BatchLimits) -> Result<(), BatchError> {
    if message.len() > limits.max_encoded_bytes {
        return Err(BatchError::EncodedTooLarge {
            actual: message.len(),
            maximum: limits.max_encoded_bytes,
        });
    }
    Ok(())
}
