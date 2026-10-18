//! Independent directional batch ciphers, after the network handshake derives a session key.

use std::fmt;

use aes::cipher::{KeyIvInit, StreamCipher};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

type AesCtr = ctr::Ctr128BE<aes::Aes256>;

const CHECKSUM_BYTES: usize = 8;

/// A fatal failure of the encrypted batch stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum EncryptionError {
    /// The ciphertext could not contain a complete checksum.
    #[error("encrypted batch has {actual} bytes, requires at least {CHECKSUM_BYTES}")]
    Truncated {
        /// Ciphertext length, excluding any transport marker.
        actual: usize,
    },
    /// Decrypted bytes failed integrity verification.
    #[error("invalid encrypted batch checksum")]
    InvalidChecksum,
    /// The directional stream was already invalidated by a fatal failure.
    #[error("encrypted batch stream is invalidated")]
    Invalidated,
    /// The cipher cannot process more bytes without repeating its keystream.
    #[error("encrypted batch keystream exhausted")]
    KeystreamExhausted,
    /// The checksum sequence counter cannot advance without wrapping.
    #[error("encrypted batch counter exhausted")]
    CounterExhausted,
    /// Adding the checksum would overflow the payload length.
    #[error("encrypted batch length overflow")]
    LengthOverflow,
}

/// Encrypts outgoing compressed batch bodies in their send order.
///
/// One instance belongs to one direction of one session. It cannot be cloned or
/// reset. The session key and expanded cipher key are zeroized on drop.
#[derive(Debug)]
pub struct BatchEncryptor(CipherState);

impl BatchEncryptor {
    /// Starts the outgoing stream using the key derived by the network handshake.
    ///
    /// Never reuse this key to start another session. The caller remains responsible
    /// for erasing any copy of the key it retains.
    pub fn new(key: [u8; 32]) -> Self {
        Self(CipherState::new(key))
    }

    /// Appends the checksum and encrypts one body, excluding the transport marker.
    ///
    /// The input includes the compression marker when compression is enabled.
    /// The caller must retain every returned ciphertext until it is sent, in order;
    /// cancellation must not discard an encoded batch and continue this stream.
    ///
    /// # Errors
    /// Returns an error if the stream is invalidated, its counters are exhausted,
    /// or the checksum cannot be appended. A failure invalidates this direction.
    pub fn encrypt(&mut self, body: Bytes) -> Result<Bytes, EncryptionError> {
        let next = self.0.next_counter()?;
        if body.len().checked_add(CHECKSUM_BYTES).is_none() {
            return self.0.invalidate(EncryptionError::LengthOverflow);
        }
        let checksum = self.0.checksum(&body);
        let mut body = body
            .try_into_mut()
            .unwrap_or_else(|shared| shared.as_ref().into());
        body.extend_from_slice(&checksum);
        if self.0.cipher.try_apply_keystream(&mut body).is_err() {
            body.as_mut().zeroize();
            return self.0.invalidate(EncryptionError::KeystreamExhausted);
        }
        self.0.counter = next;
        Ok(body.freeze())
    }
}

/// Decrypts and authenticates incoming batch bodies in their receive order.
///
/// Verification precedes decompression. A dropped compressed batch still consumes
/// its ciphertext and checksum counter, so use this same instance for the next batch.
#[derive(Debug)]
pub struct BatchDecryptor(CipherState);

impl BatchDecryptor {
    /// Starts the incoming stream using the key derived by the network handshake.
    pub fn new(key: [u8; 32]) -> Self {
        Self(CipherState::new(key))
    }

    /// Decrypts a body without its transport marker and verifies its checksum.
    ///
    /// Successful output excludes the checksum and is ready for decompression.
    /// Checksums are compared in constant time; diagnostics contain no plaintext
    /// or key material. The caller must bound ciphertext length before this call.
    ///
    /// # Errors
    /// Returns an error for short ciphertext, failed integrity verification,
    /// exhausted counters or an invalidated stream. Every failure is fatal for
    /// this direction; later calls return [`EncryptionError::Invalidated`].
    pub fn decrypt(&mut self, body: Bytes) -> Result<Bytes, EncryptionError> {
        let next = self.0.next_counter()?;
        let Some(length) = body.len().checked_sub(CHECKSUM_BYTES) else {
            return self
                .0
                .invalidate(EncryptionError::Truncated { actual: body.len() });
        };
        let mut body = body
            .try_into_mut()
            .unwrap_or_else(|shared| shared.as_ref().into());
        if self.0.cipher.try_apply_keystream(&mut body).is_err() {
            body.as_mut().zeroize();
            return self.0.invalidate(EncryptionError::KeystreamExhausted);
        }
        let checksum = self.0.checksum(&body[..length]);
        if !bool::from(checksum.ct_eq(&body[length..])) {
            body.as_mut().zeroize();
            return self.0.invalidate(EncryptionError::InvalidChecksum);
        }
        body.truncate(length);
        self.0.counter = next;
        Ok(body.freeze())
    }
}

/// Private state for one stream direction; debug output deliberately excludes secrets.
struct CipherState {
    cipher: AesCtr,
    key: Zeroizing<[u8; 32]>,
    counter: u64,
    invalidated: bool,
}

impl CipherState {
    /// Derives the protocol IV from the session key and starts its continuous stream.
    fn new(key: [u8; 32]) -> Self {
        let key = Zeroizing::new(key);
        let mut iv = Zeroizing::new([0; 16]);
        iv[..12].copy_from_slice(&key[..12]);
        iv[15] = 2;
        let cipher = AesCtr::new_from_slices(key.as_ref(), iv.as_ref())
            .expect("fixed-size AES-256 key and CTR IV");
        Self {
            cipher,
            key,
            counter: 0,
            invalidated: false,
        }
    }

    /// Checks that the direction can advance before mutating cipher state.
    fn next_counter(&mut self) -> Result<u64, EncryptionError> {
        if self.invalidated {
            return Err(EncryptionError::Invalidated);
        }
        match self.counter.checked_add(1) {
            Some(next) => Ok(next),
            None => self.invalidate(EncryptionError::CounterExhausted),
        }
    }

    /// Computes the checksum for this direction's next batch.
    fn checksum(&self, body: &[u8]) -> [u8; CHECKSUM_BYTES] {
        let mut hash = Sha256::new();
        hash.update(self.counter.to_le_bytes());
        hash.update(body);
        hash.update(self.key.as_ref());
        let mut digest = hash.finalize();
        let mut checksum = [0; CHECKSUM_BYTES];
        checksum.copy_from_slice(&digest[..CHECKSUM_BYTES]);
        digest.as_mut_slice().zeroize();
        checksum
    }

    /// Prevents reuse after any fatal encryption failure.
    fn invalidate<T>(&mut self, error: EncryptionError) -> Result<T, EncryptionError> {
        self.invalidated = true;
        Err(error)
    }
}

impl fmt::Debug for CipherState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CipherState")
            .field("counter", &self.counter)
            .field("invalidated", &self.invalidated)
            .finish_non_exhaustive()
    }
}
