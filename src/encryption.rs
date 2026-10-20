//! Independent directional batch ciphers, after the network handshake derives a session key.

use std::fmt;

use bytes::{Bytes, BytesMut};
use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;
use openssl::sha::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::BatchHeader;

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
    /// A RakNet batch has no valid transport marker.
    #[error("invalid encrypted batch transport marker")]
    InvalidBatchHeader,
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
        self.encrypt_from(body, 0)
    }

    /// Encrypts a complete batch while retaining its transport marker and allocation.
    ///
    /// Uses the same ordered stream and failure rules as [`Self::encrypt`].
    /// # Errors
    /// Returns an error for an invalid transport marker or any stream failure.
    pub fn encrypt_batch(
        &mut self,
        header: BatchHeader,
        message: Bytes,
    ) -> Result<Bytes, EncryptionError> {
        let offset = self.0.body_offset(header, &message)?;
        self.encrypt_from(message, offset)
    }

    /// Encrypts the suffix in place, leaving any validated transport prefix untouched.
    fn encrypt_from(&mut self, body: Bytes, offset: usize) -> Result<Bytes, EncryptionError> {
        let next = self.0.next_counter()?;
        if body.len().checked_add(CHECKSUM_BYTES).is_none() {
            return self.0.invalidate(EncryptionError::LengthOverflow);
        }
        let checksum = self.0.checksum(&body[offset..]);
        let mut body = body.try_into_mut().unwrap_or_else(|shared| {
            let mut owned = BytesMut::with_capacity(shared.len() + CHECKSUM_BYTES);
            owned.extend_from_slice(&shared);
            owned
        });
        body.extend_from_slice(&checksum);
        if self.0.apply_keystream(&mut body[offset..]).is_err() {
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
        self.decrypt_from(body, 0)
    }

    /// Decrypts a complete batch while retaining its transport marker and allocation.
    ///
    /// Uses the same ordered stream and failure rules as [`Self::decrypt`].
    /// # Errors
    /// Returns an error for an invalid transport marker or any stream failure.
    pub fn decrypt_batch(
        &mut self,
        header: BatchHeader,
        message: Bytes,
    ) -> Result<Bytes, EncryptionError> {
        let offset = self.0.body_offset(header, &message)?;
        self.decrypt_from(message, offset)
    }

    /// Authenticates the encrypted suffix before returning the original envelope.
    fn decrypt_from(&mut self, body: Bytes, offset: usize) -> Result<Bytes, EncryptionError> {
        let next = self.0.next_counter()?;
        let Some(length) = body.len().checked_sub(offset + CHECKSUM_BYTES) else {
            return self.0.invalidate(EncryptionError::Truncated {
                actual: body.len() - offset,
            });
        };
        let length = length + offset;
        let mut body = body
            .try_into_mut()
            .unwrap_or_else(|shared| shared.as_ref().into());
        if self.0.apply_keystream(&mut body[offset..]).is_err() {
            body.as_mut().zeroize();
            return self.0.invalidate(EncryptionError::KeystreamExhausted);
        }
        let checksum = self.0.checksum(&body[offset..length]);
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
    cipher: CipherCtx,
    blocks: u128,
    partial: usize,
    key: Zeroizing<[u8; 32]>,
    counter: u64,
    invalidated: bool,
}

impl CipherState {
    /// Validates the cleartext transport marker before consuming stream state.
    fn body_offset(
        &mut self,
        header: BatchHeader,
        message: &[u8],
    ) -> Result<usize, EncryptionError> {
        if self.invalidated {
            return Err(EncryptionError::Invalidated);
        }
        match header.marker() {
            Some(marker) if message.first() != Some(&marker) => {
                self.invalidate(EncryptionError::InvalidBatchHeader)
            }
            Some(_) => Ok(1),
            None => Ok(0),
        }
    }

    /// Derives the protocol IV from the session key and starts its continuous stream.
    fn new(key: [u8; 32]) -> Self {
        let key = Zeroizing::new(key);
        let mut iv = Zeroizing::new([0; 16]);
        iv[..12].copy_from_slice(&key[..12]);
        iv[15] = 2;
        let mut cipher = CipherCtx::new().expect("allocate AES-256-CTR context");
        cipher
            .encrypt_init(
                Some(Cipher::aes_256_ctr()),
                Some(key.as_ref()),
                Some(iv.as_ref()),
            )
            .expect("fixed-size AES-256 key and CTR IV");
        Self {
            cipher,
            blocks: 0,
            partial: 0,
            key,
            counter: 0,
            invalidated: false,
        }
    }

    /// Applies the continuous native CTR stream, checking exhaustion before touching plaintext.
    fn apply_keystream(&mut self, body: &mut [u8]) -> Result<(), EncryptionError> {
        let tail = self.partial + body.len() % 16;
        let blocks = self
            .blocks
            .checked_add((body.len() / 16) as u128 + (tail / 16) as u128)
            .ok_or(EncryptionError::KeystreamExhausted)?;
        let partial = tail % 16;
        blocks
            .checked_add(u128::from(partial != 0))
            .ok_or(EncryptionError::KeystreamExhausted)?;
        for chunk in body.chunks_mut(i32::MAX as usize) {
            let length = chunk.len();
            match self.cipher.cipher_update_inplace(chunk, length) {
                Ok(written) if written == length => {}
                _ => return Err(EncryptionError::KeystreamExhausted),
            }
        }
        self.blocks = blocks;
        self.partial = partial;
        Ok(())
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
        hash.update(&self.counter.to_le_bytes());
        hash.update(body);
        hash.update(self.key.as_ref());
        let digest = Zeroizing::new(hash.finish());
        let mut checksum = [0; CHECKSUM_BYTES];
        checksum.copy_from_slice(&digest[..CHECKSUM_BYTES]);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciphers_keep_their_public_thread_and_unwind_traits() {
        /// Checks the original public auto-trait bounds without exposing private state.
        fn traits<T: Send + Sync + std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {}
        traits::<BatchEncryptor>();
        traits::<BatchDecryptor>();
    }

    #[test]
    fn ctr_exhaustion_checks_a_partial_final_block_before_mutation() {
        let mut encryptor = BatchEncryptor::new([9; 32]);
        encryptor.0.blocks = u128::MAX - 1;
        encryptor.0.partial = 15;
        encryptor.0.apply_keystream(&mut [0]).unwrap();
        assert_eq!(encryptor.0.blocks, u128::MAX);
        assert_eq!(encryptor.0.partial, 0);
        assert_eq!(
            encryptor.encrypt(Bytes::new()),
            Err(EncryptionError::KeystreamExhausted)
        );
        assert_eq!(
            encryptor.encrypt(Bytes::new()),
            Err(EncryptionError::Invalidated)
        );
    }

    #[test]
    fn checksum_counter_exhaustion_invalidates_before_advancing_the_stream() {
        let mut encryptor = BatchEncryptor::new([9; 32]);
        encryptor.0.counter = u64::MAX;
        assert_eq!(
            encryptor.encrypt(Bytes::new()),
            Err(EncryptionError::CounterExhausted)
        );
        assert_eq!((encryptor.0.blocks, encryptor.0.partial), (0, 0));
        assert_eq!(
            encryptor.encrypt(Bytes::new()),
            Err(EncryptionError::Invalidated)
        );
    }
}
