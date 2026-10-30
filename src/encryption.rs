//! Independent directional batch ciphers, after the network handshake derives a session key.

use std::fmt;

use aes::cipher::{
    BlockSizeUser, KeyIvInit, StreamCipher, StreamCipherBackend, StreamCipherClosure,
    StreamCipherCore, StreamCipherSeek,
    typenum::{U16, Unsigned},
};
use bytes::{Bytes, BytesMut};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::BatchHeader;

type AesCtr = ctr::Ctr128BE<aes::Aes256Enc>;
type FastAesCtr = ctr::Ctr32BE<aes::Aes256Enc>;

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
    /// A prefixed batch has no valid transport marker.
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

    /// Computes the complete ciphertext length without advancing this stream.
    ///
    /// # Errors
    /// Returns an error if the checksum cannot fit in the payload length.
    pub fn ciphertext_len(&self, plaintext_len: usize) -> Result<usize, EncryptionError> {
        plaintext_len
            .checked_add(CHECKSUM_BYTES)
            .ok_or(EncryptionError::LengthOverflow)
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
        let received = u64::from_le_bytes(
            body[length..]
                .try_into()
                .expect("validated checksum length"),
        );
        if !bool::from(u64::from_le_bytes(checksum).ct_eq(&received)) {
            body.as_mut().zeroize();
            return self.0.invalidate(EncryptionError::InvalidChecksum);
        }
        body.truncate(length);
        self.0.counter = next;
        Ok(body.freeze())
    }
}

/// Reads the selected backend's group size without advancing the CTR stream.
fn parallel_bytes(core: &mut impl StreamCipherCore<BlockSize = U16>) -> usize {
    struct GroupSize<'a>(&'a mut usize);

    impl BlockSizeUser for GroupSize<'_> {
        type BlockSize = U16;
    }

    impl StreamCipherClosure for GroupSize<'_> {
        fn call<B: StreamCipherBackend<BlockSize = U16>>(self, _backend: &mut B) {
            *self.0 = B::ParBlocksSize::USIZE * 16;
        }
    }

    let mut bytes = 16;
    core.process_with_backend(GroupSize(&mut bytes));
    bytes
}

/// Retains unused bytes from parallel AES blocks without exposing them in debug output.
struct KeystreamCache {
    bytes: Zeroizing<Vec<u8>>,
    start: usize,
    end: usize,
}

impl KeystreamCache {
    /// Allocates one group for the stream's selected parallel AES backend.
    fn new(group_bytes: usize) -> Self {
        Self {
            bytes: Zeroizing::new(vec![0; group_bytes]),
            start: 0,
            end: 0,
        }
    }

    /// Applies complete parallel groups and saves the unused tail for the next batch.
    fn apply(
        &mut self,
        cipher: &mut impl StreamCipher,
        body: &mut [u8],
    ) -> Result<(), aes::cipher::StreamCipherError> {
        let cached = self.end - self.start;
        cipher.check_remaining(body.len().saturating_sub(cached))?;
        let head_len = cached.min(body.len());
        let (head, rest) = body.split_at_mut(head_len);
        for (byte, key) in head.iter_mut().zip(&self.bytes[self.start..]) {
            *byte ^= key;
        }
        self.start += head_len;
        if rest.is_empty() {
            return Ok(());
        }
        let group_bytes = self.bytes.len();
        let (groups, tail) = rest.split_at_mut(rest.len() / group_bytes * group_bytes);
        cipher.unchecked_apply_keystream(groups);
        if !tail.is_empty() {
            self.end = if cipher.check_remaining(group_bytes).is_ok() {
                group_bytes
            } else {
                tail.len()
            };
            cipher.unchecked_write_keystream(&mut self.bytes[..self.end]);
            for (byte, key) in tail.iter_mut().zip(self.bytes.iter()) {
                *byte ^= key;
            }
            self.start = tail.len();
        }
        Ok(())
    }
}

impl fmt::Debug for KeystreamCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeystreamCache")
            .finish_non_exhaustive()
    }
}

/// Uses the narrower primitive only while its counter blocks match the full stream.
enum CipherStream {
    Fast {
        cipher: FastAesCtr,
        limit: Zeroizing<u128>,
    },
    Wide(AesCtr),
}

impl CipherStream {
    /// Starts a narrow stream with a protected limit and returns its backend width.
    fn new(key: &[u8; 32], iv: &[u8; 16]) -> (Self, usize) {
        let mut core =
            ctr::CtrCore::<aes::Aes256Enc, ctr::flavors::Ctr32BE>::new_from_slices(key, iv)
                .expect("fixed-size AES-256 key and CTR IV");
        let group_bytes = parallel_bytes(&mut core);
        let low = Zeroizing::new(u32::from_be_bytes(
            iv[12..].try_into().expect("four IV bytes"),
        ));
        // The narrow primitive also excludes its last relative counter block.
        let limit =
            Zeroizing::new(((1_u128 << 32) - u128::from(*low)).min(u128::from(u32::MAX)) * 16);
        (
            Self::Fast {
                cipher: FastAesCtr::from_core(core),
                limit,
            },
            group_bytes,
        )
    }

    /// Promotes before generating a different counter block, retaining cached bytes.
    fn apply(
        &mut self,
        key: &[u8; 32],
        iv: &[u8; 16],
        cache: &mut KeystreamCache,
        body: &mut [u8],
    ) -> Result<(), aes::cipher::StreamCipherError> {
        if let Self::Fast { cipher, limit } = self {
            let needed = body.len().saturating_sub(cache.end - cache.start);
            let group = cache.bytes.len() as u128;
            // Include unused prefetched bytes, which advance the underlying stream too.
            let generated = needed.div_ceil(cache.bytes.len()) as u128 * group;
            let position = cipher.current_pos::<u128>();
            if position + generated > **limit {
                let mut wide =
                    AesCtr::new_from_slices(key, iv).expect("fixed-size AES-256 key and CTR IV");
                wide.try_seek(position)?;
                *self = Self::Wide(wide);
            }
        }
        match self {
            Self::Fast { cipher, .. } => cache.apply(cipher, body),
            Self::Wide(cipher) => cache.apply(cipher, body),
        }
    }
}

/// Derives the protected original protocol IV from the session key.
fn protocol_iv(key: &[u8; 32]) -> Zeroizing<[u8; 16]> {
    let mut iv = Zeroizing::new([0; 16]);
    iv[..12].copy_from_slice(&key[..12]);
    iv[15] = 2;
    iv
}

/// Private state for one stream direction; debug output deliberately excludes secrets.
struct CipherState {
    cipher: CipherStream,
    cache: KeystreamCache,
    key: Zeroizing<[u8; 32]>,
    iv: Zeroizing<[u8; 16]>,
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
        let iv = protocol_iv(&key);
        let (cipher, parallel_bytes) = CipherStream::new(&key, &iv);
        Self {
            cipher,
            cache: KeystreamCache::new(parallel_bytes),
            key,
            iv,
            counter: 0,
            invalidated: false,
        }
    }

    /// Applies the same cached stream to either direction after checking its full length.
    fn apply_keystream(&mut self, body: &mut [u8]) -> Result<(), aes::cipher::StreamCipherError> {
        self.cipher
            .apply(&self.key, &self.iv, &mut self.cache, body)
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
    fn consecutive_decryption_preserves_block_and_checksum_boundaries() {
        for header in [BatchHeader::Prefixed, BatchHeader::NetherNet] {
            let mut encryptor = BatchEncryptor::new([9; 32]);
            let mut decryptor = BatchDecryptor::new([9; 32]);
            let mut reference =
                AesCtr::new_from_slices(&[9; 32], protocol_iv(&[9; 32]).as_ref()).unwrap();
            let lengths = (0..=16)
                .chain(55..=65)
                .chain(128 - 9..=128 + 9)
                .chain(480 - 9..=480 + 9)
                .chain(1024 - 9..=1024 + 9)
                .chain(16 * 1024 - 9..=16 * 1024 + 9)
                .chain(32 * 1024 - 9..=32 * 1024 + 9);
            for length in lengths {
                let mut message = BytesMut::with_capacity(length + 1 + CHECKSUM_BYTES);
                if let Some(marker) = header.marker() {
                    message.extend_from_slice(&[marker]);
                }
                message.extend((0..length).map(|index| index.wrapping_mul(37) as u8));
                let expected = message.to_vec();
                let offset = usize::from(header.marker().is_some());
                let mut reference_message = expected.clone();
                reference_message.extend_from_slice(&encryptor.0.checksum(&expected[offset..]));
                reference
                    .try_apply_keystream(&mut reference_message[offset..])
                    .unwrap();
                let allocation = message.as_ptr();
                let ciphertext = encryptor.encrypt_batch(header, message.freeze()).unwrap();
                assert_eq!(ciphertext, reference_message);
                assert_eq!(ciphertext.as_ptr(), allocation);
                let original = ciphertext.as_ptr();
                let plaintext = decryptor.decrypt_batch(header, ciphertext).unwrap();
                assert_eq!(plaintext, expected, "{header:?}, length {length}");
                assert_eq!(plaintext.as_ptr(), original);
            }
        }
    }

    #[test]
    fn narrow_stream_promotes_at_exact_byte_positions_before_either_counter_limit() {
        let key = [0xff; 32];
        for (low, blocks) in [
            (0, u32::MAX),
            (1, u32::MAX),
            (2, u32::MAX - 1),
            (u32::MAX - 2, 3),
            (u32::MAX, 1),
        ] {
            for high in [[0; 12], [0xff; 12]] {
                let mut iv = [0; 16];
                iv[..12].copy_from_slice(&high);
                iv[12..].copy_from_slice(&low.to_be_bytes());
                let limit = u128::from(blocks) * 16;
                for distance in [1, 15, 16, 17, 1025] {
                    let Some(position) = limit.checked_sub(distance) else {
                        continue;
                    };
                    for group_bytes in [16, 128, 480, 1024] {
                        let (mut stream, _) = CipherStream::new(&key, &iv);
                        let CipherStream::Fast {
                            cipher,
                            limit: bound,
                        } = &mut stream
                        else {
                            panic!("new narrow stream")
                        };
                        assert_eq!(**bound, limit);
                        cipher.try_seek(position).unwrap();
                        let mut cache = KeystreamCache::new(group_bytes);
                        let mut reference = AesCtr::new_from_slices(&key, &iv).unwrap();
                        reference.try_seek(position).unwrap();
                        for length in [0, 1, 7, 16, 33, group_bytes - 1, group_bytes + 2049] {
                            let mut expected = vec![0xa5; length];
                            let mut actual = expected.clone();
                            reference.try_apply_keystream(&mut expected).unwrap();
                            stream.apply(&key, &iv, &mut cache, &mut actual).unwrap();
                            assert_eq!(
                                actual, expected,
                                "high {high:?}, low {low}, position {position}, group {group_bytes}, length {length}"
                            );
                        }
                        assert!(matches!(stream, CipherStream::Wide(_)));
                    }
                }
            }
        }
    }

    #[test]
    fn narrow_stream_budgets_prefetch_and_retains_cached_bytes_during_promotion() {
        let key = [0xff; 32];
        let iv = protocol_iv(&key);
        // This protocol IV is ffffffffffffffff_ffffffff00000002.
        let limit = u128::from(u32::MAX - 1) * 16;
        for distance in [1024, 1023, 17, 1] {
            let position = limit - distance;
            let (mut stream, _) = CipherStream::new(&key, &iv);
            let CipherStream::Fast { cipher, .. } = &mut stream else {
                panic!("new narrow stream")
            };
            cipher.try_seek(position).unwrap();
            let mut cache = KeystreamCache::new(1024);
            let mut reference = AesCtr::new_from_slices(&key, iv.as_ref()).unwrap();
            reference.try_seek(position).unwrap();
            for length in [1, 7, 16, 1001, 1033, 2] {
                let mut actual = vec![0xa5; length];
                let mut expected = actual.clone();
                reference.try_apply_keystream(&mut expected).unwrap();
                stream.apply(&key, &iv, &mut cache, &mut actual).unwrap();
                assert_eq!(actual, expected, "distance {distance}, length {length}");
                if length == 1 {
                    assert_eq!(
                        matches!(stream, CipherStream::Fast { .. }),
                        distance == 1024
                    );
                    assert_eq!(cache.end - cache.start, 1023);
                }
            }
            assert!(matches!(stream, CipherStream::Wide(_)));
        }
    }

    #[test]
    fn decryption_rejects_tampering_across_large_bodies_and_checksums() {
        let mut encryptor = BatchEncryptor::new([9; 32]);
        let ciphertext = encryptor
            .encrypt(vec![0xa5; 32 * 1024 + 17].into())
            .unwrap();
        for index in [0, 16 * 1024 - 1, 16 * 1024, 32 * 1024 - 1, 32 * 1024]
            .into_iter()
            .chain(ciphertext.len() - CHECKSUM_BYTES..ciphertext.len())
        {
            let mut damaged = ciphertext.to_vec();
            damaged[index] ^= 1;
            let mut decryptor = BatchDecryptor::new([9; 32]);
            assert_eq!(
                decryptor.decrypt(damaged.into()),
                Err(EncryptionError::InvalidChecksum),
                "byte {index}"
            );
            assert_eq!(
                decryptor.decrypt(ciphertext.clone()),
                Err(EncryptionError::Invalidated)
            );
        }
    }

    #[test]
    fn cached_decryption_checks_full_capacity_before_mutating_output() {
        use aes::cipher::StreamCipherSeekCore;

        let mut decryptor = BatchDecryptor::new([9; 32]);
        let mut core = ctr::CtrCore::<aes::Aes256Enc, ctr::flavors::Ctr128BE>::new_from_slices(
            &[9; 32], &[0; 16],
        )
        .unwrap();
        core.set_block_pos(u128::MAX - 1025);
        let mut cipher = AesCtr::from_core(core);
        cipher.try_apply_keystream(&mut [0; 15]).unwrap();
        let position = cipher.get_core().get_block_pos();
        decryptor.0.cipher = CipherStream::Wide(cipher);
        let mut ciphertext = vec![0xa5; 16 * 1024 + 2];
        assert!(decryptor.0.apply_keystream(&mut ciphertext).is_err());
        assert!(ciphertext.iter().all(|byte| *byte == 0xa5));
        let CipherStream::Wide(cipher) = &decryptor.0.cipher else {
            panic!("wide stream")
        };
        assert_eq!(cipher.get_core().get_block_pos(), position);
        assert_eq!(
            decryptor.decrypt(ciphertext.into()),
            Err(EncryptionError::KeystreamExhausted)
        );
        assert_eq!(decryptor.0.counter, 0);
        assert_eq!(
            decryptor.decrypt(Bytes::new()),
            Err(EncryptionError::Invalidated)
        );
    }

    #[test]
    fn cached_decryption_uses_exact_remaining_capacity_near_exhaustion() {
        use aes::cipher::StreamCipherSeekCore;

        for group_bytes in [16, 64, 128, 480, 1024] {
            for capacity in [160, group_bytes] {
                let mut core =
                    ctr::CtrCore::<aes::Aes256Enc, ctr::flavors::Ctr128BE>::new_from_slices(
                        &[9; 32], &[0; 16],
                    )
                    .unwrap();
                core.set_block_pos(u128::MAX - (capacity / 16) as u128);
                let mut reference_core =
                    ctr::CtrCore::<aes::Aes256Enc, ctr::flavors::Ctr128BE>::new_from_slices(
                        &[9; 32], &[0; 16],
                    )
                    .unwrap();
                reference_core.set_block_pos(u128::MAX - (capacity / 16) as u128);
                let mut reference = AesCtr::from_core(reference_core);
                let mut cipher = AesCtr::from_core(core);
                let mut cache = KeystreamCache::new(group_bytes);
                for length in [1, capacity / 2, capacity - capacity / 2 - 1] {
                    let mut expected = vec![0xa5; length];
                    let mut actual = expected.clone();
                    reference.try_apply_keystream(&mut expected).unwrap();
                    cache.apply(&mut cipher, &mut actual).unwrap();
                    assert_eq!(actual, expected);
                    if length == 1 {
                        let position = cipher.get_core().get_block_pos();
                        let cached = (cache.start, cache.end);
                        let mut excessive = vec![0xa5; capacity];
                        assert!(cache.apply(&mut cipher, &mut excessive).is_err());
                        assert!(excessive.iter().all(|byte| *byte == 0xa5));
                        assert_eq!(cipher.get_core().get_block_pos(), position);
                        assert_eq!((cache.start, cache.end), cached);
                    }
                }
                let mut byte = [0xa5];
                assert!(cache.apply(&mut cipher, &mut byte).is_err());
                assert_eq!(byte, [0xa5]);
                assert_eq!(cipher.get_core().get_block_pos(), u128::MAX);
            }
        }
    }

    #[test]
    fn ctr_exhaustion_checks_a_partial_final_block_before_mutation() {
        let mut encryptor = BatchEncryptor::new([9; 32]);
        use aes::cipher::StreamCipherSeekCore;
        let mut core = ctr::CtrCore::<aes::Aes256Enc, ctr::flavors::Ctr128BE>::new_from_slices(
            &[9; 32], &[0; 16],
        )
        .unwrap();
        core.set_block_pos(u128::MAX - 1);
        let mut cipher = AesCtr::from_core(core);
        cipher.try_apply_keystream(&mut [0; 15]).unwrap();
        cipher.try_apply_keystream(&mut [0]).unwrap();
        encryptor.0.cipher = CipherStream::Wide(cipher);
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
        let CipherStream::Fast { cipher, .. } = &encryptor.0.cipher else {
            panic!("new stream")
        };
        assert_eq!(cipher.current_pos::<u128>(), 0);
        assert_eq!(
            encryptor.encrypt(Bytes::new()),
            Err(EncryptionError::Invalidated)
        );
    }
}
