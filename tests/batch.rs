//! Behavioral checks for batch compatibility and untrusted framing.

use bedrock_net::encryption::{BatchDecryptor, BatchEncryptor, EncryptionError};
use bedrock_net::{
    BatchCodec, BatchError, BatchHeader, BatchLimits, BatchPhase, CompressionAlgorithm,
    CompressionSettings, DecodeOutcome, DropReason, Negotiated, VisitOutcome,
};
use bytes::Bytes;

#[path = "fixtures/go_batches.rs"]
mod go;

/// Builds a codec after compression negotiation, using the supplied safety policy.
fn negotiated(algorithm: CompressionAlgorithm, limits: BatchLimits) -> BatchCodec<Negotiated> {
    BatchCodec::new(BatchHeader::RakNet, limits).negotiate(CompressionSettings {
        algorithm,
        threshold: 0,
    })
}

/// Extracts the packets, failing the test if a batch unexpectedly drops.
fn packets<S: BatchPhase>(codec: &BatchCodec<S>, wire: Bytes) -> Vec<Bytes> {
    match codec.decode(wire).unwrap() {
        DecodeOutcome::Packets { packets, .. } => packets.collect(),
        DecodeOutcome::Dropped(reason) => panic!("unexpected dropped batch: {reason}"),
    }
}

#[test]
fn decodes_go_vectors_by_declared_algorithm() {
    let expected = [
        Bytes::from_static(&[2, 0, 0, 0, 0]),
        Bytes::from_static(&[9, 3, b'h', b'e', b'y']),
    ];
    // The negotiated outgoing algorithm must not restrict incoming algorithms.
    let codec = negotiated(CompressionAlgorithm::Deflate, BatchLimits::default());
    for wire in [go::GO_BATCH_0, go::GO_BATCH_1, go::GO_BATCH_65535] {
        assert_eq!(packets(&codec, Bytes::from_static(wire)), expected);
    }
}

#[test]
fn client_empty_entries_preserve_packets() {
    let codec = negotiated(
        CompressionAlgorithm::Deflate,
        BatchLimits {
            max_packets: 2,
            max_incoming_packets: None,
            ..BatchLimits::default()
        },
    );
    let expected = [
        Bytes::from_static(&[2, 0, 0, 0, 0]),
        Bytes::from_static(&[9, 3, b'h', b'e', b'y']),
    ];
    for wire in [
        go::GO_BATCH_EMPTY_0,
        go::GO_BATCH_EMPTY_1,
        go::GO_BATCH_EMPTY_65535,
    ] {
        let DecodeOutcome::Packets {
            packets,
            skipped_empty_packets,
            ..
        } = codec.decode(Bytes::from_static(wire)).unwrap()
        else {
            panic!("empty-entry fixture was dropped");
        };
        assert_eq!(packets.collect::<Vec<_>>(), expected);
        assert_eq!(skipped_empty_packets, 3);
    }
    let initial = BatchCodec::new(
        BatchHeader::RakNet,
        BatchLimits {
            max_packets: 0,
            max_incoming_packets: None,
            ..BatchLimits::default()
        },
    );
    let DecodeOutcome::Packets {
        packets,
        skipped_empty_packets,
        ..
    } = initial.decode(Bytes::from_static(&[0xfe, 0, 0])).unwrap()
    else {
        panic!("initial empty-entry batch was dropped");
    };
    assert!(packets.is_empty());
    assert_eq!(skipped_empty_packets, 2);
    assert!(matches!(
        codec.encode(&[Bytes::new()]),
        Err(BatchError::EmptyPacket)
    ));
}

#[test]
fn negotiation_changes_headers_and_compresses_at_threshold_equality() {
    let input = [Bytes::from_static(&[2, 0, 0, 0, 0])];
    for header in [BatchHeader::RakNet, BatchHeader::NetherNet] {
        let codec = BatchCodec::new(header, BatchLimits::default());
        let marker = usize::from(header == BatchHeader::RakNet);
        let initial = codec.encode(&input).unwrap().pop().unwrap();
        assert_eq!(&initial[marker..], &[5, 2, 0, 0, 0, 0]);
        assert_eq!(packets(&codec, initial), input);

        let codec = codec.negotiate(CompressionSettings {
            algorithm: CompressionAlgorithm::Deflate,
            threshold: 7,
        });
        let below = codec.encode(&input).unwrap().pop().unwrap();
        assert_eq!(below[marker], 0xff);
        assert_eq!(packets(&codec, below), input);

        let codec =
            BatchCodec::new(header, BatchLimits::default()).negotiate(CompressionSettings {
                algorithm: CompressionAlgorithm::Deflate,
                threshold: 6,
            });
        let at = codec.encode(&input).unwrap().pop().unwrap();
        assert_eq!(at[marker], CompressionAlgorithm::Deflate.network_id() as u8);
        assert_eq!(packets(&codec, at), input);
    }
}

#[test]
fn splits_count_and_byte_limited_batches_without_reordering() {
    for limits in [
        BatchLimits::default(),
        BatchLimits {
            max_packets: 7,
            max_decoded_bytes: 29,
            ..BatchLimits::default()
        },
    ] {
        let input: Vec<_> = (0..BatchLimits::default().max_packets * 2 + 1)
            .map(|index| Bytes::from(index.to_le_bytes().to_vec()))
            .collect();
        for algorithm in [CompressionAlgorithm::Deflate, CompressionAlgorithm::Snappy] {
            let codec = negotiated(algorithm, limits);
            let batches = codec.encode(&input).unwrap();
            assert!(batches.len() >= 3);
            let mut received = Vec::new();
            for batch in batches {
                let batch = packets(&codec, batch);
                assert!(batch.len() <= limits.max_packets);
                received.extend(batch);
            }
            assert_eq!(received, input);
        }
    }
}

#[test]
fn client_batch_count_accepts_a_server_batch_above_the_outgoing_ceiling() {
    let outgoing = BatchLimits::default();
    let input: Vec<_> = (0..outgoing.max_packets + 1)
        .map(|index| Bytes::from(index.to_le_bytes().to_vec()))
        .collect();
    let incoming = BatchLimits {
        max_packets: input.len(),
        ..outgoing
    };
    for header in [BatchHeader::RakNet, BatchHeader::NetherNet] {
        let client = BatchCodec::new(header, outgoing);
        let split = client.encode(&input).unwrap();
        assert_eq!(split.len(), 2);
        assert_eq!(
            packets(&client, split[0].clone()).len(),
            outgoing.max_packets
        );
        assert_eq!(
            packets(&client, split[1].clone()),
            input[outgoing.max_packets..]
        );

        let mut original = BatchCodec::new(header, incoming).encode(&input).unwrap();
        assert_eq!(original.len(), 1);
        assert!(original[0].len() < outgoing.max_decoded_bytes);
        assert_eq!(packets(&client, original.remove(0)), input);
    }
}

#[test]
fn client_batch_count_preserves_declared_compression_and_decoded_byte_limits() {
    let outgoing = BatchLimits::default();
    let input: Vec<_> = (0..outgoing.max_packets + 1)
        .map(|index| Bytes::from(index.to_le_bytes().to_vec()))
        .collect();
    let incoming = BatchLimits {
        max_packets: input.len(),
        ..outgoing
    };
    let body = BatchCodec::new(BatchHeader::NetherNet, incoming)
        .encode(&input)
        .unwrap()
        .pop()
        .unwrap();
    for algorithm in [
        CompressionAlgorithm::Deflate,
        CompressionAlgorithm::Snappy,
        CompressionAlgorithm::None,
    ] {
        let mut original = negotiated(algorithm, incoming).encode(&input).unwrap();
        assert_eq!(original.len(), 1);
        let original = original.remove(0);
        let bounded = negotiated(
            CompressionAlgorithm::Deflate,
            BatchLimits {
                max_decoded_bytes: body.len() - 1,
                ..outgoing
            },
        );
        assert!(matches!(
            bounded.decode(original.clone()),
            Err(BatchError::DecodedTooLarge { .. })
        ));
        let client = negotiated(CompressionAlgorithm::Deflate, outgoing);
        assert_eq!(packets(&client, original), input);
    }
}

#[test]
fn malformed_tail_never_exposes_a_partial_batch() {
    let codec = BatchCodec::new(BatchHeader::RakNet, BatchLimits::default());
    for tail in [
        &[0, 0x80][..],
        &[3, 2][..],
        &[0x80][..],
        &[0xff, 0xff, 0xff, 0xff, 0x10][..],
        &[0xff, 0xff, 0xff, 0xff, 0x8f, 0][..],
    ] {
        let mut batch = vec![0xfe, 1, 2]; // One valid packet before the malformed entry.
        batch.extend_from_slice(tail);
        assert!(codec.decode(Bytes::from(batch)).is_err());
    }
    let codec = BatchCodec::new(
        BatchHeader::RakNet,
        BatchLimits {
            max_packets: 1,
            max_incoming_packets: Some(1),
            ..BatchLimits::default()
        },
    );
    assert!(matches!(
        codec.decode(Bytes::from_static(&[0xfe, 1, 2, 1, 3])),
        Err(BatchError::TooManyPackets { maximum: 1 })
    ));
}

#[test]
fn compressed_failures_drop_but_missing_headers_and_framing_are_fatal() {
    let codec = negotiated(CompressionAlgorithm::Deflate, BatchLimits::default());
    for wire in [
        &[0xfe, 2][..],
        &[0xfe, 0, 0xff, 0xff, 0xff][..],
        &[0xfe, 0][..],
        &[0xfe, 1, 0x80][..],
    ] {
        assert!(matches!(
            codec.decode(Bytes::copy_from_slice(wire)).unwrap(),
            DecodeOutcome::Dropped(_)
        ));
        assert_eq!(packets(&codec, Bytes::from_static(go::GO_BATCH_0)).len(), 2);
    }
    assert!(matches!(
        codec.decode(Bytes::from_static(&[0xfe, 2])),
        Ok(DecodeOutcome::Dropped(DropReason::UnknownCompression(2)))
    ));
    assert!(matches!(
        codec.decode(Bytes::from_static(&[0xfe])),
        Err(BatchError::MissingCompressionHeader)
    ));
    assert!(matches!(
        codec.decode(Bytes::from_static(&[0xfe, 0xff, 3, 2])),
        Err(BatchError::TruncatedPacket { .. })
    ));
}

#[test]
fn decoded_limits_are_fatal_for_every_algorithm_and_accept_exact_boundary() {
    let input = [Bytes::from(vec![2; 8192])];
    // This packet's length prefix takes two bytes.
    let decoded_len = input[0].len() + 2;
    for algorithm in [
        CompressionAlgorithm::Deflate,
        CompressionAlgorithm::Snappy,
        CompressionAlgorithm::None,
    ] {
        let sender = negotiated(algorithm, BatchLimits::default());
        let wire = sender.encode(&input).unwrap().pop().unwrap();
        let at = negotiated(
            algorithm,
            BatchLimits {
                max_decoded_bytes: decoded_len,
                ..BatchLimits::default()
            },
        );
        assert_eq!(packets(&at, wire.clone()), input);
        let below = negotiated(
            algorithm,
            BatchLimits {
                max_decoded_bytes: decoded_len - 1,
                ..BatchLimits::default()
            },
        );
        assert!(matches!(
            below.decode(wire),
            Err(BatchError::DecodedTooLarge { .. })
        ));
    }
}

#[test]
fn oversized_deflate_with_a_corrupt_tail_is_still_fatal() {
    // A non-final stored block expands before an invalid block type is reached.
    let mut wire = vec![0xfe, 0, 0, 20, 0, 0xeb, 0xff];
    wire.extend_from_slice(&[2; 20]);
    wire.push(7);
    let codec = negotiated(
        CompressionAlgorithm::Deflate,
        BatchLimits {
            max_decoded_bytes: 4,
            ..BatchLimits::default()
        },
    );
    assert!(matches!(
        codec.decode(Bytes::from(wire)),
        Err(BatchError::DecodedTooLarge { maximum: 4 })
    ));
}

#[test]
fn wire_limits_apply_before_decompression_and_outgoing_delivery() {
    let codec = negotiated(
        CompressionAlgorithm::None,
        BatchLimits {
            max_encoded_bytes: 2,
            ..BatchLimits::default()
        },
    );
    assert!(matches!(
        codec.decode(Bytes::from_static(&[0xfe, 0, 0xff])),
        Err(BatchError::EncodedTooLarge { .. })
    ));
    assert!(matches!(
        codec.encode(&[Bytes::from_static(&[2])]),
        Err(BatchError::EncodedTooLarge { .. })
    ));
}

#[test]
fn directional_encryption_matches_consecutive_go_batches_byte_for_byte() {
    let key = std::array::from_fn(|index| u8::try_from(index).unwrap());
    let mut encryptor = BatchEncryptor::new(key);
    let mut decryptor = BatchDecryptor::new(key);
    let plaintext = Bytes::from_static(&go::GO_BATCH_65535[1..]);
    for wire in [go::GO_ENCRYPTED_0, go::GO_ENCRYPTED_1, go::GO_ENCRYPTED_2] {
        let encrypted = encryptor.encrypt(plaintext.clone()).unwrap();
        assert_eq!(encrypted, &wire[1..]);
        assert_eq!(decryptor.decrypt(encrypted).unwrap(), plaintext);
    }
    // The opposite direction starts independently, even after outgoing traffic.
    let mut opposite = BatchEncryptor::new(key);
    assert_eq!(
        opposite.encrypt(plaintext).unwrap(),
        &go::GO_ENCRYPTED_0[1..]
    );
}

#[test]
fn discarded_compression_still_advances_the_encrypted_stream() {
    let mut encryptor = BatchEncryptor::new([7; 32]);
    let mut decryptor = BatchDecryptor::new([7; 32]);
    let codec = BatchCodec::new(BatchHeader::NetherNet, BatchLimits::default()).negotiate(
        CompressionSettings {
            algorithm: CompressionAlgorithm::Deflate,
            threshold: 0,
        },
    );
    let bad = encryptor.encrypt(Bytes::from_static(&[2])).unwrap();
    let body = decryptor.decrypt(bad).unwrap();
    assert!(matches!(
        codec.decode(body),
        Ok(DecodeOutcome::Dropped(DropReason::UnknownCompression(2)))
    ));
    let good = encryptor
        .encrypt(Bytes::from_static(&go::GO_BATCH_65535[1..]))
        .unwrap();
    assert_eq!(packets(&codec, decryptor.decrypt(good).unwrap()).len(), 2);
}

#[test]
fn integrity_and_truncation_failures_permanently_invalidate_the_direction() {
    for truncate in [false, true] {
        let mut encryptor = BatchEncryptor::new([9; 32]);
        let mut decryptor = BatchDecryptor::new([9; 32]);
        let mut encrypted = encryptor
            .encrypt(Bytes::from_static(b"synthetic packet body"))
            .unwrap()
            .to_vec();
        if truncate {
            encrypted.truncate(7);
        } else {
            encrypted[0] ^= 1;
        }
        let error = decryptor.decrypt(Bytes::from(encrypted)).unwrap_err();
        if truncate {
            assert_eq!(error, EncryptionError::Truncated { actual: 7 });
        } else {
            assert_eq!(error, EncryptionError::InvalidChecksum);
        }
        let subsequent = encryptor.encrypt(Bytes::from_static(b"next body")).unwrap();
        assert_eq!(
            decryptor.decrypt(subsequent).unwrap_err(),
            EncryptionError::Invalidated
        );
    }
}

#[test]
fn incoming_cursor_validates_full_body_and_explicit_count_before_exposure() {
    let limits = BatchLimits::default();
    let count = limits.max_packets + 1;
    let input: Vec<_> = (0..count)
        .map(|index| Bytes::from(index.to_le_bytes().to_vec()))
        .collect();
    let wire = BatchCodec::new(
        BatchHeader::RakNet,
        BatchLimits {
            max_packets: count,
            ..limits
        },
    )
    .encode(&input)
    .unwrap()
    .remove(0);
    for maximum in [None, Some(count)] {
        let client = BatchCodec::new(
            BatchHeader::RakNet,
            BatchLimits {
                max_packets: 1,
                max_incoming_packets: maximum,
                ..limits
            },
        );
        let DecodeOutcome::Packets { packets, .. } = client.decode(wire.clone()).unwrap() else {
            panic!("valid cursor batch was dropped");
        };
        assert_eq!(packets.len(), count);
        assert!(packets.eq(input.iter().cloned()));
    }
    for maximum in [0, count - 1] {
        let client = BatchCodec::new(
            BatchHeader::RakNet,
            BatchLimits {
                max_incoming_packets: Some(maximum),
                ..limits
            },
        );
        assert!(matches!(
            client.decode(wire.clone()),
            Err(BatchError::TooManyPackets { maximum: actual }) if actual == maximum
        ));
    }
    let mut malformed = wire.to_vec();
    malformed.push(0x80);
    assert!(matches!(
        BatchCodec::new(BatchHeader::RakNet, limits).decode(Bytes::from(malformed)),
        Err(BatchError::InvalidPacketLength { .. })
    ));
}

#[test]
fn incoming_cursor_retains_unread_bytes_and_releases_them_on_drop_or_exhaustion() {
    let limits = BatchLimits::default();
    let count = limits.max_packets * 8 + 1;
    let input: Vec<_> = (0..count)
        .map(|index| Bytes::from(index.to_le_bytes().to_vec()))
        .collect();
    let wire = BatchCodec::new(
        BatchHeader::RakNet,
        BatchLimits {
            max_packets: count,
            ..limits
        },
    )
    .encode(&input)
    .unwrap()
    .remove(0);
    for finish in [false, true] {
        let owner: std::sync::Arc<[u8]> = wire.as_ref().into();
        let lifetime = std::sync::Arc::downgrade(&owner);
        let DecodeOutcome::Packets { mut packets, .. } =
            BatchCodec::new(BatchHeader::RakNet, limits)
                .decode(Bytes::from_owner(owner))
                .unwrap()
        else {
            panic!("owned cursor batch was dropped");
        };
        assert_eq!(packets.size_hint(), (count, Some(count)));
        let first = packets.next().unwrap();
        assert_eq!(first, input[0]);
        assert_eq!(packets.len(), count - 1);
        if finish {
            drop(first);
            for (index, expected) in input.iter().enumerate().skip(1) {
                let packet = packets.next().unwrap();
                assert_eq!(&packet, expected);
                assert_eq!(packets.len(), count - index - 1);
            }
            assert!(packets.is_empty());
            assert!(packets.next().is_none());
            assert!(lifetime.upgrade().is_none());
        } else {
            drop(packets);
            assert!(lifetime.upgrade().is_some());
            drop(first);
            assert!(lifetime.upgrade().is_none());
        }
    }
}

#[test]
fn negotiated_incoming_decoded_limit_preserves_defaults_and_output_policy() {
    let limits = BatchLimits {
        max_decoded_bytes: 8,
        max_encoded_bytes: 128,
        max_packets: 2,
        ..BatchLimits::default()
    };
    let input = [Bytes::from_static(&[2; 9])];
    // One byte of length framing is part of the decoded ceiling.
    let decoded_len = input[0].len() + 1;
    for header in [BatchHeader::RakNet, BatchHeader::NetherNet] {
        let plain = BatchCodec::new(header, limits);
        let initial = BatchCodec::new(
            header,
            BatchLimits {
                max_decoded_bytes: decoded_len,
                ..limits
            },
        )
        .encode(&input)
        .unwrap()
        .remove(0);
        assert!(matches!(
            plain.decode(initial),
            Err(BatchError::DecodedTooLarge { maximum: 8 })
        ));
        for algorithm in [
            CompressionAlgorithm::Deflate,
            CompressionAlgorithm::Snappy,
            CompressionAlgorithm::None,
        ] {
            let settings = CompressionSettings {
                algorithm,
                threshold: 0,
            };
            let wire = BatchCodec::new(
                header,
                BatchLimits {
                    max_decoded_bytes: decoded_len,
                    ..limits
                },
            )
            .negotiate(settings)
            .encode(&input)
            .unwrap()
            .remove(0);
            let original = BatchCodec::new(header, limits).negotiate(settings);
            assert!(matches!(
                original.decode(wire.clone()),
                Err(BatchError::DecodedTooLarge { maximum: 8 })
            ));
            let at = BatchCodec::new(header, limits)
                .negotiate(settings)
                .with_incoming_decoded_limit(decoded_len);
            assert_eq!(packets(&at, wire.clone()), input);
            assert!(matches!(
                at.encode(&input),
                Err(BatchError::DecodedTooLarge { maximum: 8 })
            ));
            let below = BatchCodec::new(header, limits)
                .negotiate(settings)
                .with_incoming_decoded_limit(decoded_len - 1);
            assert!(matches!(
                below.decode(wire),
                Err(BatchError::DecodedTooLarge { maximum }) if maximum == decoded_len - 1
            ));
            let outgoing: [Bytes; 3] = std::array::from_fn(|_| Bytes::from_static(&[2; 3]));
            let original_batches = original.encode(&outgoing).unwrap();
            assert_eq!(original_batches.len(), 2);
            assert_eq!(at.encode(&outgoing).unwrap(), original_batches);
        }
    }
}

#[test]
fn negotiated_incoming_decoded_limit_keeps_wire_count_and_framing_validation() {
    let limits = BatchLimits {
        max_decoded_bytes: 8,
        max_encoded_bytes: 128,
        max_incoming_packets: Some(1),
        ..BatchLimits::default()
    };
    let input: [Bytes; 2] = std::array::from_fn(|_| Bytes::from_static(&[2; 4]));
    let wire = negotiated(
        CompressionAlgorithm::None,
        BatchLimits {
            max_decoded_bytes: 10,
            ..limits
        },
    )
    .encode(&input)
    .unwrap()
    .remove(0);
    let counted = negotiated(CompressionAlgorithm::None, limits).with_incoming_decoded_limit(10);
    assert!(matches!(
        counted.decode(wire.clone()),
        Err(BatchError::TooManyPackets { maximum: 1 })
    ));
    let bounded_wire = negotiated(
        CompressionAlgorithm::None,
        BatchLimits {
            max_encoded_bytes: wire.len() - 1,
            ..limits
        },
    )
    .with_incoming_decoded_limit(10);
    assert!(matches!(
        bounded_wire.decode(wire.clone()),
        Err(BatchError::EncodedTooLarge { .. })
    ));
    let mut malformed = wire.to_vec();
    malformed.push(0x80);
    let validated = negotiated(
        CompressionAlgorithm::None,
        BatchLimits {
            max_incoming_packets: None,
            ..limits
        },
    )
    .with_incoming_decoded_limit(11);
    assert!(matches!(
        validated.decode(Bytes::from(malformed)),
        Err(BatchError::InvalidPacketLength { .. })
    ));
    let zero = negotiated(CompressionAlgorithm::None, limits).with_incoming_decoded_limit(0);
    assert!(matches!(
        zero.decode(wire.clone()),
        Err(BatchError::DecodedTooLarge { maximum: 0 })
    ));
    // The actual encoded envelope without any body remains a valid empty batch.
    assert!(packets(&zero, wire.slice(..2)).is_empty());
}

#[test]
fn framing_regression_matches_directional_empty_and_overflow_lengths() {
    for maximum in [0, 1, 1600] {
        let accepting = BatchCodec::new(
            BatchHeader::RakNet,
            BatchLimits {
                max_incoming_packets: Some(maximum),
                ..BatchLimits::default()
            },
        );
        assert!(matches!(
            accepting.decode(Bytes::from_static(&[0xfe, 0])),
            Err(BatchError::EmptyPacket)
        ));
    }
    let client = BatchCodec::new(BatchHeader::RakNet, BatchLimits::default());
    for fifth in [0x10, 0x20, 0x70] {
        let batch = Bytes::from(vec![0xfe, 0x81, 0x80, 0x80, 0x80, fifth, 2, 1, 3]);
        assert_eq!(
            packets(&client, batch),
            [Bytes::from_static(&[2]), Bytes::from_static(&[3])]
        );
    }
    assert!(matches!(
        client.decode(Bytes::from_static(&[0xfe, 0x81, 0x80, 0x80, 0x80, 0x80])),
        Err(BatchError::InvalidPacketLength { .. })
    ));
}

#[test]
fn negotiated_codec_keeps_const_construction_and_thread_safety() {
    /// Requires the public codec to keep its original thread-safety bounds.
    fn assert_send_sync<T: Send + Sync>(_: &T) {}
    let codec = const {
        BatchCodec::new(
            BatchHeader::RakNet,
            BatchLimits {
                max_encoded_bytes: 1024,
                max_decoded_bytes: 1024,
                max_packets: 10,
                max_incoming_packets: None,
            },
        )
        .negotiate(CompressionSettings {
            algorithm: CompressionAlgorithm::Deflate,
            threshold: 0,
        })
        .with_incoming_decoded_limit(2048)
    };
    assert_send_sync(&codec);
    let input = [Bytes::from_static(b"constant codec")];
    assert_eq!(
        packets(&codec, codec.encode(&input).unwrap().pop().unwrap()),
        input
    );
}

#[test]
fn encoder_writes_the_same_packet_view_it_validated() {
    struct ChangingPacket {
        reads: std::cell::Cell<usize>,
    }
    impl AsRef<[u8]> for ChangingPacket {
        /// Supplies a different safe view on each call to catch repeated packet resolution.
        fn as_ref(&self) -> &[u8] {
            let reads = self.reads.replace(self.reads.get() + 1);
            if reads == 0 { b"first" } else { b"" }
        }
    }
    for algorithm in [
        CompressionAlgorithm::None,
        CompressionAlgorithm::Deflate,
        CompressionAlgorithm::Snappy,
    ] {
        let codec = negotiated(algorithm, BatchLimits::default());
        let input = [ChangingPacket {
            reads: std::cell::Cell::new(0),
        }];
        let wire = codec.encode(&input).unwrap().pop().unwrap();
        assert_eq!(input[0].reads.get(), 1);
        assert_eq!(packets(&codec, wire), [Bytes::from_static(b"first")]);
    }
}

#[test]
fn encoding_reuses_only_consumed_unique_buffers_and_clears_failed_output() {
    let codec = BatchCodec::new(
        BatchHeader::RakNet,
        BatchLimits {
            max_packets: 1,
            ..BatchLimits::default()
        },
    );
    let input = [vec![0x42; 1 << 20], vec![0x43; 1 << 20]];
    let mut output = codec.encode(&input).unwrap();
    let pointers: Vec<_> = output.iter().map(|batch| batch.as_ptr()).collect();
    codec.encode_into(&input, &mut output).unwrap();
    assert_eq!(
        output
            .iter()
            .map(|batch| batch.as_ptr())
            .collect::<Vec<_>>(),
        pointers
    );
    let retained = output[0].clone();
    let original = retained.to_vec();
    codec.encode_into(&[vec![7; 1024]], &mut output).unwrap();
    assert_eq!(retained, original);
    assert_ne!(output[0].as_ptr(), retained.as_ptr());
    assert!(
        codec
            .encode_into(&[b"valid".as_slice(), b""], &mut output)
            .is_err()
    );
    assert!(output.is_empty());
}

#[test]
fn complete_batch_encryption_keeps_owned_storage_and_matches_go() {
    let key = std::array::from_fn(|index| u8::try_from(index).unwrap());
    for header in [BatchHeader::RakNet, BatchHeader::NetherNet] {
        let offset = usize::from(header == BatchHeader::NetherNet);
        let mut encryptor = BatchEncryptor::new(key);
        let mut decryptor = BatchDecryptor::new(key);
        for expected in [go::GO_ENCRYPTED_0, go::GO_ENCRYPTED_1, go::GO_ENCRYPTED_2] {
            let mut storage = Vec::with_capacity(go::GO_BATCH_65535.len() + 8);
            storage.extend_from_slice(&go::GO_BATCH_65535[offset..]);
            let original = storage.as_ptr();
            let encrypted = encryptor.encrypt_batch(header, storage.into()).unwrap();
            assert_eq!(encrypted.as_ptr(), original);
            assert_eq!(encrypted, &expected[offset..]);
            let decrypted = decryptor.decrypt_batch(header, encrypted).unwrap();
            assert_eq!(decrypted.as_ptr(), original);
            assert_eq!(decrypted, &go::GO_BATCH_65535[offset..]);
        }
    }
}

#[test]
fn encoded_batch_reserves_checksum_space_and_shared_encryption_preserves_input() {
    for header in [BatchHeader::RakNet, BatchHeader::NetherNet] {
        for algorithm in [
            CompressionAlgorithm::None,
            CompressionAlgorithm::Deflate,
            CompressionAlgorithm::Snappy,
        ] {
            let codec =
                BatchCodec::new(header, BatchLimits::default()).negotiate(CompressionSettings {
                    algorithm,
                    threshold: 0,
                });
            let input = [vec![0x42; 32768]];
            let message = codec.encode(&input).unwrap().pop().unwrap();
            let original = message.as_ptr();
            let mut encryptor = BatchEncryptor::new([9; 32]);
            let encrypted = encryptor.encrypt_batch(header, message).unwrap();
            assert_eq!(encrypted.as_ptr(), original, "{header:?} {algorithm:?}");
            let shared = encrypted.clone();
            let mut decryptor = BatchDecryptor::new([9; 32]);
            let decrypted = decryptor.decrypt_batch(header, encrypted).unwrap();
            assert_ne!(decrypted.as_ptr(), shared.as_ptr());
            assert_eq!(packets(&codec, decrypted), input);
            let mut another = BatchDecryptor::new([9; 32]);
            assert_eq!(
                packets(&codec, another.decrypt_batch(header, shared).unwrap()),
                input
            );
        }
    }
}

#[test]
fn complete_batch_crypto_checks_marker_and_invalidates_on_failure() {
    for message in [Bytes::new(), Bytes::from_static(&[0xfd, 0xff])] {
        let mut encryptor = BatchEncryptor::new([9; 32]);
        let mut decryptor = BatchDecryptor::new([9; 32]);
        assert_eq!(
            encryptor.encrypt_batch(BatchHeader::RakNet, message.clone()),
            Err(EncryptionError::InvalidBatchHeader)
        );
        assert_eq!(
            decryptor.decrypt_batch(BatchHeader::RakNet, message),
            Err(EncryptionError::InvalidBatchHeader)
        );
        assert_eq!(
            encryptor.encrypt(Bytes::new()),
            Err(EncryptionError::Invalidated)
        );
        assert_eq!(
            decryptor.decrypt(Bytes::new()),
            Err(EncryptionError::Invalidated)
        );
    }
    let mut decryptor = BatchDecryptor::new([9; 32]);
    assert_eq!(
        decryptor.decrypt_batch(BatchHeader::RakNet, Bytes::from_static(&[0xfe])),
        Err(EncryptionError::Truncated { actual: 0 })
    );
}

#[test]
fn synchronous_snappy_decode_reuses_scratch_and_validates_before_visiting() {
    let mut codec = negotiated(CompressionAlgorithm::Snappy, BatchLimits::default());
    let wire = codec.encode(&[vec![0x42; 4096]]).unwrap().pop().unwrap();
    let mut pointers = Vec::new();
    for _ in 0..2 {
        let outcome = codec
            .decode_with(wire.clone(), |packet| {
                assert_eq!(packet, vec![0x42; 4096]);
                pointers.push(packet.as_ptr());
            })
            .unwrap();
        assert!(matches!(
            outcome,
            VisitOutcome::Packets {
                count: 1,
                skipped_empty_packets: 0
            }
        ));
    }
    assert_eq!(pointers[0], pointers[1]);
    assert!(!format!("{codec:?}").contains("66, 66, 66"));
    for maximum in [None, Some(1)] {
        let mut codec = negotiated(
            CompressionAlgorithm::Snappy,
            BatchLimits {
                max_incoming_packets: maximum,
                ..BatchLimits::default()
            },
        );
        let mut visits = 0;
        let mut wire = vec![0xfe, 1];
        wire.extend(
            snap::raw::Encoder::new()
                .compress_vec(&[0, 1, 7, 0])
                .unwrap(),
        );
        match codec.decode_with(wire.into(), |_| visits += 1) {
            Ok(VisitOutcome::Packets {
                count: 1,
                skipped_empty_packets: 2,
            }) => assert!(maximum.is_none()),
            Err(BatchError::EmptyPacket) => assert!(maximum.is_some()),
            result => panic!("unexpected result: {result:?}"),
        }
        visits = 0;
        let mut wire = vec![0xfe, 1];
        wire.extend(
            snap::raw::Encoder::new()
                .compress_vec(&[1, 7, 10, 8])
                .unwrap(),
        );
        assert!(codec.decode_with(wire.into(), |_| visits += 1).is_err());
        assert_eq!(visits, 0);
    }
}
