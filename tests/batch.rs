//! Behavioral checks for batch compatibility and untrusted framing.

use bedrock_net::{
    BatchCodec, BatchError, BatchHeader, BatchLimits, CompressionAlgorithm, CompressionSettings,
    DecodeOutcome, DropReason,
};
use bytes::Bytes;

#[path = "fixtures/go_batches.rs"]
mod go;

/// Builds a codec after compression negotiation, using the supplied safety policy.
fn negotiated(algorithm: CompressionAlgorithm, limits: BatchLimits) -> BatchCodec {
    let mut codec = BatchCodec::new(BatchHeader::RakNet, limits);
    codec.enable_compression(CompressionSettings {
        algorithm,
        threshold: 0,
    });
    codec
}

/// Extracts the packets, failing the test if a batch unexpectedly drops.
fn packets(codec: &BatchCodec, wire: Bytes) -> Vec<Bytes> {
    match codec.decode(wire).unwrap() {
        DecodeOutcome::Packets(packets) => packets,
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
fn negotiation_changes_headers_and_compresses_at_threshold_equality() {
    let input = [Bytes::from_static(&[2, 0, 0, 0, 0])];
    for header in [BatchHeader::RakNet, BatchHeader::NetherNet] {
        let mut codec = BatchCodec::new(header, BatchLimits::default());
        let marker = usize::from(header == BatchHeader::RakNet);
        let initial = codec.encode(&input).unwrap().pop().unwrap();
        assert_eq!(&initial[marker..], &[5, 2, 0, 0, 0, 0]);
        assert_eq!(packets(&codec, initial), input);

        codec.enable_compression(CompressionSettings {
            algorithm: CompressionAlgorithm::Deflate,
            threshold: 7,
        });
        let below = codec.encode(&input).unwrap().pop().unwrap();
        assert_eq!(below[marker], 0xff);
        assert_eq!(packets(&codec, below), input);

        codec.enable_compression(CompressionSettings {
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
fn malformed_tail_never_exposes_a_partial_batch() {
    let codec = BatchCodec::new(BatchHeader::RakNet, BatchLimits::default());
    for tail in [
        &[0][..],
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
