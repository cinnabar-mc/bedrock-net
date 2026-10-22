// SPDX-License-Identifier: MIT

use super::*;
use bedrock_net::CompressionAlgorithm;

#[tokio::test]
async fn typed_effect_splits_at_the_original_packet_count_limit() {
    let limits = BatchLimits::default();
    let packets = (0..=limits.max_packets)
        .map(|index| {
            SetTime {
                time: wire::ZigZag32(i32::try_from(index).unwrap()),
            }
            .into()
        })
        .collect();
    split_effect(packets, &[limits.max_packets, 1], false).await;
}

#[tokio::test]
async fn typed_effect_splits_individually_valid_packets_at_the_original_byte_limit() {
    let limits = BatchLimits::default();
    let payload = Bytes::from(vec![b'k'; limits.max_decoded_bytes / 2]);
    let packets = (0..2)
        .map(|index| {
            packets::ResourcePackChunkData {
                resource_name: Bytes::from_static(b"synthetic-pack").into(),
                chunk_id: wire::U32LE(index),
                byte_offset: wire::U64LE(u64::from(index) * payload.len() as u64),
                chunk_data: payload.clone(),
            }
            .into()
        })
        .collect();
    split_effect(packets, &[1, 1], true).await;
}

/// Drops every committed receipt borrow and resumes one effect on its original cipher and deadline.
async fn split_effect(packets: Vec<packets::Packet>, expected_counts: &[usize], byte_split: bool) {
    tokio::time::timeout(TIMEOUT, async {
        let limits = BatchLimits::default();
        let expected: Vec<_> = packets.iter().map(encoded_entry).collect();
        if byte_split {
            assert!(expected.iter().map(Bytes::len).sum::<usize>() > limits.max_decoded_bytes);
        } else {
            assert!(expected.len() > limits.max_packets);
        }
        let mut pair = signed_pair().await;
        let deadline = tokio::time::Instant::now().into_std() + TIMEOUT;
        let compression = CompressionSettings {
            algorithm: CompressionAlgorithm::Snappy,
            threshold: 0,
        };
        pair.wire.compression_flushed(compression).unwrap();
        let key = zeroize::Zeroizing::new(rand::random::<[u8; 32]>());
        pair.wire
            .encryption_flushed((
                BatchEncryptor::new(*key),
                BatchDecryptor::new(rand::random()),
            ))
            .unwrap();
        let preparation = pair.wire.prepare_packets(packets, deadline).map(drop);
        if let Err(error) = preparation {
            assert!(
                pair.finish().await,
                "original signed accepting owners leaked"
            );
            panic!("individually valid effects must split before admission: {error}");
        }
        let mut commits = 0;
        let mut pending_receipts = 0;
        loop {
            let mut sending = pair.wire.resume_send().unwrap();
            assert_eq!(sending.deadline(), deadline);
            let Some(capacity) = sending.next().await.unwrap() else {
                break;
            };
            capacity.commit().unwrap();
            commits += 1;
            let mut next = pin!(sending.next());
            if poll_fn(|cx| Poll::Ready(next.as_mut().poll(cx).is_pending())).await {
                pending_receipts += 1;
            }
        }
        let outcome = pair
            .wire
            .begin_send_retirement(deadline + TIMEOUT)
            .finish()
            .await
            .unwrap();
        pair.wire.resume_send().unwrap().finish().unwrap();
        let codec = BatchCodec::new(BatchHeader::NetherNet, limits).negotiate(compression);
        let mut decryptor = BatchDecryptor::new(*key);
        let mut received = Vec::new();
        let mut batch_counts = Vec::new();
        for _ in expected_counts {
            let ciphertext = pair.client.recv().await.unwrap().unwrap();
            let plaintext = decryptor.decrypt(ciphertext).unwrap();
            let DecodeOutcome::Packets { packets, .. } = codec.decode(plaintext).unwrap() else {
                panic!("original effect batch was dropped");
            };
            batch_counts.push(packets.len());
            received.extend(packets);
        }
        assert!(
            pair.finish().await,
            "original signed accepting owners leaked"
        );
        assert_eq!(commits, expected_counts.len());
        assert_eq!(pending_receipts, commits);
        assert_eq!(outcome, SendOutcome::Complete);
        assert_eq!(batch_counts, expected_counts);
        assert_eq!(received, expected);
    })
    .await
    .expect("finite actual multi-batch effect fixture stalled");
}

/// Uses the generated primary header/body codec and proves each packet fits individually.
fn encoded_entry(packet: &packets::Packet) -> Bytes {
    let mut framed = Vec::new();
    wire::encode_frame_with(
        &mut framed,
        wire::PacketHeader::new(packet.id() as u32),
        BatchLimits::default().max_decoded_bytes,
        |writer| packet.encode(writer),
    )
    .unwrap();
    let framed = Bytes::from(framed);
    let mut reader = wire::Reader::from_shared(&framed);
    let length = reader.read_var_u32().unwrap();
    let entry = framed.slice(reader.position()..);
    assert_eq!(usize::try_from(length).unwrap(), entry.len());
    entry
}
