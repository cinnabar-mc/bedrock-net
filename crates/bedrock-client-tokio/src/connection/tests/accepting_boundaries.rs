// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;
use crate::server::test_support::{TIMEOUT, signed_pair_with_key};
use bedrock_net::BatchHeader;
use p384::{ecdsa::SigningKey, elliptic_curve::Generate};
use std::sync::Arc;

/// Builds distinct complete packet entries using the original generated encoder.
fn time_packet(time: i32) -> packets::Packet {
    packets::SetTime {
        time: wire::ZigZag32(time),
    }
    .into()
}

#[tokio::test]
async fn late_raw_completion_replays_once_before_siblings_without_replaying_delivered_input() {
    tokio::time::timeout(TIMEOUT, async {
        let (mut pair, _) = signed_pair_with_key(
            Arc::new(SigningKey::generate()),
            BatchLimits::default().max_decoded_bytes,
        )
        .await;
        let prefix = [1, 2, 3].map(|time| {
            let packet = time_packet(time);
            packet_bytes(wire::PacketHeader::new(packet.id() as u32), &packet)
        });
        let mut batches = BatchCodec::new(BatchHeader::NetherNet, BatchLimits::default())
            .encode(&prefix)
            .unwrap();
        assert_eq!(batches.len(), 1);
        pair.client.send(batches.remove(0)).await.unwrap();
        let deadline = tokio::time::Instant::now().into_std() + TIMEOUT;
        let first = pair.wire.receive_raw(deadline).await.unwrap();
        assert_eq!(first, prefix[0]);
        let connection = pair.wire.connection_mut();
        assert_eq!(connection.current_raw(), Some(&prefix[0]));
        let expired = connection
            .next_raw_before(tokio::time::Instant::now().into_std())
            .await;
        let delivered_current_untouched = connection.current_raw() == Some(&prefix[0]);
        assert_eq!(connection.pending.front(), Some(&prefix[1]));
        let second = connection.next_raw().await.unwrap();
        assert_eq!(second, prefix[1]);
        assert_eq!(connection.current_raw(), Some(&prefix[1]));

        let late = connection.finish_raw_read(Ok(second), deadline, deadline);
        let next = connection.next_raw().await.unwrap();
        let following = if connection.pending.front().is_some() {
            Some(connection.next_raw().await.unwrap())
        } else {
            None
        };
        let exhausted = connection.pending.front().is_none();
        assert!(
            pair.finish().await,
            "original signed accepting owners leaked"
        );
        assert!(matches!(expired, Err(error) if error.kind() == io::ErrorKind::TimedOut));
        assert!(delivered_current_untouched);
        assert!(matches!(late, Err(error) if error.kind() == io::ErrorKind::TimedOut));
        assert_eq!(next, prefix[1], "the late raw result was lost");
        assert_eq!(following, Some(prefix[2].clone()));
        assert!(exhausted, "the raw completion was replayed more than once");
    })
    .await
    .expect("finite actual raw completion fixture stalled");
}

/// Measures the generated full frame and its declared header/body without duplicating wire math.
fn frame_lengths(packet: &packets::Packet) -> (usize, usize) {
    let mut framed = Vec::new();
    wire::encode_frame_with(
        &mut framed,
        wire::PacketHeader::new(packet.id() as u32),
        usize::MAX,
        |writer| packet.encode(writer),
    )
    .unwrap();
    let mut reader = wire::Reader::new(&framed);
    let declared = reader.read_var_u32().unwrap() as usize;
    assert_eq!(reader.remaining(), declared);
    (framed.len(), declared)
}

/// Uses only synthetic bytes in the generated resource-pack chunk model.
fn chunk_packet(data: Bytes) -> packets::Packet {
    packets::ResourcePackChunkData {
        resource_name: Bytes::from_static(b"synthetic-pack").into(),
        chunk_id: wire::U32LE(0),
        byte_offset: wire::U64LE(0),
        chunk_data: data,
    }
    .into()
}

#[tokio::test]
async fn full_frame_bound_accepts_exact_limit_and_skips_one_over_without_losing_siblings() {
    tokio::time::timeout(TIMEOUT, async {
        let (mut pair, _) = signed_pair_with_key(
            Arc::new(SigningKey::generate()),
            BatchLimits::default().max_decoded_bytes,
        )
        .await;
        let limit = BatchLimits::default().max_decoded_bytes;
        let payload = Bytes::from(vec![0; limit]);
        let excess = frame_lengths(&chunk_packet(payload.clone())).0 - limit;
        let fitting = chunk_packet(payload.slice(..payload.len() - excess));
        let oversized = chunk_packet(payload.slice(..payload.len() - excess + 1));
        assert_eq!(frame_lengths(&fitting).0, limit);
        let (framed, declared) = frame_lengths(&oversized);
        assert_eq!(framed, limit + 1);
        assert!(
            declared <= limit,
            "fixture must pass the generated writer bound"
        );
        let connection = pair.wire.connection_mut();
        let mut exact = Vec::new();
        let fitting_result = connection.append_packet_frame(
            &mut exact,
            wire::PacketHeader::new(fitting.id() as u32),
            &fitting,
        );
        let fitting_length = exact.len();
        drop(exact);
        let before = vec![0x41, 0x42];
        let mut body = before.clone();
        let oversized_result = connection.append_packet_frame(
            &mut body,
            wire::PacketHeader::new(oversized.id() as u32),
            &oversized,
        );
        let rolled_back = body == before;
        drop(body);
        let key = zeroize::Zeroizing::new(rand::random::<[u8; 32]>());
        pair.wire
            .encryption_flushed((
                BatchEncryptor::new(*key),
                BatchDecryptor::new(rand::random()),
            ))
            .unwrap();
        let deadline = tokio::time::Instant::now().into_std() + TIMEOUT;
        let prepared = pair
            .wire
            .prepare_packets(vec![time_packet(1), oversized, time_packet(2)], deadline)
            .map(drop);
        let received = if prepared.is_ok() {
            let mut sending = pair.wire.resume_send().unwrap();
            while let Some(capacity) = sending.next().await.unwrap() {
                capacity.commit().unwrap();
            }
            sending.finish().unwrap();
            let ciphertext = pair.client.recv().await.unwrap().unwrap();
            let plaintext = BatchDecryptor::new(*key).decrypt(ciphertext).unwrap();
            match BatchCodec::new(BatchHeader::NetherNet, BatchLimits::default())
                .decode(plaintext)
                .unwrap()
            {
                DecodeOutcome::Packets { packets, .. } => Some(packets.collect::<Vec<_>>()),
                DecodeOutcome::Dropped(_) => panic!("plaintext fixture message was dropped"),
            }
        } else {
            None
        };
        assert!(
            pair.finish().await,
            "original signed accepting owners leaked"
        );
        assert!(fitting_result.is_ok());
        assert_eq!(fitting_length, limit);
        assert!(
            prepared.is_ok(),
            "a one-over frame discarded valid siblings: {prepared:?}"
        );
        assert!(
            matches!(oversized_result, Err(error) if error.kind() == io::ErrorKind::InvalidInput)
        );
        assert!(rolled_back, "a rejected full frame was retained");
        let expected = [1, 2].map(|time| {
            let packet = time_packet(time);
            packet_bytes(wire::PacketHeader::new(packet.id() as u32), &packet)
        });
        assert_eq!(received, Some(expected.to_vec()));
    })
    .await
    .expect("finite actual full-frame boundary fixture stalled");
}
