use super::*;
use crate::connection::{PacketDirection, PacketObserver};
use crate::server::test_support::{TIMEOUT, signed_pair_with_key};
use p384::{ecdsa::SigningKey, elliptic_curve::Generate};
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn raw_batches_preserve_boundaries_errors_and_immediate_forwarding() {
    tokio::time::timeout(TIMEOUT, async {
        let (mut pair, _) = signed_pair_with_key(Arc::new(SigningKey::generate()), 4096).await;
        let observed = Arc::new(Mutex::new(Vec::new()));
        let saved = Arc::clone(&observed);
        let mut ids = [packets::SetTime::ID];
        let observer = PacketObserver::new(ids.iter().copied(), move |packet| {
            saved
                .lock()
                .unwrap()
                .push((packet.direction, packet.header, packet.payload.to_vec()));
        })
        .unwrap();
        ids[0] = 1023;
        assert_eq!(ids, [1023]);
        pair.wire
            .connection_mut()
            .set_packet_observer(Some(observer));
        pair.wire
            .connection_mut()
            .set_identity(identity::WireIdentity {
                display_name: "Canonical".into(),
                xuid: "123".into(),
                uuid: uuid::Uuid::nil().to_string(),
            });
        let valid = packet_bytes(
            wire::PacketHeader::new(packets::SetTime::ID),
            &packets::SetTime {
                time: wire::ZigZag32(7),
            }
            .into(),
        );
        let mut unknown = vec![0xff, 0x07];
        unknown.extend_from_slice(b"opaque");
        let unknown = Bytes::from(unknown);
        let malformed = Bytes::copy_from_slice(&[packets::SetTime::ID as u8, 0x80]);
        let first = [valid.clone(), unknown.clone(), malformed.clone()];
        let codec = BatchCodec::new(BatchLimits::default());
        let body = codec.encode(&first).unwrap().remove(0);
        pair.client.send(body.clone()).await.unwrap();
        pair.client
            .send(
                codec
                    .encode(std::slice::from_ref(&valid))
                    .unwrap()
                    .remove(0),
            )
            .await
            .unwrap();
        let batch = pair
            .wire
            .connection_mut()
            .read_batch_raw(|id| id == packets::SetTime::ID)
            .await
            .unwrap();
        assert_eq!(batch.packets().len(), 3);
        assert_eq!(
            batch
                .packets()
                .iter()
                .map(|packet| packet.data.clone())
                .collect::<Vec<_>>(),
            first
        );
        assert!(batch.packets()[0].decoded.as_ref().unwrap().is_ok());
        assert!(batch.packets()[1].decoded.is_none());
        assert!(batch.packets()[2].decoded.as_ref().unwrap().is_err());
        pair.wire
            .connection_mut()
            .send_batch_raw(batch.into_body(), None)
            .await
            .unwrap();
        // No later write, read or close is needed to emit the forwarded batch.
        assert_eq!(pair.client.recv().await.unwrap().unwrap(), body);
        let replay = pair.wire.connection_mut().next_raw().await.unwrap();
        pair.wire.connection_mut().replay_current();
        let next = pair
            .wire
            .connection_mut()
            .read_batch_raw(|_| false)
            .await
            .unwrap();
        assert_eq!(next.packets().len(), 1);
        assert_eq!(next.packets()[0].data, replay);
        assert!(next.packets()[0].decoded.is_none());
        pair.wire
            .connection_mut()
            .send_packet(
                &packets::SetTime {
                    time: wire::ZigZag32(9),
                }
                .into(),
                wire::Peer::Server,
                0,
                0,
            )
            .await
            .unwrap();
        assert!(pair.client.recv().await.unwrap().is_some());
        // Raw output must not parse identity-bearing bodies, even with identity normalization set.
        let skin = Bytes::from_static(&[packets::PlayerSkin::ID as u8, 0x80]);
        pair.wire
            .connection_mut()
            .write_packet_raw(skin.clone(), None)
            .await
            .unwrap();
        assert_eq!(
            pair.client.recv().await.unwrap().unwrap(),
            codec.encode(&[skin]).unwrap().remove(0)
        );
        {
            let observations = observed.lock().unwrap();
            assert_eq!(observations.len(), 6);
            assert_eq!(
                observations
                    .iter()
                    .filter(|(direction, ..)| *direction == PacketDirection::Received)
                    .count(),
                3
            );
            assert!(
                observations
                    .iter()
                    .all(|(_, header, _)| header.id == packets::SetTime::ID)
            );
        }
        assert!(pair.finish().await);
    })
    .await
    .unwrap();
}

#[test]
fn raw_packet_views_keep_noncanonical_and_ignored_header_bits() {
    let data = Bytes::from_static(&[0x8a, 0x88, 0x80, 0x02, 14]);
    let body = BatchCodec::new(BatchLimits::default())
        .encode(std::slice::from_ref(&data))
        .unwrap()
        .remove(0);
    let DecodeOutcome::Packets { packets, .. } = BatchCodec::new(BatchLimits::default())
        .decode(body.clone())
        .unwrap()
    else {
        unreachable!()
    };
    let batch = RawBatch::from_packets(
        packets,
        &wire::Limits::receiving_from(wire::Peer::Server),
        |_| true,
    )
    .unwrap();
    assert_eq!(batch.packets()[0].data, data);
    assert_eq!(batch.packets()[0].header.id, packets::SetTime::ID);
    assert_eq!(batch.packets()[0].header.sender_subclient, 1);
    assert!(batch.packets()[0].decoded.as_ref().unwrap().is_ok());
    assert_eq!(batch.into_body(), body);
}

#[test]
fn observer_interests_reject_ids_outside_the_wire_header() {
    assert!(PacketObserver::new([1024], |_| {}).is_err());
}

#[tokio::test]
async fn sealed_raw_sends_do_not_observe_or_replace_retained_work() {
    tokio::time::timeout(TIMEOUT, async {
        let (mut pair, _) = signed_pair_with_key(Arc::new(SigningKey::generate()), 4096).await;
        let observations = Arc::new(Mutex::new(0));
        let saved = Arc::clone(&observations);
        pair.wire.connection_mut().set_packet_observer(Some(
            PacketObserver::new([packets::SetTime::ID], move |_| *saved.lock().unwrap() += 1)
                .unwrap(),
        ));
        let packet = packet_bytes(
            wire::PacketHeader::new(packets::SetTime::ID),
            &packets::SetTime {
                time: wire::ZigZag32(7),
            }
            .into(),
        );
        let deadline = tokio::time::Instant::now().into_std() + TIMEOUT;
        drop(pair.wire.prepare_raw(packet.clone(), deadline).unwrap());
        pair.wire
            .begin_send_retirement(deadline)
            .finish()
            .await
            .unwrap();
        assert!(pair.wire.prepare_raw(packet.clone(), deadline).is_err());
        assert!(
            pair.wire
                .connection_mut()
                .write_packet_raw(packet, None)
                .await
                .is_err()
        );
        assert_eq!(*observations.lock().unwrap(), 1);
        assert!(pair.finish().await);
    })
    .await
    .unwrap();
}
