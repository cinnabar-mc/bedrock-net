// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;
use crate::{PacketIo, connect::lan};
use bedrock_net::{BatchCodec, BatchHeader, BatchLimits, DecodeOutcome};
use nethernet_tokio::{ConnectionConfig, LanConfig, LanSignaling, NetherServer, ServerData};
use std::{sync::Arc, time::Duration};
use tokio::net::UdpSocket;

/// Uses real generated pack requests and the established association's original codec.
#[tokio::test]
async fn pack_effects_split_at_both_byte_and_packet_limits() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let signaling = Arc::new(
            LanSignaling::with_config(
                73,
                address,
                LanConfig {
                    discovery_port: address.port(),
                    ..Default::default()
                },
            )
            .await
            .unwrap(),
        );
        let mut data = ServerData::new("Fixture".into(), "World".into());
        data.flag_b = true;
        data.session_id = "pack-effects-fixture".into();
        data.protocol_version = bedrock_protocol::PROTOCOL_VERSION as u32;
        signaling.set_server_data(data);
        let config = ConnectionConfig {
            allow_unsigned_answers: true,
            ..Default::default()
        };
        let mut listener = NetherServer::bind_with(Arc::clone(&signaling), config.clone())
            .await
            .unwrap();
        let options = lan::DirectedLanConfig {
            connection: config,
            selection: lan::LanSelection::SelfSigned,
            max_nonce_bytes: 0,
            credential_expires: None,
        };
        let (connected, peer) = tokio::join!(
            lan::connect_directed(
                address,
                &options,
                tokio::time::Instant::now() + Duration::from_secs(20),
            ),
            listener.accept(),
        );
        let mut peer = peer.unwrap();
        let packets: Vec<packets::Packet> = [80, 80, 12, 12, 12]
            .into_iter()
            .enumerate()
            .map(|(chunk, length)| {
                packets::ResourcePackChunkRequest {
                    resource_name: vec![b'a'; length].into(),
                    chunk: wire::I32LE(chunk as i32),
                }
                .into()
            })
            .collect();
        let size = |index| {
            let mut framed = Vec::new();
            wire::encode_frame_with(
                &mut framed,
                wire::PacketHeader::new(packets[index].id() as u32),
                usize::MAX,
                |writer| packets[index].encode(writer),
            )
            .unwrap();
            framed.len()
        };
        let limits = BatchLimits {
            max_decoded_bytes: size(0) + size(2),
            max_packets: 2,
            ..Default::default()
        };
        let mut connection =
            Connection::new(connected.unwrap().0, limits, wire::Limits::default(), 0);
        let mut observed = Vec::new();
        let result = send_packets(&mut connection, &packets, None, &mut |event| {
            if let Observation::Sent(packets) = event {
                observed.extend_from_slice(packets);
            }
        })
        .await;
        let codec = BatchCodec::new(BatchHeader::NetherNet, limits);
        let mut received = Vec::new();
        let mut batch_counts = Vec::new();
        if result.is_ok() {
            while received.len() < packets.len() {
                let body = peer.reliable.recv().await.unwrap().unwrap();
                let DecodeOutcome::Packets { packets, .. } = codec.decode(body).unwrap() else {
                    panic!("original uncompressed pack requests must decode");
                };
                let before = received.len();
                for entry in packets {
                    let mut reader = wire::Reader::from_shared(&entry);
                    let header = wire::PacketHeader::from_raw(reader.read_var_u32().unwrap());
                    received.push(
                        packets::Packet::decode_body(
                            packets::PacketId::from_raw(header.id).unwrap(),
                            &mut reader,
                        )
                        .unwrap(),
                    );
                    reader.expect_consumed().unwrap();
                }
                batch_counts.push(received.len() - before);
            }
        }
        let close = connection.close().await;
        let mut retired = peer.close();
        while retired.reliable.recv().await.unwrap().is_some() {}
        while retired.unreliable.recv().await.unwrap().is_some() {}
        retired.session.closed().await;
        listener.close().await.unwrap();
        drop(listener);
        Arc::try_unwrap(signaling).ok().unwrap().shutdown().await;
        let _released = UdpSocket::bind(address).await.unwrap();
        close.unwrap();
        result.expect("valid individual pack effects must split at the decoded byte boundary");
        assert_eq!(batch_counts, [1, 2, 2]);
        assert_eq!(received, packets);
        assert_eq!(observed, packets);
    })
    .await
    .expect("finite pack effect fixture stalled");
}
