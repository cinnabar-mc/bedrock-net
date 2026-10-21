// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;
use crate::connect::lan::{self, DirectedLanConfig, LanSelection};
use nethernet_tokio::{ConnectionConfig, LanConfig, LanSignaling, NetherServer, ServerData};
use std::time::Duration;
use tokio::net::UdpSocket;

/// Final retirement drains the original receivers without replacing an already reported input cause.
#[tokio::test]
async fn cached_orderly_eof_does_not_prevent_original_receiver_retirement() {
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
        data.session_id = "accepted-retirement-fixture".into();
        data.protocol_version = bedrock_protocol::PROTOCOL_VERSION as u32;
        signaling.set_server_data(data);
        let config = ConnectionConfig {
            allow_unsigned_answers: true,
            ..Default::default()
        };
        let mut listener = NetherServer::bind_with(Arc::clone(&signaling), config.clone())
            .await
            .unwrap();
        let options = DirectedLanConfig {
            connection: config,
            selection: LanSelection::SelfSigned,
            max_nonce_bytes: 0,
            credential_expires: None,
        };
        let (client, accepted) = tokio::join!(
            lan::connect_directed(
                address,
                &options,
                tokio::time::Instant::now() + Duration::from_secs(20),
            ),
            listener.accept(),
        );
        let mut client = client.unwrap().0;
        let accepted = accepted.unwrap();
        let client_address = accepted.session.remote_addr().await.socket_addr.unwrap();
        let mut server = AcceptedTransport::new(accepted);
        let original = Bytes::from_static(b"original accepted prefix");
        client.send_until(original.clone(), None).await.unwrap();
        let received = server.recv().await;
        let requested = client.close().await;
        // The unfinished operation cannot complete first; only real incoming EOF ends this wait.
        let progress = server.progress(std::future::pending::<()>()).await;
        let cached = server.input_failure.as_ref().cloned();
        let repeated = server.progress(std::future::ready(())).await;
        let finished = server.finish_close().await;
        let replayed = server.recv().await;
        let retained = match (&cached, &server.input_failure) {
            (Some(original), Some(current)) => Arc::ptr_eq(original, current),
            _ => false,
        };
        // Rescue the same original queues before any final behavioral assertion on the baseline.
        let State::Retired(accepted) = server.state.as_mut().unwrap() else {
            panic!("final close must consume the original established owner");
        };
        let reliable = accepted.reliable.recv().await;
        let unreliable = accepted.unreliable.recv().await;
        accepted.session.closed().await;
        drop(server);
        let client_finished = client.finish_close().await;
        drop(client);
        let listener_closed = listener.close().await;
        drop(listener);
        Arc::try_unwrap(signaling).ok().unwrap().shutdown().await;
        let client_released = std::net::UdpSocket::bind(client_address).is_ok();
        let signaling_released = std::net::UdpSocket::bind(address).is_ok();

        assert!(client_released && signaling_released);
        assert!(matches!(reliable, Ok(None)), "{reliable:?}");
        assert!(matches!(unreliable, Ok(None)), "{unreliable:?}");
        requested.unwrap();
        client_finished.unwrap();
        listener_closed.unwrap();
        assert_eq!(received.unwrap(), original);
        let expected = Inbox::closed_during_write();
        for result in [progress, repeated, replayed.map(|_| ())] {
            let error = result.unwrap_err();
            assert_eq!(error.kind(), expected.kind());
            assert_eq!(error.to_string(), expected.to_string());
        }
        assert!(
            retained,
            "physical retirement replaced the original input cause"
        );
        assert!(
            finished.is_ok(),
            "already reported orderly EOF prevented original receiver retirement: {finished:?}"
        );
    })
    .await
    .expect("finite original accepted retirement fixture stalled");
}
