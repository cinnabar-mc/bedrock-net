// SPDX-License-Identifier: MIT

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
        let requested = client.close().await;
        // The unfinished operation cannot complete first; only real incoming EOF ends this wait.
        let progress = server.progress(std::future::pending::<()>()).await;
        let cached = server.input_failure.as_ref().cloned();
        let received = server.recv().await;
        let repeated = server.progress(std::future::ready(())).await;
        let cached_send = server
            .send_until(Bytes::from_static(b"after observed EOF"), None)
            .await;
        let settled = server.settle(std::future::ready(23)).await;
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
        assert_eq!(settled.unwrap(), 23);
        requested.unwrap();
        client_finished.unwrap();
        listener_closed.unwrap();
        assert_eq!(received.unwrap(), original);
        let expected = Inbox::closed_during_write();
        for result in [progress, repeated, cached_send, replayed.map(|_| ())] {
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

/// Incoming failures during actual blocked sends retain their prefix and terminal cause.
#[tokio::test]
async fn failed_input_during_send_is_cached_but_send_timeouts_are_not() {
    use crate::server::test_support::{TIMEOUT, signed_pair_with_key};
    use p384::{ecdsa::SigningKey, elliptic_curve::Generate};
    tokio::time::timeout(TIMEOUT, async {
        let (mut pair, _) = signed_pair_with_key(
            Arc::new(SigningKey::generate()),
            bedrock_net::BatchLimits::default().max_decoded_bytes,
        )
        .await;
        let mut permits = Vec::new();
        loop {
            let mut reservation = Box::pin(pair.sender.reserve_send(None));
            match futures::poll!(&mut reservation) {
                std::task::Poll::Ready(Ok(permit)) => permits.push(permit),
                std::task::Poll::Pending => break,
                std::task::Poll::Ready(Err(error)) => panic!("send capacity failed: {error}"),
            }
        }
        let super::super::State::Accepted(server) =
            &mut pair.wire.connection_mut().transport_mut().state
        else {
            panic!("fixture lost its original accepted owner");
        };
        let timed_out = server
            .send_until(Bytes::from_static(b"pending"), Some(Instant::now()))
            .await;
        let send_failed_without_input_failure =
            timed_out.is_err() && server.input_failure.is_none();
        server.configure_limits(bedrock_net::BatchLimits {
            max_encoded_bytes: 8,
            ..Default::default()
        });
        pair.client.send(Bytes::from_static(b"head")).await.unwrap();
        pair.client
            .send(Bytes::from_static(b"oversized input"))
            .await
            .unwrap();
        let failure = server
            .send_until(Bytes::from_static(b"pending"), None)
            .await
            .unwrap_err();
        let cached = server.input_failure.is_some();
        let repeated = server.progress(std::future::ready(())).await;
        let first = server.recv().await;
        let terminal = if cached {
            Some(server.recv().await)
        } else {
            None
        };
        drop(permits);
        assert!(pair.finish().await);
        assert!(
            send_failed_without_input_failure,
            "ordinary send timeout poisoned incoming progress"
        );
        assert_eq!(first.unwrap(), b"head"[..]);
        assert!(cached, "send_until lost its observed incoming failure");
        for result in [repeated, terminal.unwrap().map(|_| ())] {
            let error = result.unwrap_err();
            assert_eq!(error.kind(), failure.kind());
            assert_eq!(error.to_string(), failure.to_string());
        }
    })
    .await
    .expect("finite accepted send failure fixture stalled");
}
