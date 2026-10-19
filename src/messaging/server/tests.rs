use super::*;
use bedrock_services::signaling::websocket::test_support;

/// The original external cancellation wakes actual service maintenance without a peer or timer.
#[tokio::test]
async fn bound_server_cancellation_retires_service_and_joins_original_listener() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let network_id = 7;
        let (socket, mut peer) = test_support::pair(network_id).await;
        let mut config = test_config();
        let cancellation = config.cancel_token.clone();
        config.max_sessions = 1;
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        let mut server = PreparedMessagingServer::new(socket, network_id)
            .bind(config, CallerServerSignalingConfig::default(), deadline)
            .await
            .unwrap();
        assert_eq!(server.local_network_id(), network_id);
        cancellation.cancel();
        assert!(matches!(server.maintain().await, Err(Error::Closed)));
        assert!(matches!(server.accept().await, Err(Error::Closed)));
        let mut closing = server.begin_close();
        closing.finish_close().await.unwrap();
        closing.finish_close().await.unwrap();
        assert!(closing.try_finish().is_ok());
        assert!(matches!(
            peer.recv_text().await,
            Ok(None)
                | Err(bedrock_services::signaling::websocket::SocketError::Closed
                    | bedrock_services::signaling::websocket::SocketError::Transport)
        ));
        let _ = peer.close().await;
    })
    .await
    .expect("finite accepting cancellation fixture stalled");
}

/// Uses real SDP keys; no game identity or MPSD/world approval is fabricated here.
fn test_config() -> ConnectionConfig {
    use nethernet::identity::{ServerIdentity, TokenTrust};
    ConnectionConfig {
        identity: Some(std::sync::Arc::new(
            ServerIdentity::generate("loopback-fixture.invalid", std::time::SystemTime::now())
                .unwrap(),
        )),
        token_trust: Some(TokenTrust::Any),
        ..ConnectionConfig::default()
    }
}

/// Exercises actual SDK WebSocket envelopes, existing accepting transport and real UDP data.
#[tokio::test]
async fn accepting_messaging_routes_the_authenticated_peer_and_retires_actual_owners() {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        use bytes::Bytes;
        use nethernet::connection::IceMode;
        use nethernet::identity::TokenTrust;
        use nethernet_tokio::{CallerSignaling, CallerSignalingConfig, ClientIceConfig, NetherClient};
        use std::net::{Ipv4Addr, SocketAddr};
        use uuid::Uuid;

        let server_id = Uuid::from_u128(101);
        let client_id = Uuid::from_u128(102);
        let network_id = 7;
        let (socket, peer) = test_support::pair(network_id).await;
        let mut server_config = test_config();
        server_config.max_sessions = 1;
        server_config.server_ice = Some(ServerIceConfig {
            ice: Default::default(),
            bind_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        });
        let signaling = CallerServerSignalingConfig {
            signaling: CallerSignalingConfig { ice_mode: IceMode::Full, ..Default::default() },
            ..Default::default()
        };
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        let mut server = PreparedMessagingServer::new(socket, network_id)
            .bind(server_config, signaling, deadline).await.unwrap();
        let (caller, client_service) = CallerSignaling::new(client_id.to_string(), server_id.to_string(), signaling.signaling).unwrap();
        let mut client_config = test_config();
        client_config.server_trust = Some(TokenTrust::Any);
        client_config.client_ice = Some(ClientIceConfig {
            ice: Default::default(),
            bind_addr: Some(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)),
        });
        let application = async {
            let (client, accepted) = tokio::join!(
                NetherClient::connect_with(caller, server_id.to_string(), client_config),
                server.accept(),
            );
            let mut client = client.unwrap();
            let mut accepted = accepted.unwrap();
            assert_eq!(accepted.session.remote_addr().await.network_id, client_id.to_string());
            let transfer = async {
                client.send(Bytes::from_static(b"visitor to host")).await.unwrap();
                assert_eq!(accepted.reliable.recv().await.unwrap().unwrap(), "visitor to host");
                accepted.session.send(Bytes::from_static(b"host to visitor")).await.unwrap();
                assert_eq!(client.recv().await.unwrap().unwrap(), "host to visitor");
                let retired_client = client.close();
                let retired_peer = accepted.close();
                tokio::join!(retired_client.session.closed(), retired_peer.session.closed());
            };
            tokio::pin!(transfer);
            tokio::select! {
                () = &mut transfer => {}
                result = server.maintain() => panic!("service retired during reliable transfer: {result:?}"),
            }
            let mut closing = server.begin_close();
            assert!(!closing.joined);
            closing.finish_close().await.unwrap();
            assert!(closing.try_finish().is_ok());
        };
        tokio::join!(application, service(peer, client_service, server_id, client_id, deadline));
    }).await.expect("finite accepting Messaging transport fixture stalled");
}

/// Represents only a finite synthetic Messaging service, not account or game authorization.
async fn service(
    mut peer: test_support::Peer,
    mut client: nethernet_tokio::CallerSignalingDriver,
    server_id: uuid::Uuid,
    client_id: uuid::Uuid,
    deadline: Instant,
) {
    use nethernet_tokio::SignalDelivery;
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use uuid::Uuid;
    let mut pending = HashMap::new();
    let mut client_open = true;
    loop {
        tokio::select! {
            request = client.recv(), if client_open => {
                let Some(request) = request else { client_open = false; continue; };
                let message = Uuid::new_v4();
                let wire = request.signal().to_string();
                if request.requires_peer_receipt() {
                    pending.insert(message, request);
                } else {
                    request.finish(Ok(SignalDelivery::ServiceAccepted));
                }
                let callback = json!({"jsonrpc":"2.0","id":message.to_string(),"method":"Signaling_ReceiveMessage_v1_0",
                    "params":{"From":client_id,"Id":message,"Message":json!({"jsonrpc":"2.0","method":"Signaling_WebRtc_v1_0",
                        "params":{"netherNetId":"untrusted-advertised-network","message":wire}}).to_string()}});
                peer.send_text(&callback.to_string()).await.unwrap();
            }
            wire = peer.recv_text() => {
                let wire = match wire { Ok(Some(wire)) => wire, Ok(None) | Err(_) => break };
                let frame: Value = serde_json::from_str(&wire).unwrap();
                let Some(method) = frame["method"].as_str() else {
                    assert!(frame.get("result").is_some());
                    continue;
                };
                assert_eq!(method, "Signaling_SendClientMessage_v1_0");
                assert_eq!(frame["params"]["toPlayerId"], client_id.to_string());
                let inner: Value = serde_json::from_str(frame["params"]["message"].as_str().unwrap()).unwrap();
                match inner["method"].as_str().unwrap() {
                    "Signaling_DeliveryNotification_V1_0" => {
                        let message = Uuid::parse_str(inner["params"]["messageId"].as_str().unwrap()).unwrap();
                        pending.remove(&message).expect("receipt for the original offer").finish(Ok(SignalDelivery::PeerReceived));
                    }
                    "Signaling_WebRtc_v1_0" => {
                        client.prepare_delivery_before(&server_id.to_string(), inner["params"]["message"].as_str().unwrap(), deadline).unwrap().await.unwrap();
                    }
                    _ => panic!("unexpected synthetic service request"),
                }
                peer.send_text(&json!({"jsonrpc":"2.0","id":frame["id"],"result":null}).to_string()).await.unwrap();
            }
        }
    }
    assert!(
        pending.is_empty(),
        "original offer receipt was never observed"
    );
    client.close();
    let _ = peer.close().await;
}
