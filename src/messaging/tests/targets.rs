//! Both service response owners enter the same authenticated Player Messaging dial adapter.

use super::super::*;
use bedrock_services::signaling::websocket::test_support;
use bedrock_services::{minecraft::gatherings::JoinAddress, realms::RealmAddress};
use nethernet::identity::{ServerIdentity, TokenTrust};
use serde_json::{Value, json};
use std::time::{Duration, SystemTime};

/// Realms and Gatherings targets produce the actual SDK recipient without a signaling selector.
#[tokio::test]
async fn service_targets_share_the_actual_json_rpc_dial_adapter() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for gathering in [false, true] {
            let peer_id = Uuid::from_u128(23);
            let realm: RealmAddress = serde_json::from_value(json!({
                "address":format!(" {peer_id} "),"networkProtocol":" nethernet_jsonrpc "
            }))
            .unwrap();
            let experience: JoinAddress = serde_json::from_value(json!({
                "netherNetId":format!(" {peer_id} "),"networkProtocol":" nethernet_jsonrpc "
            }))
            .unwrap();
            let target = if gathering {
                experience.target()
            } else {
                realm.target()
            }
            .unwrap();
            let (socket, mut service) = test_support::pair(7).await;
            let prepared = PreparedMessaging::from_target(socket, 7, target).unwrap();
            assert_eq!(prepared.recipient().network_id(), peer_id.to_string());
            let config = ConnectionConfig {
                identity: Some(Arc::new(
                    ServerIdentity::generate("fixture", SystemTime::now()).unwrap(),
                )),
                server_trust: Some(TokenTrust::Any),
                client_ice: Some(ClientIceConfig {
                    ice: Default::default(),
                    bind_addr: Some("127.0.0.1:0".parse().unwrap()),
                    turn_streams: Vec::new(),
                    turn_tls: None,
                }),
                ..Default::default()
            };
            let cancellation = config.cancel_token.clone();
            let operation = prepared.connect(config, Instant::now() + Duration::from_secs(10));
            let wire = async {
                let credentials: Value =
                    serde_json::from_str(&service.recv_text().await.unwrap().unwrap()).unwrap();
                service
                    .send_text(
                        &json!({"jsonrpc":"2.0","id":credentials["id"],"result":{
                            "ExpirationInSeconds":300,"TurnAuthServers":[]
                        }})
                        .to_string(),
                    )
                    .await
                    .unwrap();
                let offer: Value =
                    serde_json::from_str(&service.recv_text().await.unwrap().unwrap()).unwrap();
                assert_eq!(offer["method"], "Signaling_SendClientMessage_v1_0");
                assert_eq!(offer["params"]["toPlayerId"], peer_id.to_string());
                let inner: Value =
                    serde_json::from_str(offer["params"]["message"].as_str().unwrap()).unwrap();
                assert_eq!(inner["method"], "Signaling_WebRtc_v1_0");
                assert!(!offer.to_string().contains("connectionType"));
                cancellation.cancel();
                while matches!(service.recv_text().await, Ok(Some(_))) {}
                let _ = service.close().await;
            };
            let (result, ()) = tokio::join!(operation, wire);
            assert!(result.err().unwrap().is_cancelled());
        }
    })
    .await
    .unwrap();
}

/// A service's opaque ID stays valid metadata but receives the runtime's explicit UUID routing refusal.
#[tokio::test]
async fn unrepresentable_service_recipient_is_a_typed_failure_before_signaling() {
    use std::error::Error as _;
    let realm: RealmAddress = serde_json::from_value(json!({
        "address":"opaque-target", "networkProtocol":"NETHERNET_JSONRPC"
    }))
    .unwrap();
    let target = realm.target().unwrap();
    assert_eq!(target.nethernet_id(), "opaque-target");
    let (socket, mut peer) = test_support::pair(7).await;
    let error = PreparedMessaging::from_target(socket, 7, target)
        .err()
        .unwrap();
    assert!(error.source().is_some());
    assert!(!format!("{error:?}").contains("opaque-target"));
    assert!(matches!(peer.recv_text().await, Ok(None) | Err(_)));
    let _ = peer.close().await;
}
