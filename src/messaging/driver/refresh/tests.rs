use super::*;
use bedrock_services::signaling::websocket::test_support;
use nethernet_tokio::{CallerServerSignaling, CallerServerSignalingConfig};
use serde_json::{Value, json};
use std::{future::pending, time::Duration};

/// Actual fatal service retirement drops the moved secret without losing original receipt identity.
#[tokio::test]
async fn fatal_service_close_retires_the_actual_completed_turn_credential_owner() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let network_id = 7;
        let (socket, mut peer) = test_support::pair(network_id).await;
        let config = CallerServerSignalingConfig::default();
        let (_caller, caller_driver) =
            CallerServerSignaling::new(network_id.to_string(), config).unwrap();
        let mut driver = Driver::server(
            socket,
            caller_driver,
            config.signaling.send_timeout,
            pending::<()>(),
        );
        let receipt = driver
            .begin_turn_refresh(Instant::now() + Duration::from_secs(10))
            .unwrap();
        let request = {
            let finish = driver.finish_turn_refresh(&receipt);
            tokio::pin!(finish);
            let wire = tokio::select! { biased;
                wire = peer.recv_text() => wire.unwrap().unwrap(),
                _ = &mut finish => panic!("TURN refresh completed before its actual response"),
            };
            serde_json::from_str::<Value>(&wire).unwrap()
        };
        peer.send_text(&json!({
            "jsonrpc":"2.0", "id":request["id"], "result":{
                "ExpirationInSeconds":120, "TurnAuthServers":[{
                    "Username":"fresh-owned-fixture", "Password":"synthetic-turn-password",
                    "Urls":["turn:fixture.invalid:3478"]
                }]
            }
        }).to_string()).await.unwrap();
        let marker = "turn-credential-captured";
        peer.send_text(&json!({
            "jsonrpc":"2.0", "id":marker, "method":"Fixture_TurnCaptured", "params":{}
        }).to_string()).await.unwrap();
        let reply = {
            let maintenance = driver.run(pending::<()>());
            tokio::pin!(maintenance);
            tokio::select! { biased;
                wire = peer.recv_text() => wire.unwrap().unwrap(),
                _ = &mut maintenance => panic!("service retired before processing the actual result"),
            }
        };
        assert_eq!(
            serde_json::from_str::<Value>(&reply).unwrap(),
            json!({"jsonrpc":"2.0", "id":marker, "result":null})
        );
        assert!(driver.refresh.as_ref().is_some_and(|refresh| {
            matches!(&refresh.result, Some(Ok(credentials))
                if credentials.servers()[0].username() == "fresh-owned-fixture")
        }), "the actual correlated response did not transfer its owned credentials");

        drop(peer);
        let terminal = driver.run(pending::<()>()).await.unwrap_err();
        let result_retired = driver
            .refresh
            .as_ref()
            .is_some_and(|refresh| refresh.result.is_none());
        let correlation_retained = driver
            .refresh
            .as_ref()
            .is_some_and(|refresh| refresh.matches(&receipt));
        let finished = driver.finish_turn_refresh(&receipt).await;
        let consumed = driver.finish_turn_refresh(&receipt).await;
        drop(driver);

        assert!(result_retired, "fatal service close retained the completed TURN credential owner");
        assert!(correlation_retained, "fatal close lost the original refresh receipt");
        assert!(matches!((terminal, finished),
            (Error::Messaging(first), Err(Error::Messaging(reported))) if first == reported
        ), "matching finish must preserve the original actual service failure");
        assert!(matches!(consumed, Err(Error::Admission)));
    }).await.expect("finite fatal TURN credential retirement fixture stalled");
}
