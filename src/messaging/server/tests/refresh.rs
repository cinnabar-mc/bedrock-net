//! Actual socket ownership and request correlation, with no account or retail authority claim.

use super::*;
use bedrock_services::signaling::Event;
use serde_json::{Value, json};
use std::time::Duration;

/// Creates a real original cache before handing the same socket to the accepting driver.
async fn cached_server(network: u64) -> (MessagingServer, test_support::Peer, Instant) {
    let (mut socket, mut peer) = test_support::pair(network).await;
    let request = socket
        .request_credentials(Instant::now() + Duration::from_secs(10))
        .unwrap();
    let application = async {
        loop {
            if matches!(socket.drive().await.unwrap(), Event::Completed { request:got,result:Ok(()) } if got==request)
            {
                break;
            }
        }
    };
    let service = async {
        let wire = peer.recv_text().await.unwrap().unwrap();
        let request: Value = serde_json::from_str(&wire).unwrap();
        peer.send_text(
            &json!({"jsonrpc":"2.0","id":request["id"],"result":credentials("old-cache",120)})
                .to_string(),
        )
        .await
        .unwrap();
    };
    tokio::join!(application, service);
    let old_expiry = socket.credentials().unwrap().expires_at();
    let server = PreparedMessagingServer::new(socket, network)
        .bind(
            test_config(),
            CallerServerSignalingConfig::default(),
            Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap();
    (server, peer, old_expiry)
}

/// Models only the service's finite TURN response; endpoints are never contacted by this control.
fn credentials(username: &str, seconds: u64) -> Value {
    json!({"ExpirationInSeconds":seconds,"TurnAuthServers":[{
        "Username":username,"Password":"fixture-turn-password","Urls":["turn:fixture.invalid:3478"]}]})
}

/// Observes the actual first write before dropping the same borrowed finish wait.
async fn written_request(
    server: &mut MessagingServer,
    peer: &mut test_support::Peer,
    receipt: &TurnRefresh,
) -> Value {
    let finish = server.finish_turn_refresh(receipt);
    tokio::pin!(finish);
    let wire = tokio::select! { biased;
        wire=peer.recv_text()=>wire.unwrap().unwrap(),
        _=&mut finish=>panic!("refresh finished before its actual service response"),
    };
    serde_json::from_str(&wire).unwrap()
}

/// A later actual callback reply proves maintenance processed the earlier correlated result.
async fn completed_while_maintaining(
    server: &mut MessagingServer,
    peer: &mut test_support::Peer,
    response: &str,
) -> (Value, Instant, Instant) {
    let before = Instant::now();
    peer.send_text(response).await.unwrap();
    let marker = "refresh-result-observed";
    peer.send_text(
        &json!({"jsonrpc":"2.0","id":marker,"method":"Fixture_RefreshMarker","params":{}})
            .to_string(),
    )
    .await
    .unwrap();
    let maintenance = server.maintain();
    tokio::pin!(maintenance);
    let wire = tokio::select! { biased;
        wire=peer.recv_text()=>wire.unwrap().unwrap(),
        _=&mut maintenance=>panic!("original service retired before refresh marker reply"),
    };
    let reply: Value = serde_json::from_str(&wire).unwrap();
    (reply, before, Instant::now())
}

/// Retires the same original server and peer before returning the observed outcomes.
async fn close_server(
    server: MessagingServer,
    mut peer: test_support::Peer,
) -> (Result<(), Error>, bool) {
    let mut closing = server.begin_close();
    let peer_close = async {
        let terminal = peer.recv_text().await;
        let closed = peer.close().await;
        matches!(terminal, Ok(None)) && closed.is_ok()
    };
    let (closed, peer_closed) = tokio::join!(closing.finish_close(), peer_close);
    let finished = closing.try_finish().is_ok();
    (closed, peer_closed && finished)
}

/// Fresh actual results survive canceled waits and unrelated maintenance; receipts cannot cross sockets.
#[tokio::test]
async fn turn_refresh_retains_actual_result_and_rejects_cross_server_receipts() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (mut first, mut first_peer, old_first) = cached_server(7).await;
        let (mut second, mut second_peer, old_second) = cached_server(8).await;
        let deadline = Instant::now() + Duration::from_secs(10);
        let first_receipt = first.begin_turn_refresh(deadline).unwrap();
        let second_receipt = second.begin_turn_refresh(deadline).unwrap();
        let cross_refused = matches!(
            second.finish_turn_refresh(&first_receipt).await,
            Err(Error::Admission)
        );
        let still_pending = matches!(second.begin_turn_refresh(deadline), Err(Error::Admission));
        let first_request = written_request(&mut first, &mut first_peer, &first_receipt).await;
        let second_request = written_request(&mut second, &mut second_peer, &second_receipt).await;
        let first_marker = completed_while_maintaining(
            &mut first, &mut first_peer,
            &json!({"jsonrpc":"2.0","id":first_request["id"],"result":credentials("fresh-first",30)}).to_string(),
        ).await;
        let second_marker = completed_while_maintaining(
            &mut second, &mut second_peer,
            &json!({"jsonrpc":"2.0","id":second_request["id"],"result":credentials("fresh-second",30)}).to_string(),
        ).await;
        let first_result = first.finish_turn_refresh(&first_receipt).await;
        let second_result = second.finish_turn_refresh(&second_receipt).await;
        let consumed_refused = matches!(
            first.finish_turn_refresh(&first_receipt).await,
            Err(Error::Admission)
        );
        let elapsed_refused = matches!(
            first.begin_turn_refresh(Instant::now()),
            Err(Error::TimedOut)
        );
        let rejected_receipt = first.begin_turn_refresh(deadline).unwrap();
        let rejected_request = written_request(&mut first, &mut first_peer, &rejected_receipt).await;
        let rejected_marker = completed_while_maintaining(
            &mut first, &mut first_peer,
            &json!({"jsonrpc":"2.0","id":rejected_request["id"],"error":{"code":42}}).to_string(),
        ).await;
        let rejection_preserved = matches!(first.finish_turn_refresh(&rejected_receipt).await, Err(Error::Ice));
        let (first_close, second_close) = tokio::join!(
            close_server(first, first_peer),
            close_server(second, second_peer)
        );

        assert!(cross_refused && still_pending && consumed_refused && elapsed_refused && rejection_preserved);
        assert_eq!(
            first_request["id"], second_request["id"],
            "actual equal numeric IDs must not identify another socket"
        );
        assert_eq!(first_request["method"], second_request["method"]);
        for (reply, _, _) in [&first_marker, &second_marker, &rejected_marker] {
            assert_eq!(
                reply,
                &json!({"jsonrpc":"2.0","id":"refresh-result-observed","result":null})
            );
        }
        let first_result = first_result.unwrap();
        let second_result = second_result.unwrap();
        for (result, name, old, (_, before, after)) in [
            (&first_result, "fresh-first", old_first, first_marker),
            (&second_result, "fresh-second", old_second, second_marker),
        ] {
            assert_eq!(result.servers()[0].username(), name);
            assert_eq!(result.servers()[0].password(), "fixture-turn-password");
            assert!(result.expires_at() < old);
            assert!(result.expires_at() >= before + Duration::from_secs(30));
            assert!(result.expires_at() <= after + Duration::from_secs(30));
        }
        assert!(first_close.0.is_ok() && first_close.1);
        assert!(second_close.0.is_ok() && second_close.1);
    })
    .await
    .expect("finite original TURN refresh fixture stalled");
}
