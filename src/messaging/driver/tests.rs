use super::*;
use bedrock_services::signaling::{Messaging, Outgoing, ReceivedSignal};
use futures::{FutureExt, StreamExt};
use nethernet_tokio::{CallerSignaling, CallerSignalingConfig, Signal};
use serde_json::{Value, json};
use std::time::Duration;

/// Encodes original synthetic service callbacks without a socket or account.
fn incoming(state: &mut Messaging, peer: Uuid, method: &str, params: Value) -> Vec<Event> {
    let wire = json!({"jsonrpc":"2.0", "id":"callback", "method":"Signaling_ReceiveMessage_v1_0",
        "params":{"From":peer,"Id":Uuid::new_v4(),"Message":json!({
            "jsonrpc":"2.0","method":method,"params":params}).to_string()}});
    state
        .receive(&serde_json::to_vec(&wire).unwrap(), Instant::now())
        .unwrap()
}

/// Uses the actual SDK request ID rather than inventing a parallel correlation counter.
fn accepted(state: &mut Messaging, outgoing: &Outgoing) -> Vec<Event> {
    let request: Value = serde_json::from_slice(outgoing.as_bytes()).unwrap();
    state
        .receive(
            &serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":request["id"], "result":null}))
                .unwrap(),
            Instant::now(),
        )
        .unwrap()
}

/// Extracts a decoded SDK envelope, keeping its authenticated sender and advertised network ID distinct.
fn received(state: &mut Messaging, peer: Uuid, advertised: &str, wire: &str) -> ReceivedSignal {
    incoming(
        state,
        peer,
        "Signaling_WebRtc_v1_0",
        json!({"netherNetId":advertised,"message":wire}),
    )
    .into_iter()
    .find_map(|event| match event {
        Event::Signal(signal) => Some(signal),
        _ => None,
    })
    .unwrap()
}

/// Exercises both real state owners: offers need service plus matching-peer receipt;
/// inbound routing follows envelope UUID and connection ID, never advertised IDs.
#[tokio::test]
async fn sdk_completion_and_envelope_identity_reach_the_existing_caller_owner() {
    let peer = Uuid::from_u128(1);
    let (caller, mut driver) = CallerSignaling::new(
        "7".into(),
        peer.to_string(),
        CallerSignalingConfig::default(),
    )
    .unwrap();
    let mut signals = caller.signals().unwrap();
    let sending = caller.signal(Signal::offer(9, "opaque-sdp".into(), peer.to_string()));
    tokio::pin!(sending);
    let request = tokio::select! {
        request = driver.recv() => request.unwrap(),
        _ = &mut sending => panic!("offer completed without service evidence"),
    };
    let mut state = Messaging::new(7);
    let message = Uuid::from_u128(2);
    let outgoing = state
        .send_signal(
            peer,
            message,
            &request.signal().to_string(),
            request.requires_peer_receipt(),
            request.deadline(),
        )
        .unwrap();
    assert!(
        !accepted(&mut state, &outgoing)
            .iter()
            .any(|event| matches!(event, Event::Completed { .. }))
    );
    assert!(
        !incoming(
            &mut state,
            Uuid::from_u128(3),
            "Signaling_DeliveryNotification_V1_0",
            json!({"messageId":message})
        )
        .iter()
        .any(|event| matches!(event, Event::Completed { .. }))
    );
    let completion = incoming(
        &mut state,
        peer,
        "Signaling_DeliveryNotification_V1_0",
        json!({"messageId":message}),
    );
    let result = completion
        .into_iter()
        .find_map(|event| match event {
            Event::Completed {
                request: id,
                result,
            } if Some(id) == outgoing.request_id() => Some(result),
            _ => None,
        })
        .unwrap();
    complete(request, result);
    sending.await.unwrap();
    let signal = received(
        &mut state,
        peer,
        "untrusted-advertised-id",
        &Signal::candidate(9, "candidate-data".into(), peer.to_string()).to_string(),
    );
    assert!(admit(&driver, &signal).unwrap());
    assert_eq!(signals.next().await.unwrap().network_id, peer.to_string());
    let wrong = received(
        &mut state,
        Uuid::from_u128(3),
        &peer.to_string(),
        &Signal::candidate(9, "wrong-peer".into(), peer.to_string()).to_string(),
    );
    assert!(!admit(&driver, &wrong).unwrap());
    let stale = received(
        &mut state,
        peer,
        "7",
        &Signal::candidate(10, "old-connection".into(), peer.to_string()).to_string(),
    );
    assert!(!admit(&driver, &stale).unwrap());
    assert!(signals.next().now_or_never().is_none());
    driver.close();
    assert!(signals.next().await.is_none());
}

/// Abandoning a transport wait retires its held request and explicit SDK handle,
/// without converting a late service success into new delivery evidence.
#[tokio::test]
async fn dropped_transport_wait_cancels_the_correlated_sdk_request_once() {
    let peer = Uuid::from_u128(1);
    let (caller, mut driver) = CallerSignaling::new(
        "7".into(),
        peer.to_string(),
        CallerSignalingConfig::default(),
    )
    .unwrap();
    let _signals = caller.signals().unwrap();
    let mut sending =
        Box::pin(caller.signal(Signal::offer(9, "opaque-sdp".into(), peer.to_string())));
    let request = tokio::select! {
        request = driver.recv() => request.unwrap(),
        _ = &mut sending => panic!("offer completed without service evidence"),
    };
    let mut state = Messaging::new(7);
    let outgoing = state
        .send_signal(
            peer,
            Uuid::from_u128(2),
            &request.signal().to_string(),
            true,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    drop(sending);
    assert!(request.is_cancelled());
    assert!(state.cancel(outgoing.request_id().unwrap()));
    assert!(
        !accepted(&mut state, &outgoing)
            .iter()
            .any(|event| matches!(event, Event::Completed { .. }))
    );
    drop(request);
    driver.close();
}
