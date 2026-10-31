use super::*;
use bedrock_services::signaling::{Messaging, Outgoing, ReceivedSignal};
use futures::{FutureExt, StreamExt};
use nethernet_tokio::{CallerSignaling, CallerSignalingConfig, Signal};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

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
    let mut batch = Batch::default();
    batch
        .push(&driver, signal, Instant::now() + Duration::from_secs(5))
        .unwrap();
    batch
        .front_mut()
        .unwrap()
        .waiting
        .as_mut()
        .unwrap()
        .await
        .unwrap();
    batch.admitted();
    assert!(batch.front_mut().unwrap().waiting.is_none());
    assert_eq!(signals.next().await.unwrap().network_id, peer.to_string());
    let wrong = received(
        &mut state,
        Uuid::from_u128(3),
        &peer.to_string(),
        &Signal::candidate(9, "wrong-peer".into(), peer.to_string()).to_string(),
    );
    batch.acknowledged();
    batch
        .push(&driver, wrong, Instant::now() + Duration::from_secs(5))
        .unwrap();
    assert!(batch.front_mut().is_none());
    let stale = received(
        &mut state,
        peer,
        "7",
        &Signal::candidate(10, "old-connection".into(), peer.to_string()).to_string(),
    );
    batch
        .push(&driver, stale, Instant::now() + Duration::from_secs(5))
        .unwrap();
    assert!(batch.front_mut().is_none());
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

/// One actual SDK callback batch crosses the caller's smaller queue without capacity failure or reordering.
#[tokio::test]
async fn a_complete_sdk_signal_batch_waits_for_transport_capacity_in_order() {
    let peer = Uuid::from_u128(1);
    let config = CallerSignalingConfig::default();
    let capacity = config.capacity.get();
    let (caller, mut driver) = CallerSignaling::new("7".into(), peer.to_string(), config).unwrap();
    let mut signals = caller.signals().unwrap();
    let mut offer = Box::pin(caller.signal(Signal::offer(9, "sdp".into(), peer.to_string())));
    let request = tokio::select! {
        request = driver.recv() => request.unwrap(),
        _ = &mut offer => panic!("offer completed without service evidence"),
    };
    request.finish(Ok(SignalDelivery::PeerReceived));
    offer.await.unwrap();
    let envelopes: Vec<_> = (0..capacity * 2).map(|index| json!({
        "From":peer,"Id":Uuid::new_v4(),"Message":json!({"jsonrpc":"2.0",
            "method":"Signaling_WebRtc_v1_0","params":{"netherNetId":"untrusted-advertised-id",
                "message":Signal::candidate(9,index.to_string(),peer.to_string()).to_string()}}).to_string()
    })).collect();
    let wire = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":"batch",
        "method":"Signaling_ReceiveMessage_v1_0","params":envelopes}))
    .unwrap();
    let mut sdk = Messaging::new(7);
    let mut batch = Batch::default();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut retained = 0;
    for event in sdk.receive(&wire, Instant::now()).unwrap() {
        if let Event::Signal(signal) = event {
            batch.push(&driver, signal, deadline).unwrap();
            retained += 1;
        }
    }
    assert_eq!(retained, capacity * 2);
    let handoff = async {
        while let Some(front) = batch.front_mut() {
            front.waiting.as_mut().unwrap().await.unwrap();
            batch.admitted();
            assert!(batch.front_mut().unwrap().waiting.is_none());
            // The socket step acknowledges only this already handed-off envelope.
            batch.acknowledged();
        }
    };
    let receive = async {
        for index in 0..capacity * 2 {
            assert_eq!(signals.next().await.unwrap().data, index.to_string());
        }
    };
    futures::join!(handoff, receive);
    assert!(batch.front_mut().is_none());

    for index in 0..capacity {
        driver
            .try_deliver(
                &peer.to_string(),
                &Signal::candidate(9, index.to_string(), peer.to_string()).to_string(),
            )
            .unwrap();
    }
    let signal = received(
        &mut sdk,
        peer,
        "7",
        &Signal::candidate(9, "abandoned".into(), peer.to_string()).to_string(),
    );
    batch.push(&driver, signal, deadline).unwrap();
    assert!(futures::poll!(batch.front_mut().unwrap().waiting.as_mut().unwrap()).is_pending());
    batch.clear();
    for index in 0..capacity {
        assert_eq!(signals.next().await.unwrap().data, index.to_string());
    }
    assert!(signals.next().now_or_never().is_none());
    driver.close();
}

/// A retired subscription's real prepared route cannot close a fresh unrelated route or issue a receipt.
#[tokio::test]
async fn stale_accepting_admission_preserves_the_shared_service_and_healthy_route() {
    use bedrock_services::signaling::websocket::test_support;
    use nethernet_tokio::{CallerServerSignaling, CallerServerSignalingConfig};

    tokio::time::timeout(Duration::from_secs(10), async {
        let stale_peer = Uuid::from_u128(21);
        let healthy_peer = Uuid::from_u128(22);
        let network_id = 7;
        let (socket, mut peer) = test_support::pair(network_id).await;
        let (caller, caller_driver) = CallerServerSignaling::new(
            network_id.to_string(),
            CallerServerSignalingConfig::default(),
        )
        .unwrap();
        let mut old_subscription = caller.signals().unwrap();
        caller_driver
            .try_deliver(
                &stale_peer.to_string(),
                &Signal::offer(9, "original route".into(), stale_peer.to_string()).to_string(),
            )
            .unwrap();
        assert_eq!(
            old_subscription.next().await.unwrap().data,
            "original route"
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut sdk = Messaging::new(network_id);
        let stale = received(
            &mut sdk,
            stale_peer,
            "untrusted advertised id",
            &Signal::candidate(9, "late candidate".into(), stale_peer.to_string()).to_string(),
        );
        let mut retained = Batch::default();
        retained
            .push_server(&caller_driver, stale, deadline)
            .unwrap();
        assert!(retained.front_mut().unwrap().waiting.is_some());

        // The actual subscription owner removes its unclaimed route. The retained
        // admission still carries the original route and subscription epochs.
        drop(old_subscription);
        let mut healthy_subscription = caller.signals().unwrap();
        caller_driver
            .try_deliver(
                &healthy_peer.to_string(),
                &Signal::offer(10, "healthy route".into(), healthy_peer.to_string()).to_string(),
            )
            .unwrap();
        let mut service = Driver::server(
            socket,
            caller_driver,
            Duration::from_secs(5),
            std::future::pending(),
        );
        service.incoming = retained;
        let healthy_offer = service
            .run(healthy_subscription.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(healthy_offer.network_id, healthy_peer.to_string());
        assert_eq!(healthy_offer.data, "healthy route");
        assert!(
            service.failure().is_none(),
            "one stale accepting admission retired the shared service: {:?}",
            service.failure()
        );
        assert!(service.incoming.front_mut().is_none());

        let healthy = received(
            &mut sdk,
            healthy_peer,
            "another untrusted advertised id",
            &Signal::candidate(10, "still usable".into(), healthy_peer.to_string()).to_string(),
        );
        service
            .socket_progress(Ok(SocketStep::Event(Ok(Event::Signal(healthy)))))
            .unwrap();
        let candidate = service
            .run(healthy_subscription.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(candidate.network_id, healthy_peer.to_string());
        assert_eq!(candidate.data, "still usable");
        assert!(service.failure().is_none());

        let receipt = service
            .run(peer.recv_text())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let receipt: Value = serde_json::from_str(&receipt).unwrap();
        assert_eq!(receipt["method"], "Signaling_SendClientMessage_v1_0");
        assert_eq!(receipt["params"]["toPlayerId"], healthy_peer.to_string());
        let inner: Value =
            serde_json::from_str(receipt["params"]["message"].as_str().unwrap()).unwrap();
        assert_eq!(inner["method"], "Signaling_DeliveryNotification_V1_0");
        assert!(service.incoming.front_mut().is_none());
        service.close();
        assert!(healthy_subscription.next().await.is_none());
        let _ = peer.close().await;
    })
    .await
    .expect("finite stale accepting-route fixture stalled");
}

#[tokio::test]
async fn ready_application_output_does_not_postpone_signal_writes() {
    use bedrock_services::signaling::websocket::test_support;
    let peer_id = Uuid::from_u128(1);
    let (socket, mut peer) = test_support::pair(7).await;
    let config = CallerSignalingConfig::default();
    let (caller, caller_driver) =
        CallerSignaling::new("7".into(), peer_id.to_string(), config).unwrap();
    let _signals = caller.signals().unwrap();
    let mut sending = Box::pin(caller.signal(Signal::offer(9, "sdp".into(), peer_id.to_string())));
    assert!(futures::poll!(&mut sending).is_pending());
    let mut driver = Driver::new(
        socket,
        caller_driver,
        Recipient::Messaging(peer_id),
        config.send_timeout,
        Instant::now() + Duration::from_secs(5),
    );
    assert_eq!(driver.run(std::future::ready(7)).await.unwrap(), 7);
    assert!(
        driver.outgoing.is_none(),
        "ready output deferred signal admission"
    );
    let wire = tokio::time::timeout(Duration::from_secs(1), peer.recv_text())
        .await
        .expect("same driver poll must write the signal")
        .unwrap()
        .unwrap();
    assert!(wire.contains("sdp"));
}

#[tokio::test]
async fn receipt_admission_drives_its_wire_write_before_returning() {
    use bedrock_services::signaling::websocket::test_support;
    let peer_id = Uuid::from_u128(1);
    let (mut socket, mut peer) = test_support::pair(7).await;
    let signal = received(
        &mut Messaging::new(7),
        peer_id,
        "7",
        &Signal::offer(9, "sdp".into(), peer_id.to_string()).to_string(),
    );
    let step = socket_step(
        &mut socket,
        Some((
            &signal,
            Uuid::from_u128(2),
            Instant::now() + Duration::from_secs(5),
        )),
        None,
    )
    .await
    .unwrap();
    assert!(matches!(step, SocketStep::Acknowledged(_)));
    let wire = tokio::time::timeout(Duration::from_secs(1), peer.recv_text())
        .await
        .expect("receipt must reach the wire in its admission poll")
        .unwrap()
        .unwrap();
    assert!(wire.contains("Signaling_DeliveryNotification"));
}
