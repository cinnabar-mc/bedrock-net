use super::*;
use bedrock_services::signaling::{MAX_BATCH_MESSAGES, Messaging};
use futures::{FutureExt, SinkExt, StreamExt};
use nethernet_tokio::{CallerSignaling, CallerSignalingConfig, Signal};
use serde_json::json;
use std::collections::VecDeque;
use tokio::net::{TcpListener, TcpStream};
use tokio_websockets::{ClientBuilder, Message, ServerBuilder};

/// Receives a finite original corpus over actual loopback WebSockets and decodes it with the SDK.
/// Retaining these ready events makes the service burst independent of kernel read pacing.
/// Protected upgrade and SDK heartbeat behavior remain the SDK's separate owning tests.
async fn readable_burst(peer: Uuid, total: usize) -> VecDeque<Event> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let builder = ClientBuilder::new().uri("ws://localhost/fixture").unwrap();
    let server_builder = ServerBuilder::new();
    let (client, server) = tokio::join!(builder.connect_on(tcp), server_builder.accept(server));
    let (mut client, _) = client.unwrap();
    let (_, mut server) = server.unwrap();
    let sending = async {
        for first in (0..total).step_by(MAX_BATCH_MESSAGES) {
            let envelopes: Vec<_> = (first..total.min(first + MAX_BATCH_MESSAGES))
                .map(|index| json!({"From":peer,"Id":Uuid::new_v4(),
                    "Message":json!({"jsonrpc":"2.0","method":"Signaling_WebRtc_v1_0",
                        "params":{"netherNetId":"untrusted-advertised-id",
                            "message":Signal::candidate(9,index.to_string(),peer.to_string()).to_string()}}).to_string()}))
                .collect();
            server
                .send(Message::text(
                    json!({"jsonrpc":"2.0","id":first.to_string(),
                "method":"Signaling_ReceiveMessage_v1_0","params":envelopes})
                    .to_string(),
                ))
                .await
                .unwrap();
            let reply = server.next().await.unwrap().unwrap();
            let reply: serde_json::Value = serde_json::from_slice(reply.as_payload()).unwrap();
            assert_eq!(reply["id"], first.to_string());
            assert!(reply["result"].is_null());
        }
    };
    let receiving = async {
        let mut sdk = Messaging::new(7);
        let mut ready = VecDeque::with_capacity(total);
        while ready.len() < total {
            let frame = client.next().await.unwrap().unwrap();
            for event in sdk.receive(frame.as_payload(), Instant::now()).unwrap() {
                match event {
                    Event::Reply(reply) => client
                        .send(Message::text(reply.as_bytes().to_vec()))
                        .await
                        .unwrap(),
                    Event::Signal(_) => ready.push_back(event),
                    _ => panic!("unexpected fixture event"),
                }
            }
        }
        ready
    };
    let ((), ready) = tokio::join!(sending, receiving);
    ready
}

/// A continuously readable service cannot fill the retained batch while transport capacity is free.
#[tokio::test]
async fn readable_websocket_burst_cannot_starve_ready_transport_admission() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let peer = Uuid::from_u128(1);
        let (caller, mut driver) = CallerSignaling::new(
            "7".into(),
            peer.to_string(),
            CallerSignalingConfig::default(),
        )
        .unwrap();
        let mut signals = caller.signals().unwrap();
        let mut offer = Box::pin(caller.signal(Signal::offer(9, "sdp".into(), peer.to_string())));
        let request = tokio::select! {
            request = driver.recv() => request.unwrap(),
            _ = &mut offer => panic!("offer completed without evidence"),
        };
        request.finish(Ok(SignalDelivery::PeerReceived));
        offer.await.unwrap();
        let total = super::super::incoming::MAX_SIGNALS + 1;
        let mut wire = readable_burst(peer, total).await;
        let mut batch = Batch::default();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut delivered = 0;
        while delivered < total {
            let progress = {
                let waiting = batch.front_mut().map(|front| &mut front.waiting);
                race::step(
                    async {
                        match wire.pop_front() {
                            Some(event) => Ok(SocketStep::Event(Ok(event))),
                            None => pending().await,
                        }
                    },
                    async {
                        match waiting {
                            Some(Some(wait)) => wait.await,
                            _ => pending().await,
                        }
                    },
                )
                .await
            };
            if let Some(admitted) = progress.admitted {
                admitted.unwrap();
                batch.admitted();
                let signal = signals
                    .next()
                    .now_or_never()
                    .flatten()
                    .expect("actual admission must make one transport signal available");
                assert_eq!(signal.data, delivered.to_string());
                delivered += 1;
                // Receipt completion is immediate in this admission-only fixture.
                batch.acknowledged();
            }
            if let Some(event) = progress.socket {
                let SocketStep::Event(Ok(Event::Signal(signal))) = event.unwrap() else {
                    panic!("unexpected service action")
                };
                let result = batch.push(&driver, signal, deadline);
                assert!(
                    result.is_ok(),
                    "ready transport admission starved: {result:?}"
                );
            }
        }
        assert!(wire.is_empty());
        assert!(batch.front_mut().is_none());
        assert!(signals.next().now_or_never().is_none());
        driver.close();
    })
    .await
    .expect("bounded socket burst must finish");
}

/// A known terminal admission cannot dispatch another socket action in the same turn.
#[tokio::test]
async fn failed_admission_stops_before_socket_dispatch() {
    let (dispatched, mut observed) = tokio::sync::oneshot::channel();
    let progress = race::step(
        async move {
            dispatched.send(()).unwrap();
            Ok(SocketStep::Acknowledged)
        },
        std::future::ready(Err(CallerSignalingError::Closed)),
    )
    .await;
    assert!(matches!(
        progress.admitted,
        Some(Err(CallerSignalingError::Closed))
    ));
    assert!(progress.socket.is_none());
    assert!(matches!(
        observed.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Closed)
    ));
}

/// An actual accepted transport signal survives a socket terminal observed in that same turn.
#[tokio::test]
async fn socket_terminal_retains_simultaneous_actual_transport_handoff() {
    let peer = Uuid::from_u128(1);
    let (caller, mut driver) = CallerSignaling::new(
        "7".into(),
        peer.to_string(),
        CallerSignalingConfig::default(),
    )
    .unwrap();
    let mut signals = caller.signals().unwrap();
    let mut offer = Box::pin(caller.signal(Signal::offer(9, "sdp".into(), peer.to_string())));
    let request = tokio::select! {
        request = driver.recv() => request.unwrap(),
        _ = &mut offer => panic!("offer completed without evidence"),
    };
    request.finish(Ok(SignalDelivery::PeerReceived));
    offer.await.unwrap();
    let delivery = driver
        .prepare_delivery_before(
            &peer.to_string(),
            &Signal::candidate(9, "accepted-prefix".into(), peer.to_string()).to_string(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    let progress = race::step(std::future::ready(Err(Error::Closed)), delivery).await;
    assert!(matches!(progress.admitted, Some(Ok(()))));
    assert!(matches!(progress.socket, Some(Err(Error::Closed))));
    assert_eq!(
        signals.next().now_or_never().flatten().unwrap().data,
        "accepted-prefix"
    );
    driver.close();
}
