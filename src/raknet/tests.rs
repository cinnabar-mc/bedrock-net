//! Regressions for terminal packet draining and cancellation of graceful close.

use std::future::{Future, poll_fn};
use std::net::Ipv4Addr;
use std::task::Poll;

use ::raknet::prelude::{
    ClientGuid, RakClient, RakClientInput, RakClientOutput, RakClock, RakServer, RakServerConfig,
    RakServerInput, RakServerOutput,
};

use ::raknet::test_support::send_bundle;

use super::*;

std::thread_local! {
    static MAINTENANCE_PASSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Counts full maintenance passes independently of burst size and elapsed time.
pub(super) fn record_maintenance_pass() {
    MAINTENANCE_PASSES.with(|passes| passes.set(passes.get() + 1));
}

#[tokio::test(start_paused = true)]
async fn congested_send_burst_does_not_repeat_full_maintenance() {
    for count in [256, 512, 1024, 2048] {
        let (mut connection, _peer, _sender) = connected_pair().await;
        // Fill the initial congestion window without processing any acknowledgements.
        for _ in 0..64 {
            connection
                .queue_send(Bytes::from(vec![0xfe; 1024]))
                .unwrap();
        }
        let retained = connection.engine.session.as_ref().unwrap().outbound_bytes();
        let now = Instant::now();
        MAINTENANCE_PASSES.set(0);
        for _ in 0..count {
            connection
                .queue_send(Bytes::from_static(&[0xfe; 64]))
                .unwrap();
        }
        assert!(
            connection.engine.session.as_ref().unwrap().outbound_bytes() >= retained + count * 64,
            "the unacknowledged burst must remain retained under congestion"
        );
        assert_eq!(Instant::now(), now);
        assert_eq!(
            MAINTENANCE_PASSES.get(),
            0,
            "send admission must not revisit retained traffic through full maintenance"
        );
        connection.flush().await.unwrap();
        assert_eq!(
            MAINTENANCE_PASSES.get(),
            1,
            "explicit maintenance still runs"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn queued_send_reaches_the_socket_with_an_unread_receive_backlog() {
    let (mut connection, peer, mut sender) = connected_pair().await;
    let backlog = Bytes::from_static(b"unread input");
    connection.engine.incoming.push_back(backlog.clone());
    connection.engine.incoming_bytes = backlog.len();
    let start = Instant::now();
    let message = Bytes::from_static(&[0xfe, 42]);
    connection.queue_send(message.clone()).unwrap();
    let mut buffer = [0; UDP_BUFFER_BYTES];
    let mut received = None;
    // Poll only the peer and reactor; the sending connection is never driven again.
    for _ in 0..128 {
        match peer.try_recv(&mut buffer) {
            Ok(length) => {
                sender
                    .handle(RakSessionInput::Datagram(
                        buffer[..length].into(),
                        start.into_std(),
                    ))
                    .unwrap();
                while let Some(output) = sender.poll() {
                    if let RakSessionOutput::Packet(bytes) = output {
                        received = Some(bytes);
                    }
                }
                if received.is_some() {
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::task::yield_now().await;
            }
            Err(error) => panic!("peer receive failed: {error}"),
        }
    }
    assert_eq!(received.as_deref(), Some(message.as_ref()));
    assert_eq!(Instant::now(), start);
    assert_eq!(connection.engine.incoming.front(), Some(&backlog));
    assert_eq!(connection.recv().await.unwrap(), backlog);
}

/// Establishes both core owners through public negotiation before attaching real UDP sockets.
async fn connected_pair() -> (RakNetConnection, UdpSocket, RakSession<Established>) {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let local = socket.local_addr().unwrap();
    let address = peer.local_addr().unwrap();
    socket.connect(address).await.unwrap();
    peer.connect(local).await.unwrap();
    socket.writable().await.unwrap();
    let now = Instant::now().into_std();
    let mut client = RakClient::new(RakClientConfig::default(), RakClock::new(now))
        .unwrap()
        .connect(address, local, ClientGuid::from_raw(1 << 63), now)
        .unwrap();
    let mut server =
        RakServer::new(RakServerConfig::default(), address, RakClock::new(now), now).unwrap();
    let mut receiver: Option<RakSession<Established>> = None;
    let mut sender: Option<RakSession<Established>> = None;
    for _ in 0..128 {
        let mut moved = false;
        while let Some(output) = client.poll() {
            match output {
                RakClientOutput::MtuProbe { id, datagram, .. } => {
                    client
                        .handle(RakClientInput::MtuProbeResult {
                            id,
                            now,
                            elapsed: Duration::ZERO,
                            too_large: false,
                        })
                        .unwrap();
                    server
                        .handle(RakServerInput::Datagram(datagram, local, now))
                        .unwrap();
                    moved = true;
                }
                RakClientOutput::SocketDatagram(bytes, _) => {
                    server
                        .handle(RakServerInput::Datagram(bytes, local, now))
                        .unwrap();
                    moved = true;
                }
                RakClientOutput::SessionConnected(session) => receiver = Some(session),
                RakClientOutput::SessionDatagram(bytes) => {
                    receiver
                        .as_mut()
                        .unwrap()
                        .handle(RakSessionInput::Datagram(bytes, now))
                        .unwrap();
                }
                RakClientOutput::SessionClosing(_) => panic!("fresh client negotiation closed"),
                RakClientOutput::Wait(_) | RakClientOutput::Pong { .. } => {}
            }
        }
        while let Some(output) = server.poll() {
            match output {
                RakServerOutput::SocketDatagram(bytes, _) => {
                    client
                        .handle(RakClientInput::Datagram(bytes, address, now))
                        .unwrap();
                    moved = true;
                }
                RakServerOutput::SessionDatagram(bytes, _) => {
                    sender
                        .as_mut()
                        .unwrap()
                        .handle(RakSessionInput::Datagram(bytes, now))
                        .unwrap();
                }
                RakServerOutput::SessionConnected(session) => sender = Some(session),
                RakServerOutput::SessionClosing(_) => panic!("fresh server negotiation closed"),
            }
        }
        if let Some(session) = &mut receiver {
            session.tick(now).unwrap();
            while let Some(output) = session.poll() {
                if let RakSessionOutput::Datagram(bytes, _) = output {
                    server
                        .handle(RakServerInput::Datagram(bytes, local, now))
                        .unwrap();
                    moved = true;
                }
            }
        }
        if let Some(session) = &mut sender {
            session.tick(now).unwrap();
            while let Some(output) = session.poll() {
                if let RakSessionOutput::Datagram(bytes, _) = output {
                    client
                        .handle(RakClientInput::Datagram(bytes, address, now))
                        .unwrap();
                    moved = true;
                }
            }
        }
        if !moved {
            match (receiver, sender) {
                (Some(receiver), Some(sender)) => {
                    assert_eq!(receiver.outbound_bytes(), 0);
                    assert_eq!(sender.outbound_bytes(), 0);
                    return (
                        RakNetConnection {
                            engine: Box::new(Engine {
                                socket: Some(socket),
                                local,
                                peer: address,
                                session: Some(SessionSlot::Established(receiver)),
                                options: RakNetOptions::default(),
                                incoming: VecDeque::new(),
                                incoming_bytes: 0,
                                pending_message: None,
                                pending_datagram: None,
                                receive_buffer: vec![0; UDP_BUFFER_BYTES],
                                next_tick: Instant::now(),
                                close_deadline: None,
                                failure: None,
                                rtt: RttObservation::new(),
                            }),
                        },
                        peer,
                        sender,
                    );
                }
                (partial_receiver, partial_sender) => {
                    receiver = partial_receiver;
                    sender = partial_sender;
                }
            }
        }
    }
    panic!("public negotiation did not complete within the controlled work bound");
}

#[tokio::test]
async fn active_receive_drains_a_legal_datagram_larger_than_its_staging_count() {
    let (mut connection, peer, mut sender) = connected_pair().await;
    let count = connection.engine.options.receive_buffer_messages + 1;
    let now = Instant::now().into_std();
    send_bundle(
        &mut sender,
        (0..count).map(|index| {
            let mut message = vec![0xfe];
            message.extend_from_slice(&u32::try_from(index).unwrap().to_le_bytes());
            message.into_boxed_slice()
        }),
        now,
    );
    let mut sent = 0;
    while let Some(output) = sender.poll() {
        if let RakSessionOutput::Datagram(datagram, _) = output {
            peer.send(&datagram).await.unwrap();
            sent += 1;
        }
    }
    assert_eq!(
        sent, 1,
        "the real core packed the complete controlled burst"
    );
    for index in 0..count {
        let message = connection.recv().await.unwrap();
        assert_eq!(message[0], 0xfe);
        assert_eq!(&message[1..], &u32::try_from(index).unwrap().to_le_bytes());
    }
}

#[tokio::test]
async fn completed_burst_precedes_the_peers_graceful_close() {
    let (mut connection, peer, mut sender) = connected_pair().await;
    let count = connection.engine.options.receive_buffer_messages + 1;
    let now = Instant::now().into_std();
    send_bundle(
        &mut sender,
        (0..count).map(|index| {
            let mut message = vec![0xfe];
            message.extend_from_slice(&u32::try_from(index).unwrap().to_le_bytes());
            message.into_boxed_slice()
        }),
        now,
    );
    let mut sent = 0;
    while let Some(output) = sender.poll() {
        if let RakSessionOutput::Datagram(datagram, _) = output {
            peer.send(&datagram).await.unwrap();
            sent += 1;
        }
    }
    assert_eq!(
        sent, 1,
        "the real core packed the complete controlled burst"
    );
    let mut sender = sender.close(now).unwrap();
    let closing_peer = async {
        let mut buffer = [0; UDP_BUFFER_BYTES];
        loop {
            sender
                .handle(RakSessionInput::Update(Instant::now().into_std()))
                .unwrap();
            while let Some(output) = sender.poll() {
                if let RakSessionOutput::Datagram(datagram, _) = output {
                    peer.send(&datagram).await.unwrap();
                }
            }
            if sender.state() == RakSessionState::Disconnected {
                break;
            }
            let length = peer.recv(&mut buffer).await.unwrap();
            sender
                .handle(RakSessionInput::Datagram(
                    buffer[..length].into(),
                    Instant::now().into_std(),
                ))
                .unwrap();
        }
    };
    let receiving = async {
        for index in 0..count {
            let message = connection.recv().await.unwrap();
            assert_eq!(message[0], 0xfe);
            assert_eq!(&message[1..], &u32::try_from(index).unwrap().to_le_bytes());
        }
        assert!(matches!(
            connection.recv().await,
            Err(RakNetError::Disconnected(DisconnectReason::Remote))
        ));
        assert!(matches!(connection.recv().await, Err(RakNetError::Closed)));
    };
    tokio::join!(closing_peer, receiving);
}

#[tokio::test(start_paused = true)]
async fn expired_close_retains_the_completed_burst_before_its_original_terminal() {
    let (mut connection, peer, mut sender) = connected_pair().await;
    let count = connection.engine.options.receive_buffer_messages + 1;
    connection
        .queue_send(Bytes::from_static(&[0xfe, 0x7f]))
        .unwrap();
    let mut connection = connection.begin_close().unwrap();
    let deadline = connection.engine.close_deadline.unwrap();
    connection.flush().await.unwrap();
    let now = Instant::now().into_std();
    send_bundle(
        &mut sender,
        (0..count).map(|index| {
            let mut message = vec![0xfe];
            message.extend_from_slice(&u32::try_from(index).unwrap().to_le_bytes());
            message.into_boxed_slice()
        }),
        now,
    );
    let mut sent = 0;
    let mut buffer = [0; UDP_BUFFER_BYTES];
    while let Some(output) = sender.poll() {
        if let RakSessionOutput::Datagram(datagram, _) = output {
            peer.send(&datagram).await.unwrap();
            let length = connection
                .engine
                .socket
                .as_ref()
                .unwrap()
                .recv(&mut buffer)
                .await
                .unwrap();
            connection
                .engine
                .session
                .as_mut()
                .unwrap()
                .handle(RakSessionInput::Datagram(buffer[..length].into(), now))
                .unwrap();
            sent += 1;
        }
    }
    assert_eq!(
        sent, 1,
        "the real core packed the complete controlled burst"
    );
    tokio::time::advance(
        deadline.saturating_duration_since(Instant::now()) + Duration::from_nanos(1),
    )
    .await;
    connection.finish_close().await.unwrap();
    let Err(mut connection) = connection.try_finish() else {
        panic!("retirement discarded the unread accepted burst");
    };
    for index in 0..count {
        let message = connection.recv().await.unwrap();
        assert_eq!(message[0], 0xfe);
        assert_eq!(&message[1..], &u32::try_from(index).unwrap().to_le_bytes());
    }
    let Err(mut connection) = connection.try_finish() else {
        panic!("retirement discarded the original unobserved terminal");
    };
    assert!(matches!(
        connection.recv().await,
        Err(RakNetError::Disconnected(DisconnectReason::Requested))
    ));
    assert!(matches!(connection.recv().await, Err(RakNetError::Closed)));
    let Ok(closed) = connection.try_finish() else {
        panic!("drained retirement did not finish");
    };
    UdpSocket::bind(closed.local_addr()).await.unwrap();
}

#[tokio::test]
async fn receive_aggregate_pressure_returns_every_original_message() {
    let (mut connection, peer, mut sender) = connected_pair().await;
    connection.engine.options.receive_buffer_bytes = 64;
    let now = Instant::now().into_std();
    send_bundle(
        &mut sender,
        [vec![0xfe, 1], vec![0xfe; 63], vec![0xfe, 3]]
            .into_iter()
            .map(Vec::into_boxed_slice),
        now,
    );
    let mut sent = 0;
    while let Some(output) = sender.poll() {
        if let RakSessionOutput::Datagram(datagram, _) = output {
            peer.send(&datagram).await.unwrap();
            sent += 1;
        }
    }
    assert_eq!(sent, 1);
    assert_eq!(
        connection.recv().await.unwrap(),
        Bytes::from_static(&[0xfe, 1])
    );
    assert_eq!(connection.recv().await.unwrap().as_ref(), vec![0xfe; 63]);
    assert_eq!(connection.recv().await.unwrap().as_ref(), [0xfe, 3]);
    let mut closing = connection.begin_close().unwrap();
    closing.finish_close().await.unwrap();
    drop((closing, peer, sender));
}

#[tokio::test]
async fn individually_oversized_message_rejects_only_after_its_accepted_prefix() {
    let (mut connection, peer, mut sender) = connected_pair().await;
    connection.engine.options.receive_buffer_bytes = 64;
    let now = Instant::now().into_std();
    send_bundle(
        &mut sender,
        [vec![0xfe, 1], vec![0xfe; 65], vec![0xfe, 3]]
            .into_iter()
            .map(Vec::into_boxed_slice),
        now,
    );
    let mut sent = 0;
    while let Some(output) = sender.poll() {
        if let RakSessionOutput::Datagram(datagram, _) = output {
            peer.send(&datagram).await.unwrap();
            sent += 1;
        }
    }
    assert_eq!(sent, 1);
    assert_eq!(
        connection.recv().await.unwrap(),
        Bytes::from_static(&[0xfe, 1])
    );
    assert!(matches!(
        connection.recv().await,
        Err(RakNetError::ReceiveBufferExceeded)
    ));
    assert!(matches!(connection.recv().await, Err(RakNetError::Closed)));
    let local = connection.local_addr();
    drop((connection, peer, sender));
    UdpSocket::bind(local).await.unwrap();
}

#[tokio::test]
async fn completed_message_precedes_a_later_frame_error_in_the_same_datagram() {
    let (mut connection, peer, mut sender) = connected_pair().await;
    let now = Instant::now().into_std();
    send_bundle(
        &mut sender,
        [Box::from([0xfe, 42].as_slice()), Box::from([0].as_slice())],
        now,
    );
    let mut sent = 0;
    while let Some(output) = sender.poll() {
        if let RakSessionOutput::Datagram(datagram, _) = output {
            peer.send(&datagram).await.unwrap();
            sent += 1;
        }
    }
    assert_eq!(sent, 1, "both frames exercise a single handler call");
    assert_eq!(
        connection.recv().await.unwrap(),
        Bytes::from_static(&[0xfe, 42])
    );
    assert!(matches!(
        connection.recv().await,
        Err(RakNetError::Session(_))
    ));
    assert!(matches!(connection.recv().await, Err(RakNetError::Closed)));
    UdpSocket::bind(connection.local_addr()).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn cancelled_close_keeps_its_deadline_when_recv_resumes_driving() {
    let (mut connection, _peer, mut sender) = connected_pair().await;
    connection.engine.options.close_timeout = Duration::from_millis(100);
    connection
        .queue_send(Bytes::from_static(&[0xfe, 1]))
        .unwrap();
    let mut connection = connection.begin_close().unwrap();
    let mut closing = Box::pin(connection.finish_close());
    poll_fn(|cx| {
        assert!(closing.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(closing);
    // Model a completed input whose outputs have not yet been collected when close expires.
    let now = Instant::now().into_std();
    sender
        .send(
            Box::new([0xfe, 2]),
            RakReliability::ReliableOrdered,
            RakPriority::Normal,
            now,
        )
        .unwrap();
    sender.tick(now).unwrap();
    while let Some(output) = sender.poll() {
        if let RakSessionOutput::Datagram(datagram, _) = output {
            connection
                .engine
                .session
                .as_mut()
                .unwrap()
                .handle(RakSessionInput::Datagram(datagram, now))
                .unwrap();
        }
    }
    tokio::time::advance(Duration::from_millis(101)).await;
    let mut receiving = Box::pin(connection.recv());
    let result = poll_fn(|cx| match receiving.as_mut().poll(cx) {
        Poll::Ready(result) => Poll::Ready(result),
        Poll::Pending => panic!("expired close deadline retained the socket"),
    })
    .await;
    assert_eq!(result.unwrap(), Bytes::from_static(&[0xfe, 2]));
    drop(receiving);
    let Err(mut connection) = connection.try_finish() else {
        panic!("close completion discarded the unobserved terminal");
    };
    assert!(matches!(
        connection.recv().await,
        Err(RakNetError::Disconnected(DisconnectReason::Requested))
    ));
    let Ok(closed) = connection.try_finish() else {
        panic!("drained local retirement did not finish");
    };
    UdpSocket::bind(closed.local_addr()).await.unwrap();
}

/// Uses a genuinely negotiated owner and bound socket, not a readiness flag surrogate.
#[tokio::test(start_paused = true)]
async fn ready_connection_cannot_escape_original_connect_deadline() {
    for delayed in [false, true] {
        let (connection, _peer, _session) = connected_pair().await;
        let local = connection.local_addr();
        let deadline = Instant::now() + Duration::from_millis(10);
        let ready = std::future::ready(Ok(connection));
        if delayed {
            tokio::time::advance(Duration::from_millis(11)).await;
        }
        let result = connect::finish_connect(deadline, ready).await;
        if delayed {
            assert!(
                matches!(result, Err(RakNetError::ConnectTimeout)),
                "ready connection escaped the original connect deadline"
            );
        } else {
            let connection = result.expect("timely ready connection remains admitted");
            assert_eq!(connection.local_addr(), local);
            drop(connection);
        }
        UdpSocket::bind(local)
            .await
            .expect("expired or dropped connection releases its socket");
    }
}

/// Uses actual acknowledged traffic and the runtime clock, then retains the observation across retirement.
#[tokio::test(start_paused = true)]
async fn rtt_observation_uses_original_ack_estimate_and_retires_with_owner() {
    let (mut connection, peer, mut sender) = connected_pair().await;
    let observation = connection.observe_rtt();
    assert_eq!(observation.get(), None);
    connection
        .queue_send(Bytes::from_static(b"measure actual reliable delivery"))
        .unwrap();
    connection.flush().await.unwrap();
    let mut buffer = [0; UDP_BUFFER_BYTES];
    let length = peer.recv(&mut buffer).await.unwrap();
    tokio::time::advance(Duration::from_millis(25)).await;
    let now = Instant::now().into_std();
    sender
        .handle(RakSessionInput::Datagram(buffer[..length].into(), now))
        .unwrap();
    sender.tick(now).unwrap();
    sender
        .send(
            b"acknowledged marker".as_slice().into(),
            RakReliability::ReliableOrdered,
            RakPriority::Normal,
            now,
        )
        .unwrap();
    while let Some(output) = sender.poll() {
        if let RakSessionOutput::Datagram(datagram, _) = output {
            peer.send(&datagram).await.unwrap();
        }
    }
    assert_eq!(connection.recv().await.unwrap(), "acknowledged marker");
    let original = connection.engine.session.as_ref().unwrap().rtt();
    assert!(
        !original.is_zero(),
        "the original ACK did not measure a round trip"
    );
    assert_eq!(observation.get(), Some(original));
    let closing = connection.begin_close().unwrap();
    assert_eq!(observation.get(), None);
    drop(closing);
    assert_eq!(
        observation.get(),
        None,
        "retired observation retained a measurement"
    );
    let (connection, _peer, _sender) = connected_pair().await;
    let abrupt = connection.observe_rtt();
    drop(connection);
    assert_eq!(abrupt.get(), None, "abrupt drop retained a measurement");
}

/// The original consuming close must stay callable while an RTT observation is retained.
#[tokio::test]
async fn rtt_observation_does_not_block_synchronous_retirement() {
    let (connection, peer, sender) = connected_pair().await;
    let observation = connection.observe_rtt();
    let held = observation.get();
    let (completed, completion) = std::sync::mpsc::channel();
    let closer = std::thread::spawn(move || {
        let closing = connection.begin_close();
        let _ = completed.send(());
        closing
    });
    // Retaining a copied snapshot never delays the original owner's close.
    let closed_while_observed = completion.recv_timeout(Duration::from_secs(1)).is_ok();
    let _ = held;
    let closing = closer.join().expect("owned close thread panicked");
    let close_succeeded = closing.is_ok();
    drop((closing, peer, sender, observation));
    assert!(close_succeeded, "original consuming close failed");
    assert!(
        closed_while_observed,
        "RTT observation blocked synchronous retirement"
    );
}

mod backpressure;
