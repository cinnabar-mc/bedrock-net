//! Regressions for terminal packet draining and cancellation of graceful close.

use std::future::{Future, poll_fn};
use std::net::Ipv4Addr;
use std::task::Poll;

use ::raknet::prelude::{
    ClientGuid, RakClient, RakClientInput, RakClientOutput, RakClock, RakServer, RakServerConfig,
    RakServerInput, RakServerOutput,
};

use super::*;

/// Establishes both core owners through public negotiation before attaching real UDP sockets.
async fn connected_pair() -> (RakNetConnection, UdpSocket, RakSession<Established>) {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let local = socket.local_addr().unwrap();
    let address = peer.local_addr().unwrap();
    socket.connect(address).await.unwrap();
    peer.connect(local).await.unwrap();
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
                                pending_datagram: None,
                                receive_buffer: vec![0; UDP_BUFFER_BYTES],
                                next_tick: Instant::now(),
                                close_deadline: None,
                                failure: None,
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
    for index in 0..count {
        let mut message = vec![0xfe];
        message.extend_from_slice(&u32::try_from(index).unwrap().to_le_bytes());
        sender
            .send(
                message.into_boxed_slice(),
                RakReliability::ReliableOrdered,
                RakPriority::Normal,
                now,
            )
            .unwrap();
    }
    sender.tick(now).unwrap();
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
    for index in 0..count {
        let mut message = vec![0xfe];
        message.extend_from_slice(&u32::try_from(index).unwrap().to_le_bytes());
        sender
            .send(
                message.into_boxed_slice(),
                RakReliability::ReliableOrdered,
                RakPriority::Normal,
                now,
            )
            .unwrap();
    }
    sender.tick(now).unwrap();
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
    for index in 0..count {
        let mut message = vec![0xfe];
        message.extend_from_slice(&u32::try_from(index).unwrap().to_le_bytes());
        sender
            .send(
                message.into_boxed_slice(),
                RakReliability::ReliableOrdered,
                RakPriority::Normal,
                now,
            )
            .unwrap();
    }
    sender.tick(now).unwrap();
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
async fn receive_overflow_returns_only_the_prefix_before_the_rejected_message() {
    let (mut connection, peer, mut sender) = connected_pair().await;
    connection.engine.options.receive_buffer_bytes = 64;
    let now = Instant::now().into_std();
    for message in [vec![0xfe, 1], vec![0xfe; 63], vec![0xfe, 3]] {
        sender
            .send(
                message.into_boxed_slice(),
                RakReliability::ReliableOrdered,
                RakPriority::Normal,
                now,
            )
            .unwrap();
    }
    sender.tick(now).unwrap();
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
}

#[tokio::test]
async fn completed_message_precedes_a_later_frame_error_in_the_same_datagram() {
    let (mut connection, peer, mut sender) = connected_pair().await;
    let now = Instant::now().into_std();
    for message in [Box::from([0xfe, 42].as_slice()), Box::from([0].as_slice())] {
        sender
            .send(
                message,
                RakReliability::ReliableOrdered,
                RakPriority::Normal,
                now,
            )
            .unwrap();
    }
    sender.tick(now).unwrap();
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
