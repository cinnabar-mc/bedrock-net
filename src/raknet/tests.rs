//! Regressions for terminal packet draining and cancellation of graceful close.

use std::future::{Future, poll_fn};
use std::net::Ipv4Addr;
use std::task::Poll;

use ::raknet::prelude::{RakClock, RakSessionId};

use super::*;

/// Creates an established driver and owned local peer without a handshake.
async fn connected_pair() -> (RakNetConnection, UdpSocket, RakSession) {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let local = socket.local_addr().unwrap();
    let address = peer.local_addr().unwrap();
    socket.connect(address).await.unwrap();
    peer.connect(local).await.unwrap();
    let now = Instant::now().into_std();
    let receiver = RakSession::new(
        RakSessionId(1),
        address,
        1,
        1492,
        now,
        RakClock::new(now),
        Default::default(),
    );
    let sender = RakSession::new(
        RakSessionId(2),
        local,
        2,
        1492,
        now,
        RakClock::new(now),
        Default::default(),
    );
    (
        RakNetConnection {
            socket: Some(socket),
            local,
            peer: address,
            session: Some(Box::new(receiver)),
            options: RakNetOptions::default(),
            incoming: VecDeque::new(),
            incoming_bytes: 0,
            pending_datagram: None,
            receive_buffer: vec![0; UDP_BUFFER_BYTES],
            next_tick: Instant::now(),
            close_deadline: None,
            failure: None,
        },
        peer,
        sender,
    )
}

#[tokio::test]
async fn receive_overflow_returns_only_the_prefix_before_the_rejected_message() {
    let (mut connection, peer, mut sender) = connected_pair().await;
    connection.options.receive_buffer_bytes = 64;
    let now = Instant::now().into_std();
    for message in [vec![0xfe, 1], vec![0xfe; 63], vec![0xfe, 3]] {
        sender
            .handle(RakSessionInput::Send(
                message.into_boxed_slice(),
                RakReliability::ReliableOrdered,
                RakPriority::Normal,
                now,
            ))
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
            .handle(RakSessionInput::Send(
                message,
                RakReliability::ReliableOrdered,
                RakPriority::Normal,
                now,
            ))
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
    connection.options.close_timeout = Duration::from_millis(100);
    connection
        .queue_send(Bytes::from_static(&[0xfe, 1]))
        .unwrap();
    let mut closing = Box::pin(connection.close());
    poll_fn(|cx| {
        assert!(closing.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(closing);
    // Model a completed input whose outputs have not yet been collected when close expires.
    let now = Instant::now().into_std();
    sender
        .handle(RakSessionInput::Send(
            Box::new([0xfe, 2]),
            RakReliability::ReliableOrdered,
            RakPriority::Normal,
            now,
        ))
        .unwrap();
    sender.tick(now).unwrap();
    while let Some(output) = sender.poll() {
        if let RakSessionOutput::Datagram(datagram, _) = output {
            connection
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
    assert!(matches!(
        connection.recv().await,
        Err(RakNetError::Disconnected(DisconnectReason::Requested))
    ));
    UdpSocket::bind(connection.local_addr()).await.unwrap();
}
