use super::*;

/// Sends the actual peer's queued wire output and returns its complete received messages.
async fn peer_output(peer: &UdpSocket, sender: &mut RakSession<Established>) -> Vec<Box<[u8]>> {
    let mut received = Vec::new();
    while let Some(output) = sender.poll() {
        match output {
            RakSessionOutput::Datagram(bytes, _) => {
                assert_eq!(peer.send(&bytes).await.unwrap(), bytes.len());
            }
            RakSessionOutput::Packet(bytes) => received.push(bytes),
            RakSessionOutput::Wait(_) => {}
            output => panic!("unexpected peer terminal: {output:?}"),
        }
    }
    received
}

/// Produces one real datagram whose individually valid bodies exceed aggregate capacity.
async fn send_burst(peer: &UdpSocket, sender: &mut RakSession<Established>) {
    let now = Instant::now().into_std();
    send_bundle(
        sender,
        [vec![0xfe, 1], vec![0xfe; 63], vec![0xfe, 3]]
            .into_iter()
            .map(Vec::into_boxed_slice),
        now,
    );
    assert!(peer_output(peer, sender).await.is_empty());
}

#[tokio::test]
async fn control_maintenance_keeps_full_byte_fifo_and_the_original_atomic_write() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (mut connection, peer, mut sender) = connected_pair().await;
        connection.engine.options.receive_buffer_bytes = 64;
        send_burst(&peer, &mut sender).await;
        while connection.engine.incoming.is_empty() {
            connection.engine.step().await.unwrap();
            connection.flush().await.unwrap();
        }
        let marker = Bytes::from_static(&[0xfe, 77]);
        connection.queue_send(marker.clone()).unwrap();
        let mut maintenance = Box::pin(connection.maintain());
        let mut buffer = [0; UDP_BUFFER_BYTES];
        let mut saw_marker = false;
        while !saw_marker || sender.outbound_bytes() != 0 {
            tokio::select! {
                () = &mut maintenance => panic!("maintenance completed without input consumption"),
                received = peer.recv(&mut buffer) => {
                    let length = received.unwrap();
                    let now = Instant::now().into_std();
                    sender.handle(RakSessionInput::Datagram(buffer[..length].into(), now)).unwrap();
                    sender.tick(now).unwrap();
                    for received in peer_output(&peer, &mut sender).await {
                        assert_eq!(received.as_ref(), marker.as_ref());
                        saw_marker = true;
                    }
                }
            }
        }
        drop(maintenance);
        assert_eq!(
            sender.outbound_bytes(),
            0,
            "the burst's actual ACK must progress"
        );
        assert_eq!(connection.recv().await.unwrap().as_ref(), [0xfe, 1]);
        assert_eq!(connection.recv().await.unwrap().as_ref(), vec![0xfe; 63]);
        assert_eq!(connection.recv().await.unwrap().as_ref(), [0xfe, 3]);
        while connection
            .engine
            .session
            .as_ref()
            .is_some_and(|session| session.outbound_bytes() != 0)
        {
            connection.engine.step().await.unwrap();
            connection.flush().await.unwrap();
        }
        let local = connection.local_addr();
        let mut closing = connection.begin_close().unwrap();
        closing.finish_close().await.unwrap();
        drop((closing, peer, sender));
        UdpSocket::bind(local).await.unwrap();
    })
    .await
    .expect("original socket/control owners must finish within the test bound");
}

#[tokio::test]
async fn control_maintenance_keeps_remote_terminal_behind_the_full_accepted_prefix() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for (message_limit, byte_limit) in [(1, 64), (64, 64)] {
            let (mut connection, peer, mut sender) = connected_pair().await;
            connection.engine.options.receive_buffer_messages = message_limit;
            connection.engine.options.receive_buffer_bytes = byte_limit;
            send_burst(&peer, &mut sender).await;
            while connection.engine.incoming.is_empty() {
                connection.engine.step().await.unwrap();
                connection.flush().await.unwrap();
            }
            let mut sender = sender.abort(Instant::now().into_std()).unwrap();
            while let Some(output) = sender.poll() {
                if let RakSessionOutput::Datagram(bytes, _) = output {
                    assert_eq!(peer.send(&bytes).await.unwrap(), bytes.len());
                }
            }
            while connection.engine.socket.is_some() {
                connection.engine.step().await.unwrap();
                connection.flush().await.unwrap();
            }
            let mut maintenance = Box::pin(connection.maintain());
            poll_fn(|cx| {
                assert!(maintenance.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(maintenance);
            let local = connection.local_addr();
            let mut closing = connection.begin_close().unwrap();
            assert_eq!(closing.recv().await.unwrap().as_ref(), [0xfe, 1]);
            assert_eq!(closing.recv().await.unwrap().as_ref(), vec![0xfe; 63]);
            assert_eq!(closing.recv().await.unwrap().as_ref(), [0xfe, 3]);
            assert!(matches!(
                closing.recv().await,
                Err(RakNetError::Disconnected(DisconnectReason::Remote))
            ));
            assert!(matches!(closing.recv().await, Err(RakNetError::Closed)));
            assert!(closing.try_finish().is_ok());
            assert!(sender.finish().is_ok());
            drop(peer);
            UdpSocket::bind(local).await.unwrap();
        }
    })
    .await
    .expect("original socket/control owners must finish within the test bound");
}
