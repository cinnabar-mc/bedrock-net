//! Transport integration against Cinnabar's pinned Go RakNet implementation.
#![cfg(feature = "raknet")]

use std::net::{Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bedrock_net::raknet::{RakNetConnection, RakNetError, RakNetOptions};
use bytes::Bytes;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UdpSocket;
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// Reads a relay datagram, tolerating ICMP errors from endpoints closed during teardown.
/// Callers bound the exchange with a timeout or abort the owned relay task.
async fn relay_recv(socket: &UdpSocket, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
    loop {
        match socket.recv_from(buffer).await {
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused
                ) => {}
            result => return result,
        }
    }
}

/// Finds the fixture's unsplit reliable ordered acceptance and preserves all other frames.
fn inject_early_packets(datagram: &[u8], terminal: bool) -> Option<Vec<u8>> {
    if datagram.len() < 4 || datagram[0] & 0xe0 != 0x80 {
        return None;
    }
    let mut offset = 4;
    while let Some(header) = datagram.get(offset..offset + 10) {
        // The pinned Go fixture sends its connected controls with this one frame shape.
        if header[0] != (::raknet::prelude::RakReliability::ReliableOrdered as u8) << 5 {
            return None;
        }
        let payload_len = usize::from(u16::from_be_bytes([header[1], header[2]])).div_ceil(8);
        let body = offset + 10;
        let end = body + payload_len;
        let payload = datagram.get(body..end)?;
        if payload.first() == Some(&0x10) {
            let mut bytes = Vec::from(&datagram[..offset]);
            bytes.extend_from_slice(&[0, 0, 16, 0xfe, 1]);
            bytes.extend_from_slice(&datagram[offset..end]);
            bytes.extend_from_slice(&[0, 0, 16, 0xfe, 2]);
            if terminal {
                bytes.extend_from_slice(&[0, 0, 8, 0x15]);
            }
            bytes.extend_from_slice(&datagram[end..]);
            return Some(bytes);
        }
        offset = end;
    }
    None
}

#[test]
fn early_injection_selects_acceptance_after_an_earlier_control_frame() {
    let control = [0x60, 0, 72, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let acceptance = [0x60, 0, 24, 1, 0, 0, 1, 0, 0, 0, 0x10, 0x41, 0x42];
    let header = [0x84, 7, 0, 0];
    let ping_only = [header.as_slice(), &control].concat();
    assert!(inject_early_packets(&ping_only, false).is_none());
    let datagram = [header.as_slice(), &control, &acceptance, &control].concat();
    let expected = [
        header.as_slice(),
        &control,
        &[0, 0, 16, 0xfe, 1],
        &acceptance,
        &[0, 0, 16, 0xfe, 2],
        &control,
    ]
    .concat();
    assert_eq!(inject_early_packets(&datagram, false).unwrap(), expected);
}

/// Owns a loopback fixture process, which is killed by its exact child handle on test failure.
struct Peer {
    child: Child,
    address: SocketAddr,
}

/// An owned loopback relay that can discard exactly one outgoing online datagram.
struct LossRelay {
    address: SocketAddr,
    drop_next: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl LossRelay {
    /// Forwards between one client and one test peer, without changing either protocol.
    async fn start(peer: SocketAddr) -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        let drop_next = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let dropping = Arc::clone(&drop_next);
        let observed = Arc::clone(&dropped);
        let task = tokio::spawn(async move {
            let mut client = None;
            let mut buffer = [0; 65536];
            loop {
                let (length, from) = relay_recv(&socket, &mut buffer).await.unwrap();
                let target = if from == peer {
                    client.expect("client sent the first handshake datagram")
                } else {
                    client = Some(from);
                    // Online data frames have the valid bit without ACK/NACK bits.
                    let online = length != 0 && buffer[0] & 0xe0 == 0x80;
                    if online && dropping.swap(false, Ordering::Relaxed) {
                        observed.store(true, Ordering::Relaxed);
                        continue;
                    }
                    peer
                };
                socket.send_to(&buffer[..length], target).await.unwrap();
            }
        });
        Self {
            address,
            drop_next,
            dropped,
            task,
        }
    }
}

impl Drop for LossRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Peer {
    /// Starts the explicitly supplied fixture binary; unavailable fixtures produce a named skip.
    async fn start(close_after: usize) -> Option<Self> {
        Self::start_family(close_after, false).await
    }

    /// Starts a loopback peer on the selected IP family.
    async fn start_family(close_after: usize, ipv6: bool) -> Option<Self> {
        Self::start_options(close_after, ipv6, false).await
    }

    /// Starts the peer with optional reporting of the client's advertised system uptime.
    async fn start_options(close_after: usize, ipv6: bool, report_uptime: bool) -> Option<Self> {
        let Some(binary) = std::env::var_os("BEDROCK_NET_RAKNET_PEER") else {
            // CI sets BEDROCK_NET_REQUIRE_FIXTURES so a dropped helper fails instead of skipping.
            assert!(
                std::env::var_os("BEDROCK_NET_REQUIRE_FIXTURES").is_none(),
                "missing fixture: BEDROCK_NET_RAKNET_PEER; build tools/raknet-peer"
            );
            eprintln!("missing fixture: BEDROCK_NET_RAKNET_PEER; build tools/raknet-peer");
            return None;
        };
        let mut child = Command::new(binary)
            .args([
                "-close-after",
                &close_after.to_string(),
                &format!("-ipv6={ipv6}"),
                &format!("-report-uptime={report_uptime}"),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("start loopback Go fixture");
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let address = timeout(Duration::from_secs(10), lines.next_line())
            .await
            .expect("fixture publishes its address")
            .unwrap()
            .expect("fixture address line")
            .parse()
            .unwrap();
        Some(Self { child, address })
    }

    /// Waits for the owned fixture to finish after the transport closes.
    async fn finish(mut self) {
        let status = timeout(Duration::from_secs(10), self.child.wait())
            .await
            .expect("fixture exits after transport close")
            .unwrap();
        assert!(status.success(), "Go fixture failed: {status}");
    }
}

// Closing a socket immediately makes its ephemeral port eligible for another test.
// Keep network fixtures apart so release witnesses cannot observe each other's binds.
static NETWORK_FIXTURES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn go_peer_observes_client_uptime_instead_of_unix_time() {
    let _sockets = NETWORK_FIXTURES.lock().await;
    let Some(peer) = Peer::start_options(0, false, true).await else {
        return;
    };
    let exchange = async {
        let mut connection = RakNetConnection::connect(peer.address, RakNetOptions::default())
            .await
            .unwrap();
        let report = connection.recv().await.unwrap();
        assert_eq!(report.len(), 9);
        assert_eq!(report[0], 0xfe);
        let uptime_ms = i64::from_le_bytes(report[1..].try_into().unwrap());
        // This test process has not been running for a year; Unix time is decades larger.
        let year_ms = 365 * 24 * 60 * 60 * 1000;
        assert!(
            (0..year_ms).contains(&uptime_ms),
            "advertised uptime: {uptime_ms} ms"
        );
        let mut closing = connection.begin_close().unwrap();
        closing.finish_close().await.unwrap();
        peer.finish().await;
    };
    timeout(Duration::from_secs(20), exchange).await.unwrap();
}

#[tokio::test]
async fn go_peer_connects_when_a_smaller_probe_is_required_after_the_initial_grant() {
    let _sockets = NETWORK_FIXTURES.lock().await;
    let Some(peer) = Peer::start(0).await else {
        return;
    };
    let peer_address = peer.address;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let relay_address = socket.local_addr().unwrap();
    let client_cap = 1400;
    let path_mtu = 1200;
    // This fixture uses IPv4 UDP without IP options.
    let headers = 20 + usize::from(::raknet::prelude::constants::UDP_HEADER_SIZE);
    let payload_limit = path_mtu - headers;
    let mut blocked_request_two = false;
    let mut smaller_probe_arrived = false;
    let mut client_guid = None;
    let exchange = async {
        let mut connection = RakNetConnection::connect(
            relay_address,
            RakNetOptions {
                max_mtu: client_cap,
                ..RakNetOptions::default()
            },
        )
        .await
        .unwrap();
        let message = Bytes::from(vec![0xfe; 4096]);
        connection.queue_send(message.clone()).unwrap();
        assert_eq!(connection.recv().await.unwrap(), message);
        let mut closing = connection.begin_close().unwrap();
        closing.finish_close().await.unwrap();
        peer.finish().await;
    };
    {
        let forwarding = async {
            let mut client = None;
            let mut initial_probe = true;
            let mut buffer = [0; 65536];
            loop {
                let (length, from) = relay_recv(&socket, &mut buffer).await.unwrap();
                let target = if from == peer_address {
                    client.expect("client sent the first handshake datagram")
                } else {
                    client = Some(from);
                    let packet = &buffer[..length];
                    if packet.first() == Some(&0x05) {
                        if initial_probe {
                            assert_eq!(length + headers, usize::from(client_cap));
                            initial_probe = false;
                        } else if length <= payload_limit {
                            smaller_probe_arrived = true;
                        } else {
                            continue;
                        }
                    }
                    if packet.first() == Some(&0x07) {
                        let guid =
                            u64::from_be_bytes(packet[packet.len() - 8..].try_into().unwrap());
                        assert_eq!(guid >> 62, 0b10, "generated client identity type bits");
                        assert_eq!(
                            *client_guid.get_or_insert(guid),
                            guid,
                            "retry identity changed"
                        );
                        // Request 2 ends in its big-endian MTU and eight-byte GUID.
                        let mtu_at = packet.len() - 10;
                        let grant =
                            u16::from_be_bytes(packet[mtu_at..mtu_at + 2].try_into().unwrap());
                        if !smaller_probe_arrived || usize::from(grant) > path_mtu {
                            blocked_request_two = true;
                            continue;
                        }
                    }
                    if smaller_probe_arrived {
                        assert!(
                            length <= payload_limit,
                            "connected datagram exceeds the path MTU"
                        );
                    }
                    peer_address
                };
                socket.send_to(&buffer[..length], target).await.unwrap();
            }
        };
        tokio::pin!(forwarding);
        tokio::select! {
            result = timeout(Duration::from_secs(30), exchange) => {
                result.expect("a smaller probe unblocks the offline handshake");
            }
            _ = &mut forwarding => panic!("relay unexpectedly terminated"),
        }
    }
    assert!(
        blocked_request_two,
        "the first grant did not complete the handshake"
    );
    assert!(
        smaller_probe_arrived,
        "discovery continued after the initial grant"
    );
    assert!(
        client_guid.is_some(),
        "observed a client identity on the wire"
    );
}

#[tokio::test]
async fn go_peer_preserves_message_boundaries_fragmentation_and_fifo() {
    let _sockets = NETWORK_FIXTURES.lock().await;
    let Some(peer) = Peer::start(0).await else {
        return;
    };
    let mut connection = RakNetConnection::connect(peer.address, RakNetOptions::default())
        .await
        .unwrap();
    let local = connection.local_addr();
    let mut sent = Vec::new();
    for index in 0u32..12 {
        let mut message = vec![0xfe];
        message.extend_from_slice(&index.to_le_bytes());
        if index == 5 {
            message.resize(512 * 1024, 0x5a);
        }
        let message = Bytes::from(message);
        connection.queue_send(message.clone()).unwrap();
        sent.push(message);
    }
    for message in sent {
        let received = timeout(Duration::from_secs(15), connection.recv())
            .await
            .expect("loopback echo completes")
            .unwrap();
        assert_eq!(received, message);
    }
    let mut closing = connection.begin_close().unwrap();
    closing.finish_close().await.unwrap();
    // Close releases the socket even while the connection value remains alive.
    let rebound = UdpSocket::bind(local).await.unwrap();
    drop(rebound);
    peer.finish().await;
}

#[tokio::test]
async fn go_peer_exchanges_fragmented_messages_over_ipv6_and_mapped_ipv4() {
    let _sockets = NETWORK_FIXTURES.lock().await;
    for ipv6 in [true, false] {
        if ipv6 {
            match UdpSocket::bind("[::1]:0").await {
                Ok(socket) => drop(socket),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
                    ) =>
                {
                    eprintln!("missing fixture: IPv6 loopback: {error}");
                    continue;
                }
                Err(error) => panic!("bind IPv6 loopback: {error}"),
            }
        }
        let Some(peer) = Peer::start_family(0, ipv6).await else {
            return;
        };
        let address = match peer.address {
            SocketAddr::V4(v4) => SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port()),
            addr => addr,
        };
        let mut connection = RakNetConnection::connect(address, RakNetOptions::default())
            .await
            .unwrap();
        assert_eq!(connection.peer_addr(), peer.address);
        assert_eq!(connection.local_addr().is_ipv6(), ipv6);
        assert!(connection.local_addr().ip().is_loopback());
        let message = Bytes::from(vec![0xfe; 4096]);
        connection.queue_send(message.clone()).unwrap();
        assert_eq!(
            timeout(Duration::from_secs(15), connection.recv())
                .await
                .unwrap()
                .unwrap(),
            message
        );
        let mut closing = connection.begin_close().unwrap();
        closing.finish_close().await.unwrap();
        peer.finish().await;
    }
}

#[tokio::test]
async fn go_peer_acceptance_preserves_early_packets_within_configured_handshake_limits() {
    let _sockets = NETWORK_FIXTURES.lock().await;
    for (message_limit, terminal) in [(2, false), (1, false), (2, true)] {
        let Some(mut peer) = Peer::start(0).await else {
            return;
        };
        let peer_address = peer.address;
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let relay_address = socket.local_addr().unwrap();
        let exchange = async move {
            let result = RakNetConnection::connect(
                relay_address,
                RakNetOptions {
                    receive_buffer_bytes: 4,
                    receive_buffer_messages: message_limit,
                    ..RakNetOptions::default()
                },
            )
            .await;
            if message_limit == 1 {
                assert!(matches!(
                    result,
                    Err(RakNetError::Handshake(
                        ::raknet::prelude::RakClientError::HandshakeReceiveBufferExceeded
                    ))
                ));
                peer.child.kill().await.unwrap();
                return;
            }
            let mut connection = result.unwrap();
            for index in [1, 2] {
                assert_eq!(connection.recv().await.unwrap().as_ref(), [0xfe, index]);
            }
            if terminal {
                assert!(matches!(
                    connection.recv().await,
                    Err(RakNetError::Disconnected(
                        bedrock_net::raknet::DisconnectReason::Remote
                    ))
                ));
                peer.child.kill().await.unwrap();
                return;
            }
            let echoed = Bytes::from_static(&[0xfe, 3]);
            connection.queue_send(echoed.clone()).unwrap();
            assert_eq!(connection.recv().await.unwrap(), echoed);
            let mut closing = connection.begin_close().unwrap();
            closing.finish_close().await.unwrap();
            peer.finish().await;
        };
        tokio::pin!(exchange);
        let mut client = None;
        let mut injected = false;
        let mut buffer = [0; 65536];
        timeout(Duration::from_secs(15), async {
            loop {
                tokio::select! {
                    _ = &mut exchange => break,
                    received = relay_recv(&socket, &mut buffer) => {
                        let (length, from) = received.unwrap();
                        let to = if from == peer_address { client.unwrap() } else { client = Some(from); peer_address };
                        if from == peer_address && !injected
                            && let Some(bytes) = inject_early_packets(&buffer[..length], terminal) {
                            socket.send_to(&bytes, to).await.unwrap();
                            injected = true;
                            continue;
                        }
                        socket.send_to(&buffer[..length], to).await.unwrap();
                    }
                }
            }
        }).await.expect("handshake relay and owned peer finish");
        assert!(
            injected,
            "actual Go acceptance exercised early packet handoff"
        );
    }
}

#[tokio::test]
async fn go_peer_messages_are_drained_before_its_disconnect() {
    let _sockets = NETWORK_FIXTURES.lock().await;
    let Some(peer) = Peer::start(2).await else {
        return;
    };
    let mut connection = RakNetConnection::connect(peer.address, RakNetOptions::default())
        .await
        .unwrap();
    let messages = [
        Bytes::from_static(&[0xfe, 1]),
        Bytes::from_static(&[0xfe, 2]),
    ];
    for message in &messages {
        connection.queue_send(message.clone()).unwrap();
    }
    for expected in messages {
        assert_eq!(
            timeout(Duration::from_secs(10), connection.recv())
                .await
                .unwrap()
                .unwrap(),
            expected
        );
    }
    assert!(matches!(
        timeout(Duration::from_secs(10), connection.recv())
            .await
            .unwrap(),
        Err(RakNetError::Disconnected(_))
    ));
    peer.finish().await;
}

#[tokio::test]
async fn go_peer_recovers_a_lost_datagram_without_duplicate_delivery() {
    let _sockets = NETWORK_FIXTURES.lock().await;
    let Some(peer) = Peer::start(3).await else {
        return;
    };
    let relay = LossRelay::start(peer.address).await;
    let mut connection = RakNetConnection::connect(relay.address, RakNetOptions::default())
        .await
        .unwrap();
    connection.flush().await.unwrap();
    relay.drop_next.store(true, Ordering::Relaxed);
    let messages = [
        Bytes::from_static(&[0xfe, 1]),
        Bytes::from(vec![0xfe; 64 * 1024]),
        Bytes::from_static(&[0xfe, 3]),
    ];
    for message in &messages {
        connection.queue_send(message.clone()).unwrap();
    }
    for expected in messages {
        assert_eq!(
            timeout(Duration::from_secs(15), connection.recv())
                .await
                .expect("reliable delivery recovers packet loss")
                .unwrap(),
            expected
        );
    }
    assert!(relay.dropped.load(Ordering::Relaxed));
    // The peer closes after exactly three messages; a duplicate would appear here.
    assert!(matches!(
        timeout(Duration::from_secs(10), connection.recv())
            .await
            .unwrap(),
        Err(RakNetError::Disconnected(_))
    ));
    peer.finish().await;
}

#[tokio::test]
async fn go_peer_recovers_loss_during_a_burst_larger_than_its_ordered_window() {
    let _sockets = NETWORK_FIXTURES.lock().await;
    const MESSAGES: u32 = 3000;
    let Some(peer) = Peer::start(MESSAGES as usize).await else {
        return;
    };
    let relay = LossRelay::start(peer.address).await;
    let mut connection = RakNetConnection::connect(relay.address, RakNetOptions::default())
        .await
        .unwrap();
    connection.flush().await.unwrap();
    relay.drop_next.store(true, Ordering::Relaxed);
    for index in 0..MESSAGES {
        let mut message = vec![0xfe];
        message.extend_from_slice(&index.to_le_bytes());
        connection.queue_send(Bytes::from(message)).unwrap();
    }
    timeout(Duration::from_secs(30), async {
        for index in 0..MESSAGES {
            let message = connection.recv().await.unwrap();
            assert_eq!(message[0], 0xfe);
            assert_eq!(&message[1..], &index.to_le_bytes());
        }
        assert!(matches!(
            connection.recv().await,
            Err(RakNetError::Disconnected(_))
        ));
    })
    .await
    .expect("congestion-controlled burst recovers loss without outrunning ordered delivery");
    assert!(relay.dropped.load(Ordering::Relaxed));
    peer.finish().await;
}

#[tokio::test]
async fn go_peer_acknowledgements_release_send_capacity_without_consuming_messages() {
    let _sockets = NETWORK_FIXTURES.lock().await;
    let Some(peer) = Peer::start(0).await else {
        return;
    };
    let mut connection = RakNetConnection::connect(
        peer.address,
        RakNetOptions {
            send_buffer_bytes: 256,
            ..RakNetOptions::default()
        },
    )
    .await
    .unwrap();
    // Reliable handshake control messages can still occupy the configured budget.
    timeout(Duration::from_secs(10), connection.wait_send_capacity(100))
        .await
        .expect("handshake ACKs release initial application capacity")
        .unwrap();
    let mut sent = Vec::new();
    for index in 0..10u8 {
        let mut message = vec![index; 100];
        message[0] = 0xfe;
        let message = Bytes::from(message);
        match connection.queue_send(message.clone()) {
            Ok(()) => sent.push(message),
            Err(RakNetError::SendBufferFull) => break,
            Err(error) => panic!("unexpected send admission error: {error}"),
        }
    }
    assert!(
        sent.len() < 10,
        "the configured send budget applies before I/O"
    );
    assert!(
        !sent.is_empty(),
        "some application messages precede the wait"
    );
    let last = Bytes::from(vec![0xfe; 100]);
    timeout(
        Duration::from_secs(10),
        connection.wait_send_capacity(last.len()),
    )
    .await
    .expect("ACKs release outgoing capacity")
    .unwrap();
    connection.queue_send(last.clone()).unwrap();
    sent.push(last);
    for message in sent {
        assert_eq!(
            timeout(Duration::from_secs(10), connection.recv())
                .await
                .unwrap()
                .unwrap(),
            message
        );
    }
    let mut closing = connection.begin_close().unwrap();
    closing.finish_close().await.unwrap();
    peer.finish().await;
}

#[tokio::test]
async fn initial_port_refusal_retries_until_the_handshake_deadline() {
    let _sockets = NETWORK_FIXTURES.lock().await;
    let address = {
        let unused = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        unused.local_addr().unwrap()
    };
    let result = RakNetConnection::connect(
        address,
        RakNetOptions {
            connect_timeout: Duration::from_secs(1),
            ..RakNetOptions::default()
        },
    )
    .await;
    assert!(
        matches!(
            result,
            Err(RakNetError::ConnectTimeout
                | RakNetError::Handshake(::raknet::prelude::RakClientError::ConnectionFailed))
        ),
        "initial socket errors should leave retry timers active: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn cancelling_a_partial_handshake_releases_its_socket() {
    let _sockets = NETWORK_FIXTURES.lock().await;
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut connecting = Box::pin(RakNetConnection::connect(
        server.local_addr().unwrap(),
        RakNetOptions::default(),
    ));
    let mut datagram = [0; 2048];
    let client_address = tokio::select! {
        result = &mut connecting => panic!("handshake unexpectedly ended: {:?}", result.err()),
        received = server.recv_from(&mut datagram) => received.unwrap().1,
    };
    drop(connecting);
    let rebound = UdpSocket::bind(client_address).await.unwrap();
    drop(rebound);
}

#[tokio::test]
async fn handshake_deadline_releases_its_socket_without_detaching_work() {
    let _sockets = NETWORK_FIXTURES.lock().await;
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut connecting = Box::pin(RakNetConnection::connect(
        server.local_addr().unwrap(),
        RakNetOptions {
            connect_timeout: Duration::from_secs(1),
            ..RakNetOptions::default()
        },
    ));
    let mut datagram = [0; 2048];
    let client_address = tokio::select! {
        result = &mut connecting => panic!("handshake unexpectedly ended: {:?}", result.err()),
        received = server.recv_from(&mut datagram) => received.unwrap().1,
    };
    // Pause after real UDP readiness; an idle paused runtime may otherwise advance
    // the handshake deadline before the operating system delivers its first packet.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(matches!(connecting.await, Err(RakNetError::ConnectTimeout)));
    let rebound = UdpSocket::bind(client_address).await.unwrap();
    drop(rebound);
}
